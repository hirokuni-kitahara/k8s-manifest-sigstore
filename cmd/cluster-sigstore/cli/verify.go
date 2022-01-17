//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewCmdVerify() *cobra.Command {

	var imageRef string
	var keyPath string
	var configPath string
	var disableDefaultConfig bool
	var disableDryRun bool
	var legacy bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "A command to verify all Kubernetes resources",
		RunE: func(cmd *cobra.Command, args []string) error {

			namespace := ""
			if KOptions.ConfigFlags.Namespace != nil {
				namespace = *KOptions.ConfigFlags.Namespace
			}
			err := verify(keyPath, configPath, disableDefaultConfig, disableDryRun, legacy, namespace)
			if err != nil {
				log.Fatalf("error occurred during verifying: %s", err.Error())
				return nil
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "image name which bundles yaml files and be signed")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your verification key (if empty, do key-less verification)")
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to verification config YAML file or k8s object identifier like k8s://[KIND]/[NAMESPACE]/[NAME]")
	cmd.PersistentFlags().BoolVar(&disableDefaultConfig, "disable-default-config", false, "if true, disable default ignore fields configuration (default to false)")
	cmd.PersistentFlags().BoolVar(&disableDryRun, "disable-dryrun", false, "if true, disable dryrun for matching (default to false)")
	cmd.PersistentFlags().BoolVar(&legacy, "legacy", false, "if true, do legacy verification (= not simple mode)")

	KOptions.ConfigFlags.AddFlags(cmd.PersistentFlags())
	err := KOptions.init(cmd)
	if err != nil {
		log.Fatalf("error occurred initizalize kubectl options: %s", err.Error())
		return nil
	}

	return cmd
}

type VerifyResult struct {
	Verified   bool                              `json:"verified"`
	DryRunUsed bool                              `json:"dryRunUsed"`
	Metadata   ResourceMetadata                  `json:"metadata"`
	Result     *k8smanifest.VerifyResourceResult `json:"result"`
	Error      string                            `json:"error"`
}

func verify(keyPath, configPath string, disableDefaultConfig, disableDryRun, legacy bool, namespace string) error {
	resources, err := KOptions.ListAllResources([]string{"update"}, skipKinds) // apiResource which does not have "update" verb cannot be signed, so filter them
	if err != nil {
		return errors.Wrap(err, "failed to list resources")
	}

	vo := &k8smanifest.VerifyResourceOption{}
	if configPath != "" {
		vo, err = k8smanifest.LoadVerifyResourceConfig(configPath)
		if err != nil {
			return errors.Wrapf(err, "failed to load verify-resource config from %s", configPath)
		}
	}
	if !disableDefaultConfig {
		vo = k8smanifest.AddDefaultConfig(vo)
	}
	vo.SetAnnotationIgnoreFields()

	if keyPath != "" {
		vo.KeyPath = keyPath
	}
	if disableDryRun {
		vo.DisableDryRun = true
	}
	if !legacy {
		vo.Simple = true
	}

	nsList := []string{}
	if namespace != "" {
		nsList = strings.Split(namespace, ",")
	}

	count := 0
	elapsed := time.Second * 0
	for _, r := range resources {

		if len(nsList) > 0 {
			if !contains(nsList, r.GetNamespace()) {
				continue
			}
		}

		if r.GetKind() == "ReplicaSet" {
			vo.AnnotationConfig.AlternativeSignatureAnnotationBase = "signatureAlt"
		} else {
			vo.AnnotationConfig.AlternativeSignatureAnnotationBase = ""
		}

		ti := time.Now().UTC()
		result, err := k8smanifest.VerifyResource(*r, vo)
		ei := ti.Sub(time.Now().UTC())
		elapsed = elapsed + ei
		count += 1

		verified := false
		dryRunUsed := false
		errStr := ""
		if err == nil && result != nil {
			verified = result.Verified
			dryRunUsed = result.DryRunUsedForMatch
		} else {
			errStr = err.Error()
		}

		rMeta := getResourceMetadata(r)
		vr := VerifyResult{
			Verified:   verified,
			DryRunUsed: dryRunUsed,
			Metadata:   rMeta,
			Result:     result,
			Error:      errStr,
		}

		vrBytes, _ := json.Marshal(vr)
		if verified {
			log.Infof("%s", string(vrBytes))
		} else {
			log.Errorf("%s", string(vrBytes))
		}
	}
	fmt.Println("elapsed: ", elapsed)
	fmt.Println("count: ", count)
	return nil
}
