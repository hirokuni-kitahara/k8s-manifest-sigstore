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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const msgAnnotation = "cosign.sigstore.dev/message"

var skipKinds = []string{
	"Event",
	//"ReplicaSet",
}

func NewCmdSign() *cobra.Command {

	var imageRef string
	var keyPath string
	var output string
	var dryrun bool
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "A command to sign all Kubernetes resources",
		RunE: func(cmd *cobra.Command, args []string) error {

			namespace := ""
			if KOptions.ConfigFlags.Namespace != nil {
				namespace = *KOptions.ConfigFlags.Namespace
			}
			err := sign(keyPath, dryrun, namespace)
			if err != nil {
				log.Fatalf("error occurred during signing: %s", err.Error())
				return nil
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "image name which bundles yaml files and be signed")
	cmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output file name or k8s signature configmap reference (if empty, use `<filename>.signed`)")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key (if empty, do key-less signing)")
	cmd.PersistentFlags().BoolVar(&dryrun, "dry-run", false, "whether actually update resources or just test with dry run mode")
	KOptions.ConfigFlags.AddFlags(cmd.PersistentFlags())
	err := KOptions.init(cmd)
	if err != nil {
		log.Fatalf("error occurred initizalize kubectl options: %s", err.Error())
		return nil
	}

	return cmd
}

func sign(keyPath string, dryrun bool, namespace string) error {
	resources, err := KOptions.ListAllResources([]string{"update"}, skipKinds)
	if err != nil {
		return errors.Wrap(err, "failed to list resources")
	}

	dir, err := ioutil.TempDir("", "cluster-sigstore-tmp")
	if err != nil {
		return errors.Wrap(err, "failed to create tmp dir")
	}
	defer os.RemoveAll(dir)
	log.Debugf("temp dir ready: %s", dir)
	// fname := "manifest.yaml"
	// fpath := filepath.Join(dir, fname)
	// opath := filepath.Join(dir, fname+".signed")

	nsList := []string{}
	if namespace != "" {
		nsList = strings.Split(namespace, ",")
	}

	kind := ""
	for _, r := range resources {

		if len(nsList) > 0 {
			if !contains(nsList, r.GetNamespace()) {
				continue
			}
		}

		kindChanged := false
		if kind != r.GetKind() {
			kind = r.GetKind()
			kindChanged = true
			log.Infof("Kind: %s", kind)
		}
		if kindChanged {
			time.Sleep(time.Second * 1)
		}
		fname := strings.ToLower(r.GetKind()) + "-" + r.GetNamespace() + "-" + r.GetName() + ".yaml"
		fpath := filepath.Join(dir, fname)
		opath := filepath.Join(dir, fname+".signed")

		var latestResource *unstructured.Unstructured
		latestResource, err = KOptions.GetResource(r)
		if err != nil {
			return errors.Wrapf(err, "failed to get the latest %s %s %s", r.GetKind(), r.GetNamespace(), r.GetName())
		}

		annotations := latestResource.GetAnnotations()
		noSigAnnotations := map[string]string{}
		sigAnnoPrefix := "cosign.sigstore.dev"
		for k, v := range annotations {
			if strings.HasPrefix(k, sigAnnoPrefix) {
				continue
			}
			noSigAnnotations[k] = v
		}
		latestResource.SetAnnotations(noSigAnnotations)

		rBytes, _ := yaml.Marshal(latestResource.Object)
		err = ioutil.WriteFile(fpath, rBytes, 0777)
		if err != nil {
			return errors.Wrap(err, "failed to write tmp manifest file")
		}
		so := &k8smanifest.SignOption{
			KeyPath:          keyPath,
			Output:           opath,
			UpdateAnnotation: true,
			Simple:           true,
		}
		if kind == "ReplicaSet" {
			so.AnnotationConfig.AlternativeSignatureAnnotationBase = "signatureAlt"
		}
		_, err = k8smanifest.Sign(fpath, so)
		if err != nil {
			return errors.Wrapf(err, "failed to sign manifest file of %s %s %s", r.GetKind(), r.GetNamespace(), r.GetName())
		}

		sBytes, err := ioutil.ReadFile(opath)
		if err != nil {
			return errors.Wrapf(err, "failed to read a signed manifest file of %s %s %s", r.GetKind(), r.GetNamespace(), r.GetName())
		}
		log.Tracef("signed bytes: %s", string(sBytes))

		var signedResource *unstructured.Unstructured
		err = yaml.Unmarshal(sBytes, &signedResource)
		if err != nil {
			return errors.Wrapf(err, "failed to unmarshal a signed manifest of %s %s %s", r.GetKind(), r.GetNamespace(), r.GetName())
		}

		err = KOptions.UpdateResource(signedResource, dryrun)
		if err != nil {
			return errors.Wrapf(err, "failed to update a signed resource %s %s %s", r.GetKind(), r.GetNamespace(), r.GetName())
		}
		rMeta := getResourceMetadata(r)
		rMetaBytes, _ := json.Marshal(rMeta)
		log.Debugf("finished; %s", string(rMetaBytes))
	}
	return nil
}
