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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const filenameIfInputIsDir = "manifest.yaml"

func NewCmdSign() *cobra.Command {

	var resBundleRef string
	var inputDir string
	var keyPath string
	var output string
	var appendSignature bool
	var replaceSignature bool
	var applySignatureConfigMap bool
	var updateAnnotation bool
	var tarballOpt string
	var allowInsecure bool
	var force bool
	var imageAnnotations []string
	var rekorURL string
	var noTlogUpload bool
	cmd := &cobra.Command{
		Use:   "sign -f FILENAME [-i IMAGE]",
		Short: "A command to sign Kubernetes YAML manifests",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !replaceSignature {
				appendSignature = true
			}

			makeTarball := (tarballOpt == "yes")

			err := sign(inputDir, resBundleRef, keyPath, rekorURL, output, appendSignature, applySignatureConfigMap, updateAnnotation, makeTarball, allowInsecure, force, noTlogUpload, imageAnnotations)
			if err != nil {
				log.Fatalf("error occurred during signing: %s", err.Error())
				return nil
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&inputDir, "filename", "f", "", "file name which will be signed (if dir, all YAMLs inside it will be signed)")
	cmd.PersistentFlags().StringVarP(&resBundleRef, "image", "i", "", "image name which bundles yaml files and be signed")
	cmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output file name or k8s signature configmap reference (if empty, use \"<filename>.signed\")")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key (if empty, do key-less signing)")
	cmd.PersistentFlags().BoolVarP(&appendSignature, "append-signature", "A", false, "if true, keep the existing signatures and append the new one to the annotation like \"signature_1\" or \"signature_2\"")
	cmd.PersistentFlags().BoolVar(&replaceSignature, "replace-signature", true, "just to clarify the default mode of signature storing. If false, \"append-signature\" is enabled automatically")
	cmd.PersistentFlags().BoolVar(&applySignatureConfigMap, "apply-signature-configmap", false, "whether to apply a generated signature configmap only when \"output\" is k8s configmap")
	cmd.PersistentFlags().BoolVar(&updateAnnotation, "annotation-metadata", true, "whether to update annotation and generate signed yaml file")
	cmd.PersistentFlags().StringVar(&tarballOpt, "tarball", "yes", "whether to make a tarball for signing (this will be default to \"no\" in v0.5.0+)")

	// cosign cli options
	cmd.PersistentFlags().BoolVar(&allowInsecure, "allow-insecure-registry", false, "whether to allow insecure connections to registries. Don't use this for anything but testing")
	cmd.PersistentFlags().BoolVar(&force, "force", false, "skip warnings and confirmations")
	cmd.PersistentFlags().StringArrayVarP(&imageAnnotations, "annotation", "a", []string{}, "extra key=value pairs to sign")
	cmd.PersistentFlags().StringVar(&rekorURL, "rekor-url", "https://rekor.sigstore.dev", "URL of rekor STL server (default \"https://rekor.sigstore.dev\")")
	cmd.PersistentFlags().BoolVar(&noTlogUpload, "no-tlog-upload", false, "whether to not upload the transparency log")

	return cmd
}

func sign(inputDir, resBundleRef, keyPath, rekorURL, output string, appendSignature, applySignatureConfigMap, updateAnnotation, tarball, allowInsecure, noTlogUpload, force bool, annotations []string) error {
	if output == "" && updateAnnotation {
		if isDir, _ := k8smnfutil.IsDir(inputDir); isDir {
			// e.g.) "./yamls/" --> "./yamls/manifest.yaml.signed"
			output = filepath.Join(inputDir, filenameIfInputIsDir+".signed")
		} else {
			// e.g.) "configmap.yaml" --> "configmap.yaml.signed"
			output = inputDir + ".signed"
		}
	}

	var anntns map[string]interface{}
	var err error
	if len(annotations) > 0 {
		anntns, err = parseAnnotations(annotations)
		if err != nil {
			return err
		}
	}

	so := &k8smanifest.SignOption{
		ResourceBundleRef: resBundleRef,
		KeyPath:           keyPath,
		Output:            output,
		UpdateAnnotation:  updateAnnotation,
		Tarball:           &tarball,
		ImageAnnotations:  anntns,
		AppendSignature:   appendSignature,
	}
	if rekorURL != "" {
		so.RekorURL = rekorURL
	}
	if noTlogUpload {
		so.NoTlogUpload = true
	}
	if allowInsecure {
		so.AllowInsecure = true
	}
	if force {
		so.Force = true
	}

	if applySignatureConfigMap && strings.HasPrefix(output, kubeutil.InClusterObjectPrefix) {
		so.ApplySigConfigMap = true
	}

	_, err = k8smanifest.Sign(inputDir, so)
	if err != nil {
		return err
	}
	if so.UpdateAnnotation {
		finalOutput := output
		if strings.HasPrefix(output, kubeutil.InClusterObjectPrefix) && !applySignatureConfigMap {
			finalOutput = k8smanifest.K8sResourceRef2FileName(output)
		}
		log.Info("signed manifest generated at ", finalOutput)
	}
	return nil
}

func parseAnnotations(annotations []string) (map[string]interface{}, error) {
	annotationsMap := map[string]interface{}{}

	for _, annotation := range annotations {
		kvp := strings.SplitN(annotation, "=", 2)
		if len(kvp) != 2 {
			return nil, fmt.Errorf("invalid flag: %s, expected key=value", annotation)
		}

		annotationsMap[kvp[0]] = kvp[1]
	}
	return annotationsMap, nil
}
