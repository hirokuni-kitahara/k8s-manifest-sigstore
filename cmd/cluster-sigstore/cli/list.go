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
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func NewCmdList() *cobra.Command {
	var withEvent bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "A command to list all Kubernetes resources",
		RunE: func(cmd *cobra.Command, args []string) error {

			namespace := ""
			if KOptions.ConfigFlags.Namespace != nil {
				namespace = *KOptions.ConfigFlags.Namespace
			}
			err := list(withEvent, namespace)
			if err != nil {
				log.Fatalf("error occurred during listing: %s", err.Error())
				return nil
			}
			return nil
		},
	}

	cmd.PersistentFlags().BoolVar(&withEvent, "event", false, "if true, include events as resources (default to false)")
	KOptions.ConfigFlags.AddFlags(cmd.PersistentFlags())
	err := KOptions.init(cmd)
	if err != nil {
		log.Fatalf("error occurred initizalize kubectl options: %s", err.Error())
		return nil
	}

	return cmd
}

type ResourceMetadata struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

func getResourceMetadata(obj *unstructured.Unstructured) ResourceMetadata {
	return ResourceMetadata{
		APIVersion: obj.GetAPIVersion(),
		Kind:       obj.GetKind(),
		Namespace:  obj.GetNamespace(),
		Name:       obj.GetName(),
	}
}

func list(withEvent bool, namespace string) error {
	skip := []string{}
	if !withEvent {
		skip = skipKinds
	}
	resources, err := KOptions.ListAllResources([]string{}, skip)
	if err != nil {
		return err
	}

	nsList := []string{}
	if namespace != "" {
		nsList = strings.Split(namespace, ",")
	}
	for _, r := range resources {
		if len(nsList) > 0 {
			if !contains(nsList, r.GetNamespace()) {
				continue
			}
		}
		m := getResourceMetadata(r)
		mBytes, _ := json.Marshal(m)
		log.Info(string(mBytes))
	}
	return nil
}
