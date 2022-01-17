//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package cli

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

type KubectlOptions struct {
	ConfigFlags *genericclioptions.ConfigFlags

	factory                     cmdutil.Factory
	ioStreams                   genericclioptions.IOStreams
	matchVersionKubeConfigFlags *cmdutil.MatchVersionFlags
	apiResources                []*metav1.APIResource
}

func (o *KubectlOptions) init(cmd *cobra.Command) error {
	o.ioStreams = genericclioptions.IOStreams{In: cmd.InOrStdin(), Out: cmd.OutOrStdout(), ErrOut: cmd.ErrOrStderr()}
	o.matchVersionKubeConfigFlags = cmdutil.NewMatchVersionFlags(o.ConfigFlags.WithDeprecatedPasswordFlag())
	o.factory = cmdutil.NewFactory(o.matchVersionKubeConfigFlags)
	return nil
}

func (o *KubectlOptions) APIResources() ([]*metav1.APIResource, error) {
	apiResources := []*metav1.APIResource{}
	discoveryClient, err := o.factory.ToDiscoveryClient()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get discovery client")
	}
	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get server preferred resources")
	}
	for _, list := range apiResourceLists {
		if len(list.APIResources) == 0 {
			continue
		}
		gv, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			continue
		}
		for i := range list.APIResources {
			resource := &(list.APIResources[i])
			if len(resource.Verbs) == 0 {
				continue
			}
			res := resource
			res.Group = gv.Group
			res.Version = gv.Version
			apiResources = append(apiResources, res)
		}
	}
	o.apiResources = apiResources
	return apiResources, nil
}

func (o *KubectlOptions) ListResources(apiResource *metav1.APIResource) ([]*unstructured.Unstructured, error) {
	dynamicClient, err := o.factory.DynamicClient()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get dynamic client")
	}
	gvr := schema.GroupVersionResource{
		Group:    apiResource.Group,
		Version:  apiResource.Version,
		Resource: apiResource.Name,
	}
	resourceClient := dynamicClient.Resource(gvr)

	resources := []*unstructured.Unstructured{}
	var tmpList *unstructured.UnstructuredList
	if apiResource.Namespaced {
		tmpList, err = resourceClient.Namespace("").List(context.Background(), metav1.ListOptions{})
	} else {
		tmpList, err = resourceClient.List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list resources for kind: %s", apiResource.Kind)
	}

	for i := range tmpList.Items {
		r := tmpList.Items[i]
		resources = append(resources, &r)
	}
	return resources, nil
}

func (o *KubectlOptions) ListAllResources(additionalVerbs, skipKinds []string) ([]*unstructured.Unstructured, error) {
	apiResources, err := o.APIResources()
	if err != nil {
		return nil, errors.Wrap(err, "failed to list api resources")
	}
	resources := []*unstructured.Unstructured{}
	for _, apiRes := range apiResources {
		if !contains(apiRes.Verbs, "list") {
			continue
		}
		verbsSupported := true
		for _, v := range additionalVerbs {
			if !contains(apiRes.Verbs, v) {
				verbsSupported = false
				break
			}
		}
		if !verbsSupported {
			continue
		}
		if contains(skipKinds, apiRes.Kind) {
			continue
		}
		tmpResources, err := o.ListResources(apiRes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to list resources")
		}
		resources = append(resources, tmpResources...)
	}
	return resources, nil
}

func (o *KubectlOptions) GetResource(resource *unstructured.Unstructured) (*unstructured.Unstructured, error) {

	dynamicClient, err := o.factory.DynamicClient()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get dynamic client")
	}
	gvr, err := o.getGroupVersionResource(resource)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get group version resource")
	}
	resourceClient := dynamicClient.Resource(*gvr)

	gopt := metav1.GetOptions{}

	namespaced := (resource.GetNamespace() != "")
	var latestResource *unstructured.Unstructured
	if namespaced {
		latestResource, err = resourceClient.Namespace(resource.GetNamespace()).Get(context.Background(), resource.GetName(), gopt)
	} else {
		latestResource, err = resourceClient.Get(context.Background(), resource.GetName(), gopt)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get a resource %s %s", resource.GetKind(), resource.GetName())
	}
	return latestResource, nil
}

func (o *KubectlOptions) UpdateResource(resource *unstructured.Unstructured, dryrun bool) error {

	dynamicClient, err := o.factory.DynamicClient()
	if err != nil {
		return errors.Wrap(err, "failed to get dynamic client")
	}
	gvr, err := o.getGroupVersionResource(resource)
	if err != nil {
		return errors.Wrap(err, "failed to get group version resource")
	}
	resourceClient := dynamicClient.Resource(*gvr)

	uo := metav1.UpdateOptions{}
	if dryrun {
		uo.DryRun = []string{metav1.DryRunAll}
	}

	namespaced := (resource.GetNamespace() != "")
	if namespaced {
		_, err = resourceClient.Namespace(resource.GetNamespace()).Update(context.Background(), resource, uo)
	} else {
		_, err = resourceClient.Update(context.Background(), resource, uo)
	}
	if err != nil {
		return errors.Wrapf(err, "failed to update a resource %s %s", resource.GetKind(), resource.GetName())
	}
	return nil
}

func (o *KubectlOptions) getGroupVersionResource(resource *unstructured.Unstructured) (*schema.GroupVersionResource, error) {
	if len(o.apiResources) == 0 {
		_, err := o.APIResources()
		if err != nil {
			return nil, errors.Wrap(err, "failed to list api resources")
		}
	}
	kind := resource.GetKind()
	apiVersion := resource.GetAPIVersion()
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse group version")
	}
	gvr := &schema.GroupVersionResource{Group: gv.Group, Version: gv.Version}

	for _, apiResource := range o.apiResources {
		if apiResource.Kind == kind {
			gvr.Resource = apiResource.Name
			return gvr, nil
		}
	}
	return nil, fmt.Errorf("failed to find resource name for kind %s", kind)
}

func contains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

func sortAPIResources(apiResources []*metav1.APIResource, priorities []string) []*metav1.APIResource {
	if len(priorities) == 0 {
		return apiResources
	}
	sorted := []*metav1.APIResource{}
	picked := map[int]bool{}
	// add prioritized API Resources in the priority order
	for _, kind := range priorities {
		for i := range apiResources {
			if apiResources[i].Kind == kind {
				sorted = append(sorted, apiResources[i])
				picked[i] = true
				continue
			}
		}
	}

	// add rest of API Resources
	for i := range apiResources {
		if picked[i] {
			continue
		}
		sorted = append(sorted, apiResources[i])
	}

	return sorted
}
