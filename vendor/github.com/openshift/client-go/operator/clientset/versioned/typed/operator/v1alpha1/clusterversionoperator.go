// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"

	v1alpha1 "github.com/openshift/api/operator/v1alpha1"
	operatorv1alpha1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1alpha1"
	scheme "github.com/openshift/client-go/operator/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// ClusterVersionOperatorsGetter has a method to return a ClusterVersionOperatorInterface.
// A group's client should implement this interface.
type ClusterVersionOperatorsGetter interface {
	ClusterVersionOperators() ClusterVersionOperatorInterface
}

// ClusterVersionOperatorInterface has methods to work with ClusterVersionOperator resources.
type ClusterVersionOperatorInterface interface {
	Create(ctx context.Context, clusterVersionOperator *v1alpha1.ClusterVersionOperator, opts v1.CreateOptions) (*v1alpha1.ClusterVersionOperator, error)
	Update(ctx context.Context, clusterVersionOperator *v1alpha1.ClusterVersionOperator, opts v1.UpdateOptions) (*v1alpha1.ClusterVersionOperator, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, clusterVersionOperator *v1alpha1.ClusterVersionOperator, opts v1.UpdateOptions) (*v1alpha1.ClusterVersionOperator, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.ClusterVersionOperator, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.ClusterVersionOperatorList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterVersionOperator, err error)
	Apply(ctx context.Context, clusterVersionOperator *operatorv1alpha1.ClusterVersionOperatorApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.ClusterVersionOperator, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, clusterVersionOperator *operatorv1alpha1.ClusterVersionOperatorApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.ClusterVersionOperator, err error)
	ClusterVersionOperatorExpansion
}

// clusterVersionOperators implements ClusterVersionOperatorInterface
type clusterVersionOperators struct {
	*gentype.ClientWithListAndApply[*v1alpha1.ClusterVersionOperator, *v1alpha1.ClusterVersionOperatorList, *operatorv1alpha1.ClusterVersionOperatorApplyConfiguration]
}

// newClusterVersionOperators returns a ClusterVersionOperators
func newClusterVersionOperators(c *OperatorV1alpha1Client) *clusterVersionOperators {
	return &clusterVersionOperators{
		gentype.NewClientWithListAndApply[*v1alpha1.ClusterVersionOperator, *v1alpha1.ClusterVersionOperatorList, *operatorv1alpha1.ClusterVersionOperatorApplyConfiguration](
			"clusterversionoperators",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *v1alpha1.ClusterVersionOperator { return &v1alpha1.ClusterVersionOperator{} },
			func() *v1alpha1.ClusterVersionOperatorList { return &v1alpha1.ClusterVersionOperatorList{} }),
	}
}
