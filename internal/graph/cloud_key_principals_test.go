// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// M3-L3: a cloud access key finding acts as its principal — an AWS IAM user
// by its ARN, a GCP service account by project and email, an Azure
// application by object id — named as G2 names lease targets, so a key and a
// lease to the same principal meet on one node; a finding that does not name
// its principal exactly (a missing or foreign ARN, an ARN for another user,
// another kind) gets no edge.
func TestCloudAccessKeyActsAsItsPrincipalM3L3(t *testing.T) {
	finding := func(id string, meta map[string]any) store.DiscoveryFinding {
		raw, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		return store.DiscoveryFinding{ID: id, Kind: "cloud_access_key", Metadata: raw}
	}
	g := New()
	lease := "res:gcp_service_account:gcp://projects/orders-prod/serviceAccounts/deployer@orders-prod.iam.gserviceaccount.com"
	g.AddNode(Node{ID: lease, Kind: KindResource, Name: "lease target", Attrs: map[string]string{"resource_kind": "cloud_identity", "from": "lease"}})
	cases := []struct {
		f    store.DiscoveryFinding
		want string
	}{
		{finding("aws", map[string]any{"provider": "aws-iam", "user": "deployer", "user_arn": "arn:aws:iam::123456789012:user/ci/deployer"}),
			"res:aws_iam_user:arn:aws:iam::123456789012:user/ci/deployer"},
		{finding("gcp", map[string]any{"provider": "gcp-iam", "user": "deployer@orders-prod.iam.gserviceaccount.com", "project": "orders-prod"}), lease},
		{finding("azure", map[string]any{"provider": "azure-entra", "user": "Orders API", "app_object_id": "0F3C9A71-2D4E-4B8A-9C1D-5E6F7A8B9C0D"}),
			"res:azure_application:azure://applications/0f3c9a71-2d4e-4b8a-9c1d-5e6f7a8b9c0d"},
		{finding("aws-no-arn", map[string]any{"provider": "aws-iam", "user": "deployer"}), ""},
		{finding("aws-other-user", map[string]any{"provider": "aws-iam", "user": "deployer", "user_arn": "arn:aws:iam::123456789012:user/someone-else"}), ""},
		{finding("aws-role", map[string]any{"provider": "aws-iam", "user": "deployer", "user_arn": "arn:aws:iam::123456789012:role/deployer"}), ""},
		{store.DiscoveryFinding{ID: "secret", Kind: "secret_store", Metadata: json.RawMessage(`{"provider":"aws-iam"}`)}, ""},
	}
	for _, c := range cases {
		addCloudKeyPrincipal(g, c.f, "disc:"+c.f.ID)
		var got string
		for _, e := range g.edges {
			if e.From == "disc:"+c.f.ID && e.Type == EdgeGrantsAccess {
				got = e.To
			}
		}
		if got != c.want {
			t.Fatalf("%s: principal %q, want %q", c.f.ID, got, c.want)
		}
	}
	if n, _ := g.Node(lease); n.Attrs["from"] != "lease" {
		t.Fatalf("the lease's node was replaced: %+v", n)
	}
}
