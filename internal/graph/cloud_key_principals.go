// SPDX-License-Identifier: BUSL-1.1

package graph

import (
	"encoding/json"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/discovery/cloudkeys"
	"trstctl.com/trstctl/internal/store"
)

// M3-L3: a discovered cloud access key authenticates as one principal — an
// AWS IAM user, a GCP service account, an Azure application — so the graph
// draws key → principal (GRANTS_ACCESS): whoever has the key acts as that
// principal. The principal is the node the access graph already names it by
// (G2's lease targets), so a key and a lease reaching the same principal
// meet there. A key whose principal its finding does not name exactly gets
// no edge.

var awsIAMUserARN = regexp.MustCompile(`^arn:aws(-us-gov|-cn)?:iam::[0-9]{12}:user/[A-Za-z0-9+=,.@_/-]+$`)

var gcpServiceAccountEmail = regexp.MustCompile(`^[a-z0-9-]+@[a-z0-9.-]+\.gserviceaccount\.com$`)

var gcpProjectID = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

var azureObjectID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// cloudKeyPrincipal names the principal a cloud access key finding
// authenticates as: its target kind and reference, or ok false.
func cloudKeyPrincipal(f store.DiscoveryFinding) (kind, ref string, ok bool) {
	if f.Kind != cloudkeys.FindingKind {
		return "", "", false
	}
	var meta struct {
		Provider    string `json:"provider"`
		User        string `json:"user"`
		UserARN     string `json:"user_arn"`
		Project     string `json:"project"`
		AppObjectID string `json:"app_object_id"`
	}
	if json.Unmarshal(f.Metadata, &meta) != nil {
		return "", "", false
	}
	switch meta.Provider {
	case cloudkeys.ProviderAWSIAM:
		if awsIAMUserARN.MatchString(meta.UserARN) && strings.HasSuffix(meta.UserARN, "/"+meta.User) {
			return "aws_iam_user", meta.UserARN, true
		}
	case cloudkeys.ProviderGCPIAM:
		if gcpServiceAccountEmail.MatchString(meta.User) && gcpProjectID.MatchString(meta.Project) {
			return "gcp_service_account", "gcp://projects/" + meta.Project + "/serviceAccounts/" + meta.User, true
		}
	case cloudkeys.ProviderAzureEntra:
		if azureObjectID.MatchString(meta.AppObjectID) {
			return "azure_application", "azure://applications/" + strings.ToLower(meta.AppObjectID), true
		}
	}
	return "", "", false
}

// addCloudKeyPrincipal draws the key → principal edge for a cloud access key
// finding whose node is keyNode.
func addCloudKeyPrincipal(g *Graph, f store.DiscoveryFinding, keyNode string) {
	kind, ref, ok := cloudKeyPrincipal(f)
	if !ok {
		return
	}
	id := resourceID(kind + ":" + ref)
	if _, exists := g.Node(id); !exists {
		g.AddNode(Node{ID: id, Kind: KindResource, Name: ref, Attrs: map[string]string{
			"resource_kind": "cloud_identity", "target_kind": kind, "target": ref,
		}})
	}
	g.AddEdge(Edge{From: keyNode, To: id, Type: EdgeGrantsAccess, Source: "cloud access key owner read by discovery", Confidence: "observed"})
}
