// Package helm holds reality tests for the certctl control-plane Helm chart under
// deploy/helm/certctl. The chart itself is plain YAML/templates; these tests
// assert it exists, is structurally complete (control plane + isolated signer,
// external datastores, NetworkPolicy, TLS), and that every template is
// syntactically valid Go/Helm templating — `helm lint`/`helm template` run the
// full render in CI.
package helm
