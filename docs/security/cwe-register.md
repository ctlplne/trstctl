<!-- GENERATED FILE — do not edit by hand.
     Regenerate: scripts/ci/gen-cwe-docs.py
     CI verifies freshness with --check. -->

# CWE register

Every triaged weakness finding in this repository: what was fixed (with the
guard that fails if the weakness returns) and every accepted or
false-positive verdict, harvested from the `#nosec G### -- reason` waivers
in the source itself. A waiver with no rule id or no reason fails the
generator, so a blanket suppression cannot exist in the tree.

The scan scope is the `make lint` scope (`clients cmd deploy docs internal
scripts tools`). `ee/` is outside the golangci/gosec scope and is covered by
CodeQL in CI. CodeQL itself runs server-side (`security-extended`, push/PR/
weekly); its findings are triaged in the code-scanning UI and land here as
fixes or waivers when they surface. There are currently no open CodeQL
alerts recorded against this register.

## Detectors wired into CI

| Detector | Coverage | Wired at |
|---|---|---|
| CodeQL `security-extended` | the broadest CWE query set; push, PR, and weekly | `.github/workflows/codeql.yml` |
| gosec (in golangci-lint) | Go-specific CWE-mapped rules G1xx-G7xx over the full lint scope; zero open findings — every site is fixed or carries a reasoned in-source waiver listed below | `.golangci.yml via make lint` |
| govulncheck | reachability-aware dependency vulnerabilities | `make vuln + the govulncheck CI job` |
| gitleaks | committed secrets (CWE-798) | `.github/workflows/security.yml` |
| Trivy | container image and native-binary CVEs | `.github/workflows/security.yml` |
| ClusterFuzzLite + TestEveryUntrustedParserIsFuzzed | memory/parsing classes on untrusted input | `repo fuzz targets` |
| trstctllint (9 analyzers) | architecture classes: tenant scoping (CWE-639-shaped), key material in strings (CWE-316-shaped), SSRF/exec surfaces (CWE-918/CWE-78), certificate-verification bypass (CWE-295), crypto boundary, idempotency, event sourcing, editions fence | `tools/trstctllint via make lint` |
| npm audit surfaces + license audits | console and SDK-generator dependency advisories | `scripts/ci/npm-audit-dependency-surfaces.sh` |

## Fixed, each with a guard

| CWE | Where | What was fixed | Guard that fails if it returns |
|---|---|---|---|
| CWE-190 | `internal/crypto/seal/seal.go` | Seal accepted a wrapped DEK larger than the v1 container's 2-byte length prefix and silently mis-framed it; now refused with ErrFormat. | TestSealRefusesOversizedWrappedDEK (internal/crypto/seal/bounds_guard_test.go) |
| CWE-295 | `internal/crypto/mtls/mtls.go` | Pinned TLS configs enforced the key pin only in VerifyPeerCertificate, which resumed sessions skip, so a session ticket could outlive a pin rotation; pinned listeners now disable tickets and re-verify the pin in VerifyConnection. | TestPinnedConfigsEnforcePinOnResumedSessions (internal/crypto/mtls/resumption_pin_test.go) |
| CWE-79 | `internal/secretstore/access.go` | The secret-store access API returned secret bytes with no declared content type, inviting browsers to sniff them into a renderable type; every response now declares Content-Type and X-Content-Type-Options: nosniff. | TestAPIResponsesDeclareContentTypeAndNosniff (internal/secretstore/access_headers_test.go) |
| CWE-295 | `tools/trstctllint/tlsverify` | Class guard, not an instance fix: the ninth trstctllint analyzer forbids InsecureSkipVerify outside the tlsprobe discovery prober, the mtls loopback liveness probe, and _test.go files, so the class cannot reappear anywhere in shipped code. | TestTLSVerify fixtures (tools/trstctllint/tlsverify) + the repo-wide linter selftest |

## Waivers (accepted or false-positive, in-source, reasoned)

1041 annotated sites across 25 rules. Each row is
generated from the `#nosec` comment at that exact line; edit the source,
not this file.

### G101 — CWE-798 Use of hardcoded credentials (229 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:93` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `cmd/trstctl/main_test.go:371` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/demo/demo_test.go:68` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/deploycheck_test.go:1444` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/deploycheck_test.go:1446` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/deploycheck_test.go:1466` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:164` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:600` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:802` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:811` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:827` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:887` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1085` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1188` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1196` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1495` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1526` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1528` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/agent/discovery/kubernetes.go:89` | metadata key naming the Kubernetes Secret a public certificate was found in; no credential value present (CWE-798) |
| `internal/agent/k8s/client.go:29` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/agent/relay/relay_test.go:133` | "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798) |
| `internal/agent/relay/relay_test.go:175` | "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798) |
| `internal/agent/relay/relay_test.go:313` | reference NAME, not a credential (CWE-798) |
| `internal/agent/relay/relay_test.go:371` | reference NAME (CWE-798) |
| `internal/agent/transport/agentservice.go:587` | an RPC method name, not a credential. The material this |
| `internal/agent/transport/receipt.go:158` | an operator-facing refusal phrase matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/aimodel/redactor_test.go:39` | fixture: AWS's documented example key id; the redactor must catch it (CWE-798) |
| `internal/aimodel/redactor_test.go:69` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/aimodel/redactor_test.go:82` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/aimodel/redactor_test.go:87` | fixture: fabricated DSN password; the redactor must catch it (CWE-798) |
| `internal/aimodel/redactor_test.go:92` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/aimodel/redactor_test.go:97` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/aimodel/redactor_test.go:102` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/aimodel/redactor_test.go:107` | fixture: fabricated PEM fragment; the redactor must catch it (CWE-798) |
| `internal/aimodel/redactor_test.go:112` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/aimodel/redactor_test.go:157` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/aimodel/redactor_test.go:162` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/acme_dns01.go:505` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/agents.go:58` | source-kind label naming where key material was located; no credential value present (CWE-798) |
| `internal/api/aisurface_contract_test.go:148` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/idempotency_binding_test.go:19` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:11` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:17` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:26` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:27` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:28` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:41` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/managedkeys_test.go:181` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/nhi_inventory.go:166` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/notifications.go:619` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/notifications.go:945` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/notifications_helpers_test.go:68` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/openapi.go:159` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_posture.go:778` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_posture.go:926` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:423` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:447` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:503` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:513` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:523` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/auth/oidc_client_secret.go:15` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/broker/issuanceprecondition_test.go:48` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/ca/ejbca/ejbcafake/ejbcafake.go:28` | test-support package compiled only into test binaries (CWE-798) |
| `internal/ca/letsencrypt/acmefake/acmefake.go:29` | fabricated fixture challenge token in a test double; no value is real (CWE-798) |
| `internal/ca/venafi/venafifake/venafifake.go:25` | test-support package compiled only into test binaries (CWE-798) |
| `internal/cbom/coverage/envelope.go:42` | precondition identifier matching the credential-name heuristic; no credential value (CWE-798) |
| `internal/cbom/coverage/envelope.go:45` | precondition identifier matching the credential-name heuristic; no credential value (CWE-798) |
| `internal/cbom/coverage/envelope.go:46` | precondition identifier matching the credential-name heuristic; no credential value (CWE-798) |
| `internal/cloudauth/azure.go:19` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/cloudauth/gcp.go:22` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/cloudauth/gcp.go:23` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/cloudauth/gcp.go:24` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/config/ai_test.go:91` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/audit_test.go:32` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/audit_test.go:67` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/audit_test.go:80` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config.go:1834` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/config/config.go:2415` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/config/config_test.go:64` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:169` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:353` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:359` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:362` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:365` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:368` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:11` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:43` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:45` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:46` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:47` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:49` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:67` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:91` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/ldap_test.go:8` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/migrate_config_test.go:24` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/migrate_config_test.go:45` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/oidc_test.go:13` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/oidc_test.go:114` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/ratelimit_test.go:30` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/ratelimit_test.go:56` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/saml_test.go:8` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/scim_test.go:10` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/scim_test.go:56` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secret_integrations_test.go:153` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secret_integrations_test.go:157` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secret_integrations_test.go:161` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secret_integrations_test.go:165` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secrets_config_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secrets_config_test.go:41` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secrets_config_test.go:60` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:35` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:47` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:107` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:115` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/acm/acm_test.go:20` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/azurekv/token_test.go:20` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/azurekv/token_test.go:63` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/fortigate/fortigate_test.go:19` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/gcpcm/gcpcm_test.go:18` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/kemp/kemp_test.go:65` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/paloalto/paloalto_test.go:21` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/discovery/apikey/apikey_test.go:13` | synthetic credential REFERENCE (ref + fingerprint only, no value): the package's contract (CWE-798) |
| `internal/discovery/apikey/apikey_test.go:20` | synthetic credential REFERENCE (ref + fingerprint only, no value): the package's contract (CWE-798) |
| `internal/discovery/apikey/apikey_test.go:25` | synthetic credential REFERENCE (ref + fingerprint only, no value): the package's contract (CWE-798) |
| `internal/dns/akamai/akamai_test.go:26` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/dns/cloudflare/cloudflare_test.go:24` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/dns/googledns/googledns_test.go:267` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/dns/ns1/ns1.go:45` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/dns/ns1/ns1_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/dns/ultradns/ultradns_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/kms/gcpkms/gcpkms_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/mcpserver/mcpserver_test.go:82` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/notify/notify.go:62` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/notify/webhook/webhook_test.go:23` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/operator/client.go:37` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/reconcile_test.go:312` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/operator/secretinjection.go:22` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:23` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:24` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:25` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:27` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:28` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:29` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:30` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:31` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretsync.go:26` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretsync.go:27` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretsync.go:28` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/orchestrator/outbox_internal_test.go:914` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/orchestrator/outbox_internal_test.go:963` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/perf/capacity.go:11` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/perf/perf_test.go:178` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/projections/apitoken_test.go:59` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/projections/cli_api_test.go:90` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/projections/secret_integrations.go:28` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/risk/contextual_test.go:109` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/aisurface_served_test.go:112` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/auth_unit_test.go:96` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/azure_workload_identity_served_test.go:26` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:626` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:628` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:747` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:964` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1044` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1050` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1089` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1102` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1128` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1322` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1334` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2056` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2189` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2198` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2375` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2514` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2536` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2704` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2715` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2725` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/gcp_workload_identity_served_test.go:27` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:24` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:33` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:125` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:134` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:147` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:183` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:192` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:211` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:219` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/managedkeys_cloudkms_served_test.go:30` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:45` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:47` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:449` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:56` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:162` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:195` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:584` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:309` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:445` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:536` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:573` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:643` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:719` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:893` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:32` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:52` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:53` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:55` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/scim_served_test.go:33` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_integrations.go:919` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/server/secret_third_party_scan_served_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_scan_served_test.go:125` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_served_test.go:384` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_served_test.go:1079` | fabricated STS exchange fixture; no real credential (CWE-798) |
| `internal/server/secrets_sync_served_test.go:386` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_sync_served_test.go:397` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_sync_served_test.go:407` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_sync_served_test.go:416` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:28` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:149` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:150` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:151` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:152` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/store/agent_bootstrap_token_test.go:67` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/store/secret_sync_workload_identity.go:202` | SQL column list matching the secret-name heuristic; a query, not a credential (CWE-798) |
| `tools/dodcensus/claims.go:162` | developer-tool constant matching the secret-name heuristic; no credential value (CWE-798) |
| `tools/dodcensus/runtime.go:39` | developer-tool constant matching the secret-name heuristic; no credential value (CWE-798) |
| `tools/trstctllint/keymaterial/keymaterial_test.go:51` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `tools/trstctllint/keymaterial/keymaterial_test.go:87` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |

### G107 — CWE-88 Argument injection (variable URL request) (1 sites)

| Location | Reason |
|---|---|
| `internal/protocols/scep/profile_routes_test.go:106` | test drives its own local server URL (CWE-88) |

### G112 — CWE-400 Uncontrolled resource consumption (slowloris) (8 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:423` | local test listener owned and torn down by the test (CWE-400) |
| `internal/agent/http_enroll_test.go:148` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/reload_test.go:95` | loopback test listener torn down by the test (CWE-400) |
| `internal/crypto/mtls/server_test.go:32` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/server_test.go:95` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/server_test.go:168` | local test listener owned and torn down by the test (CWE-400) |
| `internal/server/dod_parent_substrate_bridge_runtime_test.go:183` | local test listener owned and torn down by the test (CWE-400) |
| `internal/server/serve_test.go:17` | local test listener owned and torn down by the test (CWE-400) |

### G115 — CWE-190 Integer overflow or wraparound (130 sites)

| Location | Reason |
|---|---|
| `deploy/helm/helm_test.go:1705` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/api/machine_sessions_served_test.go:61` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/api/notifications_helpers_test.go:187` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/api/secretjson.go:167` | rune already range-checked below 0x20 before hex packing (CWE-190) |
| `internal/api/vault_compat_complete.go:672` | DER length of a public key, far under the uint32 bound (CWE-190) |
| `internal/audit/audit.go:148` | event sequence/count fits int64 by construction; bounded by the log (CWE-190) |
| `internal/audit/retention.go:246` | event sequence/count fits int64 by construction; bounded by the log (CWE-190) |
| `internal/backup/backup.go:170` | record counts bounded by the event log; fits both int and uint64 (CWE-190) |
| `internal/backup/backup.go:620` | record counts bounded by the event log; fits both int and uint64 (CWE-190) |
| `internal/ca/hierarchy/hierarchy_test.go:39` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/cli/doctor/doctor_test.go:37` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/crypto/argon2id.go:69` | length of a stored KDF hash, far under the uint32 bound (CWE-190) |
| `internal/crypto/ctlog/ctlogtest/ctlogtest.go:286` | test-support package compiled only into test binaries (CWE-190) |
| `internal/crypto/ctlog/ctlogtest/ctlogtest.go:303` | test-support package compiled only into test binaries (CWE-190) |
| `internal/crypto/seal/seal.go:198` | bounded to maxUint16Value by the check above (CWE-190) |
| `internal/crypto/seal/seal.go:550` | validateDomain above caps the length at maxUint16Value (CWE-190) |
| `internal/crypto/seal/seal.go:553` | bounded to maxUint16Value by the guard above (CWE-190) |
| `internal/crypto/signauth.go:66` | enum purpose and bounded message length framing (CWE-190) |
| `internal/crypto/signauth.go:76` | enum purpose and bounded message length framing (CWE-190) |
| `internal/crypto/ssh.go:69` | certificate validity epoch seconds; non-negative by validation (CWE-190) |
| `internal/crypto/ssh.go:70` | certificate validity epoch seconds; non-negative by validation (CWE-190) |
| `internal/crypto/tenantwrap/tenantwrap.go:238` | fixed-format buffer: a wrapped domain KEK has a fixed sealed length; an impossible oversize panics the slice bounds rather than truncating (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:246` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:263` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:283` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:298` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:299` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:314` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:339` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:343` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dynsecret/drivers.go:208` | SQL Server TDS prelogin framing of short bounded fields (CWE-190) |
| `internal/dynsecret/drivers.go:216` | SQL Server TDS prelogin framing of short bounded fields (CWE-190) |
| `internal/dynsecret/providers_real_test.go:480` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/events/backup_history_test.go:206` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/historycontinuity/continuity_test.go:157` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/idemgc/idemgc_test.go:35` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/awskms/awskms_test.go:84` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/pkcs11/pkcs11_test.go:44` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/tpm/tpm_test.go:60` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/tpm/tpm_test.go:94` | deliberate byte packing of a bounded TPM handle in a test helper (CWE-190) |
| `internal/kms/tpm/tpm_test.go:95` | deliberate byte packing of a bounded TPM handle in a test helper (CWE-190) |
| `internal/kms/tpm/tpm_test.go:96` | deliberate byte packing of a bounded TPM handle in a test helper (CWE-190) |
| `internal/kms/tpm/tpm_test.go:245` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/leader/leader_test.go:36` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/mdm/challenge.go:79` | unix-epoch seconds round-trip; in int64 range until year 292e9 (CWE-190) |
| `internal/mdm/challenge.go:90` | unix-epoch seconds round-trip; in int64 range until year 292e9 (CWE-190) |
| `internal/observ/trace.go:228` | deliberate byte packing of a trace id (CWE-190) |
| `internal/orchestrator/main_test.go:67` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/outboxgc/outboxgc_test.go:37` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/perf/live.go:848` | page size is positive and small (CWE-190) |
| `internal/projections/full_dr_test.go:369` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/projections/projections_test.go:45` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/projections/tenant_key_domain_test.go:59` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/projections/tenant_key_domain_test.go:341` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/protocols/ari/ari.go:94` | deterministic per-certificate renewal jitter (int64 seed reinterpreted for the PCG); scheduling spread, not a security decision (CWE-338, CWE-190) |
| `internal/protocols/est/property_test.go:142` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/protocols/est/property_test.go:155` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/protocols/ssh/krl_binary_test.go:23` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/protocols/ssh/ssh.go:330` | SSH wire string length, far under the uint32 bound for certificate fields (CWE-190) |
| `internal/query/adversarial_test.go:51` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/backup.go:107` | record counts bounded by the event log (CWE-190) |
| `internal/server/backup.go:258` | record counts bounded by the event log (CWE-190) |
| `internal/server/bundled_pg.go:65` | port validated into uint16 range by config parsing (CWE-190) |
| `internal/server/managedkeys_pkcs11_served_test.go:47` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/pam_served_test.go:216` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/protocol_mounts.go:775` | DER lengths of certificates/keys are orders of magnitude under the uint32 bound (CWE-190) |
| `internal/server/protocol_mounts.go:777` | DER lengths of certificates/keys are orders of magnitude under the uint32 bound (CWE-190) |
| `internal/server/revocation.go:382` | value reduced modulo the shard count before conversion (CWE-190) |
| `internal/server/secrets_rotation_served_test.go:476` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/signing/keystore.go:107` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:109` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:111` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:113` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:120` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/store/acme_dns01.go:231` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/acme_dns01.go:276` | non-negative by construction (CWE-190) |
| `internal/store/audit_checkpoint.go:30` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/audit_checkpoint.go:52` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/audit_checkpoint.go:72` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/ca.go:457` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/ca.go:527` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/cryptoasset_migration_test.go:38` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/store/discovery_coverage.go:37` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/discovery_coverage.go:57` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/discovery_coverage.go:81` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/endpoint_verification.go:112` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/endpoint_verification.go:156` | non-negative by construction (CWE-190) |
| `internal/store/federation.go:58` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/offboard_test.go:40` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/store/outbox_reconciliation_checkpoint.go:34` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/pam.go:73` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:268` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:323` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:427` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:78` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:93` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/snapshot.go:170` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tenant.go:27` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tenant.go:49` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tenant.go:67` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tenant_key_domain.go:146` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/tenantseal/idempotency.go:96` | length framing of short bounded fields (CWE-190) |
| `internal/tsa/fuzz_test.go:133` | crafted DER length byte for fuzz corpus; truncation is the crafted input (CWE-190) |
| `internal/tsa/fuzz_test.go:135` | crafted DER length byte for fuzz corpus (CWE-190) |
| `internal/tsa/fuzz_test.go:137` | crafted DER length bytes for fuzz corpus (CWE-190) |
| `scripts/perf/cmd/capacitycalibrate/main.go:217` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:236` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:237` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:328` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:408` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:479` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:675` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:676` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:700` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:372` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1123` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1150` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1251` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1672` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1709` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1883` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1887` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:2530` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:144` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:150` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:156` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:163` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/substrate_broker.go:391` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/substrate_broker.go:415` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/substrate_broker.go:445` | bounded value packing in a developer tool, not a served binary (CWE-190) |

### G117 — CWE-200 Exposure of sensitive information (marshaled secret field) (1 sites)

| Location | Reason |
|---|---|
| `internal/dynsecret/providers_real.go:1153` | the dynamic-secret provider's minted credential payload; returning it is the API (CWE-200) |

### G118 — CWE-664 Improper lifetime control (goroutine context) (2 sites)

| Location | Reason |
|---|---|
| `internal/events/privacy_erasure_test.go:230` | test goroutine lifecycle is managed by the test (CWE-664) |
| `internal/server/agenthttprenewal.go:64` | shutdown grace period must outlive the already-canceled parent context (CWE-664) |

### G122 — CWE-367 Time-of-check time-of-use race (walk callback) (22 sites)

| Location | Reason |
|---|---|
| `deploy/deploycheck_test.go:558` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `deploy/helm/airgap_bundle_test.go:123` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/ai_surface_placement_test.go:27` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/docs_test.go:2509` | test walks the repo's own checkout; no hostile symlink exposure (CWE-367) |
| `docs/est_differential_test.go:190` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_completeness_test.go:236` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:852` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:915` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:4441` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/provenance/authorship_test.go:103` | test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367) |
| `internal/agent/discovery/filesystem.go:57` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/privatekey.go:69` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/truststore.go:74` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/auditsink/discard_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/crypto/acmekey/production_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/notify/response_buffer_guard_test.go:37` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/backup_test.go:565` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/protect_correct102_guard_test.go:100` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/design_test.go:136` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/managedkeys_test.go:445` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/store/store_isolation_test.go:236` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/store/store_isolation_test.go:282` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |

### G124 — CWE-1004 Sensitive cookie without protective attributes (31 sites)

| Location | Reason |
|---|---|
| `internal/api/auth.go:695` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth.go:706` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth.go:718` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth.go:725` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth_hardening_test.go:21` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:145` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:146` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:147` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:148` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:198` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:199` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:200` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:201` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:348` | test cookie against the test's own local server (CWE-1004) (mismatch) |
| `internal/api/auth_test.go:368` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:369` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:396` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:397` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:426` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:447` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:494` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:37` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:52` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:53` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:70` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:71` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/rate_limit_guard_test.go:50` | test cookie against the test's own local server (CWE-1004) |
| `internal/connector/netscaler/netscaler.go:272` | cookie on an outbound API request; response-cookie attributes do not apply (CWE-1004) |
| `internal/projections/auth_resolver_test.go:150` | test cookie against the test's own local server (CWE-1004) |
| `internal/projections/auth_resolver_test.go:159` | test cookie against the test's own local server (CWE-1004) |
| `internal/server/scim_served_test.go:201` | test cookie against the test's own local server (CWE-1004) |

### G203 — CWE-? (unmapped rule) (2 sites)

| Location | Reason |
|---|---|
| `ee/whitelabel/email.go:99` | scheme and host validated above; https only (CWE-79) |
| `ee/whitelabel/email.go:116` | raster image data URI with a decodable base64 payload (CWE-79) |

### G204 — CWE-78 OS command injection (135 sites)

| Location | Reason |
|---|---|
| `clients/embedded/est_client_test.go:47` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:74` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:101` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:140` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:172` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:181` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:200` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:217` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `cmd/trstctl-agent/sshtrust.go:167` | operator-configured sshd reload command; running it is the feature (CWE-78) |
| `cmd/trstctl/backup_cmd_test.go:40` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/deploycheck_test.go:119` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/deploycheck_test.go:442` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/deploycheck_test.go:452` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:408` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:511` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:802` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:867` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/reproducible_test.go:64` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/airgap_bundle_test.go:34` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/airgap_bundle_test.go:49` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/helm_docs_commands_test.go:48` | executes the repo's own documented helm command under test (CWE-78) |
| `deploy/helm/helm_docs_commands_test.go:113` | executes the repo's own documented helm command under test (CWE-78) |
| `deploy/helm/helm_test.go:1115` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/kubernetes/manifests_test.go:416` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/kubernetes/manifests_test.go:434` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/claim_applications_test.go:67` | test runs the repository's own committed generator against tempdir fixtures it just wrote itself (CWE-78) |
| `docs/cwe_register_test.go:18` | test runs the repo's own committed generator (CWE-78) |
| `docs/cwe_register_test.go:40` | test runs the repo's own committed generator against a tempdir fixture (CWE-78) |
| `docs/docs_drift_test.go:184` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/lint_gate_test.go:25` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/lint_gate_test.go:39` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/vuln_gate_test.go:44` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/decommission/conformance/release_test.go:438` | fixed argv, no user input (CWE-78) |
| `ee/rpverify/verifier_test.go:380` | fixed argv, no user input (CWE-78) |
| `ee/succession/conformance/edition_test.go:118` | fixed argv, no user input (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:61` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:153` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:179` | live-sshd test harness validating its own config with the resolved sshd binary (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:188` | HUPs the harness's own child sshd by pid (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:240` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/api/headerauth_guard_test.go:34` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/api/headerauth_guard_test.go:39` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/ca/shellca/shellca.go:120` | the shell-CA backend exists to run the operator's configured signing command (CWE-78) |
| `internal/cli/cli_test.go:1291` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/connector/localops.go:210` | operator-configured local-ops action command; running it is the feature (CWE-78) |
| `internal/crypto/kmswrap/external_kms.go:122` | operator-configured external KMS helper command (CWE-78) |
| `internal/kms/pkcs11/softhsm_container_test.go:26` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/kms/pkcs11/softhsm_container_test.go:60` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/perf/live.go:728` | perf harness building/running the repo's own signer with the go toolchain (CWE-78) |
| `internal/perf/live.go:892` | perf harness building/running the repo's own signer with the go toolchain (CWE-78) |
| `internal/projections/server_assembly_test.go:44` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/acme/certbot_client_test.go:240` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/conformance_test.go:116` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/openssl_client_test.go:45` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/openssl_client_test.go:111` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/est/differential_test.go:101` | test executes a fixed local tool or fixture it built itself (CWE-78) (-g: get cacerts) |
| `internal/protocols/est/differential_test.go:169` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/est/differential_test.go:196` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/scep/sscep_client_test.go:55` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/scep/sscep_client_test.go:74` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/ssh/krl_binary_test.go:168` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/ssh/krl_binary_test.go:187` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/ssh/ssh_test.go:66` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/secretscan/gitdiff.go:169` | fixed git/gitleaks binaries over the operator's own repository (CWE-78) |
| `internal/secretscan/gitdiff_test.go:93` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/secretscan/gitleaks.go:147` | fixed git/gitleaks binaries over the operator's own repository (CWE-78) |
| `internal/secretscan/repository.go:96` | fixed git/gitleaks binaries over the operator's own repository (CWE-78) |
| `internal/secretscli/secretscli.go:87` | runs the operator's own command line verbatim; injecting secrets into their process is the feature (CWE-78) |
| `internal/server/auth_ldap_served_test.go:127` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:132` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:138` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:155` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:166` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:172` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/dod_signer_binary_test.go:77` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/java_sdk_served_test.go:55` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/java_sdk_served_test.go:59` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/java_sdk_served_test.go:90` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:303` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:306` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:308` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:311` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:315` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:325` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:347` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:378` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:381` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:286` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:345` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:373` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:478` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:521` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:536` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:195` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:269` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:288` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:347` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:471` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_tsa_test.go:46` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_tsa_test.go:70` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/python_sdk_served_test.go:81` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/revocation_openssl_test.go:184` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/signer_token_command.go:61` | operator-configured token-helper command (CWE-78) |
| `internal/server/vault_compat_served_test.go:95` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/signing/helpers_test.go:29` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/signing/static_test.go:41` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/signing/supervisor.go:46` | spawns the repo's own signer binary; AN-4 child-process mode (CWE-78) |
| `internal/signing/supervisor.go:216` | spawns the repo's own signer binary; AN-4 child-process mode (CWE-78) |
| `internal/testutil/openssltest/openssltest.go:97` | test-support helper running the system openssl found above; not linked into served binaries (CWE-78) |
| `internal/tsa/http_test.go:48` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/tsa/http_test.go:75` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/tsa/tsa_rfc3161_test.go:128` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `scripts/perf/cmd/perfgate/main_test.go:28` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `scripts/perf/cmd/soakcapture/main_test.go:62` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `scripts/perf/cmd/soakgate/main_test.go:133` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/connector_substrate_test.go:83` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/external_ca_substrate_test.go:168` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/kmip_substrate_test.go:38` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/main.go:312` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/managed_key_manifest_test.go:526` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/managed_key_manifest_test.go:562` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/launched.go:261` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/launched.go:524` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/launched.go:1273` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/launched.go:1309` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/proof.go:322` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:997` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1039` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1123` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/runtime_runner.go:819` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/substrate_broker.go:222` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/pqclab/main.go:594` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/trstctllint/repo_selftest_test.go:22` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/trstctllint/repo_selftest_test.go:109` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/trstctllint/repo_selftest_test.go:158` | test executes a fixed local tool or fixture it built itself (CWE-78) |

### G301 — CWE-276 Incorrect default permissions (directory) (45 sites)

| Location | Reason |
|---|---|
| `clients/embedded/est_client_test.go:71` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `clients/embedded/est_client_test.go:136` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `clients/embedded/est_client_test.go:197` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `deploy/docker/dist_test.go:746` | npm fixture tree in t.TempDir; mirrors a real package layout, nothing secret (CWE-276) |
| `internal/agent/destination/fs_unix_test.go:79` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/discovery/discovery_test.go:270` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/discovery/privatekey_test.go:27` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/sshdiscovery/sshdiscovery_test.go:26` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/api/machine_sessions_served_test.go:54` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/api/openapi_golden_test.go:59` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/api/vault_compat_contract_test.go:246` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:173` | non-secret fixture directory in t.TempDir (CWE-22, CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:61` | deliberately loose fixture dir; secretfile must refuse it (CWE-276) |
| `internal/dynsecret/providers_real_test.go:468` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/dynsecret/providers_real_test.go:471` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/dynsecret/providers_real_test.go:474` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/projections/golden_events_test.go:107` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/projections/sshdiscovery_store_test.go:92` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:48` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:69` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:275` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:291` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/cmp/openssl_client_test.go:165` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/scep/sscep_client_test.go:196` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/agentchannel_served_test.go:1224` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/java_sdk_served_test.go:44` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/pam_served_test.go:209` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:50` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:80` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:612` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:626` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_tsa_test.go:103` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/secret_third_party_scan_served_test.go:154` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/secrets_rotation_served_test.go:469` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/server.go:1826` | served CA certificate directory; the PEM is public material (CWE-276) |
| `internal/tsa/http_test.go:103` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `scripts/perf/cmd/capacitycalibrate/main.go:137` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/perfgate/main.go:52` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakcapture/main.go:82` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakgate/main.go:120` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/spineburst/main.go:170` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/dodcensus/main.go:1285` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/pqclab/main.go:795` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/trstctllint/eventsource/eventsource_test.go:98` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/trstctllint/idempotency/idempotency_test.go:145` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |

### G302 — CWE-276 Incorrect default permissions (chmod) (21 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/main.go:316` | 0700 on a directory: the execute bit is required to traverse it (CWE-276) |
| `internal/agent/destination/fs_unix_test.go:82` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_unix_test.go:28` | deliberately loosens the fixture key's mode; detecting exactly this is what the test proves (CWE-276) |
| `internal/agent/drift/drift_unix_test.go:53` | deliberately loosens the fixture key's mode; detecting exactly this is what the test proves (CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:64` | deliberately loose fixture mode; secretfile must refuse it (CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:67` | restores the fixture dir so t.TempDir cleanup can remove it (CWE-276) |
| `internal/server/external_ca_config_test.go:120` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/managed_key_signer_config.go:27` | 0700 on a directory: the execute bit is required to traverse it (CWE-276) |
| `internal/server/protocols_served_tsa_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/signing/serve.go:148` | 0700 on a directory: the execute bit is required to traverse it (CWE-276) |
| `internal/signing/socket_mode_unix_test.go:206` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/tsa/http_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `tools/dodcensus/proof/proof_test.go:710` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:730` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:757` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:147` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:153` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:153` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:159` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:162` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:277` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |

### G304 — CWE-22 Path traversal (file inclusion via variable) (274 sites)

| Location | Reason |
|---|---|
| `clients/embedded/est_client_test.go:79` | test reads its own fixture/tempdir path (CWE-22) |
| `cmd/trstctl-agent/cosign_attach.go:89` | operator-configured local path from the agent's own config (CWE-22) |
| `cmd/trstctl-agent/main.go:552` | operator-supplied PIN file path, read at their instruction (CWE-22) |
| `cmd/trstctl-agent/sshtrust.go:90` | operator-configured local path from the agent's own config (CWE-22) |
| `cmd/trstctl/backup_cmd_test.go:46` | test reads its own fixture/tempdir path (CWE-22) |
| `cmd/trstctl/backup_cmd_test.go:64` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/demo/demo_test.go:35` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:98` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:212` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:294` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:364` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:462` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:558` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `deploy/deploycheck_test.go:651` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:720` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:808` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:938` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:944` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:950` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1013` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1103` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1286` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1530` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/docker/dist_test.go:23` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/docker/dist_test.go:818` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/docker/reproducible_test.go:35` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/airgap_bundle_test.go:123` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `deploy/helm/airgap_bundle_test.go:139` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/airgap_bundle_test.go:185` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/helm_docs_commands_test.go:130` | reads the repo's own docs pages from a walked list (CWE-22) |
| `deploy/helm/helm_test.go:1077` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/helm_test.go:1138` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/iac/iac_test.go:279` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/kubernetes/manifests_test.go:477` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/kubernetes/manifests_test.go:494` | test reads its own fixture/tempdir path (CWE-22) |
| `docs/ai_surface_placement_test.go:27` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/doctor_doc_test.go:32` | fixed literal list of the repo's own committed doctor sources; no external input reaches this path (CWE-22) |
| `docs/est_differential_test.go:190` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/nolint_gosec_guard_test.go:90` | test reads a path listed by this repository's own git index (CWE-22) |
| `docs/operational_transfer_test.go:64` | test reads its own fixture/tempdir path (CWE-22) |
| `docs/protect_guards_completeness_test.go:236` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:852` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:915` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:4441` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/provenance/authorship_test.go:38` | fixed sibling path inside the package's own directory (CWE-22) |
| `docs/provenance/authorship_test.go:103` | test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367) |
| `internal/agent/destination/destination_test.go:49` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/destination/destination_test.go:53` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/destination/destination_test.go:81` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/destination/destination_test.go:88` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/discovery/filesystem.go:57` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/privatekey.go:69` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/truststore.go:74` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/truststore.go:185` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/drift/drift.go:150` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/drift/drift_test.go:127` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/drift/drift_test.go:184` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/drift/drift_test.go:209` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/drift/drift_test.go:244` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/relay/hostexec.go:108` | operator-supplied profile path, read at their instruction (CWE-22) |
| `internal/agent/secretinject/secretinject.go:179` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/secretinject/secretinject_test.go:26` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/secretinject/secretinject_test.go:56` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:60` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:79` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:96` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:119` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:143` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshtrust/sshd_live_test.go:49` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/sshtrust/sshd_live_test.go:99` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/sshtrust/sshd_live_test.go:149` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/sshtrust/sshd_live_test.go:279` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/api/sdk_spec_pinned_test.go:49` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/api/vault_compat_contract_test.go:255` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/audit/key.go:25` | operator-configured audit signing-key path from deployment config (CWE-22) |
| `internal/auditsink/discard_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/backup/encrypted_artifact.go:62` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/backup/encrypted_artifact.go:194` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/backup/encrypted_artifact.go:211` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/backup/encrypted_artifact.go:249` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/backup/full_manifest.go:92` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/backup/full_manifest.go:116` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/backup/full_manifest.go:134` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/backup/full_manifest.go:175` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/backup/full_manifest.go:184` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/backup/full_manifest_io_test.go:46` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/backup/full_manifest_io_test.go:53` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/backup/manifest_test.go:32` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/external_error_redaction_test.go:62` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/profilelint/profilelint_test.go:146` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/shellca/shellca.go:104` | operator-configured shell-CA output path; the shell CA is an explicit operator integration (CWE-22) |
| `internal/ca/shellca/shellca_test.go:161` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/cbom/hostsource/hostsource.go:38` | declared host-config path from the discovery source's own config (CWE-22) |
| `internal/cli/cli.go:409` | operator-passed local file argument on their own command line (CWE-22) |
| `internal/cli/cli_test.go:923` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/cli/doctor/doctor.go:203` | operator-supplied path to their own deployment's audit key (CWE-22) |
| `internal/cli/doctor/doctor_test.go:94` | test reads its own tempdir receipt (CWE-22) |
| `internal/cloudhttp/adoption_guard_test.go:127` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/config/config.go:1907` | the config loader reading the operator's own config file (CWE-22) |
| `internal/connector/localops.go:147` | operator-configured local-ops connector path; local file deploy is the feature (CWE-22) |
| `internal/connector/localops.go:180` | operator-configured local-ops connector path; local file deploy is the feature (CWE-22) |
| `internal/crypto/acmekey/production_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/crypto/mtls/agent.go:214` | operator-configured certificate/key path from deployment config (CWE-22) |
| `internal/crypto/mtls/agent.go:232` | operator-configured certificate/key path from deployment config (CWE-22) |
| `internal/crypto/mtls/server.go:101` | operator-configured certificate/key path from deployment config (CWE-22) |
| `internal/crypto/mtls/signer.go:107` | operator-configured peer CA trust anchor path from the signer's own config (CWE-22) |
| `internal/crypto/mtls/signer_test.go:47` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/parserfuzz_audit_test.go:172` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/parserfuzz_audit_test.go:259` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/pfx/pfx_test.go:43` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/pfx/pfx_test.go:44` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/secretfile/secretfile.go:34` | operator-configured local secret path; parents and file mode validated above (CWE-22) |
| `internal/crypto/secretfile/secretfile.go:65` | operator-configured local secret path; O_EXCL + 0600, parents validated above (CWE-22) |
| `internal/dynsecret/providers_real_test.go:227` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/events/protect_schema005_guard_test.go:92` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/catalog.go:80` | fixed repo-relative catalog path read by tools and tests (CWE-22) |
| `internal/featureparity/feature_facet_coverage_test.go:110` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/feature_facet_coverage_test.go:114` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/feature_facet_coverage_test.go:140` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/mcp_rest_coverage.go:53` | fixed repo-relative catalog path read by tools and tests (CWE-22) |
| `internal/license/license.go:277` | operator-supplied license file path (CWE-22) |
| `internal/notify/response_buffer_guard_test.go:37` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/perf/smoke.go:173` | perf harness reading its own artifact path (CWE-22) |
| `internal/pluginhost/containment_test.go:122` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/pluginhost/reference_plugin_test.go:49` | fixed in-repo reference plugin path (CWE-22) |
| `internal/pluginhost/reference_plugin_test.go:129` | test reads the path it granted (CWE-22) |
| `internal/pluginhost/sandbox_test.go:95` | test reads the fixture path it just granted (CWE-22) |
| `internal/pluginhost/sandbox_test.go:171` | test reads the fixture it created (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:178` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:253` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:303` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:308` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:333` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:352` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:77` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:130` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:169` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:175` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:197` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/est/differential_test.go:107` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:180` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:200` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:205` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:233` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/secretscan/gitleaks.go:159` | reads the report file this process asked gitleaks to write in its own tempdir (CWE-22) |
| `internal/secretscan/gitleaks_options_test.go:108` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/secretscan/secretscan_test.go:123` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/agentchannel.go:104` | operator-configured agent CA certificate path from this server's own config (CWE-22) |
| `internal/server/backup.go:45` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:94` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:249` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:284` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:367` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:466` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:470` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:512` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup_test.go:290` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/backup_test.go:338` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/backup_test.go:473` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/backup_test.go:565` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/breakglass.go:123` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/bundled_pg_verify.go:110` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/idempotency_protection_wiring_test.go:61` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/pam_served_test.go:350` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/plugins.go:199` | operator-configured plugin dir; WASM and signature are verified after the read (CWE-22) |
| `internal/server/plugins.go:203` | operator-configured plugin dir; WASM and signature are verified after the read (CWE-22) |
| `internal/server/protect_correct102_guard_test.go:100` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/protocol_mounts.go:555` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/protocol_mounts.go:662` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/protocol_mounts.go:727` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/protocols_served_spiffe_ssh_test.go:539` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:213` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:495` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:508` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:642` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:648` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:50` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:107` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/server/rekor.go:46` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/response_buffer_guard_test.go:63` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/run.go:898` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/run.go:1251` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/run_connectors_test.go:89` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/server.go:1788` | operator-configured local file path from deployment config (CWE-22) |
| `internal/signing/design_test.go:30` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/design_test.go:136` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/hardening_contract_test.go:55` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/keystore.go:241` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/signing/keystore_test.go:107` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/keystore_test.go:197` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/managedkeys.go:525` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/signing/managedkeys.go:668` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/signing/managedkeys_test.go:445` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/sign_journal.go:205` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/spireupstream/plugin.go:238` | operator-configured upstream-authority plugin config path (CWE-22) |
| `internal/store/dynamic_secret_lock_order_test.go:110` | fixed sibling path inside this package's own directory (CWE-22) |
| `internal/store/migration_safety_test.go:82` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/store/store_isolation_test.go:236` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/store/store_isolation_test.go:282` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/supportbundle/supportbundle.go:363` | operator-invoked support bundle collecting its configured files (CWE-22) |
| `internal/supportbundle/supportbundle_test.go:97` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/supportbundle/supportbundle_test.go:101` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/supportbundle/supportbundle_test.go:112` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/telemetry/instanceid.go:21` | fixed instance-id file under the configured data dir (CWE-22) |
| `internal/tsa/http_test.go:52` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/tsa/http_test.go:107` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/tsa/http_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/tsa/tsa_rfc3161_test.go:136` | test reads its own fixture/tempdir path (CWE-22) |
| `scripts/perf/cmd/capacitycalibrate/main.go:346` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `scripts/perf/cmd/soakcapture/main_test.go:68` | test reads its own fixture/tempdir path (CWE-22) |
| `scripts/perf/cmd/soakgate/main.go:130` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `scripts/perf/cmd/soakgate/main_test.go:56` | test reads its own fixture/tempdir path (CWE-22) |
| `scripts/perf/cmd/soakgate/main_test.go:139` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/cbomcoveragedoc/main.go:66` | operator/CI-supplied path to this repo's own generated page (CWE-22) |
| `tools/dodcensus/artifact.go:85` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/artifact.go:167` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/claims.go:61` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/claims.go:72` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/claims.go:76` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/main.go:500` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/main_test.go:519` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:538` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:557` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:578` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:603` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:634` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:657` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:706` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:1179` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_closure.go:47` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:81` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:141` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:221` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:247` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:272` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:324` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:335` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:358` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:404` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:591` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/proof/launched.go:467` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:1190` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:1895` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2006` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2101` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2248` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2327` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2581` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:251` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:910` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:1048` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime.go:132` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:153` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:224` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:438` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:1139` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:1472` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:94` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:638` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:716` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:760` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:288` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:415` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:469` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:473` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/pqclab/main.go:233` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/pqclab/main.go:298` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/pqclab/main_test.go:76` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/pqclab/main_test.go:80` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/trstctllint/docs_test.go:75` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/trstctllint/hotspot_test.go:205` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/trstctllint/hotspot_test.go:295` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/trstctllint/licenseboundary/licenseboundary.go:35` | developer tool reading the repo paths it is pointed at (CWE-22) |

### G306 — CWE-276 Incorrect default permissions (file write) (81 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:201` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:82` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:131` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:158` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:182` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:224` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-license/main.go:67` | writes the license PUBLIC key/inspection output; public material (CWE-276) |
| `cmd/trstctl-license/main.go:138` | writes the license PUBLIC key/inspection output; public material (CWE-22, CWE-276) |
| `cmd/trstctl/backup_cmd_test.go:31` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `deploy/docker/dist_test.go:749` | non-secret npm fixture manifest in t.TempDir (CWE-276) |
| `deploy/docker/dist_test.go:752` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `deploy/docker/dist_test.go:758` | fake npm shim in a test tempdir must be executable (CWE-276) |
| `docs/lint_gate_test.go:88` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/destination/fs_unix_test.go:57` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/discovery/discovery_test.go:273` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/discovery/privatekey_test.go:33` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:26` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:73` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:109` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:169` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:226` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_unix_test.go:81` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) (world-readable) |
| `internal/agent/sshdiscovery/sshdiscovery_test.go:29` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/transport/regen_schema_test.go:43` | committed wire contract fixture, reviewed in the diff (CWE-276) |
| `internal/api/openapi_golden_test.go:62` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/api/vault_compat_contract_test.go:249` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/backup/full_manifest_io_test.go:23` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:241` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:254` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/cbom/hostsource/hostsource_test.go:22` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/cli/cli_test.go:1321` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/cli/secret_scan_local.go:135` | a git hook must be executable; 0755 is the working minimum (CWE-276) |
| `internal/connector/localops_test.go:87` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/crypto/external_kms_test.go:88` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/crypto/mtls/agent.go:205` | certificate chain PEM is public material; the key is written 0600 separately (CWE-276) |
| `internal/crypto/mtls/signer.go:217` | writes the PUBLIC CA trust anchor bundle; world-readable is intended, no key material (CWE-276) |
| `internal/crypto/mtls/signer.go:264` | writes the PUBLIC leaf certificate chain; the private key beside it is written 0600 (CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:48` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/crypto/tenantwrap/tenantwrap_test.go:110` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/projections/cbom_store_test.go:38` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/projections/discovery_store_test.go:93` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/projections/discovery_store_test.go:96` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:225` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/ssh/krl_binary_test.go:155` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/ssh/krl_binary_test.go:163` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/ssh/krl_binary_test.go:184` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/ssh/ssh_test.go:63` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/secrets/vault_test.go:147` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/secrets/vault_test.go:180` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/secretscan/gitleaks_options_test.go:100` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/auth_unit_test.go:64` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/cbom_served_test.go:62` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/pam_served_test.go:287` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/pam_served_test.go:299` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_spiffe_ssh_test.go:474` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_spiffe_ssh_test.go:518` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:453` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/secrets_scan_served_test.go:36` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/server.go:1830` | served CA certificate PEM is public material (CWE-276) |
| `internal/server/signer_authorization_test.go:132` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/signer_authorization_test.go:192` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/ssh_journey_served_test.go:172` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/signing/keystore_test.go:242` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/signing/signauth_secret_test.go:47` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/testutil/openssltest/openssltest_test.go:14` | fake openssl shim must be executable; 0700 is the minimum that runs (CWE-276) |
| `scripts/gen-terraform-provider-routes/main.go:84` | generated Go source committed to the repo; world-readable by design (CWE-276) |
| `scripts/perf/cmd/capacitycalibrate/main.go:140` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/capacitycalibrate/main_test.go:180` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `scripts/perf/cmd/perfgate/main.go:55` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakcapture/main.go:85` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakgate/main.go:123` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/spineburst/main.go:173` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:193` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:212` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:242` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:327` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:340` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:361` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:364` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/trstctllint/eventsource/eventsource_test.go:101` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/trstctllint/idempotency/idempotency_test.go:148` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |

### G401 — CWE-328 Use of weak hash (4 sites)

| Location | Reason |
|---|---|
| `internal/crypto/certinfo/certinfo.go:362` | display/lookup fingerprint in the industry-standard form; not a security control (CWE-328) |
| `internal/crypto/leafca.go:567` | RFC 5280 4.2.1.2 method-1 SKID: an identifier, not integrity (CWE-328) |
| `internal/crypto/opaque_x509.go:221` | RFC 5280 4.2.1.2 method-1 SKID: an identifier, not integrity (CWE-328) |
| `internal/crypto/tsa.go:187` | RFC 5816 ESSCertIDv1 is defined over SHA-1; identifier only, v2 uses SHA-256 (CWE-328) |

### G402 — CWE-295 Improper certificate validation (InsecureSkipVerify) (5 sites)

| Location | Reason |
|---|---|
| `internal/crypto/mtls/mtls.go:373` | operator-selected lab escape hatch, off by default, and |
| `internal/crypto/mtls/reload_test.go:64` | reload probe of the test's own loopback listener; reads only the served serial, carries no data (CWE-295) |
| `internal/crypto/mtls/server.go:189` | localhost liveness probe of this process's own ephemeral self-signed listener; no credential, no data (CWE-295) |
| `internal/crypto/mtls/server_test.go:131` | test TLS client speaking to the test's own server (CWE-295) |
| `internal/crypto/tlsprobe/tlsprobe.go:96` | discovery inventories whatever cert is served; the connection is never trusted and never carries data (CWE-295) |

### G403 — CWE-326 Inadequate encryption strength (RSA key size) (1 sites)

| Location | Reason |
|---|---|
| `internal/crypto/jose/bounds_test.go:52` | deliberately undersized key; the test proves the verifier refuses it (CWE-326) |

### G404 — CWE-338 Cryptographically weak PRNG (15 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/backoff_test.go:22` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:49` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:68` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:69` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:86` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:95` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:113` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/bootstrap_token_test.go:370` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/bootstrap_token_test.go:376` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/bootstrap_token_test.go:384` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/main.go:373` | reconnect jitter, not a security decision (CWE-338) |
| `internal/cli/cli.go:417` | idempotency-key uniqueness suffix; deliberately outside the AN-3 boundary, not a secret (CWE-338) |
| `internal/orchestrator/outbox.go:402` | retry backoff jitter, not a security decision (CWE-338) |
| `internal/protocols/ari/ari.go:94` | deterministic per-certificate renewal jitter (int64 seed reinterpreted for the PCG); scheduling spread, not a security decision (CWE-338, CWE-190) |
| `internal/query/adversarial_test.go:223` | test jitter/shuffle, not a security decision (CWE-338) |

### G505 — CWE-328 Weak hash import (SHA-1) (4 sites)

| Location | Reason |
|---|---|
| `internal/crypto/certinfo/certinfo.go:15` | SHA-1 only for the conventional certificate fingerprint identifier, never integrity (CWE-328) |
| `internal/crypto/leafca.go:7` | SHA-1 only for RFC 5280 4.2.1.2 method-1 Subject Key Identifier derivation (CWE-328) |
| `internal/crypto/opaque_x509.go:14` | SHA-1 only for RFC 5280 4.2.1.2 method-1 Subject Key Identifier derivation (CWE-328) |
| `internal/crypto/tsa.go:20` | RFC 5816 ESSCertIDv1 is defined over SHA-1; identifier only, v2 uses SHA-256 (CWE-328) |

### G602 — CWE-118 Incorrect access of indexable resource (5 sites)

| Location | Reason |
|---|---|
| `internal/auth/tenantmap_test.go:118` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `internal/crypto/ctlog/ctlog_test.go:116` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `internal/projections/graph_api_test.go:246` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `internal/server/issuance_dispatcher_test.go:1188` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `tools/dodcensus/managed_key_closure.go:670` | fixed-shape data inside a developer tool (CWE-118) |

### G702 — CWE-78 OS command injection (taint) (6 sites)

| Location | Reason |
|---|---|
| `internal/protocols/est/differential_test.go:101` | test executes a fixed local tool or fixture it built itself (CWE-78) (-g: get cacerts) |
| `internal/server/protocols_served_stock_clients_test.go:195` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:997` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1039` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1123` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/runtime_runner.go:819` | developer tool running fixed toolchain commands over the repo (CWE-78) |

### G703 — CWE-22 Path traversal (taint) (55 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-license/main.go:138` | writes the license PUBLIC key/inspection output; public material (CWE-22, CWE-276) |
| `docs/provenance/authorship_test.go:103` | test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367) |
| `internal/agent/sshtrust/sshd_live_test.go:115` | temp file beside the harness-owned sshd config in a test dir (CWE-22) |
| `internal/agent/sshtrust/sshd_live_test.go:131` | atomic replace of the harness-owned sshd config in a test dir (CWE-22) |
| `internal/ca/profilelint/profilelint_test.go:146` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/profilelint/profilelint_test.go:173` | non-secret fixture directory in t.TempDir (CWE-22, CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:241` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:254` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/ca/shellca/shellca_test.go:161` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/shellca/shellca_test.go:182` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:275` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:291` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:308` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:165` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/cmp/openssl_client_test.go:175` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/est/differential_test.go:166` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:134` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:196` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/scep/sscep_client_test.go:205` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/secretscan/gitleaks.go:278` | locates the pinned gitleaks binary in known tool dirs (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:206` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:571` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:612` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:626` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:648` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:103` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_tsa_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/server/secrets_scan_served_test.go:189` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/signer_authorization_test.go:192` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/vault_compat_served_test.go:78` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/signing/keystore_test.go:201` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/testutil/openssltest/openssltest.go:89` | test-support helper probing fixed well-known openssl paths; not linked into served binaries (CWE-22) |
| `internal/tsa/http_test.go:103` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/tsa/http_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `tools/dodcensus/main_test.go:524` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/main_test.go:544` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/main_test.go:562` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/main_test.go:589` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/main_test.go:619` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/main_test.go:644` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/main_test.go:667` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/main_test.go:721` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/main_test.go:1480` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:149` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:229` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:363` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:412` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:603` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/proof/launched.go:1118` | developer tool probing repo/toolchain paths, not a served binary (CWE-22) |
| `tools/dodcensus/proof/proof.go:89` | developer tool probing repo/toolchain paths, not a served binary (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:256` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:1149` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/runtime_runner.go:804` | developer tool probing repo/toolchain paths, not a served binary (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:293` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:423` | test path inside its own tempdir/checkout (CWE-22) |

### G704 — CWE-918 Server-side request forgery (taint) (4 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl/connector.go:188` | CLI calling the operator-specified connector base URL; their own target (CWE-918) |
| `cmd/trstctl/connector.go:200` | CLI calling the operator-specified connector base URL; their own target (CWE-918) |
| `internal/discovery/cloudcert/httpfetch.go:42` | fetches the cloud provider endpoint declared by the operator's discovery source (CWE-918) |
| `tools/dodcensus/proof/launched.go:1592` | developer tool calling the endpoint it was pointed at (CWE-918) |

### G705 — CWE-79 Cross-site scripting (taint) (11 sites)

| Location | Reason |
|---|---|
| `internal/ca/letsencrypt/acmefake/acmefake.go:233` | test-support package compiled only into test binaries (CWE-79) |
| `internal/ca/letsencrypt/acmefake/acmefake.go:256` | test-support package compiled only into test binaries (CWE-79) |
| `internal/connector/fortigate/fortigate_test.go:127` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/dns/akamai/akamai_test.go:131` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/operator/reconcile_test.go:217` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/secretstore/access.go:86` | the secret read API returns the secret by contract; served as octet-stream with nosniff, never an HTML context (CWE-79) |
| `internal/secretstore/access.go:97` | fixed-shape JSON carrying only an integer version, served as application/json with nosniff (CWE-79) |
| `internal/secretstore/access.go:113` | fixed-shape JSON carrying only an integer version, served as application/json with nosniff (CWE-79) |
| `internal/server/secrets_sync_served_test.go:901` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/server/secrets_sync_served_test.go:972` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/server/secrets_sync_served_test.go:1082` | test writes fixture bytes to its own recorder/local server (CWE-79) |

### G710 — CWE-601 Open redirect (taint) (1 sites)

| Location | Reason |
|---|---|
| `internal/server/auth_served_test.go:65` | test redirect within its own local server (CWE-601) |

