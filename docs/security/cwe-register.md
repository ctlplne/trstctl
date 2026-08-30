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

1344 annotated sites across 26 rules. Each row is
generated from the `#nosec` comment at that exact line; edit the source,
not this file.

### G101 — CWE-798 Use of hardcoded credentials (293 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:96` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `cmd/trstctl/main_test.go:388` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/demo/demo_test.go:78` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/deploycheck_test.go:1483` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/deploycheck_test.go:1485` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/deploycheck_test.go:1505` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/docker/dist_test.go:385` | names are non-secret evaluation OIDC configuration keys (CWE-798) |
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
| `ee/decommission/reprotect/credential_test.go:16` | NewCredentialID is public fixture metadata, not credential material (CWE-798). |
| `ee/provider/aud58_test.go:173` | deterministic non-deployable test bearer exercises hashing/authentication (CWE-798). |
| `ee/provider/aud59_test.go:24` | deterministic non-deployable test bearer (CWE-798). |
| `ee/provider/aud60_test.go:16` | deterministic non-deployable test bearer (CWE-798). |
| `ee/provider/scim_fuzz_test.go:30` | deterministic non-deployable fuzz authenticator (CWE-798). |
| `internal/agent/discovery/kubernetes.go:89` | metadata key naming the Kubernetes Secret a public certificate was found in; no credential value present (CWE-798) |
| `internal/agent/k8s/client.go:29` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/agent/relay/mdmsync_test.go:23` | credential reference (secret store pointer), no credential value present (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:70` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:93` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:113` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:132` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:151` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:171` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:190` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:259` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:297` | credential REFERENCE NAMES, not credentials: the relay looks values up in redeemed material by these keys (CWE-798) |
| `internal/agent/relay/relay_test.go:138` | "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798) |
| `internal/agent/relay/relay_test.go:180` | "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798) |
| `internal/agent/relay/relay_test.go:318` | reference NAME, not a credential (CWE-798) |
| `internal/agent/relay/relay_test.go:376` | reference NAME (CWE-798) |
| `internal/agent/relay/ticketsync_test.go:66` | TokenRef is a non-secret locator in a deterministic test fixture (CWE-798). |
| `internal/agent/transport/agentservice.go:742` | an RPC method name, not a credential. The material this |
| `internal/agent/transport/agentservice.go:749` | an RPC method name. This call carries a CSR up and returns |
| `internal/agent/transport/receipt.go:196` | an operator-facing refusal phrase matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/agent/transport/receipt_custody_test.go:15` | the credential fingerprint is public fixture metadata, not a credential (CWE-798). |
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
| `internal/api/acme_dns01.go:548` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/agents.go:57` | source-kind label naming where key material was located; no credential value present (CWE-798) |
| `internal/api/aisurface_contract_test.go:148` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/idempotency_binding_test.go:21` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:11` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:17` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:26` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:27` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:28` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:41` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/managedkeys_test.go:182` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/nhi_inventory.go:199` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/notifications.go:691` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/notifications.go:1046` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/notifications_helpers_test.go:68` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/openapi.go:171` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_posture.go:780` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_posture.go:928` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:423` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:447` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:503` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:513` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:523` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/audit/audit_test.go:146` | deliberately toxic non-routable fixture proves redaction (CWE-798). |
| `internal/audit/audit_test.go:178` | deliberately toxic fixture proves retained-prefix redaction (CWE-798). |
| `internal/auth/oidc_client_secret.go:15` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/authmethod/aws_iam_http_test.go:16` | fabricated signed-request fixture (CWE-798) |
| `internal/authmethod/aws_iam_http_test.go:37` | fabricated signed-request fixture (CWE-798) |
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
| `internal/config/audit_test.go:31` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/audit_test.go:66` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/audit_test.go:79` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config.go:2205` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/config/config.go:2893` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/config/config_test.go:64` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:173` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:357` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:363` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:366` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:369` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:372` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:11` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:43` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:45` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:46` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:47` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:48` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:50` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:68` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:92` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/ldap_test.go:8` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/migrate_config_test.go:24` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/migrate_config_test.go:45` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/oidc_test.go:13` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/oidc_test.go:114` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/provider_identity_aud58_test.go:43` | values are configuration names and file paths, never secret bytes (CWE-798). |
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
| `internal/config/secrets_config_test.go:64` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:51` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:63` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:123` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:131` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/acm/acm_test.go:20` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/azurekv/token_test.go:20` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/azurekv/token_test.go:63` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/cisco/cisco_test.go:21` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/cisco/ciscotest/ciscotest_test.go:16` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/gcpcm/gcpcm_test.go:18` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/kemp/kemp_test.go:65` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/paloalto/paloalto_test.go:28` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
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
| `internal/notify/notify.go:76` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
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
| `internal/orchestrator/cmdb_sweep_test.go:17` | TokenRef is a non-secret locator in a deterministic fixture (CWE-798). |
| `internal/orchestrator/outbox_internal_test.go:1202` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/orchestrator/outbox_internal_test.go:1251` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/perf/capacity.go:11` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/perf/perf_test.go:211` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/projections/apitoken_test.go:59` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/projections/cli_api_test.go:90` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/projections/secret_integrations.go:220` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/risk/contextual_test.go:192` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/risk/contextual_test.go:214` | fabricated identifier, not credential material (CWE-798) |
| `internal/schedulerhistory/history_test.go:12` | deliberately toxic non-routable fixture proves redaction (CWE-798). |
| `internal/schedulerhistory/history_test.go:81` | deliberately toxic fixture proves closed parsing without echo (CWE-798). |
| `internal/server/acme_dns01_qualification.go:23` | this is an operator-facing disclosure sentence, not credential material. |
| `internal/server/adcs_inventory_served_test.go:42` | this is a logical fixture name, not secret material (CWE-798). |
| `internal/server/adcs_inventory_served_test.go:43` | this is a non-secret reference, not secret material (CWE-798). |
| `internal/server/agent_jobs_served_test.go:23` | secret-store reference/pointer, never credential material (CWE-798) |
| `internal/server/aisurface_served_test.go:112` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/audit_feed_served_test.go:43` | token_ref is a non-secret environment locator (CWE-798). |
| `internal/server/audit_feed_served_test.go:142` | the credential-bearing URL is a negative fixture that production must reject (CWE-798). |
| `internal/server/audit_feed_served_test.go:160` | token_ref is a non-secret environment locator (CWE-798). |
| `internal/server/audit_feed_served_test.go:167` | token_ref is a non-secret environment locator (CWE-798). |
| `internal/server/auth_unit_test.go:96` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/azure_workload_identity_served_test.go:26` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/cmdb_served_test.go:32` | credential reference (env: pointer), no credential value present (CWE-798) |
| `internal/server/cmdb_served_test.go:36` | credential reference (secret store pointer), no credential value present (CWE-798) |
| `internal/server/cmdb_served_test.go:44` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_recovery_served_test.go:202` | reference names only; fixture values are synthetic and never shipped |
| `internal/server/discovery_recovery_served_test.go:211` | reference names only; fixture values are synthetic and never shipped |
| `internal/server/discovery_recovery_served_test.go:220` | reference names only; fixture values are synthetic and never shipped |
| `internal/server/discovery_recovery_served_test.go:228` | metadata-only fabricated token reference; no credential value is present |
| `internal/server/discovery_served_test.go:646` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:648` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:767` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:984` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1085` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1091` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1130` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1143` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1169` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1363` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:1375` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2097` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2230` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2239` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2416` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2555` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2577` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2751` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2763` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2774` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
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
| `internal/server/mdm_poller_served_test.go:33` | credential reference (env: pointer), no credential value present (CWE-798) |
| `internal/server/mdm_poller_served_test.go:36` | credential reference (secret store pointer), no credential value present (CWE-798) |
| `internal/server/native_connectors_served_test.go:43` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:45` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:450` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:452` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:454` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:56` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:162` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:195` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:584` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_certbot_aud73_test.go:18` | fabricated test-only webhook credential (CWE-798) |
| `internal/server/protocols_served_stock_clients_test.go:59` | fabricated test-only webhook credential (CWE-798) |
| `internal/server/protocols_served_stock_clients_test.go:188` | fabricated secret reference, never raw credential material (CWE-798) |
| `internal/server/protocols_served_test.go:313` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:377` | opaque fake secret reference used only by the local test provider (CWE-798). |
| `internal/server/protocols_served_test.go:613` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:722` | fabricated secret reference, never raw credential material (CWE-798) |
| `internal/server/protocols_served_test.go:866` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:903` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:974` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:1051` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:1251` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:32` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:52` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:53` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:55` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/scheduler_history_assembled_test.go:34` | deliberately toxic non-routable fixture proves sanitation (CWE-798). |
| `internal/server/scheduler_history_sanitation_test.go:14` | deliberately toxic non-routable fixture proves sanitation (CWE-798). |
| `internal/server/scim_served_test.go:33` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_integrations.go:919` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/server/secret_third_party_scan_served_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_scan_served_test.go:125` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_served_test.go:577` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_served_test.go:2472` | fabricated STS exchange fixture; no real credential (CWE-798) |
| `internal/server/secrets_sync_served_test.go:400` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_sync_served_test.go:412` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_sync_served_test.go:423` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_sync_served_test.go:433` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/ticket_intake_served_test.go:26` | credential reference (secret store pointer), no credential value present (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:28` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:149` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:150` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:151` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:152` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/store/agent_bootstrap_token_test.go:67` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/store/approved_target_fences.go:229` | SQL column identifiers only; this constant contains no credential material. |
| `internal/store/dynamic_secret_lease.go:579` | sealed_credential is a SQL column name, not a hardcoded credential (CWE-798). |
| `internal/store/privacy_erasure_preparation.go:153` | SQL column identifiers only; this constant contains no credential material. |
| `internal/store/secret_rotation_schedule_privacy.go:694` | SQL authority columns are names, not embedded credentials (CWE-798). |
| `internal/store/secret_store.go:325` | SQL column identifiers only; this constant contains no credential material. |
| `internal/store/secret_sync_workload_identity.go:202` | SQL column list matching the secret-name heuristic; a query, not a credential (CWE-798) |
| `internal/ticketintake/intake_test.go:103` | TokenRef is a non-secret locator in a deterministic fixture (CWE-798). |
| `internal/ticketintake/intake_test.go:150` | TokenRef is a non-secret locator in a deterministic fixture (CWE-798). |
| `tools/dodcensus/claims.go:162` | developer-tool constant matching the secret-name heuristic; no credential value (CWE-798) |
| `tools/dodcensus/runtime.go:39` | developer-tool constant matching the secret-name heuristic; no credential value (CWE-798) |
| `tools/trstctllint/keymaterial/keymaterial_test.go:51` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `tools/trstctllint/keymaterial/keymaterial_test.go:87` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |

### G107 — CWE-88 Argument injection (variable URL request) (3 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:584` | loopback-only assembled test listener (CWE-918) |
| `internal/protocols/scep/profile_routes_test.go:106` | test drives its own local server URL (CWE-88) |
| `internal/server/license_entitlement_test.go:70` | fixed localhost-only assembled-test server (CWE-918) |

### G112 — CWE-400 Uncontrolled resource consumption (slowloris) (13 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:459` | local test listener owned and torn down by the test (CWE-400) |
| `internal/agent/http_enroll_test.go:150` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/reload_test.go:95` | loopback test listener torn down by the test (CWE-400) |
| `internal/crypto/mtls/server_test.go:166` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/server_test.go:229` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/server_test.go:302` | local test listener owned and torn down by the test (CWE-400) |
| `internal/server/dod_parent_substrate_bridge_runtime_test.go:183` | local test listener owned and torn down by the test (CWE-400) |
| `internal/server/host_agent_remote_served_test.go:275` | loopback fixture is closed below (CWE-400) |
| `internal/server/host_agent_remote_served_test.go:494` | loopback fixture closed below (CWE-400) |
| `internal/server/incident_fleet_reissuance_served_test.go:352` | loopback test fixture is explicitly closed (CWE-400) |
| `internal/server/migration_run_served_test.go:87` | loopback fixture is closed below (CWE-400) |
| `internal/server/migration_run_served_test.go:329` | loopback fixture is closed below (CWE-400) |
| `internal/server/serve_test.go:21` | local test listener owned and torn down by the test (CWE-400) |

### G115 — CWE-190 Integer overflow or wraparound (213 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/main.go:365` | the MaxUint32 check above proves the narrowing is exact (CWE-190). |
| `deploy/helm/helm_test.go:1705` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `ee/silo/lanedrill_test.go:96` | bounds-checked to [1, MaxUint16] above (CWE-190) |
| `internal/agent/relay/adcsscan_wire_test.go:217` | this fixed fixture is 40 bytes, below MaxUint16 (CWE-190). |
| `internal/agent/relay/adcsscan_wire_test.go:229` | this fixed fixture is below MaxUint16 (CWE-190). |
| `internal/api/application_secret_approval.go:412` | ApplicationSecretApprovalBinding just proved the version is positive (CWE-190). |
| `internal/api/machine_sessions_served_test.go:61` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/api/notifications_helpers_test.go:187` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/api/secretjson.go:173` | rune already range-checked below 0x20 before hex packing (CWE-190) |
| `internal/api/vault_compat_complete.go:714` | DER length of a public key, far under the uint32 bound (CWE-190) |
| `internal/audit/audit.go:151` | event sequence/count fits int64 by construction; bounded by the log (CWE-190) |
| `internal/audit/retention.go:247` | event sequence/count fits int64 by construction; bounded by the log (CWE-190) |
| `internal/backup/backup.go:172` | record counts bounded by the event log; fits both int and uint64 (CWE-190) |
| `internal/backup/backup.go:703` | receiptIndex starts at zero and is bounded by len(affectedOrder) above (CWE-190). |
| `internal/backup/backup.go:988` | record counts bounded by the event log; fits both int and uint64 (CWE-190) |
| `internal/ca/hierarchy/hierarchy_test.go:39` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/cli/doctor/doctor_test.go:41` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/crypto/argon2id.go:69` | length of a stored KDF hash, far under the uint32 bound (CWE-190) |
| `internal/crypto/ctlog/ctlogtest/ctlogtest.go:286` | test-support package compiled only into test binaries (CWE-190) |
| `internal/crypto/ctlog/ctlogtest/ctlogtest.go:303` | test-support package compiled only into test binaries (CWE-190) |
| `internal/crypto/seal/seal.go:117` | slice lengths cannot exceed uint64. |
| `internal/crypto/seal/seal.go:120` | slice lengths cannot exceed uint64. |
| `internal/crypto/seal/seal.go:224` | bounded to maxUint16Value by the check above (CWE-190) |
| `internal/crypto/seal/seal.go:576` | validateDomain above caps the length at maxUint16Value (CWE-190) |
| `internal/crypto/seal/seal.go:579` | bounded to maxUint16Value by the guard above (CWE-190) |
| `internal/crypto/signauth.go:66` | enum purpose and bounded message length framing (CWE-190) |
| `internal/crypto/signauth.go:76` | enum purpose and bounded message length framing (CWE-190) |
| `internal/crypto/ssh.go:69` | certificate validity epoch seconds; non-negative by validation (CWE-190) |
| `internal/crypto/ssh.go:70` | certificate validity epoch seconds; non-negative by validation (CWE-190) |
| `internal/crypto/sshkeys/property_test.go:37` | generator bounds the value to 0..2 (CWE-190) |
| `internal/crypto/sshkeys/property_test.go:40` | generator bounds the value to 0..3 (CWE-190) |
| `internal/crypto/sshkeys/property_test.go:114` | generator bounds the value to one byte (CWE-190) |
| `internal/crypto/sshkeys/property_test.go:117` | generator bounds the value to 0..2 (CWE-190) |
| `internal/crypto/tenantwrap/tenantwrap.go:238` | fixed-format buffer: a wrapped domain KEK has a fixed sealed length; an impossible oversize panics the slice bounds rather than truncating (CWE-190) |
| `internal/discovery/adcs/acl.go:76` | the offset is uint32-derived and bounded against len(raw) above (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:205` | the fixed malformed fixture is below MaxUint16 (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:240` | test SID inputs have at most 255 sub-authorities (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:242` | ParseUint limits authority to 48 bits and this loop emits one byte at a time (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:255` | deterministic test SIDs keep the ACE below MaxUint16 (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:264` | deterministic test SIDs keep the object ACE below MaxUint16 (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:284` | test call sites pass a bounded literal ACE set (CWE-190). |
| `internal/dns/rfc2136/rfc2136.go:246` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:263` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:283` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:298` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:299` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:314` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:339` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:343` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dynsecret/drivers.go:230` | SQL Server TDS prelogin framing of short bounded fields (CWE-190) |
| `internal/dynsecret/drivers.go:238` | SQL Server TDS prelogin framing of short bounded fields (CWE-190) |
| `internal/dynsecret/providers_real_test.go:480` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/events/backup_history_test.go:216` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/events/backup_restore_floor_test.go:593` | tiny fixed test sequence |
| `internal/historycontinuity/continuity_test.go:203` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/idemgc/idemgc_test.go:35` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/awskms/awskms_test.go:84` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/pkcs11/pkcs11_test.go:44` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/tpm/tpm_test.go:60` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/tpm/tpm_test.go:94` | deliberate byte packing of a bounded TPM handle in a test helper (CWE-190) |
| `internal/kms/tpm/tpm_test.go:95` | deliberate byte packing of a bounded TPM handle in a test helper (CWE-190) |
| `internal/kms/tpm/tpm_test.go:96` | deliberate byte packing of a bounded TPM handle in a test helper (CWE-190) |
| `internal/kms/tpm/tpm_test.go:245` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/leader/leader_test.go:36` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/mdm/challenge/challenge.go:79` | unix-epoch seconds round-trip; in int64 range until year 292e9 (CWE-190) |
| `internal/mdm/challenge/challenge.go:90` | unix-epoch seconds round-trip; in int64 range until year 292e9 (CWE-190) |
| `internal/observ/trace.go:228` | deliberate byte packing of a trace id (CWE-190) |
| `internal/orchestrator/main_test.go:67` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/orchestrator/operation_approvals.go:389` | a negative stored version is classified as drift before conversion (CWE-190). |
| `internal/orchestrator/secret_rotation.go:340` | the positive int64 value always fits exactly in uint64 (CWE-190). |
| `internal/orchestrator/tenant_registration_test.go:241` | bounded test sequence. |
| `internal/orchestrator/tenant_registration_test.go:322` | test event sequence is PostgreSQL bigint-bounded. |
| `internal/outboxgc/outboxgc_test.go:37` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/perf/live.go:855` | page size is positive and small (CWE-190) |
| `internal/projections/application_secret_rebuild_test.go:50` | the binding validator proved this fixture version is positive (CWE-190). |
| `internal/projections/application_secret_rebuild_test.go:76` | the binding validator proved this fixture version is positive (CWE-190). |
| `internal/projections/aud64_test.go:42` | every generated fixture sequence is a positive small integer (CWE-190). |
| `internal/projections/discovery_declaration_convergence_test.go:432` | migration 0199 constrains the sequence to non-negative bigint values |
| `internal/projections/full_dr_test.go:447` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/projections/projections_test.go:45` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/projections/secret_integrations.go:232` | the explicit bound above proves this event sequence fits PostgreSQL bigint. |
| `internal/projections/secret_integrations.go:239` | the explicit bound above proves this event sequence fits PostgreSQL bigint. |
| `internal/projections/secret_integrations_test.go:651` | embedded JetStream fixture sequences are bounded far below MaxInt64 (CWE-190). |
| `internal/projections/secret_integrations_test.go:804` | fixture sequence is tiny and asserted positive above. |
| `internal/projections/secret_sync_lifecycle.go:318` | observe checked the explicit PostgreSQL bigint bound. |
| `internal/projections/secret_sync_lifecycle_test.go:26` | fixture sequences are single-digit seconds (CWE-190). |
| `internal/projections/tenant_key_domain_test.go:59` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/projections/tenant_key_domain_test.go:341` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/protocols/acme/property_test.go:103` | test generator bounds the value to 0..4 (CWE-190) |
| `internal/protocols/acme/property_test.go:160` | generator output is bounded to ASCII a-z (CWE-190) |
| `internal/protocols/acme/property_test.go:170` | generator bounds the value to one byte (CWE-190) |
| `internal/protocols/ari/ari.go:94` | deterministic per-certificate renewal jitter (int64 seed reinterpreted for the PCG); scheduling spread, not a security decision (CWE-338, CWE-190) |
| `internal/protocols/est/property_test.go:142` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/protocols/est/property_test.go:155` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/protocols/ssh/krl_binary_test.go:23` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/protocols/ssh/ssh.go:375` | SSH wire string length, far under the uint32 bound for certificate fields (CWE-190) |
| `internal/query/adversarial_test.go:51` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/agentchannel_served_test.go:804` | fixture sequences are single-digit seconds (CWE-190). |
| `internal/server/aud65_test.go:37` | fixture sequences are single-digit seconds (CWE-190). |
| `internal/server/backup.go:209` | record counts bounded by the event log (CWE-190) |
| `internal/server/backup.go:369` | record counts bounded by the event log (CWE-190) |
| `internal/server/bundled_pg.go:65` | port validated into uint16 range by config parsing (CWE-190) |
| `internal/server/managedkeys_pkcs11_served_test.go:47` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/pam_served_test.go:216` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/protocol_mounts.go:899` | DER lengths of certificates/keys are orders of magnitude under the uint32 bound (CWE-190) |
| `internal/server/protocol_mounts.go:901` | DER lengths of certificates/keys are orders of magnitude under the uint32 bound (CWE-190) |
| `internal/server/recovery_projection_factory_test.go:172` | event test sequence is PostgreSQL bigint-bounded. |
| `internal/server/revocation.go:422` | value reduced modulo the shard count before conversion (CWE-190) |
| `internal/server/secret_integrations_outbox.go:810` | positive int64 is exactly representable as uint64. |
| `internal/server/secret_integrations_outbox.go:811` | positive int64 is exactly representable as uint64. |
| `internal/server/secret_integrations_outbox.go:814` | positive int64 is exactly representable as uint64. |
| `internal/server/secret_integrations_outbox.go:823` | positive int64 is exactly representable as uint64. |
| `internal/server/secrets_rotation_served_test.go:2454` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/signing/keystore.go:108` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:110` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:112` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:114` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:121` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/store/acme_dns01.go:292` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/acme_dns01.go:337` | non-negative by construction (CWE-190) |
| `internal/store/application_secret_approval_test.go:49` | the binding validator proved this fixture version is positive (CWE-190). |
| `internal/store/audit_checkpoint.go:30` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/audit_checkpoint.go:52` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/audit_checkpoint.go:72` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/audit_feed.go:397` | PostgreSQL bigint event sequence is non-negative by schema (CWE-190) |
| `internal/store/audit_feed.go:398` | PostgreSQL bigint tenant sequence is non-negative by schema (CWE-190) |
| `internal/store/audit_feed.go:399` | PostgreSQL bigint tenant sequence is non-negative by schema (CWE-190) |
| `internal/store/audit_feed.go:400` | PostgreSQL bigint tenant sequence is non-negative by schema (CWE-190) |
| `internal/store/audit_feed.go:413` | positive PostgreSQL bigint by schema (CWE-190) |
| `internal/store/audit_feed.go:414` | positive PostgreSQL bigint by schema (CWE-190) |
| `internal/store/ca.go:457` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/ca.go:527` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/connector_lifecycle.go:443` | JetStream sequence fits PostgreSQL bigint by construction (CWE-190) |
| `internal/store/connector_lifecycle.go:497` | constrained positive PostgreSQL bigint (CWE-190) |
| `internal/store/connector_lifecycle.go:500` | constrained positive PostgreSQL bigint (CWE-190) |
| `internal/store/cryptoasset_migration_test.go:38` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/store/discovery.go:177` | JetStream event sequences are stored in PostgreSQL bigint throughout the projection spine (CWE-190) |
| `internal/store/discovery.go:221` | the migration constrains this PostgreSQL bigint to non-negative values (CWE-190) |
| `internal/store/discovery_coverage.go:37` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/discovery_coverage.go:57` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/discovery_coverage.go:81` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/discovery_segments.go:74` | JetStream event sequences are stored in PostgreSQL bigint throughout the projection spine (CWE-190) |
| `internal/store/discovery_segments.go:104` | the migration constrains this PostgreSQL bigint to non-negative values (CWE-190) |
| `internal/store/discovery_segments.go:135` | the migration constrains this PostgreSQL bigint to non-negative values (CWE-190) |
| `internal/store/discovery_segments.go:193` | the migration constrains this PostgreSQL bigint to non-negative values (CWE-190) |
| `internal/store/endpoint_verification.go:112` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/endpoint_verification.go:156` | non-negative by construction (CWE-190) |
| `internal/store/endpoint_verification.go:197` | constrained positive database sequence (CWE-190) |
| `internal/store/enrollment_diagnostics.go:95` | JetStream sequence fits positive bigint (CWE-190) |
| `internal/store/enrollment_diagnostics.go:234` | JetStream/PostgreSQL sequences share the signed-bigint storage bound (CWE-190) |
| `internal/store/enrollment_diagnostics.go:275` | JetStream/PostgreSQL sequences share the signed-bigint storage bound (CWE-190) |
| `internal/store/enrollment_diagnostics.go:372` | constrained positive bigint written from a JetStream sequence (CWE-190) |
| `internal/store/federation.go:58` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/migration_run.go:52` | JetStream/PostgreSQL event sequence is bounded by bigint (CWE-190) |
| `internal/store/migration_run.go:168` | positive bigint constrained by migration (CWE-190) |
| `internal/store/migration_run.go:192` | positive bigint constrained by migration (CWE-190) |
| `internal/store/migration_run.go:225` | positive bigint constrained by migration (CWE-190) |
| `internal/store/offboard_test.go:44` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/store/operation_approvals.go:252` | the explicit MaxInt64 bound above prevents narrowing (CWE-190). |
| `internal/store/outbox_reconciliation_checkpoint.go:34` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/outbox_reconciliation_conflicts.go:73` | JetStream sequence fits PostgreSQL bigint by construction (CWE-190). |
| `internal/store/ownership_assignment.go:65` | event sequences fit PostgreSQL bigint |
| `internal/store/ownership_readiness.go:205` | event sequences fit PostgreSQL bigint |
| `internal/store/ownership_readiness.go:226` | event sequences fit PostgreSQL bigint |
| `internal/store/ownership_readiness.go:286` | database constraint/event writer keeps sequence non-negative |
| `internal/store/pam.go:73` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:632` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:687` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:831` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:845` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:136` | event sequence fits the PostgreSQL bigint used by the event log (CWE-190) |
| `internal/store/projection_checkpoint.go:192` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:213` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/secret_rotation_schedule.go:289` | validateBoundSecretRotationScheduleRun rejects values above MaxInt64 (CWE-190). |
| `internal/store/secret_rotation_schedule.go:313` | validateBoundSecretRotationScheduleRun rejects values above MaxInt64 (CWE-190). |
| `internal/store/snapshot.go:442` | the projection sequence is stored in a PostgreSQL bigint throughout this file (CWE-190) |
| `internal/store/snapshot.go:457` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tenant.go:58` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tenant.go:76` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tenant_key_domain.go:146` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/tenantseal/idempotency.go:96` | length framing of short bounded fields (CWE-190) |
| `internal/tsa/fuzz_test.go:133` | crafted DER length byte for fuzz corpus; truncation is the crafted input (CWE-190) |
| `internal/tsa/fuzz_test.go:135` | crafted DER length byte for fuzz corpus (CWE-190) |
| `internal/tsa/fuzz_test.go:137` | crafted DER length bytes for fuzz corpus (CWE-190) |
| `scripts/perf/cmd/capacitycalibrate/main.go:217` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:236` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:237` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:335` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:415` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:479` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:675` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:676` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:700` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:374` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1129` | bounded process identity comparison (CWE-190) |
| `tools/dodcensus/proof/launched.go:1161` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1262` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1683` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1720` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1894` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1898` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:2541` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:144` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:150` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:156` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:163` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:178` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:190` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:199` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:209` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/substrate_broker.go:396` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/substrate_broker.go:420` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/substrate_broker.go:450` | bounded value packing in a developer tool, not a served binary (CWE-190) |

### G117 — CWE-200 Exposure of sensitive information (marshaled secret field) (1 sites)

| Location | Reason |
|---|---|
| `internal/dynsecret/providers_real.go:1162` | the dynamic-secret provider's minted credential payload; returning it is the API (CWE-200) |

### G118 — CWE-664 Improper lifetime control (goroutine context) (2 sites)

| Location | Reason |
|---|---|
| `internal/events/privacy_erasure_test.go:1433` | test goroutine lifecycle is managed by the test (CWE-664) |
| `internal/server/agenthttprenewal.go:64` | shutdown grace period must outlive the already-canceled parent context (CWE-664) |

### G122 — CWE-367 Time-of-check time-of-use race (walk callback) (24 sites)

| Location | Reason |
|---|---|
| `deploy/deploycheck_test.go:599` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `deploy/helm/airgap_bundle_test.go:163` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/ai_surface_placement_test.go:27` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/deferred_wipe_guard_test.go:45` | walking the repo's own tree (CWE-22) |
| `docs/docs_test.go:2538` | test walks the repo's own checkout; no hostile symlink exposure (CWE-367) |
| `docs/embedded_postgres_teardown_test.go:43` | walks this repository's own test sources (CWE-22) |
| `docs/est_differential_test.go:190` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_completeness_test.go:260` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:876` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:939` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:4548` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/provenance/authorship_test.go:103` | test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367) |
| `internal/agent/discovery/filesystem.go:57` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/privatekey.go:69` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/truststore.go:74` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/auditsink/discard_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/crypto/acmekey/production_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/notify/response_buffer_guard_test.go:37` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/backup_test.go:843` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/protect_correct102_guard_test.go:100` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/design_test.go:136` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/managedkeys_test.go:445` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/store/store_isolation_test.go:309` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/store/store_isolation_test.go:355` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |

### G124 — CWE-1004 Sensitive cookie without protective attributes (38 sites)

| Location | Reason |
|---|---|
| `ee/provider/saml_authenticator.go:215` | credential cookie is HttpOnly, host-only, strict, and Secure follows the served TLS mode. |
| `ee/provider/saml_authenticator.go:224` | non-HttpOnly by design for double-submit CSRF; it is not a credential without the HttpOnly session. |
| `ee/provider/saml_authenticator.go:246` | deletion preserves the HttpOnly, strict, host-only session policy; Secure is false only in explicit loopback development mode (CWE-614). |
| `ee/provider/saml_authenticator.go:250` | this non-credential double-submit cookie must remain JavaScript-readable; strict and served-mode Secure still apply (CWE-614). |
| `ee/provider/saml_authenticator.go:346` | short-lived HttpOnly state/request correlation; None is paired with Secure for the required cross-site SAML POST. |
| `ee/provider/saml_authenticator.go:353` | expiry retains HttpOnly/Lax and uses insecure transport only in explicit loopback development mode (CWE-614). |
| `internal/api/auth.go:778` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth.go:789` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth.go:813` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth.go:820` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth_hardening_test.go:21` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:226` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:227` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:228` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:229` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:283` | explicit loopback-only plaintext development test (CWE-1004) |
| `internal/api/auth_test.go:313` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:314` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:315` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:316` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:463` | test cookie against the test's own local server (CWE-1004) (mismatch) |
| `internal/api/auth_test.go:483` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:484` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:511` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:512` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:541` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:562` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:609` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:37` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:52` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:53` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:70` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:71` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/rate_limit_guard_test.go:50` | test cookie against the test's own local server (CWE-1004) |
| `internal/connector/netscaler/netscaler.go:272` | cookie on an outbound API request; response-cookie attributes do not apply (CWE-1004) |
| `internal/projections/auth_resolver_test.go:170` | test cookie against the test's own local server (CWE-1004) |
| `internal/projections/auth_resolver_test.go:179` | test cookie against the test's own local server (CWE-1004) |
| `internal/server/scim_served_test.go:203` | explicit plaintext loopback fixture; the production TLS cookie remains Secure and __Host-prefixed (CWE-1004) |

### G201 — CWE-? (unmapped rule) (1 sites)

| Location | Reason |
|---|---|
| `internal/store/migration_content_test.go:2988` | closed test table list above |

### G203 — CWE-? (unmapped rule) (2 sites)

| Location | Reason |
|---|---|
| `ee/whitelabel/email.go:99` | scheme and host validated above; https only (CWE-79) |
| `ee/whitelabel/email.go:116` | raster image data URI with a decodable base64 payload (CWE-79) |

### G204 — CWE-78 OS command injection (154 sites)

| Location | Reason |
|---|---|
| `clients/embedded/est_client_test.go:49` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:76` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:103` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:142` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:174` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:183` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:202` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `clients/embedded/est_client_test.go:219` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `cmd/trstctl-agent/selfrestart_unix.go:23` | re-exec of this process's OWN executable path with its own args; the binary at that path was just digest-verified against the campaign's pinned sha256 (CWE-78) |
| `cmd/trstctl-agent/sshtrust.go:167` | operator-configured sshd reload command; running it is the feature (CWE-78) |
| `cmd/trstctl/backup_cmd_test.go:40` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `cmd/trstctl/demo.go:151` | binary resolved beside this executable, args are our own config (CWE-78) |
| `deploy/deploycheck_test.go:119` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/deploycheck_test.go:442` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/deploycheck_test.go:452` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:691` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:794` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:1090` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:1155` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/reproducible_test.go:64` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/airgap_bundle_test.go:34` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/airgap_bundle_test.go:49` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/airgap_bundle_test.go:111` | test executes a fixed local tool (CWE-78). |
| `deploy/helm/helm_docs_commands_test.go:48` | executes the repo's own documented helm command under test (CWE-78) |
| `deploy/helm/helm_docs_commands_test.go:113` | executes the repo's own documented helm command under test (CWE-78) |
| `deploy/helm/helm_test.go:1115` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/kubernetes/manifests_test.go:416` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/kubernetes/manifests_test.go:434` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/local-oidc/oidc_test.go:79` | node path comes from LookPath and the script is a checked-in test target (CWE-78) |
| `deploy/local-oidc/oidc_test.go:155` | arguments are fixed checked-in scripts (CWE-78) |
| `docs/claim_applications_test.go:67` | test runs the repository's own committed generator against tempdir fixtures it just wrote itself (CWE-78) |
| `docs/cwe_register_test.go:18` | test runs the repo's own committed generator (CWE-78) |
| `docs/cwe_register_test.go:40` | test runs the repo's own committed generator against a tempdir fixture (CWE-78) |
| `docs/docs_drift_test.go:184` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/lint_gate_test.go:25` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/lint_gate_test.go:39` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/vuln_gate_test.go:44` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/agentid/delegation/signer_subprocess_test.go:144` | executable and argv are fixed; output is confined to TempDir (CWE-78). |
| `ee/agentid/verify/wasm_parity_test.go:49` | executable and argv are fixed; output is confined to TempDir (CWE-78). |
| `ee/agentid/verify/wasm_parity_test.go:59` | execShim is Go's fixed wasm_exec_node shim and wasmOut is this test's TempDir artifact (CWE-78). |
| `ee/decommission/conformance/release_test.go:19` | goBin is derived from runtime.GOROOT and every argument is fixed (CWE-78). |
| `ee/decommission/conformance/release_test.go:438` | fixed argv, no user input (CWE-78) |
| `ee/kmip/independent_verifier_test.go:119` | python is LookPath-resolved and module is a fixed repository verifier path (CWE-78). |
| `ee/pqc/pure_x509_openssl_test.go:129` | path is exec.LookPath("openssl") and arguments are fixed (CWE-78). |
| `ee/pqc/pure_x509_openssl_test.go:139` | executable is the LookPath-resolved OpenSSL and test call sites supply fixed verbs plus TempDir paths (CWE-78). |
| `ee/pqc/signer_served_test.go:88` | executable and argv are fixed; output is confined to TempDir (CWE-78). |
| `ee/pqcruntime/spiffe_hybrid_test.go:81` | path is exec.LookPath("openssl") and arguments are fixed (CWE-78). |
| `ee/pqcruntime/spiffe_hybrid_test.go:91` | executable is the LookPath-resolved OpenSSL and call sites supply fixed verbs plus TempDir paths (CWE-78). |
| `ee/rpverify/verifier_test.go:380` | fixed argv, no user input (CWE-78) |
| `ee/succession/conformance/edition_test.go:43` | goBin is derived from runtime.GOROOT and every argument is fixed (CWE-78). |
| `ee/succession/conformance/edition_test.go:118` | fixed argv, no user input (CWE-78) |
| `ee/succession/conformance/int20_fullstack_test.go:608` | executable/argv are fixed and ldflags contain only this test's base64 public key (CWE-78). |
| `internal/agent/sshtrust/sshd_live_test.go:61` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:153` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:179` | live-sshd test harness validating its own config with the resolved sshd binary (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:188` | HUPs the harness's own child sshd by pid (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:240` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/api/headerauth_guard_test.go:34` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/api/headerauth_guard_test.go:39` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/ca/shellca/shellca.go:120` | the shell-CA backend exists to run the operator's configured signing command (CWE-78) |
| `internal/cli/cli_test.go:1994` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/connector/localops.go:260` | operator-configured local-ops action command; running it is the feature (CWE-78) |
| `internal/crypto/kmswrap/external_kms.go:122` | operator-configured external KMS helper command (CWE-78) |
| `internal/kms/pkcs11/softhsm_container_test.go:116` | fixed Docker test-harness operations bounded by a context deadline (CWE-78) |
| `internal/kms/tpm/swtpm_container_test.go:94` | fixed Docker test-harness operations bounded by a context deadline (CWE-78) |
| `internal/perf/live.go:735` | perf harness building/running the repo's own signer with the go toolchain (CWE-78) |
| `internal/perf/live.go:899` | perf harness building/running the repo's own signer with the go toolchain (CWE-78) |
| `internal/projections/server_assembly_test.go:44` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/acme/certbot_client_test.go:240` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/conformance_test.go:116` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/openssl_client_test.go:48` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/openssl_client_test.go:114` | test executes a fixed local tool or fixture it built itself (CWE-78) |
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
| `internal/secretscan/gitleaks.go:152` | fixed git/gitleaks binaries over the operator's own repository (CWE-78) |
| `internal/secretscan/repository.go:96` | fixed git/gitleaks binaries over the operator's own repository (CWE-78) |
| `internal/secretscli/secretscli.go:87` | runs the operator's own command line verbatim; injecting secrets into their process is the feature (CWE-78) |
| `internal/server/agent_workload_api_gospiffe_test.go:215` | test executes a fixed local fixture (CWE-78) |
| `internal/server/audit_export_formats_served_test.go:267` | fixed binary built by this test; arguments are fixed/test-owned paths and enum values (CWE-78) |
| `internal/server/audit_export_formats_served_test.go:292` | fixed repository binary and test-owned destination (CWE-78) |
| `internal/server/auth_ldap_served_test.go:127` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:132` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:138` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:155` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:166` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/auth_ldap_served_test.go:172` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/backup_test.go:802` | fixed repository binary and test-owned destination (CWE-78) |
| `internal/server/bundled_pg_dependency_test.go:19` | fixed local Go tool and package pattern (CWE-78) |
| `internal/server/dod_signer_binary_test.go:105` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/enrollment_relay_served_test.go:107` | fixed current test binary and fixed test selector (CWE-78) |
| `internal/server/github_action_served_test.go:224` | the test deliberately executes a generated copy of the fixed shipped action script (CWE-78). |
| `internal/server/java_sdk_served_test.go:55` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/java_sdk_served_test.go:59` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/java_sdk_served_test.go:90` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:340` | fixed Docker test-harness operations bounded by a context deadline (CWE-78) |
| `internal/server/pam_served_test.go:350` | fixed best-effort test cleanup bounded by a context deadline (CWE-78) |
| `internal/server/pam_served_test.go:364` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:395` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:311` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:370` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:398` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:513` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:565` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:580` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:302` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:382` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:401` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:468` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:592` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_tsa_test.go:46` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_tsa_test.go:70` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/python_sdk_served_test.go:82` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/revocation_openssl_test.go:184` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/signer_token_command.go:61` | operator-configured token-helper command (CWE-78) |
| `internal/server/vault_compat_served_test.go:95` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/signing/helpers_test.go:29` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/signing/static_test.go:41` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/signing/supervisor.go:46` | spawns the repo's own signer binary; AN-4 child-process mode (CWE-78) |
| `internal/signing/supervisor.go:235` | spawns the repo's own signer binary; AN-4 child-process mode (CWE-78) |
| `internal/testutil/openssltest/openssltest.go:97` | test-support helper running the system openssl found above; not linked into served binaries (CWE-78) |
| `internal/tsa/http_test.go:48` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/tsa/http_test.go:75` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/tsa/tsa_rfc3161_test.go:128` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `scripts/perf/cmd/perfgate/main_test.go:28` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `scripts/perf/cmd/soakcapture/main_test.go:62` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `scripts/perf/cmd/soakgate/main_test.go:133` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/connector_substrate_test.go:114` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/external_ca_substrate_test.go:168` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/kmip_substrate_test.go:38` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/main.go:312` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/managed_key_manifest_test.go:526` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/managed_key_manifest_test.go:562` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/launched.go:263` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/launched.go:526` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/launched.go:1284` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/launched.go:1320` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/proof.go:322` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1016` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1058` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1142` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/runtime_runner.go:868` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/substrate_broker.go:222` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/pqclab/main.go:594` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/trstctllint/repo_selftest_test.go:22` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/trstctllint/repo_selftest_test.go:109` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/trstctllint/repo_selftest_test.go:158` | test executes a fixed local tool or fixture it built itself (CWE-78) |

### G301 — CWE-276 Incorrect default permissions (directory) (47 sites)

| Location | Reason |
|---|---|
| `clients/embedded/est_client_test.go:73` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `clients/embedded/est_client_test.go:138` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `clients/embedded/est_client_test.go:199` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `deploy/docker/dist_test.go:1034` | npm fixture tree in t.TempDir; mirrors a real package layout, nothing secret (CWE-276) |
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
| `internal/protocols/cmp/openssl_client_test.go:168` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/scep/sscep_client_test.go:196` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/agentchannel_served_test.go:1493` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/java_sdk_served_test.go:44` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/pam_served_test.go:209` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:51` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:86` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:733` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:747` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_tsa_test.go:103` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/secret_third_party_scan_served_test.go:154` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/secrets_rotation_served_test.go:2447` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/server.go:2198` | served CA certificate directory; the PEM is public material (CWE-276) |
| `internal/signing/socket_dir_symlink_test.go:24` | the loose mode IS the attack fixture this test defends against (CWE-276) |
| `internal/signing/socket_dir_symlink_test.go:56` | the wide mode IS the precondition this test proves gets narrowed (CWE-276) |
| `internal/tsa/http_test.go:103` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `scripts/perf/cmd/capacitycalibrate/main.go:137` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/perfgate/main.go:52` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakcapture/main.go:82` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakgate/main.go:120` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/spineburst/main.go:170` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/dodcensus/main.go:1285` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/pqclab/main.go:795` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/trstctllint/eventsource/eventsource_test.go:98` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/trstctllint/idempotency/idempotency_test.go:198` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |

### G302 — CWE-276 Incorrect default permissions (chmod) (28 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/main.go:462` | 0700 on a directory: the execute bit is required to traverse it (CWE-276) |
| `internal/agent/destination/fs_unix_test.go:82` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_unix_test.go:28` | deliberately loosens the fixture key's mode; detecting exactly this is what the test proves (CWE-276) |
| `internal/agent/drift/drift_unix_test.go:53` | deliberately loosens the fixture key's mode; detecting exactly this is what the test proves (CWE-276) |
| `internal/agent/relay/selfupgrade.go:206` | the file IS the executable being installed; 0755 is its required mode (CWE-276) |
| `internal/agent/workloadapi/attest.go:141` | a DIRECTORY, not a file. 0700 is the tightest mode that |
| `internal/crypto/mtls/server_test.go:113` | deliberate over-permissive negative fixture (CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:64` | deliberately loose fixture mode; secretfile must refuse it (CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:67` | restores the fixture dir so t.TempDir cleanup can remove it (CWE-276) |
| `internal/server/external_ca_config_test.go:120` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/managed_key_signer_config.go:27` | 0700 on a directory: the execute bit is required to traverse it (CWE-276) |
| `internal/server/protocols_served_tsa_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/signing/serve.go:199` | 0700 on a directory: the execute bit is required to traverse it (CWE-276) |
| `internal/signing/socket_dir_symlink_test.go:59` | deliberately widened so enforceExactSocketDirMode has something to tighten (CWE-276) |
| `internal/signing/socket_mode_unix_test.go:206` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/tsa/http_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `tools/dodcensus/proof/proof_test.go:712` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:732` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:742` | deliberately unsafe fixture mode (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:775` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:147` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:153` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:170` | private fixture-directory mode is the behavior under test (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:196` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:157` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:163` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:166` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:293` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |

### G304 — CWE-22 Path traversal (file inclusion via variable) (363 sites)

| Location | Reason |
|---|---|
| `clients/embedded/est_client_test.go:81` | test reads its own fixture/tempdir path (CWE-22) |
| `cmd/trstctl-agent/cosign_attach.go:89` | operator-configured local path from the agent's own config (CWE-22) |
| `cmd/trstctl-agent/edgeca.go:161` | operator-configured local path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/edgeca.go:185` | operator-configured local path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/edgeca.go:195` | operator-configured local handle path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/edgeca.go:276` | operator-configured journal path on the agent's own host (CWE-22) |
| `cmd/trstctl-agent/edgeca_provider.go:70` | explicit operator-owned device secret path (CWE-22) |
| `cmd/trstctl-agent/edgeca_test.go:61` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_test.go:122` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_test.go:242` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_test.go:253` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/main.go:834` | operator-supplied PIN file path, read at their instruction (CWE-22) |
| `cmd/trstctl-agent/pluginruntime.go:90` | operator-supplied trust key path (CWE-22) |
| `cmd/trstctl-agent/pluginruntime.go:343` | operator-supplied runtime configuration path (CWE-22) |
| `cmd/trstctl-agent/pluginruntime.go:370` | operator-supplied public issuer certificate (CWE-22) |
| `cmd/trstctl-agent/pluginruntime.go:400` | operator-supplied public issuer certificate (CWE-22) |
| `cmd/trstctl-agent/sshtrust.go:90` | operator-configured local path from the agent's own config (CWE-22) |
| `cmd/trstctl-license/aud56_test.go:35` | licensePath is created inside this test's TempDir (CWE-22). |
| `cmd/trstctl/backup_cmd_test.go:46` | test reads its own fixture/tempdir path (CWE-22) |
| `cmd/trstctl/backup_cmd_test.go:64` | test reads its own fixture/tempdir path (CWE-22) |
| `cmd/trstctl/backup_cmd_test.go:86` | test reads a fixed repository artifact (CWE-22) |
| `cmd/trstctl/ee_attach.go:503` | operator-supplied path to their own IdP's JWKS (CWE-22) |
| `cmd/trstctl/ee_attach.go:531` | operator-pinned local IdP metadata, validated as configuration. |
| `deploy/demo/aud66_test.go:105` | fixed repository test path (CWE-22) |
| `deploy/demo/demo_test.go:45` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:98` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:212` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:294` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:364` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:462` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:599` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `deploy/deploycheck_test.go:690` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:759` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:847` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:977` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:983` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:989` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1052` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1142` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1325` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1569` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/docker/dist_test.go:25` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/docker/dist_test.go:1106` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/docker/reproducible_test.go:35` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/airgap_bundle_test.go:62` | bundle is created inside this test's TempDir (CWE-22). |
| `deploy/helm/airgap_bundle_test.go:69` | bundle is created inside this test's TempDir (CWE-22). |
| `deploy/helm/airgap_bundle_test.go:163` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `deploy/helm/airgap_bundle_test.go:179` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/airgap_bundle_test.go:225` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/helm_docs_commands_test.go:130` | reads the repo's own docs pages from a walked list (CWE-22) |
| `deploy/helm/helm_test.go:1077` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/helm_test.go:1138` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/iac/iac_test.go:279` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/kubernetes/manifests_test.go:477` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/kubernetes/manifests_test.go:494` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/local-oidc/oidc_test.go:164` | paths are exact children of t.TempDir (CWE-22) |
| `docs/ai_surface_placement_test.go:27` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/aud56_test.go:52` | name comes from the fixed documentation manifest in this test (CWE-22). |
| `docs/aud58_test.go:15` | name comes from the fixed documentation manifest in this test (CWE-22). |
| `docs/aud65_test.go:18` | name comes from the fixed documentation manifest in this test (CWE-22). |
| `docs/deferred_wipe_guard_test.go:45` | walking the repo's own tree (CWE-22) |
| `docs/docker_acceptance_deadline_test.go:22` | test reads a fixed repository path (CWE-22) |
| `docs/doctor_doc_test.go:32` | fixed literal list of the repo's own committed doctor sources; no external input reaches this path (CWE-22) |
| `docs/embedded_postgres_teardown_test.go:43` | walks this repository's own test sources (CWE-22) |
| `docs/est_differential_test.go:190` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/nolint_gosec_guard_test.go:90` | test reads a path listed by this repository's own git index (CWE-22) |
| `docs/operational_transfer_test.go:64` | test reads its own fixture/tempdir path (CWE-22) |
| `docs/protect_guards_completeness_test.go:260` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:876` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:939` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:4548` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/provenance/authorship_test.go:38` | fixed sibling path inside the package's own directory (CWE-22) |
| `docs/provenance/authorship_test.go:103` | test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367) |
| `ee/billing/evidence_test.go:140` | test reads repo source files it names itself (CWE-22) |
| `ee/managedkeys/signerwiring/wiring.go:109` | path is the signer operator's explicit local configuration file, never remote input (CWE-22). |
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
| `internal/agent/relay/hostexec.go:121` | operator-supplied profile path, read at their instruction (CWE-22) |
| `internal/agent/relay/hostrollback.go:285` | validated agent-local state directory (CWE-22) |
| `internal/agent/relay/hostrollback_test.go:46` | test-owned temporary directory (CWE-22) |
| `internal/agent/relay/plugins.go:141` | operator-configured plugin directory (CWE-22) |
| `internal/agent/relay/plugins.go:145` | sibling of an operator-configured module (CWE-22) |
| `internal/agent/relay/rollback_test.go:200` | test-owned temporary path (CWE-22) |
| `internal/agent/relay/selfupgrade_test.go:87` | test reads its own tempdir fixture path (CWE-22) |
| `internal/agent/relay/selfupgrade_test.go:152` | test reads its own tempdir fixture path (CWE-22) |
| `internal/agent/relay/selfupgrade_test.go:156` | test reads its own tempdir fixture path (CWE-22) |
| `internal/agent/relay/trust_test.go:48` | path is created inside this test's TempDir (CWE-22). |
| `internal/agent/relay/trust_test.go:73` | path is created inside this test's TempDir (CWE-22). |
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
| `internal/api/public_route_abuse_guard_test.go:91` | reads this package's own sources in a test (CWE-22) |
| `internal/api/sdk_spec_pinned_test.go:49` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/api/vault_compat_contract_test.go:255` | test reads its own fixture/tempdir path (CWE-22) |
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
| `internal/cbom/hostsource/hostsource.go:64` | an authorized, previewed discovery selector; the read is size-bounded below (CWE-22) |
| `internal/cli/audit_verify.go:103` | path is the explicit read-only local artifact selected by this CLI command (CWE-22). |
| `internal/cli/cli.go:162` | the operator explicitly names the public trust-bundle path (CWE-22) |
| `internal/cli/cli.go:485` | operator-passed local file argument on their own command line (CWE-22) |
| `internal/cli/cli_test.go:1554` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/cli/doctor/doctor_test.go:98` | test reads its own tempdir receipt (CWE-22) |
| `internal/cloudhttp/adoption_guard_test.go:127` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/config/config.go:2278` | the config loader reading the operator's own config file (CWE-22) |
| `internal/connector/device_proof_census_test.go:46` | fixed in-tree path derived from the census (CWE-22) |
| `internal/connector/localops.go:147` | operator-configured local-ops connector path; local file deploy is the feature (CWE-22) |
| `internal/connector/localops.go:180` | operator-configured local-ops connector path; local file deploy is the feature (CWE-22) |
| `internal/connector/localops.go:219` | clean is confined to operator-approved local roots above (CWE-22) |
| `internal/connector/localops.go:230` | clean is confined to operator-approved local roots above (CWE-22) |
| `internal/crypto/acmekey/production_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/crypto/mtls/agent.go:214` | operator-configured certificate/key path from deployment config (CWE-22) |
| `internal/crypto/mtls/agent.go:232` | operator-configured certificate/key path from deployment config (CWE-22) |
| `internal/crypto/mtls/server.go:190` | parent of the validated internal TLS state path (CWE-22) |
| `internal/crypto/mtls/server.go:222` | operator-selected public certificate path, validated as a regular file (CWE-22) |
| `internal/crypto/mtls/server.go:311` | operator-selected internal TLS state path, validated as a private regular file (CWE-22) |
| `internal/crypto/mtls/server.go:357` | operator-configured certificate/key path from deployment config (CWE-22) |
| `internal/crypto/mtls/server_test.go:43` | test-owned path under t.TempDir (CWE-22) |
| `internal/crypto/mtls/server_test.go:71` | test-owned path under t.TempDir (CWE-22) |
| `internal/crypto/mtls/server_test.go:105` | test-owned path under t.TempDir (CWE-22) |
| `internal/crypto/mtls/server_test.go:109` | test-owned path under t.TempDir (CWE-22) |
| `internal/crypto/mtls/signer.go:107` | operator-configured peer CA trust anchor path from the signer's own config (CWE-22) |
| `internal/crypto/mtls/signer_test.go:47` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/parserfuzz_audit_test.go:172` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/parserfuzz_audit_test.go:259` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/pfx/pfx_test.go:43` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/pfx/pfx_test.go:44` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/secretfile/secretfile.go:34` | operator-configured local secret path; parents and file mode validated above (CWE-22) |
| `internal/crypto/secretfile/secretfile.go:65` | operator-configured local secret path; O_EXCL + 0600, parents validated above (CWE-22) |
| `internal/dynsecret/providers_real_test.go:227` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/events/protect_schema005_guard_test.go:138` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/catalog.go:94` | fixed repo-relative catalog path read by tools and tests (CWE-22) |
| `internal/featureparity/feature_facet_coverage_test.go:110` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/feature_facet_coverage_test.go:114` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/feature_facet_coverage_test.go:140` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/mcp_rest_coverage.go:53` | fixed repo-relative catalog path read by tools and tests (CWE-22) |
| `internal/fsatomic/fsatomic.go:19` | the caller's own state directory (CWE-22) |
| `internal/license/license.go:370` | operator-supplied license file path (CWE-22) |
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
| `internal/protocols/cmp/openssl_client_test.go:80` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:133` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:172` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:178` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:200` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/est/differential_test.go:107` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:180` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:200` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:205` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:233` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/secretscan/gitleaks.go:164` | reads the report file this process asked gitleaks to write in its own tempdir (CWE-22) |
| `internal/secretscan/gitleaks.go:421` | the operator's own scanner config, already validated as a path this process was told to use (CWE-22) |
| `internal/secretscan/gitleaks_options_test.go:132` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/secretscan/secretscan_test.go:124` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/agentchannel.go:122` | operator-configured agent CA certificate path from this server's own config (CWE-22) |
| `internal/server/backup.go:132` | operator-configured public trust anchor path (CWE-22) |
| `internal/server/backup.go:196` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:360` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:395` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:482` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:724` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:826` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:830` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup_test.go:344` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/backup_test.go:392` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/backup_test.go:531` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/backup_test.go:843` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/breakglass.go:123` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/bundled_pg_dependency_test.go:32` | fixed repository source path (CWE-22) |
| `internal/server/bundled_pg_dependency_test.go:46` | fixed repository source path (CWE-22) |
| `internal/server/bundled_pg_verify.go:110` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/ca_custody_test.go:91` | test-owned path verifies upgrade custody |
| `internal/server/ca_custody_test.go:95` | test-owned path verifies public mirror |
| `internal/server/ca_custody_test.go:226` | test-owned path under t.TempDir verifies fail-closed preservation (CWE-22) |
| `internal/server/ca_custody_test.go:261` | test-owned path under t.TempDir captures the planted mismatch (CWE-22) |
| `internal/server/ca_custody_test.go:269` | same test-owned path proves the mismatch was not overwritten (CWE-22) |
| `internal/server/cmdb_readonly_test.go:126` | test reads repo source files it names itself (CWE-22) |
| `internal/server/dod_connector_runtime_test.go:76` | parent-created public CA fixture (CWE-22) |
| `internal/server/dynamic_secret_failure_epoch_guard_test.go:22` | closed sibling-source fixture list. |
| `internal/server/external_poller_boundary_test.go:16` | name comes only from the closed literal source-file list above (CWE-22) |
| `internal/server/host_agent_remote_served_test.go:139` | parent-created test fixture path (CWE-22) |
| `internal/server/host_agent_remote_served_test.go:193` | parent-created public fixture (CWE-22) |
| `internal/server/host_agent_remote_served_test.go:380` | test reads its own remote-host fixture (CWE-22) |
| `internal/server/host_agent_remote_served_test.go:742` | test-owned target fixture (CWE-22) |
| `internal/server/idempotency_protection_wiring_test.go:61` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/migration_run_served_test.go:249` | test-owned fixture path (CWE-22) |
| `internal/server/migration_run_served_test.go:258` | test-owned fixture path (CWE-22) |
| `internal/server/migration_run_served_test.go:289` | test-owned fixture path (CWE-22) |
| `internal/server/pam_served_test.go:367` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/plugins.go:199` | operator-configured plugin dir; WASM and signature are verified after the read (CWE-22) |
| `internal/server/plugins.go:203` | operator-configured plugin dir; WASM and signature are verified after the read (CWE-22) |
| `internal/server/protect_correct102_guard_test.go:100` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/protocol_mounts.go:679` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/protocol_mounts.go:786` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/protocol_mounts.go:851` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/protocol_mounts.go:1126` | operator-configured trust bundle path (CWE-22) |
| `internal/server/protocols_served_spiffe_ssh_test.go:583` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:228` | test reads its own tempdir fixture (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:232` | test reads its own tempdir fixture (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:326` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:616` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:629` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:763` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:769` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:50` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:107` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/server/rekor.go:46` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/response_buffer_guard_test.go:63` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/run.go:1123` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/run.go:1514` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/run_connectors_test.go:89` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/runtime_worker_census_test.go:65` | test reads its own package directory (CWE-22) |
| `internal/server/serve_test.go:80` | test-owned path under t.TempDir (CWE-22) |
| `internal/server/serve_test.go:81` | test-owned path under t.TempDir (CWE-22) |
| `internal/server/serve_test.go:125` | test-owned path under t.TempDir (CWE-22) |
| `internal/server/server.go:2125` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/server.go:2202` | same operator-configured directory as the target certificate (CWE-22) |
| `internal/signing/design_test.go:30` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/design_test.go:136` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/gated_destruction_journal.go:226` | exact signer-owned journal path. |
| `internal/signing/hardening_contract_test.go:55` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/keystore.go:333` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/signing/keystore.go:415` | path joins a sanitized handle to the signer-owned 0700 keystore (CWE-22). |
| `internal/signing/keystore_test.go:107` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/keystore_test.go:197` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/legacy_migration.go:32` | signer operator supplies the one legacy migration path |
| `internal/signing/managedkeys.go:525` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/signing/managedkeys.go:668` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/signing/managedkeys_test.go:445` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/spireupstream/plugin.go:239` | operator-configured public CA bundle path (CWE-22) |
| `internal/spireupstream/plugin.go:318` | operator-configured upstream-authority plugin config path (CWE-22) |
| `internal/store/dynamic_secret_lock_order_test.go:124` | fixed sibling path inside this package's own directory (CWE-22) |
| `internal/store/migration_safety_test.go:85` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/store/store_isolation_test.go:309` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/store/store_isolation_test.go:355` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/supportbundle/supportbundle.go:438` | operator-invoked support bundle collecting its configured files (CWE-22) |
| `internal/supportbundle/supportbundle_test.go:97` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/supportbundle/supportbundle_test.go:101` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/supportbundle/supportbundle_test.go:151` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/telemetry/instanceid.go:21` | fixed instance-id file under the configured data dir (CWE-22) |
| `internal/transit/persist.go:247` | the store's own sealed state file (CWE-22) |
| `internal/transit/persist_test.go:118` | reads the test's own sealed keyring file (CWE-22) |
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
| `tools/connectorsupportdoc/main.go:45` | fixed in-tree doc paths (CWE-22) |
| `tools/connectorsupportdoc/main_test.go:25` | fixed in-tree doc paths (CWE-22) |
| `tools/dodcensus/artifact.go:85` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/artifact.go:167` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/claims.go:61` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/claims.go:72` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/claims.go:76` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/kubernetes_posture_manifest_test.go:18` | test reads the exact committed runtime-proof source (CWE-22) |
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
| `tools/dodcensus/managed_key_closure.go:53` | developer tool reading the repo paths it is pointed at (CWE-22) |
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
| `tools/dodcensus/proof/launched.go:469` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:1201` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:1906` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2017` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2112` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2259` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2338` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2592` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:253` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:929` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:1067` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime.go:132` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:153` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:224` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:438` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:1139` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:1472` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:93` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:648` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:765` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:809` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:338` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:465` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:519` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:523` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/secret_integrations_manifest_test.go:113` | test reads the exact committed substrate source (CWE-22) |
| `tools/dodcensus/secret_integrations_manifest_test.go:145` | test reads the exact committed runtime proof source (CWE-22) |
| `tools/featureparityreport/main.go:49` | explicit operator-selected local report output |
| `tools/pqclab/main.go:233` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/pqclab/main.go:298` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/pqclab/main_test.go:76` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/pqclab/main_test.go:80` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/trstctllint/docs_test.go:75` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/trstctllint/hotspot_test.go:205` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/trstctllint/hotspot_test.go:303` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/trstctllint/licenseboundary/licenseboundary.go:37` | developer tool reading the repo paths it is pointed at (CWE-22) |

### G306 — CWE-276 Incorrect default permissions (file write) (85 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:231` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:82` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:131` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:158` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:182` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:224` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-license/main.go:67` | writes the license PUBLIC key/inspection output; public material (CWE-276) |
| `cmd/trstctl-license/main.go:148` | writes the license PUBLIC key/inspection output; public material (CWE-22, CWE-276) |
| `cmd/trstctl/backup_cmd_test.go:31` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `deploy/docker/dist_test.go:1037` | non-secret npm fixture manifest in t.TempDir (CWE-276) |
| `deploy/docker/dist_test.go:1040` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `deploy/docker/dist_test.go:1046` | fake npm shim in a test tempdir must be executable (CWE-276) |
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
| `internal/agent/relay/selfupgrade_test.go:35` | the fixture IS an executable; 0755 is its required mode (CWE-276) |
| `internal/agent/sshdiscovery/sshdiscovery_test.go:29` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/transport/regen_schema_test.go:43` | committed wire contract fixture, reviewed in the diff (CWE-276) |
| `internal/api/openapi_golden_test.go:62` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/api/vault_compat_contract_test.go:249` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/backup/full_manifest_io_test.go:23` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:241` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:254` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/cbom/hostsource/hostsource_test.go:23` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/cli/cli_test.go:2024` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/cli/secret_scan_local.go:137` | a git hook must be executable; 0755 is the working minimum (CWE-276) |
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
| `internal/secretscan/gitleaks_options_test.go:124` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/auth_unit_test.go:64` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/cbom_served_test.go:62` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/dod_connector_runtime_test.go:815` | public CA fixture (CWE-276) |
| `internal/server/host_agent_remote_served_test.go:354` | public CA certificate fixture (CWE-276) |
| `internal/server/host_agent_remote_served_test.go:572` | public CA fixture (CWE-276) |
| `internal/server/pam_served_test.go:287` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/pam_served_test.go:299` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_spiffe_ssh_test.go:509` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_spiffe_ssh_test.go:562` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:574` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/secrets_scan_served_test.go:36` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/server.go:2208` | served CA certificate PEM is public material (CWE-276) |
| `internal/server/signer_authorization_test.go:132` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/signer_authorization_test.go:192` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/ssh_journey_served_test.go:204` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
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
| `tools/dodcensus/proof/proof_test.go:195` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:214` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:244` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:329` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:342` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:363` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:366` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/trstctllint/eventsource/eventsource_test.go:101` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/trstctllint/idempotency/idempotency_test.go:201` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |

### G401 — CWE-328 Use of weak hash (4 sites)

| Location | Reason |
|---|---|
| `internal/crypto/certinfo/certinfo.go:393` | display/lookup fingerprint in the industry-standard form; not a security control (CWE-328) |
| `internal/crypto/leafca.go:590` | RFC 5280 4.2.1.2 method-1 SKID: an identifier, not integrity (CWE-328) |
| `internal/crypto/opaque_x509.go:221` | RFC 5280 4.2.1.2 method-1 SKID: an identifier, not integrity (CWE-328) |
| `internal/crypto/tsa.go:187` | RFC 5816 ESSCertIDv1 is defined over SHA-1; identifier only, v2 uses SHA-256 (CWE-328) |

### G402 — CWE-295 Improper certificate validation (InsecureSkipVerify) (5 sites)

| Location | Reason |
|---|---|
| `internal/crypto/mtls/mtls.go:373` | operator-selected lab escape hatch, off by default, and |
| `internal/crypto/mtls/reload_test.go:64` | reload probe of the test's own loopback listener; reads only the served serial, carries no data (CWE-295) |
| `internal/crypto/mtls/server.go:447` | localhost liveness probe of this process's own ephemeral self-signed listener; no credential, no data (CWE-295) |
| `internal/crypto/mtls/server_test.go:265` | test TLS client speaking to the test's own server (CWE-295) |
| `internal/crypto/tlsprobe/tlsprobe.go:114` | discovery inventories whatever cert is served; the connection is never trusted and never carries data (CWE-295) |

### G403 — CWE-326 Inadequate encryption strength (RSA key size) (1 sites)

| Location | Reason |
|---|---|
| `internal/crypto/jose/bounds_test.go:52` | deliberately undersized key; the test proves the verifier refuses it (CWE-326) |

### G404 — CWE-338 Cryptographically weak PRNG (29 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/backoff_test.go:22` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:49` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:68` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:69` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:86` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:95` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/backoff_test.go:113` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/bootstrap_token_test.go:406` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/bootstrap_token_test.go:412` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/bootstrap_token_test.go:420` | test jitter/shuffle, not a security decision (CWE-338) |
| `cmd/trstctl-agent/main.go:580` | reconnect jitter, not a security decision (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:28` | jitter spread, not a security decision (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:61` | jitter spread (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:77` | jitter spread (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:88` | jitter spread (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:105` | jitter spread (CWE-338) |
| `internal/cli/cli.go:493` | idempotency-key uniqueness suffix; deliberately outside the AN-3 boundary, not a secret (CWE-338) |
| `internal/crypto/scep_property_test.go:145` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/scep_property_test.go:184` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/sshkeys/property_test.go:100` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/sshkeys/property_test.go:162` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/x509_property_test.go:126` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/x509_property_test.go:175` | deterministic property-test name, not security randomness (CWE-338) |
| `internal/crypto/x509_property_test.go:196` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/orchestrator/outbox.go:470` | retry backoff jitter, not a security decision (CWE-338) |
| `internal/protocols/acme/property_test.go:90` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/protocols/acme/property_test.go:144` | deterministic property-test stream, not security randomness (CWE-338) |
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
| `internal/projections/graph_api_test.go:268` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `internal/server/issuance_dispatcher_test.go:1393` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `tools/dodcensus/managed_key_closure.go:709` | fixed-shape data inside a developer tool (CWE-118) |

### G702 — CWE-78 OS command injection (taint) (7 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/selfrestart_unix.go:23` | re-exec of this process's OWN executable path with its own args; the binary at that path was just digest-verified against the campaign's pinned sha256 (CWE-78) |
| `internal/protocols/est/differential_test.go:101` | test executes a fixed local tool or fixture it built itself (CWE-78) (-g: get cacerts) |
| `internal/server/protocols_served_stock_clients_test.go:302` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1016` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1058` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1142` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/runtime_runner.go:868` | developer tool running fixed toolchain commands over the repo (CWE-78) |

### G703 — CWE-22 Path traversal (taint) (60 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-license/main.go:148` | writes the license PUBLIC key/inspection output; public material (CWE-22, CWE-276) |
| `docs/provenance/authorship_test.go:103` | test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367) |
| `internal/agent/relay/hostrollback.go:306` | both paths are inside the validated agent-local state directory (CWE-22) |
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
| `internal/protocols/cmp/openssl_client_test.go:168` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/cmp/openssl_client_test.go:178` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/est/differential_test.go:166` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:134` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:196` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/scep/sscep_client_test.go:205` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/secretscan/gitleaks.go:300` | locates the pinned gitleaks binary in known tool dirs (CWE-22) |
| `internal/server/enrollment_relay_served_test.go:54` | the parent test supplies a freshly created public-CA fixture path to this helper process (CWE-22). |
| `internal/server/protocols_served_stock_clients_test.go:316` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:692` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:733` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:747` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:769` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:103` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_tsa_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/server/secrets_scan_served_test.go:189` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/signer_authorization_test.go:192` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/vault_compat_served_test.go:78` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/signing/keystore.go:293` | both absolute paths passed the explicit signer-keystore confinement check above (CWE-22) |
| `internal/signing/keystore.go:304` | tmpPath passed the explicit signer-keystore confinement check above (CWE-22) |
| `internal/signing/keystore.go:441` | path passed the explicit signer-keystore confinement check above (CWE-22) |
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
| `tools/dodcensus/proof/launched.go:1120` | developer tool probing repo/toolchain paths, not a served binary (CWE-22) |
| `tools/dodcensus/proof/proof.go:89` | developer tool probing repo/toolchain paths, not a served binary (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:258` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:1172` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/runtime_runner.go:853` | developer tool probing repo/toolchain paths, not a served binary (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:343` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:473` | test path inside its own tempdir/checkout (CWE-22) |

### G704 — CWE-918 Server-side request forgery (taint) (5 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl/connector.go:188` | CLI calling the operator-specified connector base URL; their own target (CWE-918) |
| `cmd/trstctl/connector.go:200` | CLI calling the operator-specified connector base URL; their own target (CWE-918) |
| `internal/agent/enrollproxy/proxy.go:207` | the destination host is the operator-configured upstream, |
| `internal/discovery/cloudcert/httpfetch.go:42` | fetches the cloud provider endpoint declared by the operator's discovery source (CWE-918) |
| `tools/dodcensus/proof/launched.go:1603` | developer tool calling the endpoint it was pointed at (CWE-918) |

### G705 — CWE-79 Cross-site scripting (taint) (11 sites)

| Location | Reason |
|---|---|
| `internal/ca/letsencrypt/acmefake/acmefake.go:233` | test-support package compiled only into test binaries (CWE-79) |
| `internal/ca/letsencrypt/acmefake/acmefake.go:256` | test-support package compiled only into test binaries (CWE-79) |
| `internal/connector/fortigate/fortigatetest/fortigatetest.go:219` | test-support package compiled only into test binaries (CWE-79) |
| `internal/dns/akamai/akamai_test.go:131` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/operator/reconcile_test.go:217` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/secretstore/access.go:86` | the secret read API returns the secret by contract; served as octet-stream with nosniff, never an HTML context (CWE-79) |
| `internal/secretstore/access.go:97` | fixed-shape JSON carrying only an integer version, served as application/json with nosniff (CWE-79) |
| `internal/secretstore/access.go:113` | fixed-shape JSON carrying only an integer version, served as application/json with nosniff (CWE-79) |
| `internal/server/secrets_sync_served_test.go:920` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/server/secrets_sync_served_test.go:991` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/server/secrets_sync_served_test.go:1101` | test writes fixture bytes to its own recorder/local server (CWE-79) |

### G710 — CWE-601 Open redirect (taint) (1 sites)

| Location | Reason |
|---|---|
| `internal/server/auth_served_test.go:66` | test redirect within its own local server (CWE-601) |

