<!-- GENERATED FILE — do not edit by hand.
     Regenerate: scripts/ci/gen-cwe-docs.py
     CI verifies freshness with --check. -->

# CWE register

Every triaged weakness finding in this repository: what was fixed (with the
guard that fails if the weakness returns) and every accepted or
false-positive verdict, harvested from the `#nosec G### -- reason` waivers
in the source itself. A waiver with no rule id or no reason fails the
generator, so a blanket suppression cannot exist in the tree.

The scan scope includes `clients cmd deploy docs internal scripts tools`
and `ee/`, which runs through the separate EE lint ratchet. The table below
records configured detectors and their known limits. It does not establish
that a scan completed on the current candidate. CI declares CodeQL
`security-extended`; exact-commit results require separate evidence. Local
golangci-lint results do not replace that evidence.

## Detectors wired into CI

| Detector | Coverage | Wired at |
|---|---|---|
| CodeQL `security-extended` | the broadest CWE query set; push, PR, and weekly | `.github/workflows/codeql.yml` |
| gosec (in golangci-lint) | Core and EE Go analysis; pinned integration disables G407, filters generated-file findings and discards internal analyzer logs. Standalone analysis and independent review must account for those limits. Inline waivers are listed below; configured coverage is not current scan proof | `.golangci.yml via make lint and ee-lint-ratchet` |
| govulncheck | reachability-aware dependency vulnerabilities | `make vuln + the govulncheck CI job` |
| gitleaks | committed secrets (CWE-798) | `.github/workflows/security.yml` |
| Trivy | container image and native-binary CVEs | `.github/workflows/security.yml` |
| ClusterFuzzLite + TestEveryUntrustedParserIsFuzzed | memory/parsing classes on untrusted input | `repo fuzz targets` |
| trstctllint (9 analyzers) | architecture classes: tenant scoping (CWE-639-shaped), key material in strings (CWE-316-shaped), SSRF/exec surfaces (CWE-918/CWE-78), certificate-verification bypass (CWE-295), crypto boundary, idempotency, event sourcing, editions fence | `tools/trstctllint via make lint` |
| npm audit surfaces + license audits | console and SDK-generator dependency advisories | `scripts/ci/npm-audit-dependency-surfaces.sh` |

## Fixed, each with a guard

| CWE | Where | What was fixed | Guard that fails if it returns |
|---|---|---|---|
| CWE-400 | `internal/notify/email/email.go` | Native SMTP delivery could remain blocked after the notification dispatch deadline. The complete exchange now shares a bounded socket deadline, and context cancellation closes the connection, releasing the worker even when a relay withholds its greeting or DATA acknowledgment. | TestSMTPGreetingHonorsCancellation and TestSMTPProductionExchangeAndDataDeadline (internal/notify/email/smtp_deadline_test.go) |
| CWE-863 | `internal/api/endpoint_binding_execution.go` | Endpoint enrollment and direct destination deployment could queue certificate issuance without the ordinary issuance permission, policy, dual-control and profile checks. Both now share the identity issuance gate and retain the exact profile binding through host-agent handoff. | TestEndpointEnrollmentHonorsIssuanceAuthority (internal/server/endpoint_binding_authority_served_test.go) |
| CWE-367 | `internal/orchestrator/endpoint_binding.go` | Endpoint metadata changes do not increment the lifecycle version. Reviewed identity snapshots now participate in approval evidence and are compared under the identity row lock before issuance, preventing policy-time binding changes from authorizing different work. | TestEndpointEnrollmentHonorsIssuanceAuthority/endpoint_enrollment/identity_changed_during_policy and target_deploy/identity_changed_during_policy (internal/server/endpoint_binding_authority_served_test.go) |
| CWE-494 | `internal/server/bundled_pg.go` | Bundled PostgreSQL could execute a cold download before its committed archive checksum was checked, or reuse unrelated extracted binaries. Startup now requires independent archive authentication and fresh private extraction before execution. | TestBundledPostgresRejectsUnrelatedExtractedCache and TestBundledPostgresAuthenticatedFixtureReachesInitializerAndCleansUp (internal/server/bundled_pg_start_test.go) + TestVerifiedStartAuthenticatesColdArchiveBeforeInit (third_party/embedded-postgres/verified_binary_test.go) |
| CWE-22 | `third_party/embedded-postgres/verified_binary.go` | The served loader uses rooted extraction into a fresh private directory and rejects traversal, escaping links, special files and duplicate entries. Legacy NewDatabase callers remain a separate unresolved scope. | TestVerifiedExtractionRejectsUnsafePathsLinksAndTypes (third_party/embedded-postgres/verified_binary_test.go) |
| CWE-400 | `third_party/embedded-postgres/verified_binary.go` | Served archive acquisition and extraction now bound compressed bytes, XZ dictionary memory, the raw expanded stream including hidden TAR metadata, individual files and visible entries. | TestVerifiedExtractionBoundsHiddenMetadataAndDictionary and TestVerifiedDownloadClosesBodiesAndBoundsResponses (third_party/embedded-postgres/verified_acquisition_test.go) |
| CWE-362 | `third_party/embedded-postgres/verified_binary.go` | Served cache publication no longer depends on a process-local mutex. Atomic create-if-absent publication validates the winning archive bytes; private extracted trees are published only after complete validation. | TestVerifiedPublicationCrossProcess (third_party/embedded-postgres/verified_acquisition_test.go) + TestVerifiedPreparationConcurrencyUsesDistinctTrees (third_party/embedded-postgres/verified_binary_test.go) |
| CWE-252 | `Makefile` | Formatting enumeration, gofmt, temporary-file creation and architecture-analyzer build errors could be hidden by later successful commands. The lint gate now stops on each prerequisite failure. | TestMakeLintStopsOnToolFailure (docs/lint_failure_test.go) |
| CWE-754 | `scripts/ci/ee-lint-ratchet.py` | EE lint counted text findings without checking scanner completion. It now requires a complete, uncapped six-linter JSON report and a matching native exit status; malformed reports, tool errors and timeouts fail without changing the baseline. | TestEELintRejectsIncompleteScans and TestMakeLintStopsOnToolFailure/python-deadline-retains-output (docs/lint_failure_test.go) |
| CWE-772 | `scripts/ci/ee-lint-ratchet.py` | The scanner timeout killed only the direct child. EE lint now bounds live output and terminates the owned scanner process group on timeout, SIGINT, SIGTERM, or a leader exit that leaves descendants. | TestEELintScannerSupervision (docs/lint_supervision_test.go) |
| CWE-287 | `internal/server/workload_identity.go` | Automatic workload identities omitted the authenticated tenant under a shared CA. Versioned names now bind tenant, route, verified method and broker agent; approval recovery checks the signed tenant and method. | TestServedWorkloadIdentitiesAreTenantIsolated and TestServedEphemeralIdentitiesAndApprovalsAreTenantIsolated (internal/server/workload_identity_tenant_test.go) + TestApprovalBindingDecodesScopedSubjectWithoutChangingAuthority (internal/ephemeral/approval_test.go) |
| CWE-863 | `internal/crypto/workload_namespace.go` | Ordinary CSR profiles and manual Workload API registrations could claim automatic workload names. Both now refuse the reserved /_trstctl namespace, including alias attempts. | TestLeafProfilesCannotMintReservedWorkloadIdentities (internal/crypto/workload_namespace_test.go) + TestRegistrationCannotClaimAutomaticWorkloadNamespace (internal/protocols/spiffe/workload_namespace_test.go) |
| CWE-863 | `internal/crypto/leafca.go` | LeafProfile.ExtraExtensions could overwrite a checked SAN or another core certificate policy field. The shared classical/opaque profile gate now rejects those parsed OIDs before signing; non-core extensions remain supported. | TestLeafProfileExtraExtensionsCannotOverrideIdentityPolicy (internal/crypto/workload_namespace_test.go) |
| CWE-190 | `internal/crypto/seal/seal.go` | Seal accepted a wrapped DEK larger than the v1 container's 2-byte length prefix and silently mis-framed it; now refused with ErrFormat. | TestSealRefusesOversizedWrappedDEK (internal/crypto/seal/bounds_guard_test.go) |
| CWE-295 | `internal/crypto/mtls/mtls.go` | Pinned TLS configs enforced the key pin only in VerifyPeerCertificate, which resumed sessions skip, so a session ticket could outlive a pin rotation; pinned listeners now disable tickets and re-verify the pin in VerifyConnection. | TestPinnedConfigsEnforcePinOnResumedSessions (internal/crypto/mtls/resumption_pin_test.go) |
| CWE-79 | `internal/secretstore/access.go` | The secret-store access API returned secret bytes with no declared content type, inviting browsers to sniff them into a renderable type; every response now declares Content-Type and X-Content-Type-Options: nosniff. | TestAPIResponsesDeclareContentTypeAndNosniff (internal/secretstore/access_headers_test.go) |
| CWE-295 | `tools/trstctllint/tlsverify` | Class guard, not an instance fix: the ninth trstctllint analyzer forbids InsecureSkipVerify outside the tlsprobe discovery prober and _test.go files (the loopback liveness probe pins the served certificate), so the class cannot reappear anywhere in shipped code. | TestTLSVerify fixtures (tools/trstctllint/tlsverify) + the repo-wide linter selftest |

## Waivers (accepted or false-positive, in-source, reasoned)

3285 annotated sites across 35 rules. Each row is
generated from the `#nosec` comment at that exact line; edit the source,
not this file.

### G101 — CWE-798 Use of hardcoded credentials (807 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:96` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `cmd/trstctl/main_test.go:622` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `cmd/trstctl/reconcile_cloudkms_mapping_test.go:15` | credential file paths only, no credential value (CWE-798) |
| `cmd/trstctl/reconcile_gcp_azure_kms_mapping_test.go:15` | credential file paths only, no credential value (CWE-798) |
| `cmd/trstctl/reconcile_gcp_azure_kms_mapping_test.go:18` | credential file paths only, no credential value (CWE-798) |
| `deploy/demo/demo_test.go:241` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/demo/demo_test.go:367` | fixture paths name files; no credential value is embedded. |
| `deploy/deploycheck_test.go:1587` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/deploycheck_test.go:1589` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/deploycheck_test.go:1609` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/docker/dist_test.go:425` | names are non-secret evaluation OIDC configuration keys (CWE-798) |
| `deploy/elastic/content_test.go:94` | a test batch naming an env: reference, not a credential (CWE-798) |
| `deploy/helm/helm_test.go:164` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:603` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:805` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:814` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:830` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:890` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:954` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1078` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1158` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1261` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1269` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1568` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1599` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `deploy/helm/helm_test.go:1601` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `ee/enterpriseauth/auth_kerberos_served_test.go:35` | fabricated fixture credential; the keytab is minted in-process (CWE-798) |
| `ee/enterpriseauth/scim_bulk_served_test.go:35` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `ee/enterpriseauth/scim_custom_roles_served_test.go:108` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `ee/enterpriseauth/scim_custom_roles_served_test.go:201` | fabricated fixture credentials (CWE-798) |
| `ee/enterpriseauth/scim_served_test.go:34` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `ee/enterpriseauth/scim_subject_binding_served_test.go:38` | fabricated local fixture, not a credential (CWE-798) |
| `ee/enterpriseauth/scim_writeback_private_test.go:50` | fabricated fixture credential (CWE-798) |
| `ee/enterpriseauth/scim_writeback_rotation_served_test.go:36` | fabricated fixture credential (CWE-798) |
| `ee/enterpriseauth/scim_writeback_rotation_served_test.go:37` | fabricated fixture credentials (CWE-798) |
| `ee/enterpriseauth/scim_writeback_served_test.go:110` | fabricated fixture credential (CWE-798) |
| `ee/enterpriseauth/scim_writeback_served_test.go:111` | fabricated fixture credential (CWE-798) |
| `ee/governance/misuse/misuse.go:40` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `ee/managedkeys/signerwiring/gcp_workload_test.go:46` | a stand-in fixture value, not a credential (CWE-798) |
| `ee/provider/aud58_test.go:173` | deterministic non-deployable test bearer exercises hashing/authentication (CWE-798). |
| `ee/provider/aud59_test.go:22` | deterministic non-deployable test bearer (CWE-798). |
| `ee/provider/aud60_test.go:16` | deterministic non-deployable test bearer (CWE-798). |
| `ee/provider/custom_roles_test.go:91` | deterministic non-deployable test bearer exercises hashing/authentication (CWE-798). |
| `ee/provider/scim_bulk_test.go:27` | deterministic non-deployable test bearer (CWE-798). |
| `ee/provider/scim_fuzz_test.go:30` | deterministic non-deployable fuzz authenticator (CWE-798). |
| `ee/provider/scim_groups_test.go:36` | deterministic non-deployable test bearer exercises hashing/authentication (CWE-798). |
| `internal/accessrules/risk.go:22` | a risk category's name matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/accessrules/risk.go:30` | a risk category's name matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/agent/csisecrets/driver.go:64` | the kubelet's request key name, not a credential (CWE-798) |
| `internal/agent/csisecrets/driver_test.go:458` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/agent/discovery/keystore.go:41` | the published Java keystore default, tried as a default; not a credential of this deployment (CWE-798) |
| `internal/agent/discovery/keystore_jceks_test.go:18` | fixture file paths, not credentials (CWE-798) |
| `internal/agent/discovery/kubernetes.go:90` | metadata key naming the Kubernetes Secret a public certificate was found in; no credential value present (CWE-798) |
| `internal/agent/k8s/client.go:31` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/agent/relay/deploy_failure_log_keep_test.go:34` | a canary the log must not keep, not a credential (CWE-798) |
| `internal/agent/relay/deploy_failure_log_keep_test.go:42` | "password_ref" is a reference NAME, not a credential (CWE-798) |
| `internal/agent/relay/deploy_failure_log_test.go:35` | "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798) |
| `internal/agent/relay/hostdryrun_internal_test.go:11` | KeystorePasswordRef is a secret-store locator, not credential material (CWE-798). |
| `internal/agent/relay/legacy_rollback_test.go:36` | a secret:// reference name, not a credential (CWE-798) |
| `internal/agent/relay/mdm_jamf_client_test.go:20` | credential reference, no credential value present (CWE-798) |
| `internal/agent/relay/mdm_jamf_client_test.go:21` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/agent/relay/mdmcheckin_test.go:26` | credential reference (secret store pointer), no credential value present (CWE-798) |
| `internal/agent/relay/mdmsync_test.go:26` | credential reference (secret store pointer), no credential value present (CWE-798) |
| `internal/agent/relay/mdmsync_test.go:162` | credential reference, no credential value present (CWE-798) |
| `internal/agent/relay/mdmsync_test.go:163` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/agent/relay/mdmsync_test.go:229` | credential reference, no credential value present (CWE-798) |
| `internal/agent/relay/mdmsync_test.go:230` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/agent/relay/mdmsync_test.go:231` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/agent/relay/plugin_call_test.go:65` | a reference name (CWE-798) |
| `internal/agent/relay/readback_families_test.go:37` | a credential reference name, not a credential (CWE-798) |
| `internal/agent/relay/readback_families_test.go:45` | a credential reference name, not a credential (CWE-798) |
| `internal/agent/relay/readback_families_test.go:51` | a credential reference name, not a credential (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:76` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:99` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:119` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:138` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:157` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:177` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:196` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:217` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:240` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:259` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:332` | a credential REFERENCE NAME, not a credential: the relay looks the value up in redeemed material by this key, and the indirection is the point (CWE-798) |
| `internal/agent/relay/relay_appliance_e2e_test.go:370` | credential REFERENCE NAMES, not credentials: the relay looks values up in redeemed material by these keys (CWE-798) |
| `internal/agent/relay/relay_test.go:147` | "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798) |
| `internal/agent/relay/relay_test.go:189` | "password_ref" is a reference NAME the test asserts on, not a credential (CWE-798) |
| `internal/agent/relay/relay_test.go:344` | reference NAME, not a credential (CWE-798) |
| `internal/agent/relay/relay_test.go:402` | reference NAME (CWE-798) |
| `internal/agent/relay/revocation_ldap_failure_test.go:59` | a non-secret secret:// reference fixture, not secret material (CWE-798). |
| `internal/agent/relay/revocation_ldap_test.go:77` | a non-secret secret:// reference fixture, not secret material (CWE-798). |
| `internal/agent/relay/revocation_ldap_test.go:146` | a non-secret secret:// reference fixture, not secret material (CWE-798). |
| `internal/agent/relay/rightsize_job.go:49` | a credential REFERENCE NAME, not a credential (CWE-798) |
| `internal/agent/relay/takedown_test.go:80` | a secret:// reference name, not a credential (CWE-798) |
| `internal/agent/relay/ticketsync_test.go:66` | TokenRef is a non-secret locator in a deterministic test fixture (CWE-798). |
| `internal/agent/secretrender/secretrender_test.go:126` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/agent/transport/agentservice.go:941` | an RPC method name, not a credential. The material this |
| `internal/agent/transport/agentservice.go:948` | an RPC method name. This call carries a CSR up and returns |
| `internal/agent/transport/receipt.go:225` | an operator-facing refusal phrase matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/agent/transport/receipt.go:270` | an operator-facing refusal phrase matching the secret-name heuristic; no credential value present (CWE-798) |
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
| `internal/api/access_bundles.go:1059` | environment variable names and placeholder launch lines; no credential value present (CWE-798) |
| `internal/api/acme_dns01.go:597` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/agents.go:59` | source-kind label naming where key material was located; no credential value present (CWE-798) |
| `internal/api/aisurface_contract_test.go:148` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/compliance_report_dispatch_test.go:17` | fabricated fixture reference; no value is real (CWE-798) |
| `internal/api/decoy_kubernetes.go:42` | a Kubernetes user name, not a credential (CWE-798) |
| `internal/api/discovery_secret_move.go:30` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/dynamic_secret_preview.go:19` | public MAC domain, not a credential |
| `internal/api/idempotency_binding_test.go:21` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:11` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:17` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:26` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:27` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:28` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/itsm_test.go:57` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/managedkeys_test.go:225` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/nhi_inventory.go:206` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/notifications.go:907` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/notifications.go:1276` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/notifications_helpers_test.go:91` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/api/openapi.go:291` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secret_scan_hooks_od3_test.go:26` | fabricated fixture signing token (CWE-798) |
| `internal/api/secret_scan_known_decoy_test.go:18` | fabricated decoy fixture; no value is real (CWE-798) |
| `internal/api/secrets_posture.go:1169` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_posture.go:1317` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:40` | public MAC domain label, not a credential |
| `internal/api/secrets_scanning.go:679` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:703` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:777` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:787` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/api/secrets_scanning.go:797` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/audit/audit_test.go:179` | deliberately toxic non-routable fixture proves redaction (CWE-798). |
| `internal/audit/audit_test.go:211` | deliberately toxic fixture proves retained-prefix redaction (CWE-798). |
| `internal/auth/oidc_client_secret.go:15` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/authmethod/aws_iam_http_test.go:17` | fabricated signed-request fixture (CWE-798) |
| `internal/authmethod/aws_iam_http_test.go:38` | fabricated signed-request fixture (CWE-798) |
| `internal/authmethod/aws_iam_http_test.go:64` | fabricated signed-request fixture (CWE-798) |
| `internal/broker/issuanceprecondition_test.go:48` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/ca/ejbca/ejbcafake/ejbcafake.go:28` | test-support package compiled only into test binaries (CWE-798) |
| `internal/ca/letsencrypt/acmefake/acmefake.go:31` | fabricated fixture challenge token in a test double; no value is real (CWE-798) |
| `internal/ca/venafi/venafifake/venafifake.go:25` | test-support package compiled only into test binaries (CWE-798) |
| `internal/cbom/coverage/envelope.go:38` | an asset-class identifier matching the credential-name heuristic; no credential value (CWE-798) |
| `internal/cbom/coverage/envelope.go:57` | precondition identifier matching the credential-name heuristic; no credential value (CWE-798) |
| `internal/cbom/coverage/envelope.go:60` | precondition identifier matching the credential-name heuristic; no credential value (CWE-798) |
| `internal/cbom/coverage/envelope.go:61` | precondition identifier matching the credential-name heuristic; no credential value (CWE-798) |
| `internal/cli/access_agent_test.go:22` | a fake run token the test's fake control plane expects (CWE-798) |
| `internal/cli/agent_delegation_command_test.go:14` | API route names are public identifiers, not credential values (CWE-798) |
| `internal/cli/ci_templates_test.go:116` | a stand-in's test token, not a credential (CWE-798) |
| `internal/cloudauth/aws_credential_chain.go:31` | a link-local endpoint address, not a credential (CWE-798) |
| `internal/cloudauth/aws_credential_chain_test.go:28` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/cloudauth/aws_credential_chain_test.go:29` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/cloudauth/aws_credential_chain_test.go:30` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/cloudauth/aws_credential_chain_test.go:31` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/cloudauth/azure.go:19` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/cloudauth/gcp.go:22` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/cloudauth/gcp.go:23` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/cloudauth/gcp.go:24` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/cloudauth/gcp_token_source_test.go:53` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/config/ai_test.go:91` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/audit_test.go:31` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/audit_test.go:66` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/audit_test.go:79` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/audit_test.go:102` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config.go:3645` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/config/config.go:4451` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/config/config_awskms_test.go:25` | credential file paths only, no credential value (CWE-798) |
| `internal/config/config_gcpkms_azurekv_test.go:25` | credential file paths only, no credential value (CWE-798) |
| `internal/config/config_gcpkms_azurekv_test.go:28` | credential file paths only, no credential value (CWE-798) |
| `internal/config/config_key_dates_test.go:18` | credential file paths only (CWE-798) |
| `internal/config/config_key_dates_test.go:32` | a token file path, no value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:16` | file: and env: references to test-only values (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:73` | env: and file: references to test-only values (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:122` | file: and env: references to test-only values (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:174` | a file: reference to a test-only value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:222` | an env: reference to a test-only value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:268` | an env: reference to a test-only value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:311` | a file: reference to a test-only value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:361` | a file: reference to a test-only value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:406` | env: references, not values (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:453` | a file: reference, not a value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:495` | an env: reference, not a value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:537` | an env: reference, not a value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:581` | an env: reference, not a value (CWE-798) |
| `internal/config/config_provider_billing_sync_test.go:629` | an env: reference, not a value (CWE-798) |
| `internal/config/config_test.go:64` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:173` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:416` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:422` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:425` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:428` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/config_test.go:431` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:12` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:19` | fabricated fixture reference, no credential (CWE-798) |
| `internal/config/external_ca_test.go:46` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:48` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:49` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:50` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:51` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:52` | fabricated fixture reference, no credential (CWE-798) |
| `internal/config/external_ca_test.go:53` | fabricated fixture reference, no credential (CWE-798) |
| `internal/config/external_ca_test.go:54` | a deliberately malformed reference the validator must refuse; no credential (CWE-798) |
| `internal/config/external_ca_test.go:55` | fabricated fixture reference, no credential (CWE-798) |
| `internal/config/external_ca_test.go:58` | fabricated fixture reference, no credential (CWE-798) |
| `internal/config/external_ca_test.go:60` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:61` | fabricated fixture reference, no credential (CWE-798) |
| `internal/config/external_ca_test.go:62` | fabricated fixture reference, no credential (CWE-798) |
| `internal/config/external_ca_test.go:63` | a deliberately malformed reference the validator must refuse; no credential (CWE-798) |
| `internal/config/external_ca_test.go:64` | fabricated fixture reference, no credential (CWE-798) |
| `internal/config/external_ca_test.go:68` | fabricated fixture reference, no credential (CWE-798) |
| `internal/config/external_ca_test.go:85` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/external_ca_test.go:109` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/kerberos_test.go:8` | fabricated fixture paths and identifiers; the test needs the shape, no value is real (CWE-798) |
| `internal/config/ldap_test.go:8` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/managed_keys_azure_workload_test.go:15` | fixture tenant/client UUIDs and a token path, no credential value (CWE-798) |
| `internal/config/managed_keys_azure_workload_test.go:43` | fixture tenant/client UUIDs and a token path, no credential value (CWE-798) |
| `internal/config/managed_keys_gcp_workload_test.go:18` | a token path, no credential value (CWE-798) |
| `internal/config/managed_keys_gcp_workload_test.go:47` | a pool audience, a service account and a token path, no credential value (CWE-798) |
| `internal/config/managed_keys_providers_test.go:78` | fabricated fixture values; nothing here is real (CWE-798) |
| `internal/config/migrate_config_test.go:24` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/migrate_config_test.go:45` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/ntlm_test.go:8` | fabricated fixture paths and identifiers; the test needs the shape, no value is real (CWE-798) |
| `internal/config/oidc_test.go:13` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/oidc_test.go:114` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/provider_identity_aud58_test.go:43` | values are configuration names and file paths, never secret bytes (CWE-798). |
| `internal/config/ratelimit_test.go:30` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/ratelimit_test.go:56` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/saml_test.go:8` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/scim_group_roles_test.go:14` | fixture file path, not a credential value (CWE-798) |
| `internal/config/scim_test.go:10` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/scim_test.go:57` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/scim_writeback_egress_test.go:14` | fabricated fixture path, no credential (CWE-798) |
| `internal/config/scim_writeback_egress_test.go:47` | fabricated fixture path, no credential (CWE-798) |
| `internal/config/scim_writeback_test.go:13` | fixture file paths, not credential values (CWE-798) |
| `internal/config/scim_writeback_test.go:19` | fixture file paths, not credential values (CWE-798) |
| `internal/config/scim_writeback_test.go:20` | fixture file paths, not credential values (CWE-798) |
| `internal/config/scim_writeback_test.go:28` | fixture file paths, not credential values (CWE-798) |
| `internal/config/secret_integrations_test.go:53` | test-only file reference paths, no credential values (CWE-798) |
| `internal/config/secret_integrations_test.go:1374` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secret_integrations_test.go:1378` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secret_integrations_test.go:1382` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secret_integrations_test.go:1386` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secret_integrations_test.go:1463` | test-only file reference paths, no credential values (CWE-798) |
| `internal/config/secret_integrations_test.go:1478` | test-only file reference paths, no credential values (CWE-798) |
| `internal/config/secret_integrations_test.go:1500` | test-only file reference paths, no credential values (CWE-798) |
| `internal/config/secret_integrations_test.go:1506` | test-only file reference paths, no credential values (CWE-798) |
| `internal/config/secrets_config_test.go:23` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secrets_config_test.go:42` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/secrets_config_test.go:65` | fabricated fixture path/identifiers; no credential value is present (CWE-798) |
| `internal/config/secrets_config_test.go:89` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/servicenow_cmdb_binding_test.go:12` | reference name only; no credential value (CWE-798) |
| `internal/config/servicenow_cmdb_binding_test.go:39` | reference name only; no credential value (CWE-798) |
| `internal/config/servicenow_cmdb_binding_test.go:40` | variable name only; no credential value (CWE-798) |
| `internal/config/servicenow_cmdb_binding_test.go:41` | reference name only; no credential value (CWE-798) |
| `internal/config/signer_config_test.go:51` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:63` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:123` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/config/signer_config_test.go:131` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/acm/acm_test.go:20` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/azurekv/token_test.go:20` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/azurekv/token_test.go:63` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/cisco/cisco_test.go:22` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/cisco/ciscotest/ciscotest_test.go:16` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/gcpcm/gcpcm_test.go:18` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/kemp/kemp_test.go:65` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/connector/paloalto/paloalto_test.go:29` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/crypto/jks/jceks_test.go:22` | a fixture file path, not a credential (CWE-798) |
| `internal/crypto/pfx/keyentries_test.go:20` | keytool's published default store password on a test fixture; not a credential (CWE-798) |
| `internal/crypto/ssh_account_password.go:43` | a command path the profile runs, not a credential (CWE-798) |
| `internal/crypto/ssh_account_password.go:44` | a command path the profile runs, not a credential (CWE-798) |
| `internal/custody/custody.go:98` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/decommission/reprotect/credential_test.go:16` | NewCredentialID is public fixture metadata, not credential material (CWE-798). |
| `internal/discovery/adcs/endpoint_probe_test.go:15` | public logical reference fixture, never a credential value (CWE-798). |
| `internal/discovery/adcs/source_test.go:86` | public secret:// reference fixture; contains no credential value (CWE-798). |
| `internal/discovery/apikey/apikey_test.go:13` | synthetic credential REFERENCE (ref + fingerprint only, no value): the package's contract (CWE-798) |
| `internal/discovery/apikey/apikey_test.go:20` | synthetic credential REFERENCE (ref + fingerprint only, no value): the package's contract (CWE-798) |
| `internal/discovery/apikey/apikey_test.go:25` | synthetic credential REFERENCE (ref + fingerprint only, no value): the package's contract (CWE-798) |
| `internal/discovery/cloudkeys/awsiamkeys/awsiamkeys_test.go:80` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/discovery/cloudkeys/awsiamkeys/deactivate_test.go:34` | fabricated fixture signing value; no value is real (CWE-798) |
| `internal/discovery/cloudsecret/apikeys.go:28` | a hash domain-separation tag, not a credential (CWE-798) |
| `internal/discovery/cloudsecret/outcomes_test.go:35` | fabricated fixture secret name; the test needs the shape, no value is real (CWE-798) |
| `internal/discovery/cloudsecret/secretstoretest/conjur.go:33` | a stand-in's fixed fake access token, not a credential (CWE-798) |
| `internal/discovery/lbtls/awselb/awselb_test.go:41` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/discovery/lbtls/awselb/awselb_test.go:75` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/discovery/lbtls/bigip/bigip_test.go:40` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/discovery/lbtls/bigip/bigip_test.go:69` | a URL carrying credentials, built to prove it is refused; no value is real (CWE-798) |
| `internal/discovery/netpath/awsnetpath/awsnetpath_test.go:18` | fabricated fixture credential (CWE-798) |
| `internal/discovery/netpath/azurenetpath/azurenetpath_test.go:18` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/discovery/netpath/gcpnetpath/gcpnetpath_test.go:15` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/dns/akamai/akamai_test.go:26` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/dns/cloudflare/cloudflare_test.go:24` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/dns/googledns/googledns_test.go:267` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/dns/ns1/ns1.go:47` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/dns/ns1/ns1_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/dns/ultradns/ultradns_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/docsys/hudu/hudu_test.go:18` | a test-only value (CWE-798) |
| `internal/docsys/itglue/itglue_test.go:18` | a test-only value (CWE-798) |
| `internal/dynsecret/access_test.go:211` | test fixture DSNs with a dummy password; the test asserts it never reaches the target ref (CWE-798) |
| `internal/dynsecret/clickhouse_test.go:28` | fabricated lab administrator password (CWE-798) |
| `internal/dynsecret/couchbase_test.go:32` | fabricated stand-in administrator (CWE-798) |
| `internal/dynsecret/elasticsearch_test.go:29` | fabricated lab administrator password (CWE-798) |
| `internal/dynsecret/ibm_api_connect_test.go:42` | fabricated stand-in platform credentials (CWE-798) |
| `internal/dynsecret/ibm_api_connect_test.go:46` | fabricated stand-in token (CWE-798) |
| `internal/dynsecret/milvus_test.go:38` | fabricated stand-in administrator (CWE-798) |
| `internal/dynsecret/mongodb_atlas_test.go:34` | fabricated stand-in service account (CWE-798) |
| `internal/dynsecret/native_expiry.go:36` | a credential kind's name, no credential value (CWE-798) |
| `internal/dynsecret/native_expiry.go:37` | a credential kind's name, no credential value (CWE-798) |
| `internal/dynsecret/oauth_client_credentials_test.go:29` | fabricated lab client secret, form-encoded (CWE-798) |
| `internal/dynsecret/oauth_client_credentials_test.go:190` | fabricated fixture secret; the case fails on its scope (CWE-798) |
| `internal/dynsecret/postgres_decoy_test.go:15` | placeholder test DSNs, not credentials (CWE-798) |
| `internal/dynsecret/postgres_decoy_test.go:19` | placeholder test DSNs, not credentials (CWE-798) |
| `internal/dynsecret/rabbitmq_test.go:34` | fabricated lab administrator password (CWE-798) |
| `internal/dynsecret/tailscale_test.go:30` | fabricated stand-in API token (CWE-798) |
| `internal/dynsecret/totp_test.go:13` | the RFC 6238 test-vector seed, not a credential (CWE-798) |
| `internal/kms/gcpkms/gcpkms_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/kms/wrapadapter/aws_chain_test.go:23` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/kms/wrapadapter/aws_chain_test.go:24` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/kms/wrapadapter/aws_chain_test.go:25` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/kms/wrapadapter/aws_chain_test.go:229` | a credential source name, not a credential (CWE-798) |
| `internal/mcpserver/mcpserver_test.go:82` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/mdm/entra_test.go:21` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/mdm/entra_test.go:22` | an unsigned stand-in token shape, not a credential (CWE-798) |
| `internal/mdm/entra_test.go:99` | malformed stand-in token responses, no credential value (CWE-798) |
| `internal/mdm/jamf_client.go:30` | an endpoint path, not a credential (CWE-798) |
| `internal/mdm/jamf_client_test.go:20` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/mdm/jamf_client_test.go:21` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/mdm/jamf_client_test.go:110` | a stand-in response with no token in it (CWE-798) |
| `internal/notify/notify.go:69` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/notify/notify.go:95` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/notify/notify.go:158` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/notify/webhook/webhook_test.go:23` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/oauthrevoke/oauthrevoke_test.go:14` | fabricated fixture credential (CWE-798) |
| `internal/operator/client.go:39` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/generated_keys_test.go:29` | fabricated fixture identifiers; the test needs the shape, no value is real (CWE-798) |
| `internal/operator/generated_keys_test.go:89` | fabricated fixture identifiers; the test needs the shape, no value is real (CWE-798) |
| `internal/operator/generated_keys_test.go:117` | fabricated fixture identifiers; the test needs the shape, no value is real (CWE-798) |
| `internal/operator/networking_test.go:61` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/operator/networking_test.go:192` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/operator/reconcile_test.go:434` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/operator/reconcile_test.go:448` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/operator/secretinjection.go:23` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:24` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:25` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:26` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:28` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:29` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:30` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:31` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretinjection.go:32` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretsync.go:27` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretsync.go:28` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/operator/secretsync.go:29` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/orchestrator/cmdb_sweep_test.go:17` | TokenRef is a non-secret locator in a deterministic fixture (CWE-798). |
| `internal/orchestrator/outbox_internal_test.go:1251` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/orchestrator/outbox_internal_test.go:1300` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/perf/capacity.go:11` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/perf/perf_test.go:242` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/perf/scale.go:63` | a fabricated credential only the in-process ACM double accepts (CWE-798) |
| `internal/projections/apitoken_test.go:59` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/projections/cli_api_test.go:90` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/projections/credential_usage.go:21` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/credential_usage.go:23` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/discovery_secret_move.go:20` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/discovery_secret_move.go:23` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/projections.go:332` | an event type name, not a credential (CWE-798) |
| `internal/projections/secret_deliveries.go:16` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_integrations.go:228` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_integrations.go:230` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_migration.go:21` | event type name, no credential (CWE-798) |
| `internal/projections/secret_migration.go:22` | event type name, no credential (CWE-798) |
| `internal/projections/secret_migration.go:23` | event type name, no credential (CWE-798) |
| `internal/projections/secret_migration.go:24` | event type name, no credential (CWE-798) |
| `internal/projections/secret_migration.go:25` | event type name, no credential (CWE-798) |
| `internal/projections/secret_migration.go:26` | event type name, no credential (CWE-798) |
| `internal/projections/secret_migration.go:27` | event type name, no credential (CWE-798) |
| `internal/projections/secret_projects.go:17` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_projects.go:18` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_projects.go:19` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_projects.go:20` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_projects.go:23` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_projects.go:24` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_scoped_sync.go:18` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_scoped_sync.go:19` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_scoped_sync.go:20` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_scoped_sync.go:21` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_scoped_sync.go:22` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_scoped_sync.go:23` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_scoped_sync.go:24` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/projections/secret_scoped_sync.go:26` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/protocols/acme/eab.go:265` | an event type name, not credential material (CWE-798) |
| `internal/protocols/acme/eab_rotation_test.go:34` | fabricated fixture reference, not secret material (CWE-798) |
| `internal/protocols/acme/email_reply_test.go:23` | RFC 8823 test token and digest, not a credential (CWE-798) |
| `internal/psa/gradient/gradient_test.go:18` | a test-only value (CWE-798) |
| `internal/psa/halopsa/halopsa_test.go:21` | a test-only value, with characters a form must escape (CWE-798) |
| `internal/psa/pax8/pax8_test.go:20` | a test-only value with characters JSON must escape (CWE-798) |
| `internal/psa/syncro/syncro_test.go:19` | a test-only value (CWE-798) |
| `internal/reconcile/awskmssource_test.go:20` | fabricated fixture credential (CWE-798) |
| `internal/reconcile/cloudkms_gcp_azure_test.go:19` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/reconcile/conformance/cloud_kms_dates_e2e_test.go:33` | fabricated fixture credential (CWE-798) |
| `internal/reconcile/conformance/cloud_kms_e2e_test.go:34` | fabricated fixture credential (CWE-798) |
| `internal/reconcile/conformance/cloud_kms_e2e_test.go:154` | fabricated fixture credential (CWE-798) |
| `internal/reconcile/conformance/cloud_kms_gcp_azure_e2e_test.go:33` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/reconcile/conformance/cloud_kms_operation_note_e2e_test.go:33` | fabricated fixture credential (CWE-798) |
| `internal/rehearsal/rehearsal.go:27` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/revocationhealth/contract_test.go:91` | a non-secret secret:// reference fixture, not secret material (CWE-798). |
| `internal/risk/contextual_test.go:192` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/risk/contextual_test.go:214` | fabricated identifier, not credential material (CWE-798) |
| `internal/rmm/automate/automate_test.go:19` | a test-only value with characters JSON must escape (CWE-798) |
| `internal/rmm/datto/datto_test.go:19` | a test-only value with characters JSON and forms must escape (CWE-798) |
| `internal/rmm/kaseya/kaseya_test.go:19` | a test-only value with characters JSON must escape (CWE-798) |
| `internal/rmm/ncentral/ncentral_test.go:17` | a test-only value with characters JSON must escape (CWE-798) |
| `internal/rmm/ninjaone/ninjaone_test.go:19` | a test-only value with characters JSON and forms must escape (CWE-798) |
| `internal/scanannotate/scanannotate_test.go:14` | fabricated fixture credential (CWE-798) |
| `internal/schedulerhistory/history_test.go:12` | deliberately toxic non-routable fixture proves redaction (CWE-798). |
| `internal/schedulerhistory/history_test.go:81` | deliberately toxic fixture proves closed parsing without echo (CWE-798). |
| `internal/secretscan/known_value_test.go:17` | fabricated decoy fixture; no value is real (CWE-798) |
| `internal/secretscan/repository_annotation_test.go:14` | a credential reference to a fabricated fixture (CWE-798) |
| `internal/secretscan/repository_credential_test.go:108` | fabricated fixture token for the stand-in host (CWE-798) |
| `internal/secretsync/parameter_store_scoped_test.go:20` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/server/acme_adcs_upstream_served_test.go:182` | fabricated test-only webhook credential (CWE-798) |
| `internal/server/acme_dns01_live_txt_served_test.go:28` | fabricated fixture reference, no value is real (CWE-798) |
| `internal/server/acme_dns01_qualification.go:23` | this is an operator-facing disclosure sentence, not credential material. |
| `internal/server/acme_dns_persist_policy_served_test.go:41` | fabricated fixture reference, no value is real (CWE-798) |
| `internal/server/acme_eab_rotation_served_test.go:40` | logical fixture name, not secret material (CWE-798) |
| `internal/server/acme_eab_rotation_served_test.go:41` | a reference, not secret material (CWE-798) |
| `internal/server/adcs_endpoint_probe_command_test.go:23` | public secret:// reference fixture; contains no credential value (CWE-798). |
| `internal/server/adcs_endpoint_probe_command_test.go:78` | a public reference fixture, no credential value (CWE-798). |
| `internal/server/adcs_endpoint_probe_command_test.go:122` | public secret:// reference fixture; contains no credential value (CWE-798). |
| `internal/server/adcs_endpoint_probe_served_test.go:28` | public logical reference fixture, no credential value (CWE-798). |
| `internal/server/adcs_inventory_served_test.go:42` | this is a logical fixture name, not secret material (CWE-798). |
| `internal/server/adcs_inventory_served_test.go:43` | this is a non-secret reference, not secret material (CWE-798). |
| `internal/server/adcs_nested_command_test.go:23` | public secret:// reference fixture; contains no credential value (CWE-798). |
| `internal/server/adcs_nested_command_test.go:78` | a public reference fixture, no credential value (CWE-798). |
| `internal/server/adcs_nested_command_test.go:122` | public secret:// reference fixture; contains no credential value (CWE-798). |
| `internal/server/adcs_nested_samba_test.go:65` | public logical fixture reference (CWE-798). |
| `internal/server/adcs_nested_samba_test.go:66` | public reference, never a credential value (CWE-798). |
| `internal/server/agent_jobs_served_test.go:23` | secret-store reference/pointer, never credential material (CWE-798) |
| `internal/server/aisurface_served_test.go:111` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/application_view_served_test.go:29` | fabricated test-only credential (CWE-798) |
| `internal/server/attack_path_azure_served_test.go:27` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/server/attack_path_azure_served_test.go:72` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/attack_path_gcp_served_test.go:26` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/server/attack_path_gcp_served_test.go:57` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/attack_path_ipv6_served_test.go:27` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/server/attack_path_ipv6_served_test.go:81` | credential references only (CWE-798) |
| `internal/server/attack_path_lb_served_test.go:31` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/server/attack_path_lb_served_test.go:92` | credential references only (CWE-798) |
| `internal/server/attack_path_scheduled_served_test.go:24` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/server/attack_path_scheduled_served_test.go:55` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/attack_path_served_test.go:45` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/server/attack_path_served_test.go:103` | credential references only; no credential value enters the config (CWE-798) |
| `internal/server/attack_path_severity_served_test.go:25` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/server/attack_path_severity_served_test.go:90` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_elastic_auth_served_test.go:47` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_elastic_auth_served_test.go:80` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_index_template_lab_test.go:70` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_lab_p5_test.go:68` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_lab_p5_test.go:69` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_lab_p5_test.go:70` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_name_conflict_served_test.go:31` | token_ref is a non-secret environment locator (CWE-798). |
| `internal/server/audit_feed_name_conflict_served_test.go:73` | token_ref is a non-secret environment locator (CWE-798). |
| `internal/server/audit_feed_protected_served_test.go:88` | token_ref is a non-secret environment locator (CWE-798). |
| `internal/server/audit_feed_refusal_test.go:60` | fabricated test header values, no real credential (CWE-798) |
| `internal/server/audit_feed_rsyslog_content_lab_test.go:42` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_served_test.go:43` | token_ref is a non-secret environment locator (CWE-798). |
| `internal/server/audit_feed_served_test.go:142` | the credential-bearing URL is a negative fixture that production must reject (CWE-798). |
| `internal/server/audit_feed_served_test.go:160` | token_ref is a non-secret environment locator (CWE-798). |
| `internal/server/audit_feed_served_test.go:167` | token_ref is a non-secret environment locator (CWE-798). |
| `internal/server/audit_feed_syslog_elastic_served_test.go:61` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_syslog_elastic_served_test.go:63` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_syslog_elastic_served_test.go:65` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_syslog_mtls_lab_test.go:49` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/audit_feed_syslog_mtls_served_test.go:56` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/auth_unit_test.go:96` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/aws_acm_listener_rollback_served_test.go:31` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/server/aws_honeytoken_served_test.go:140` | the fixture's fake decoy secret, not a credential (CWE-798) |
| `internal/server/azure_keyvault_rollback_served_test.go:32` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/server/azure_workload_identity_served_test.go:26` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/cloud_access_keys_azure_served_test.go:75` | a credential reference only; no credential value enters the config (CWE-798) |
| `internal/server/cloud_access_keys_gcp_served_test.go:83` | a credential reference only; no credential value enters the config (CWE-798) |
| `internal/server/cloud_access_keys_served_test.go:82` | credential references only; no credential value enters the config (CWE-798) |
| `internal/server/cloud_access_keys_served_test.go:267` | the test's own stand-in signing value, not a credential (CWE-798) |
| `internal/server/cloud_access_keys_served_test.go:275` | credential references only; no credential value enters the config (CWE-798) |
| `internal/server/cloud_access_keys_served_test.go:374` | the test's own stand-in signing value, not a credential (CWE-798) |
| `internal/server/cloud_access_keys_served_test.go:382` | credential references only; no credential value enters the config (CWE-798) |
| `internal/server/cloud_certificate_revocation_served_test.go:55` | fabricated fixture credential references; no value is real (CWE-798) |
| `internal/server/cloud_key_replace_served_test.go:38` | the test's own stand-in signing value, not a credential (CWE-798) |
| `internal/server/cloud_key_replace_served_test.go:64` | credential references only; no credential value enters the config (CWE-798) |
| `internal/server/cloud_kms_keys_served_test.go:57` | credential references only; no credential value enters the config (CWE-798) |
| `internal/server/cloud_relay_execution_served_test.go:31` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/cloud_relay_execution_served_test.go:32` | a secret-store NAME the target references, not a credential value (CWE-798) |
| `internal/server/cmdb_served_test.go:32` | credential reference (env: pointer), no credential value present (CWE-798) |
| `internal/server/cmdb_served_test.go:36` | credential reference (secret store pointer), no credential value present (CWE-798) |
| `internal/server/cmdb_served_test.go:44` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/compliance_report_dispatch_served_test.go:44` | fabricated fixture reference; no value is real (CWE-798) |
| `internal/server/connector_rollback_control_plane_served_test.go:29` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/decoy_secret_scan_served_test.go:28` | fabricated decoy fixture; no value is real (CWE-798) |
| `internal/server/decoy_secret_scan_served_test.go:29` | fabricated fixture; no value is real (CWE-798) |
| `internal/server/decoy_secret_scan_served_test.go:57` | a decoy's path and label, no credential value (CWE-798) |
| `internal/server/destination_first_verification_served_test.go:38` | fabricated test-only credential (CWE-798) |
| `internal/server/discovery_cloud_outcomes_served_test.go:51` | env credential references and fixture endpoints; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_cloud_outcomes_served_test.go:52` | env credential reference, not a value (CWE-798) |
| `internal/server/discovery_cloud_outcomes_served_test.go:53` | env credential reference, not a value (CWE-798) |
| `internal/server/discovery_cloud_unbuilt_provider_served_test.go:46` | env credential references and fixture endpoints; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_cloud_unbuilt_provider_served_test.go:47` | env credential reference, not a value (CWE-798) |
| `internal/server/discovery_cloud_unbuilt_provider_served_test.go:48` | env credential reference, not a value (CWE-798) |
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
| `internal/server/discovery_served_test.go:2404` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2543` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2565` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2739` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2751` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/discovery_served_test.go:2762` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/dynamic_secret_access_cloud_served_test.go:39` | fabricated fixture credential; the stand-in needs the shape, no value is real (CWE-798) |
| `internal/server/dynamic_secret_api_connect_served_test.go:42` | fabricated stand-in token (CWE-798) |
| `internal/server/dynamic_secret_atlas_served_test.go:44` | fabricated stand-in service account (CWE-798) |
| `internal/server/dynamic_secret_clickhouse_served_test.go:44` | fabricated lab administrator password (CWE-798) |
| `internal/server/dynamic_secret_couchbase_served_test.go:41` | fabricated stand-in administrator (CWE-798) |
| `internal/server/dynamic_secret_elasticsearch_served_test.go:58` | fabricated lab administrator password (CWE-798) |
| `internal/server/dynamic_secret_milvus_served_test.go:44` | fabricated stand-in administrator (CWE-798) |
| `internal/server/dynamic_secret_oauth_served_test.go:60` | fabricated lab client secret (CWE-798) |
| `internal/server/dynamic_secret_rabbitmq_served_test.go:33` | fabricated lab administrator password (CWE-798) |
| `internal/server/dynamic_secret_tailscale_served_test.go:48` | fabricated stand-in API token (CWE-798) |
| `internal/server/dynamic_secret_totp_lab_test.go:38` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/endpoint_replacement_served_test.go:29` | fabricated test-only credential (CWE-798) |
| `internal/server/esxi_vcsim_served_test.go:268` | fabricated test-only password for the simulator (CWE-798) |
| `internal/server/esxi_vcsim_served_test.go:356` | fabricated test-only password for the simulator (CWE-798) |
| `internal/server/external_observer_served_test.go:62` | fabricated fixture credential (CWE-798) |
| `internal/server/gcp_workload_identity_served_test.go:27` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:25` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:34` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:126` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:135` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:148` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:184` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:193` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:212` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/itsm_served_test.go:220` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/jira_csv_annotation_served_test.go:23` | fabricated fixture credential (CWE-798) |
| `internal/server/jira_csv_annotation_served_test.go:37` | a credential reference to a fabricated fixture (CWE-798) |
| `internal/server/journey_delivery_served_test.go:36` | fabricated test-only credential (CWE-798) |
| `internal/server/journey_delivery_served_test.go:560` | fabricated test-only credential (CWE-798) |
| `internal/server/journey_delivery_served_test.go:735` | fabricated test-only credential (CWE-798) |
| `internal/server/journey_delivery_served_test.go:955` | fabricated test-only credential (CWE-798) |
| `internal/server/key_vault_disable_served_test.go:78` | test-only environment variable names, no credential values (CWE-798) |
| `internal/server/leaked_credential_correlation_served_test.go:107` | a credential reference to a fabricated fixture (CWE-798) |
| `internal/server/listener_sessions_report_served_test.go:29` | fabricated test-only credential (CWE-798) |
| `internal/server/load_balancer_tls_served_test.go:31` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/load_balancer_tls_served_test.go:32` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/load_balancer_tls_served_test.go:73` | credential references only; no credential value enters the config (CWE-798) |
| `internal/server/load_balancer_tls_served_test.go:74` | credential references only; no credential value enters the config (CWE-798) |
| `internal/server/load_balancer_tls_served_test.go:76` | credential references only; no credential value enters the config (CWE-798) |
| `internal/server/managedkeys_cloudkms_served_test.go:30` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/mdm_check_in_waves_served_test.go:77` | a secret:// reference name, not a credential (CWE-798) |
| `internal/server/mdm_jamf_api_client_served_test.go:30` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/server/mdm_poller_served_test.go:34` | credential reference (env: pointer), no credential value present (CWE-798) |
| `internal/server/mdm_poller_served_test.go:37` | credential reference (secret store pointer), no credential value present (CWE-798) |
| `internal/server/mdm_scep_dynamic_served_test.go:120` | a secret:// reference in a test fixture, not a credential value (CWE-798) |
| `internal/server/mdm_scep_dynamic_served_test.go:215` | a secret:// reference in a test fixture, not a credential value (CWE-798) |
| `internal/server/migration_cloud_store_lb_served_test.go:61` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/server/migration_cloud_store_served_test.go:41` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:46` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:48` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:130` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798). |
| `internal/server/native_connectors_served_test.go:537` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:539` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/native_connectors_served_test.go:541` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_oauth_served_test.go:67` | fabricated fixture credential (CWE-798) |
| `internal/server/nhi_posture_served_test.go:56` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:162` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:195` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/nhi_posture_served_test.go:584` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/notification_tenant_channel_families_served_test.go:87` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/server/notification_tenant_channel_families_served_test.go:88` | fabricated fixture credential (CWE-798) |
| `internal/server/oauth_provider_action_served_test.go:34` | fabricated fixture credential (CWE-798) |
| `internal/server/oauth_readback_served_test.go:23` | fabricated fixture credential (CWE-798) |
| `internal/server/oauth_readback_served_test.go:40` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/oauth_tenant_consent_served_test.go:26` | fabricated fixture credential (CWE-798) |
| `internal/server/oauth_tenant_consent_served_test.go:45` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/oauth_unblock_served_test.go:24` | fabricated fixture credential (CWE-798) |
| `internal/server/oauth_unblock_served_test.go:36` | token_ref is a non-secret environment locator (CWE-798) |
| `internal/server/oidc_issuer.go:120` | the token endpoint's path and the token lifetime, no credential (CWE-798) |
| `internal/server/opaque_access_token.go:27` | a token prefix, not a credential (CWE-798) |
| `internal/server/operations_action_run_served_test.go:26` | fabricated test-only credential (CWE-798) |
| `internal/server/operations_ledger_served_test.go:46` | fabricated test-only credential (CWE-798) |
| `internal/server/operations_ledger_served_test.go:247` | fabricated test-only credential (CWE-798) |
| `internal/server/operations_ledger_served_test.go:366` | fabricated test-only credential (CWE-798) |
| `internal/server/pam_discovery_ad_served_test.go:35` | fabricated password of a throwaway test domain (CWE-798) |
| `internal/server/pam_gateway_mysql_served_test.go:62` | fabricated test-only password for a throwaway MySQL container (CWE-798) |
| `internal/server/protocols_certbot_aud73_test.go:18` | fabricated test-only webhook credential (CWE-798) |
| `internal/server/protocols_served_stock_clients_test.go:59` | fabricated test-only webhook credential (CWE-798) |
| `internal/server/protocols_served_stock_clients_test.go:188` | fabricated secret reference, never raw credential material (CWE-798) |
| `internal/server/protocols_served_test.go:350` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:414` | opaque fake secret reference used only by the local test provider (CWE-798). |
| `internal/server/protocols_served_test.go:650` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:759` | fabricated secret reference, never raw credential material (CWE-798) |
| `internal/server/protocols_served_test.go:903` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:940` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:1011` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:1088` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/protocols_served_test.go:1288` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/provider_billing_gradient_served_test.go:121` | a test-only value (CWE-798) |
| `internal/server/provider_billing_halopsa_served_test.go:40` | a test-only value (CWE-798) |
| `internal/server/provider_billing_pax8_served_test.go:24` | test-only values (CWE-798) |
| `internal/server/provider_billing_syncro_served_test.go:40` | a test-only value (CWE-798) |
| `internal/server/provider_doc_hudu_served_test.go:21` | a test-only value (CWE-798) |
| `internal/server/provider_doc_itglue_served_test.go:55` | a test-only value (CWE-798) |
| `internal/server/provider_rmm_automate_served_test.go:28` | a test-only value (CWE-798) |
| `internal/server/provider_rmm_datto_served_test.go:66` | test-only values (CWE-798) |
| `internal/server/provider_rmm_kaseya_served_test.go:25` | test-only values (CWE-798) |
| `internal/server/provider_rmm_ncentral_served_test.go:22` | a test-only value (CWE-798) |
| `internal/server/provider_rmm_ninjaone_served_test.go:36` | test-only values (CWE-798) |
| `internal/server/redfish_mockup_served_test.go:191` | fabricated test-only password for the mockup (CWE-798) |
| `internal/server/repository_code_scanning_served_test.go:31` | fabricated fixture credential (CWE-798) |
| `internal/server/repository_code_scanning_served_test.go:62` | a credential reference to a fabricated fixture (CWE-798) |
| `internal/server/response_integrations_served_test.go:31` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:51` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:52` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/response_integrations_served_test.go:54` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/revocation_ldap_served_test.go:37` | a logical fixture name, not secret material (CWE-798). |
| `internal/server/revocation_ldap_served_test.go:38` | a non-secret reference, not secret material (CWE-798). |
| `internal/server/right_size_relay_served_test.go:34` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/right_size_relay_served_test.go:35` | a secret-store NAME the binding references, not a credential value (CWE-798) |
| `internal/server/scan_annotation_served_test.go:94` | fabricated fixture credential (CWE-798) |
| `internal/server/scheduler_history_assembled_test.go:34` | deliberately toxic non-routable fixture proves sanitation (CWE-798). |
| `internal/server/scheduler_history_sanitation_test.go:14` | deliberately toxic non-routable fixture proves sanitation (CWE-798). |
| `internal/server/secret_integrations.go:1675` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/server/secret_parameter_store_drift_served_test.go:29` | a stand-in fixture value, not a credential (CWE-798) |
| `internal/server/secret_reference_scope_served_test.go:140` | a secret:// reference or secret name in a test fixture, not a credential value (CWE-798) |
| `internal/server/secret_reference_scope_served_test.go:156` | a secret:// reference or secret name in a test fixture, not a credential value (CWE-798) |
| `internal/server/secret_reference_scope_served_test.go:174` | a secret:// reference or secret name in a test fixture, not a credential value (CWE-798) |
| `internal/server/secret_render_served_test.go:326` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_repository_private_clone_served_test.go:73` | fabricated fixture token for the stand-in host (CWE-798) |
| `internal/server/secret_repository_private_clone_served_test.go:120` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_repository_private_clone_served_test.go:121` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_scoped_sync_alert_served_test.go:81` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_scoped_sync_approval_served_test.go:33` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_scoped_sync_interval_served_test.go:25` | fabricated fixture credential; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_scoped_sync_replace_served_test.go:31` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_scoped_sync_served_test.go:196` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_scoped_sync_served_test.go:479` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_static_rotation_ldap_two_user_container_test.go:245` | fabricated lab password the first rotation retires (CWE-798) |
| `internal/server/secret_static_rotation_mongo_two_user_container_test.go:223` | fabricated lab password the first rotation retires (CWE-798) |
| `internal/server/secret_static_rotation_unix_container_test.go:34` | fabricated lab password the first rotation retires (CWE-798) |
| `internal/server/secret_store_api_key_served_test.go:104` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_api_key_served_test.go:106` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_api_key_served_test.go:107` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_api_key_served_test.go:108` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_generic_entropy_served_test.go:45` | a credential reference to a fabricated fixture (CWE-798) |
| `internal/server/secret_store_more_scopes_served_test.go:90` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_more_scopes_served_test.go:92` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_more_scopes_served_test.go:159` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_more_scopes_served_test.go:160` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_od13_served_test.go:144` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_od13_served_test.go:145` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_od13_served_test.go:146` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_od13_served_test.go:147` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_od13_served_test.go:273` | credential references to lab fixture values (CWE-798) |
| `internal/server/secret_store_od13_served_test.go:275` | credential references to lab fixture values (CWE-798) |
| `internal/server/secret_store_od14_served_test.go:50` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_od14_served_test.go:51` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_private_key_link_served_test.go:83` | a credential reference to a fabricated fixture value (CWE-798) |
| `internal/server/secret_store_providers_served_test.go:115` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_providers_served_test.go:117` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_providers_served_test.go:160` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_store_providers_served_test.go:161` | credential references to fabricated fixture values (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:359` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:416` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:475` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:533` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:586` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:658` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:697` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:790` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:850` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:935` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:980` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1053` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1139` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1193` | fabricated fixture credentials; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1252` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1319` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1405` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1478` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1558` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1656` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1703` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1763` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1826` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1905` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:1972` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:2018` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:2080` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:2151` | fabricated fixture access key; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:2366` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:2451` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:2503` | fabricated fixture credential; no value is real (CWE-798) |
| `internal/server/secret_sync_hosted_targets_served_test.go:2555` | fabricated fixture credentials; no value is real (CWE-798) |
| `internal/server/secret_third_party_scan_retention_served_test.go:25` | fabricated fixture (CWE-798) |
| `internal/server/secret_third_party_scan_served_test.go:22` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secret_third_party_scan_signature_served_test.go:29` | fabricated fixture (CWE-798) |
| `internal/server/secret_validity_served_test.go:88` | an env: reference to a test-only value (CWE-798) |
| `internal/server/secrets_scan_served_test.go:260` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_served_test.go:583` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_served_test.go:2525` | fabricated STS exchange fixture; no real credential (CWE-798) |
| `internal/server/secrets_sync_served_test.go:581` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_sync_served_test.go:593` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_sync_served_test.go:604` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/secrets_sync_served_test.go:614` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/service_account_ad_discovery_served_test.go:42` | configuration carries only a protected credential-file reference, never a credential value (CWE-798) |
| `internal/server/service_account_ad_reconcile_native_test.go:41` | protected owned lab credential-file reference, never credential bytes (CWE-798) |
| `internal/server/service_account_ad_reconcile_native_test.go:68` | protected owned lab credential-file reference, never credential bytes (CWE-798) |
| `internal/server/service_account_reconciliation_native_test.go:34` | protected owned lab credential-file reference only (CWE-798) |
| `internal/server/service_account_reconciliation_native_test.go:74` | separate protected owned lab reference only (CWE-798) |
| `internal/server/service_account_rotation_native_ad_test.go:37` | protected lab credential-file reference only, never a credential value (CWE-798) |
| `internal/server/servicenow_two_way_served_test.go:103` | the name of a test-only secret, not a credential (CWE-798) |
| `internal/server/servicenow_two_way_served_test.go:204` | an env: reference to a test-only value (CWE-798) |
| `internal/server/servicenow_two_way_served_test.go:221` | an env: reference to a test-only value (CWE-798) |
| `internal/server/servicenow_two_way_served_test.go:235` | an env: reference to a test-only value (CWE-798) |
| `internal/server/slack_annotation_retry_served_test.go:25` | fabricated fixture credential (CWE-798) |
| `internal/server/slack_annotation_retry_served_test.go:84` | a credential reference to a fabricated fixture (CWE-798) |
| `internal/server/slack_app_lost_answer_served_test.go:31` | env: references to test-only values, no credential (CWE-798) |
| `internal/server/slack_app_served_test.go:144` | env: references to test-only values, no credential (CWE-798) |
| `internal/server/slack_socket_served_test.go:128` | env: references to test-only values, no credential (CWE-798) |
| `internal/server/ssh_agentless_collection_served_test.go:27` | public host pin, restricted account and vault-reference fixtures contain no credential value (CWE-798). |
| `internal/server/thirdparty_collect_served_test.go:194` | env: references to test-only stand-in tokens, no credential values (CWE-798) |
| `internal/server/thirdparty_collect_served_test.go:195` | env: references to test-only stand-in tokens, no credential values (CWE-798) |
| `internal/server/thirdparty_collect_served_test.go:196` | env: references to test-only stand-in tokens, no credential values (CWE-798) |
| `internal/server/thirdparty_collect_served_test.go:197` | env: references to test-only stand-in tokens, no credential values (CWE-798) |
| `internal/server/thirdparty_collect_served_test.go:198` | env: references to test-only stand-in tokens, no credential values (CWE-798) |
| `internal/server/thirdparty_collect_teams_confluence_served_test.go:99` | env: references to test-only stand-in values (CWE-798) |
| `internal/server/thirdparty_collect_teams_confluence_served_test.go:100` | env: references to test-only stand-in values (CWE-798) |
| `internal/server/thirdparty_collect_teams_confluence_served_test.go:101` | env: references to test-only stand-in values (CWE-798) |
| `internal/server/thirdparty_collect_teams_confluence_served_test.go:102` | env: references to test-only stand-in values (CWE-798) |
| `internal/server/ticket_intake_served_test.go:26` | credential reference (secret store pointer), no credential value present (CWE-798) |
| `internal/server/token_exchange.go:40` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/server/token_exchange.go:41` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/server/token_exchange.go:42` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/server/token_exchange.go:48` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/server/totp_seed_replace_served_test.go:33` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/totp_seed_replace_served_test.go:34` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:28` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:149` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:150` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:151` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/unvaulted_secret_posture_served_test.go:152` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/server/vendor_dcv_served_test.go:94` | secret reference, no credential value (CWE-798) |
| `internal/server/vendor_dcv_served_test.go:216` | secret reference, no credential value (CWE-798) |
| `internal/server/vendor_dcv_served_test.go:334` | secret reference, no credential value (CWE-798) |
| `internal/sshcollection/command_test.go:12` | public host pin, restricted account and vault-reference fixtures contain no credential value (CWE-798). |
| `internal/sshcollection/report_test.go:11` | public host pin, restricted account and vault-reference fixtures contain no credential value (CWE-798). |
| `internal/store/agent_bootstrap_token_test.go:67` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `internal/store/api_token_revocation_commands.go:60` | SQL column names for an opaque command fence, not a credential. |
| `internal/store/approved_target_fences.go:230` | SQL column identifiers only; this constant contains no credential material. |
| `internal/store/decoy_secret_privacy_test.go:33` | a decoy names a fabricated test secret, no credential value (CWE-798) |
| `internal/store/decoy_secret_privacy_test.go:123` | a decoy names a fabricated test secret, no credential value (CWE-798) |
| `internal/store/discovery_secret_move.go:53` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/store/discovery_secret_move.go:56` | SQL column list, no credential (CWE-798) */ `m.finding_id::text, m.secret_name, m.secret_version, m.moved_by, m.moved_at, m.residue, |
| `internal/store/dynamic_secret_lease.go:671` | sealed_credential is a SQL column name, not a hardcoded credential (CWE-798). |
| `internal/store/honey_token.go:73` | SQL column names only; this string contains no credential material. |
| `internal/store/migration_0359_content_test.go:50` | a query naming the hash column; no credential value (CWE-798) |
| `internal/store/migration_0435_content_test.go:50` | a query naming the hash column; no credential value (CWE-798) |
| `internal/store/privacy_erasure_preparation.go:28` | this is a bounded privacy evidence label, not a credential. |
| `internal/store/privacy_erasure_preparation.go:177` | SQL column identifiers only; this constant contains no credential material. |
| `internal/store/secret_migrations.go:223` | SQL column list, no credential (CWE-798) */ `id::text, project, state, digest, plan, accepted_open, created_by, created_at, staged_at, staged_by, |
| `internal/store/secret_rotation_schedule_privacy.go:694` | SQL authority columns are names, not embedded credentials (CWE-798). |
| `internal/store/secret_scoped_sync.go:21` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/store/secret_scoped_sync.go:395` | identifier/constant matching the secret-name heuristic; no credential value present (CWE-798) |
| `internal/store/secret_scoped_sync.go:435` | SQL column list, no credential (CWE-798) |
| `internal/store/secret_static_rotation.go:359` | SQL column list, no credential (CWE-798) */ `tenant_id::text, id::text, tenant_epoch, provider, provider_type, secret_key, old_ref, new_ref, |
| `internal/store/secret_store.go:329` | SQL column identifiers only; this constant contains no credential material. |
| `internal/store/secret_sync_workload_identity.go:203` | SQL column list matching the secret-name heuristic; a query, not a credential (CWE-798) |
| `internal/store/tenant_name_held.go:42` | table names and read queries, not credentials (CWE-798) |
| `internal/store/upsert_arbiter_race_test.go:239` | an env reference name in a fixture, not a credential (CWE-798) |
| `internal/ticketintake/intake_test.go:103` | TokenRef is a non-secret locator in a deterministic fixture (CWE-798). |
| `internal/ticketintake/intake_test.go:163` | TokenRef is a non-secret locator in a deterministic fixture (CWE-798). |
| `tools/dodcensus/claims.go:165` | developer-tool constant matching the secret-name heuristic; no credential value (CWE-798) |
| `tools/dodcensus/runtime.go:40` | developer-tool constant matching the secret-name heuristic; no credential value (CWE-798) |
| `tools/trstctllint/keymaterial/keymaterial_test.go:51` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |
| `tools/trstctllint/keymaterial/keymaterial_test.go:87` | fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798) |

### G102 — CWE-? (unmapped rule) (5 sites)

| Location | Reason |
|---|---|
| `internal/cli/access_agent_confine_linux_test.go:52` | the outside listener answers on every address so the test proves the confined command reaches none of them |
| `internal/kmip/pykmip_client_test.go:108` | a test listener the PyKMIP container dials through the Docker host gateway; mutual TLS still applies (CWE-200) |
| `internal/kmip/pykmip_tenants_test.go:114` | a test listener the PyKMIP container dials through the Docker host gateway; mutual TLS still applies (CWE-200) |
| `internal/netconfine/netconfine_linux_test.go:100` | the outside listener answers on every address so the test proves the confined command reaches none of them |
| `internal/server/spire_jwt_authorities_container_test.go:258` | the test's containers reach the served API through the Docker host gateway (CWE-200) |

### G103 — CWE-? (unmapped rule) (79 sites)

| Location | Reason |
|---|---|
| `internal/agent/secretrender/restrict_windows_test.go:39` | the ACE's trailing SID, as the Windows API lays it out (CWE-242) |
| `internal/agent/workloadapi/attest_darwin.go:65` | getsockopt fills a fixed-size audit token (CWE-242) |
| `internal/agent/workloadapi/attest_darwin.go:121` | proc_info fills the caller's buffer (CWE-242) |
| `internal/crypto/secret/foreign_windows.go:23` | caller-owned native allocation remains live through release and native free; only its bounded bytes are borrowed (CWE-242) |
| `internal/crypto/secret/foreign_windows_test.go:26` | exact owned VirtualAlloc page, freed only after wipe/unlock assertions (CWE-242) |
| `internal/crypto/secret/foreign_windows_test.go:36` | exact PSAPI working-set output for the live owned allocation and current process (CWE-242) |
| `internal/crypto/secret/mem_windows.go:40` | VirtualAlloc's committed region, outside the Go heap, released only by free (CWE-242) |
| `internal/crypto/secret/mem_windows.go:84` | the address VirtualAlloc returned for this region (CWE-242) |
| `internal/crypto/secret/mem_windows_test.go:38` | reads the address of the region alloc returned, to check its alignment (CWE-242) |
| `internal/crypto/secret/mem_windows_test.go:45` | the region's address, to query its lock and release state (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:54` | synchronous native buffer-size query; raw is owned by NetAPI until the caller frees it (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:61` | borrowed read-only view uses NetApiBufferSize-confirmed length, capped at 1 MiB; caller retains and frees the allocation (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:67` | borrowed nonempty NetAPI buffer base; offset arithmetic never becomes a new pointer (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:79` | SDK SID pointer is range checked against the borrowed native allocation before byte decoding (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:86` | SDK UTF-16 pointer is range checked before bounded, terminated public-name decoding (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:97` | local DSROLE basic result pointer for one synchronous SDK call; separately freed below (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:99` | exactly the pointer allocated by DsRoleGetPrimaryDomainInformation, including any partial error result (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:108` | successful local DSROLE basic result guarantees this four-byte prefix; pointer is non-nil and separately freed (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:113` | local SAM public domain-name/SID result, no remote server parameter (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:122` | exact SDK prefix fits the checked allocation; each pointed field is independently bounded (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:155` | local-only paged alias read, fixed SDK scalar/output pointers, bounded preferred reply size (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:183` | SDK array count is checked against the exact allocation before creating a borrowed view (CWE-242) |
| `internal/crypto/winaccounts/native_windows.go:239` | checked USER_INFO_23 allocation; only public name, flags and SID are read (CWE-242) |
| `internal/crypto/winaccounts/native_windows_test.go:62` | aligned locked UTF-16 password buffer, NUL-terminated, wiped and destroyed after synchronous owned fixture calls (CWE-242) |
| `internal/crypto/winaccounts/native_windows_test.go:65` | exact USER_INFO_1 ABI for one uniquely named owned fixture; password remains in a locked byte buffer (CWE-242) |
| `internal/crypto/winaccounts/native_windows_test.go:76` | removes only the exact owned SID membership created by this fixture (CWE-242) |
| `internal/crypto/winaccounts/native_windows_test.go:86` | exact newly created account name after current SID equality check; no wildcard or pre-existing account deletion (CWE-242) |
| `internal/crypto/winaccounts/native_windows_test.go:111` | fixed local alias and exact owned SID, one membership only (CWE-242) |
| `internal/crypto/winaccounts/native_windows_test.go:123` | one correct-password local fixture login; locked password pointer is never converted to a string or argv (CWE-242) |
| `internal/crypto/winaccounts/rotation_native_windows_test.go:44` | live aligned locked UTF-16 password for one synchronous owned USER_INFO_1 fixture creation (CWE-242) |
| `internal/crypto/winaccounts/rotation_native_windows_test.go:46` | local-only uniquely named test user; locked secret never becomes a string, file or argv (CWE-242) |
| `internal/crypto/winaccounts/rotation_native_windows_test.go:58` | removes only the exact owned SID membership this fixture added (CWE-242) |
| `internal/crypto/winaccounts/rotation_native_windows_test.go:68` | deletes only the newly created name after current SID equality; never a wildcard or pre-existing account (CWE-242) |
| `internal/crypto/winaccounts/rotation_native_windows_test.go:90` | localized built-in alias, single exact owned local SID, no domain account or unrelated membership (CWE-242) |
| `internal/crypto/winaccounts/rotation_windows.go:42` | local-only public password policy result, freed below; no secret or remote target (CWE-242) |
| `internal/crypto/winaccounts/rotation_windows.go:50` | exact USER_MODALS_INFO_0 prefix fits NetApiBufferSize-checked native allocation (CWE-242) |
| `internal/crypto/winaccounts/rotation_windows.go:51` | local-only public lockout policy result with SDK level 3 and owned output pointer (CWE-242) |
| `internal/crypto/winaccounts/rotation_windows.go:59` | exact USER_MODALS_INFO_3 prefix fits the checked allocation; read-only scalar fields (CWE-242) |
| `internal/crypto/winaccounts/rotation_windows.go:113` | exact USER_INFO_4 ABI in checked allocation; only public identity/flags/counters are accessed, never Password (CWE-242) |
| `internal/crypto/winaccounts/rotation_windows.go:160` | aligned locked UTF-16 byte buffer, terminated and borrowed through Use for the synchronous SDK call (CWE-242) |
| `internal/crypto/winaccounts/rotation_windows.go:162` | local-only password field, fixed SDK level, exact preflighted public account name; no flags, membership, shell or remote target (CWE-242) |
| `internal/crypto/winaccounts/rotation_windows.go:195` | one bounded local-SAM LOGON_NETWORK authentication, which does not cache credentials; live locked password bytes only (CWE-242) |
| `internal/crypto/windependents/automation_native_windows_test.go:47` | exact PSAPI output for the current process and live locked owned BSTR, no material is copied (CWE-242) |
| `internal/crypto/windependents/automation_windows.go:53` | owned native BSTR allocator length, wiped in views no larger than 1 MiB before SysFreeString; no password string (CWE-242) |
| `internal/crypto/windependents/automation_windows.go:92` | owned SysAllocStringLen or COM BSTR, native length capped below 1 Mi UTF-16 units and locked before private use (CWE-242) |
| `internal/crypto/windependents/automation_windows.go:130` | public-only UTF-16 input stays alive through the synchronous native allocation; passwords use a separate locked path (CWE-242) |
| `internal/crypto/windependents/automation_windows.go:188` | SDK EXCEPINFO deferred callback receives its live exact output struct; all returned strings are wiped without logging (CWE-242) |
| `internal/crypto/windependents/automation_windows.go:211` | two allowlisted local native identifiers and sized SDK GUID output, no caller-selected COM class (CWE-242) |
| `internal/crypto/windependents/automation_windows.go:216` | allowlisted local native class, exact IDispatch IID and native interface output, released in the same apartment (CWE-242) |
| `internal/crypto/windependents/automation_windows.go:270` | exact live native VARIANT layout; native allocator clears non-text result ownership, text is wiped separately (CWE-242) |
| `internal/crypto/windependents/automation_windows.go:286` | live fixed IDispatch vtable, public method name, sized GUID/DISPID outputs and one bounded name (CWE-242) |
| `internal/crypto/windependents/automation_windows.go:310` | exact IDispatch ABI, at most 16 reversed typed arguments and live sized result/exception outputs; password BSTR lease remains locked (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:135` | SDK USER_INFO_1 points only to the owned public name and live locked password buffer (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:138` | exact SDK USER_INFO_1 and output scalar for a synchronous local test-account creation; password stays locked (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:144` | exact name of the successfully created test-owned account; no enumeration or global cleanup (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:169` | exact newly created test SID added to the native Users group; deletion removes only its own membership (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:197` | sized SDK LSA_OBJECT_ATTRIBUTES and handle output; local policy only for test-owned SID rights (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:206` | live native owned-account SID and length-framed public LSA right; synchronous local API (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:212` | sized SDK LSA_OBJECT_ATTRIBUTES and handle output; local policy only for test-owned SID rights (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:218` | exact test-owned account SID and the single right this fixture added, with all-rights deletion disabled (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:231` | SDK USER_INFO_1003 borrows the live locked UTF-16 predecessor/successor buffer (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:233` | exact test-owned user, SDK level 1003 and live locked UTF-16 password; no password string or file (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:247` | one bounded sign-in for the test-owned local account using a live locked UTF-16 password and token output (CWE-242) |
| `internal/crypto/windependents/services_native_windows_test.go:343` | exact new fixture service and live locked initial UTF-16 credential; only owned service is created (CWE-242) |
| `internal/crypto/windependents/services_windows.go:57` | owned nonempty native query buffer address; only offset arithmetic, never converted back to a pointer (CWE-242) |
| `internal/crypto/windependents/services_windows.go:58` | SDK-returned UTF-16 pointer is range/alignment/termination checked against the owned buffer before a byte view (CWE-242) |
| `internal/crypto/windependents/services_windows.go:67` | exact SDK status struct size and lifetime for a synchronous local status call (CWE-242) |
| `internal/crypto/windependents/services_windows.go:88` | page-aligned locked 64 KiB query buffer exceeds the SDK struct and remains alive through all bounded field reads (CWE-242) |
| `internal/crypto/windependents/services_windows.go:197` | SDK count is bounded by both returned-buffer capacity and total census before creating the native entry view (CWE-242) |
| `internal/crypto/windependents/services_windows.go:259` | password pointer borrows the locked UTF-16 buffer through Use; frozen account pointer stays in the live locked query buffer (CWE-242) |
| `internal/crypto/windependents/task_events_windows.go:32` | fixed local scheduler channel; live UTF-16 public path and native handle (CWE-242) |
| `internal/crypto/windependents/task_events_windows.go:39` | exact 16-byte EVT_VARIANT output and size for the fixed Enabled property (CWE-242) |
| `internal/crypto/windependents/task_events_windows.go:57` | owned nonempty bounded native render buffer; only checked offset arithmetic (CWE-242) |
| `internal/crypto/windependents/task_events_windows.go:134` | complete SID revision/subauthority length is checked inside the live owned render buffer (CWE-242) |
| `internal/crypto/windependents/task_events_windows.go:178` | eight fixed metadata-only XPath selectors, live through synchronous context creation (CWE-242) |
| `internal/crypto/windependents/task_events_windows.go:193` | owned locked 64 KiB buffer and sized metadata-only EVT_VARIANT outputs (CWE-242) |
| `internal/crypto/windependents/task_events_windows.go:197` | exact eight 16-byte native variants validated against returned property count and buffer length (CWE-242) |
| `internal/crypto/windependents/task_events_windows.go:248` | validated GUID/fixed schema structured query, local channel only, used and closed on this OS thread (CWE-242) |
| `internal/crypto/windependents/task_events_windows.go:265` | fixed 16-handle output array, zero wait and sized count; every returned native event is closed (CWE-242) |

### G104 — CWE-? (unmapped rule) (1 sites)

| Location | Reason |
|---|---|
| `internal/crypto/deviceattesttest/smartcardhsm.go:137` | a P-256 key the stand-in generated always encodes |

### G107 — CWE-88 Argument injection (variable URL request) (14 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:586` | loopback-only assembled test listener (CWE-918) |
| `ee/auditcompliance/protected_archive_minio_fixture_test.go:55` | loopback URL of the container this test started (CWE-88) |
| `internal/crypto/ctlog/sct_test.go:27` | loopback test log (CWE-918) |
| `internal/crypto/ctlog/sct_test.go:45` | loopback test log (CWE-918) |
| `internal/objectstore/minio_lock_test.go:56` | loopback URL of the container this test started (CWE-88) |
| `internal/protocols/scep/profile_routes_test.go:106` | test drives its own local server URL (CWE-88) |
| `internal/server/adcs_revoke_relay_served_test.go:305` | the test's own CA stand-in (CWE-918). |
| `internal/server/adcs_rogue_revoke_served_test.go:117` | the test's own CA stand-in (CWE-918). |
| `internal/server/archive_minio_served_test.go:58` | loopback URL of the container this test started (CWE-88) |
| `internal/server/ca_hierarchy_pqc_served_test.go:53` | the served test harness URL |
| `internal/server/ca_hierarchy_pqc_served_test.go:55` | the served test harness URL |
| `internal/server/ca_hierarchy_pqc_served_test.go:166` | served test harness URL |
| `internal/server/license_entitlement_test.go:70` | fixed localhost-only assembled-test server (CWE-918) |
| `internal/server/mcp_authorization_keycloak_test.go:272` | the lab container's own loopback URL (CWE-88) |

### G112 — CWE-400 Uncontrolled resource consumption (slowloris) (25 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/bootstrap_token_test.go:459` | local test listener owned and torn down by the test (CWE-400) |
| `cmd/trstctl-agent/role_grant_renewal_test.go:66` | local test listener owned and torn down by the test (CWE-400) |
| `cmd/trstctl/healthprobe_test.go:31` | local test listener owned and torn down by the test (CWE-400) |
| `internal/agent/http_enroll_test.go:150` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/hybrid_group_test.go:31` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/reload_test.go:95` | loopback test listener torn down by the test (CWE-400) |
| `internal/crypto/mtls/server_test.go:152` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/server_test.go:215` | local test listener owned and torn down by the test (CWE-400) |
| `internal/crypto/mtls/server_test.go:289` | local test listener owned and torn down by the test (CWE-400) |
| `internal/server/ca_switch_from_vendor_served_test.go:111` | loopback fixture closed below (CWE-400) |
| `internal/server/ca_switch_served_test.go:78` | loopback fixture closed by its stop func (CWE-400) |
| `internal/server/ca_switch_to_vendor_served_test.go:89` | loopback fixture closed by its stop func (CWE-400) |
| `internal/server/closed_loop_served_test.go:73` | loopback fixture closed below (CWE-400) |
| `internal/server/dod_parent_substrate_bridge_runtime_test.go:183` | local test listener owned and torn down by the test (CWE-400) |
| `internal/server/endpoint_traffic_served_test.go:74` | loopback fixture closed below (CWE-400) |
| `internal/server/evaluate_incident_served_test.go:57` | loopback fixture is closed below (CWE-400) |
| `internal/server/evaluate_served_test.go:66` | loopback fixture is closed below (CWE-400) |
| `internal/server/host_agent_remote_served_test.go:295` | loopback fixture is closed below (CWE-400) |
| `internal/server/host_agent_remote_served_test.go:533` | loopback fixture closed below (CWE-400) |
| `internal/server/host_renewal_heal_served_test.go:107` | loopback fixture is closed below (CWE-400) |
| `internal/server/incident_fleet_reissuance_served_test.go:443` | loopback test fixture is explicitly closed (CWE-400) |
| `internal/server/migration_appliance_served_test.go:115` | loopback fixture closed below (CWE-400) |
| `internal/server/migration_run_served_test.go:98` | loopback fixture is closed below (CWE-400) |
| `internal/server/migration_run_served_test.go:467` | loopback fixture is closed below (CWE-400) |
| `internal/server/serve_test.go:21` | local test listener owned and torn down by the test (CWE-400) |

### G115 — CWE-190 Integer overflow or wraparound (512 sites)

| Location | Reason |
|---|---|
| `clients/signing/cmd/trstctl-ksp-register/cng_windows.go:76` | NTSTATUS and SECURITY_STATUS are 32-bit values |
| `clients/signing/ksp/module.go:364` | RSA and P-256 key sizes fit 32 bits |
| `clients/signing/ksp/module.go:626` | RSA sizes fit 32 bits |
| `clients/signing/ksp/module.go:717` | a signature length fits 32 bits |
| `cmd/trstctl-agent/main.go:632` | the MaxUint32 check above proves the narrowing is exact (CWE-190). |
| `cmd/trstctl-signer/offline_pcas.go:158` | Count equals len(Records) above: nonnegative and bounded by the 4 MiB input (CWE-190). |
| `deploy/helm/helm_test.go:1778` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `ee/auditcompliance/retention.go:279` | event sequence/count fits int64 by construction; bounded by the log (CWE-190) |
| `ee/governance/misuse/incident.go:100` | bounded by MaxInt64 above. |
| `ee/governance/misuse/misuse.go:150` | event sequences fit int64 (CWE-190) |
| `ee/governance/misuse/misuse.go:287` | a projected event sequence is positive (CWE-190) |
| `ee/governance/misuse/policy.go:122` | bounded by MaxInt64 above. |
| `ee/managedkeys/provider_dates_e2e_test.go:269` | port is checked to be 1..65535 above (CWE-190) |
| `ee/silo/lanedrill_test.go:96` | bounds-checked to [1, MaxUint16] above (CWE-190) |
| `internal/agent/accessgateway/kubernetes.go:230` | bounded by len(p) (CWE-190) |
| `internal/agent/accessgateway/kubernetes.go:238` | take is non-negative (CWE-190) |
| `internal/agent/accessgateway/kubernetes_test.go:24` | a 7-bit length below 126 (CWE-190) |
| `internal/agent/accessgateway/kubernetes_test.go:27` | under 1<<16 (CWE-190) |
| `internal/agent/accessgateway/kubernetes_test.go:30` | a payload length, never negative (CWE-190) |
| `internal/agent/accessgateway/mongo.go:97` | a request id is its two's-complement bits (CWE-190) |
| `internal/agent/accessgateway/mongo.go:98` | a request id is its two's-complement bits (CWE-190) |
| `internal/agent/accessgateway/mongo.go:99` | an op code is a small constant (CWE-190) |
| `internal/agent/accessgateway/mongo.go:179` | bounded by the message it came from (CWE-190) |
| `internal/agent/accessgateway/mongo.go:390` | a BSON datetime's two's-complement bits (CWE-190) |
| `internal/agent/accessgateway/mongocommand.go:120` | request ID's two's-complement bits (CWE-190) |
| `internal/agent/accessgateway/mysql.go:565` | bounded by mysqlMaxLenenc just above (CWE-190) |
| `internal/agent/accessgateway/mysql_test.go:44` | the 3-byte little-endian packet length (CWE-190) |
| `internal/agent/accessgateway/mysql_test.go:47` | test strings are under 251 bytes (CWE-190) |
| `internal/agent/accessgateway/mysql_test.go:74` | one short ERR packet (CWE-190) |
| `internal/agent/accessgateway/mysqlcommand.go:185` | bounded 24-bit packet length (CWE-190) |
| `internal/agent/accessgateway/mysqlcommand.go:186` | high byte of bounded 24-bit packet length (CWE-190) |
| `internal/agent/accessgateway/pgrecord.go:183` | the wire field is a signed length (-1 is NULL) (CWE-190) |
| `internal/agent/accessgateway/pgrecord_test.go:21` | test rows are small (CWE-190) |
| `internal/agent/accessgateway/pgrecord_test.go:23` | test values are small (CWE-190) |
| `internal/agent/accessgateway/postgres.go:137` | gateway-built messages are small (CWE-190) |
| `internal/agent/accessgateway/sftp_test.go:17` | test packets are small (CWE-190) |
| `internal/agent/accessgateway/sftp_test.go:21` | test strings are small (CWE-190) |
| `internal/agent/decoy/watch_linux.go:112` | the kernel's signed file descriptor field (CWE-190) |
| `internal/agent/decoy/watch_linux.go:113` | the kernel's signed process ID field (CWE-190) |
| `internal/agent/decoy/watch_linux.go:142` | a watch descriptor the kernel numbers from 1 (CWE-190) |
| `internal/agent/decoy/watch_linux.go:162` | the kernel's signed watch descriptor field (CWE-190) |
| `internal/agent/decoy/watch_linux.go:187` | a file descriptor this process opened (CWE-190) |
| `internal/agent/desktop/server.go:553` | k is at most chunk (4096) (CWE-190) |
| `internal/agent/desktop/server.go:591` | the target's text is bounded by rdp.MaxClipboard (CWE-190) |
| `internal/agent/listenersessions/proc.go:123` | parsed with a 16-bit bound |
| `internal/agent/listenersessions/proc.go:201` | parsed with a 63-bit bound |
| `internal/agent/observe/capture_linux.go:34` | snaplen is a small configured frame size |
| `internal/agent/observe/capture_linux.go:39` | bounded by the check above; MaxWatchedPorts keeps it to tens (CWE-190) |
| `internal/agent/observe/flows.go:236` | TCP sequence numbers wrap; the difference read as a signed 32-bit distance is RFC 1982 serial arithmetic (CWE-190) |
| `internal/agent/observe/flows.go:249` | one segment's payload is under 64 KiB, and sequence numbers wrap mod 2^32 by design (CWE-190) |
| `internal/agent/observe/flows.go:284` | RFC 1982 serial arithmetic on wrapping sequence numbers (CWE-190) |
| `internal/agent/observe/flows.go:290` | a held payload is under MaxDirectionBytes, and sequence numbers wrap by design (CWE-190) |
| `internal/agent/observe/flows_test.go:23` | bounded test packet length (CWE-190) |
| `internal/agent/observe/flows_test.go:62` | bounded test fixture length (CWE-190) |
| `internal/agent/observe/pcap_test.go:80` | bounded test fixture length (CWE-190) |
| `internal/agent/observe/portfilter.go:124` | a forward jump inside this fixed program, under 255 instructions at MaxWatchedPorts (CWE-190) |
| `internal/agent/observe/portfilter.go:128` | a forward jump inside this fixed program (CWE-190) |
| `internal/agent/observe/upgrade_test.go:18` | bounded test fixture lengths (CWE-190) |
| `internal/agent/observe/upgrade_test.go:24` | bounded test fixture lengths (CWE-190) |
| `internal/agent/observe/upgrade_test.go:36` | bounded test fixture length (CWE-190) |
| `internal/agent/observe/upgrade_test.go:41` | bounded test fixture lengths (CWE-190) |
| `internal/agent/observe/upgrade_test.go:43` | bounded test fixture lengths (CWE-190) |
| `internal/agent/observe/upgrade_test.go:49` | bounded test fixture lengths (CWE-190) |
| `internal/agent/observe/wire_test.go:14` | big-endian packing of bounded test lengths (CWE-190) |
| `internal/agent/observe/wire_test.go:15` | big-endian packing of bounded test lengths (CWE-190) |
| `internal/agent/observe/wire_test.go:18` | test vectors are under 256 bytes (CWE-190) |
| `internal/agent/observe/wire_test.go:140` | bounded test fixture length (CWE-190) |
| `internal/agent/observe/wire_test.go:147` | bounded test fixture length (CWE-190) |
| `internal/agent/relay/adcsscan_wire_test.go:246` | this fixed fixture is 40 bytes, below MaxUint16 (CWE-190). |
| `internal/agent/relay/adcsscan_wire_test.go:258` | this fixed fixture is below MaxUint16 (CWE-190). |
| `internal/agent/sessionobserve/session.go:82` | a signed C field read back as signed (CWE-190) |
| `internal/agent/sessionobserve/session_test.go:15` | big-endian packing of bounded test lengths (CWE-190) |
| `internal/agent/sessionobserve/session_test.go:16` | big-endian packing of bounded test lengths (CWE-190) |
| `internal/agent/sessionobserve/session_test.go:19` | test vectors are under 256 bytes (CWE-190) |
| `internal/agent/sessionobserve/session_test.go:81` | test payloads are small (CWE-190) |
| `internal/agent/sessionobserve/session_test.go:83` | the C field is signed (CWE-190) |
| `internal/agent/sessionobserve/session_test.go:137` | small test offsets (CWE-190) |
| `internal/agent/sshkrl/revocations_test.go:167` | test fixture strings are a few bytes, far under the uint32 bound |
| `internal/api/application_secret_approval.go:420` | ApplicationSecretApprovalBinding just proved the version is positive (CWE-190). |
| `internal/api/machine_sessions_served_test.go:64` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/api/notifications_helpers_test.go:210` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/api/secretjson.go:173` | rune already range-checked below 0x20 before hex packing (CWE-190) |
| `internal/api/vault_compat_complete.go:815` | DER length of a public key, far under the uint32 bound (CWE-190) |
| `internal/audit/audit.go:172` | event sequence/count fits int64 by construction; bounded by the log (CWE-190) |
| `internal/auditarchive/reader.go:104` | positive count checked first (CWE-190) |
| `internal/auditarchive/reader.go:110` | bounded by the int count above (CWE-190) |
| `internal/backup/backup.go:175` | record counts bounded by the event log; fits both int and uint64 (CWE-190) |
| `internal/backup/backup.go:722` | receiptIndex starts at zero and is bounded by len(affectedOrder) above (CWE-190). |
| `internal/backup/backup.go:1005` | record counts bounded by the event log; fits both int and uint64 (CWE-190) |
| `internal/backup/postgres_state.go:331` | records starts at zero and advances only for exported rows; it cannot be negative (CWE-190) |
| `internal/ca/hierarchy/hierarchy_test.go:39` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/cli/doctor/doctor_test.go:41` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/clusterfuzz/internal_discovery_adcs_adcs/fuzz_test.go:26` | test SID inputs have at most 255 sub-authorities (CWE-190). |
| `internal/clusterfuzz/internal_discovery_adcs_adcs/fuzz_test.go:28` | ParseUint limits authority to 48 bits and this loop emits one byte at a time (CWE-190). |
| `internal/clusterfuzz/internal_discovery_adcs_adcs/fuzz_test.go:33` | deterministic test SIDs keep the object ACE below MaxUint16 (CWE-190). |
| `internal/clusterfuzz/internal_discovery_adcs_adcs/fuzz_test.go:53` | test call sites pass a bounded literal ACE set (CWE-190). |
| `internal/clusterfuzz/internal_discovery_adcs_adcs/fuzz_test.go:69` | ParseUint bounds revision to 8 bits and the test SID grammar caps sub-authorities at 255 (CWE-190). |
| `internal/clusterfuzz/internal_discovery_adcs_adcs/fuzz_test.go:71` | ParseUint bounds authority to 48 bits and this loop emits one byte at a time (CWE-190). |
| `internal/connector/wasm/host/host.go:159` | a wasm32 address, bounded by math.MaxUint32 just above (CWE-190). |
| `internal/crypto/argon2id.go:69` | length of a stored KDF hash, far under the uint32 bound (CWE-190) |
| `internal/crypto/bcfks/bcfks.go:301` | splitting a UTF-16 code unit into its two bytes (CWE-190) |
| `internal/crypto/bcfks/bcfks.go:323` | the CCM length field size L is 2..8 (CWE-190) |
| `internal/crypto/bcfks/bcfks.go:326` | one byte of a bounded block counter (CWE-190) |
| `internal/crypto/bcfks/bcfks.go:340` | flags from a bounded tag length and L (CWE-190) |
| `internal/crypto/bcfks/bcfks.go:343` | one byte of the bounded message length (CWE-190) |
| `internal/crypto/ctlog/ctlogtest/ctlogtest.go:333` | test-support package compiled only into test binaries (CWE-190) |
| `internal/crypto/ctlog/ctlogtest/ctlogtest.go:350` | test-support package compiled only into test binaries (CWE-190) |
| `internal/crypto/ctlog/ctlogtest/signing.go:184` | a positive test clock offset (CWE-190) |
| `internal/crypto/ctlog/merkle.go:58` | non-negative checked above (CWE-190) |
| `internal/crypto/ctlog/merkle.go:95` | non-negative checked above (CWE-190) |
| `internal/crypto/ctlog/sct.go:263` | RFC 6962 16-bit fields; callers bound v (CWE-190) |
| `internal/crypto/ctlog/sct.go:267` | byte extraction from a fixed-width value (CWE-190) |
| `internal/crypto/ctlog/sct.go:277` | bounded to 24 bits above (CWE-190) |
| `internal/crypto/deviceattest/cvc.go:211` | oidLen is checked to be 1..127 above (CWE-190) |
| `internal/crypto/deviceattesttest/smartcardhsm.go:167` | each value is one decimal digit (CWE-190) |
| `internal/crypto/deviceattesttest/smartcardhsm.go:173` | a CV tag is at most two bytes (CWE-190) |
| `internal/crypto/deviceattesttest/smartcardhsm.go:175` | a one-byte tag (CWE-190) |
| `internal/crypto/deviceattesttest/smartcardhsm.go:183` | a stand-in element is under 64 KiB (CWE-190) |
| `internal/crypto/mongosignin/bson.go:53` | command strings are short (CWE-190) |
| `internal/crypto/mongosignin/bson.go:63` | SASL payloads are short (CWE-190) |
| `internal/crypto/mongosignin/bson.go:74` | a BSON int32 is its two's-complement bits (CWE-190) |
| `internal/crypto/mongosignin/bson.go:77` | a BSON int64 is its two's-complement bits (CWE-190) |
| `internal/crypto/mongosignin/bson.go:81` | a command document is short (CWE-190) |
| `internal/crypto/mongosignin/bson.go:194` | a BSON int32's two's-complement bits (CWE-190) |
| `internal/crypto/mongosignin/bson.go:196` | a BSON int64's two's-complement bits (CWE-190) |
| `internal/crypto/mongosignin/mongosignin.go:389` | a message length is bounded by its reader (CWE-190) |
| `internal/crypto/mongosignin/mongosignin.go:390` | a request id is its two's-complement bits (CWE-190) |
| `internal/crypto/mongosignin/mongosignin.go:391` | a request id is its two's-complement bits (CWE-190) |
| `internal/crypto/mongosignin/mongosignin.go:392` | an op code is a small constant (CWE-190) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:135` | the 3-byte little-endian length of a payload checked above (CWE-190) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:197` | the capability flags' lower half (CWE-190) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:200` | the capability flags' upper half (CWE-190) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:470` | bounded by maxLenenc just above (CWE-190) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:483` | a one-byte length below 251 (CWE-190) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:485` | a two-byte length below 1<<16 (CWE-190) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:487` | the three bytes of a value under 1<<24 (CWE-190) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:489` | a length, never negative (CWE-190) |
| `internal/crypto/pfx/certonly.go:162` | r is at most 0xFFFF here, so its two bytes are exact (CWE-190) |
| `internal/crypto/pfx/certonly.go:174` | id is the KDF purpose, 1 to 3 (CWE-190) |
| `internal/crypto/pfx/certonly.go:210` | RFC 7292 B.2 adds modulo 2^(8v): keeping the low byte and carrying is the algorithm (CWE-190) |
| `internal/crypto/pfx/certonly.go:372` | pad is at most the block size (CWE-190) |
| `internal/crypto/pfx/rc2.go:55` | 255 modulo a power of two up to 256 fits a byte (CWE-190) |
| `internal/crypto/pgsignin/pgsignin.go:149` | a startup message is a few hundred bytes (CWE-190) |
| `internal/crypto/pgsignin/pgsignin.go:349` | a SCRAM client-first message is under 100 bytes (CWE-190) |
| `internal/crypto/pgsignin/pgsignin.go:407` | sign-in messages are bounded and small (CWE-190) |
| `internal/crypto/pgsignin/pgsignin_test.go:101` | a fake server's messages are a few bytes (CWE-190) |
| `internal/crypto/quicinitial/quicinitial.go:97` | the token length was checked against the datagram above (CWE-190) |
| `internal/crypto/quicinitial/quicinitial.go:107` | the length was checked against the datagram above (CWE-190) |
| `internal/crypto/quicinitial/quicinitial.go:111` | the length was checked against the datagram above (CWE-190) |
| `internal/crypto/quicinitial/quicinitial.go:158` | one byte of the packet number (CWE-190) |
| `internal/crypto/quicinitial/quicinitial.go:203` | a key length of at most 32 bytes (CWE-190) |
| `internal/crypto/quicinitial/quicinitial.go:204` | a label of under 32 bytes (CWE-190) |
| `internal/crypto/rdp/desktop.go:241` | len(text) is at most MaxClipboard (CWE-190) |
| `internal/crypto/seal/generation.go:168` | bounded to maxUint16Value by the guard above (CWE-190) |
| `internal/crypto/seal/seal.go:118` | slice lengths cannot exceed uint64. |
| `internal/crypto/seal/seal.go:121` | slice lengths cannot exceed uint64. |
| `internal/crypto/seal/seal.go:225` | bounded to maxUint16Value by the check above (CWE-190) |
| `internal/crypto/seal/seal.go:575` | validateDomain above caps the length at maxUint16Value (CWE-190) |
| `internal/crypto/seal/seal.go:576` | bounded to maxUint16Value by the guard above (CWE-190) |
| `internal/crypto/signauth.go:66` | enum purpose and bounded message length framing (CWE-190) |
| `internal/crypto/signauth.go:76` | enum purpose and bounded message length framing (CWE-190) |
| `internal/crypto/ssh.go:73` | certificate validity epoch seconds; non-negative by validation (CWE-190) |
| `internal/crypto/ssh.go:74` | certificate validity epoch seconds; non-negative by validation (CWE-190) |
| `internal/crypto/sshgateway/guard_test.go:18` | bounded by MaxExecCommandBytes (CWE-190) |
| `internal/crypto/sshgateway/sshgateway.go:96` | an OpenSSH certificate's valid-before is a Unix time (CWE-190) |
| `internal/crypto/sshgateway/sshgateway_test.go:115` | present-day Unix times are positive (CWE-190) |
| `internal/crypto/sshkeys/certificate.go:112` | clamped to maxCertificateUnix above (CWE-190) |
| `internal/crypto/sshkeys/property_test.go:37` | generator bounds the value to 0..2 (CWE-190) |
| `internal/crypto/sshkeys/property_test.go:40` | generator bounds the value to 0..3 (CWE-190) |
| `internal/crypto/sshkeys/property_test.go:114` | generator bounds the value to one byte (CWE-190) |
| `internal/crypto/sshkeys/property_test.go:117` | generator bounds the value to 0..2 (CWE-190) |
| `internal/crypto/tenantwrap/tenantwrap.go:238` | fixed-format buffer: a wrapped domain KEK has a fixed sealed length; an impossible oversize panics the slice bounds rather than truncating (CWE-190) |
| `internal/crypto/weakkey/ec.go:208` | the baby-step index is below 2^16, so it fits a uint32 (CWE-190) |
| `internal/crypto/weakkey/weakkey.go:398` | the sieve index is below 2^16, so it fits a uint64 (CWE-190) |
| `internal/decommission/reprotect/completion_durable_test.go:37` | port was checked against the uint16 maximum above. |
| `internal/decommission/store/projection.go:180` | rejected values above MaxInt64 immediately above. |
| `internal/discovery/adcs/acl.go:106` | the offset is uint32-derived and bounded against len(raw) above (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:205` | the fixed malformed fixture is below MaxUint16 (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:232` | test SID inputs have at most 255 sub-authorities (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:234` | ParseUint limits authority to 48 bits and this loop emits one byte at a time (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:247` | deterministic test SIDs keep the ACE below MaxUint16 (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:256` | deterministic test SIDs keep the object ACE below MaxUint16 (CWE-190). |
| `internal/discovery/adcs/adcs_test.go:276` | test call sites pass a bounded literal ACE set (CWE-190). |
| `internal/discovery/adcs/membership.go:287` | the signed LDAP groupType bitfield is range-checked as signed/unsigned 32-bit above (CWE-190). |
| `internal/discovery/adcs/membership.go:357` | the checked 3..18 field count makes this 0..15 (CWE-190). |
| `internal/discovery/adcs/membership.go:368` | ParseUint's 32-bit bound proves the conversion (CWE-190). |
| `internal/dns/rfc2136/rfc2136.go:246` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:263` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:293` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:308` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:309` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:323` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:348` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dns/rfc2136/rfc2136.go:352` | DNS wire encoding of protocol-bounded fields (labels <=63, RDATA <=uint16) (CWE-190) |
| `internal/dynsecret/active_directory_reset_native_lab_test.go:305` | preparation is checked at <=64KiB before conversion (CWE-190) |
| `internal/dynsecret/active_directory_reset_native_lab_test.go:306` | predecessor is checked at <=1024 bytes before conversion (CWE-190) |
| `internal/dynsecret/drivers.go:321` | SQL Server TDS prelogin framing of short bounded fields (CWE-190) |
| `internal/dynsecret/drivers.go:329` | SQL Server TDS prelogin framing of short bounded fields (CWE-190) |
| `internal/dynsecret/providers_real_test.go:688` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/dynsecret/totp.go:127` | step = now / period with now checked non-negative above (CWE-190) |
| `internal/dynsecret/totp.go:161` | s is checked non-negative above (CWE-190) |
| `internal/dynsecret/totp_verify_test.go:37` | a positive clock step in a test (CWE-190) |
| `internal/events/backup_history_test.go:227` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/events/backup_restore_floor_test.go:598` | tiny fixed test sequence |
| `internal/events/event_id_index_test.go:149` | the fixture index is bounded to one or two. |
| `internal/historycontinuity/continuity_test.go:203` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/idemgc/idemgc_test.go:35` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/awskms/awskms_test.go:84` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/pkcs11/pkcs11_test.go:44` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/tpm/tpm_test.go:60` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/tpm/tpm_test.go:94` | deliberate byte packing of a bounded TPM handle in a test helper (CWE-190) |
| `internal/kms/tpm/tpm_test.go:95` | deliberate byte packing of a bounded TPM handle in a test helper (CWE-190) |
| `internal/kms/tpm/tpm_test.go:96` | deliberate byte packing of a bounded TPM handle in a test helper (CWE-190) |
| `internal/kms/tpm/tpm_test.go:245` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/kms/wrapadapter/adapter.go:328` | bounded by the check above (CWE-190) |
| `internal/leader/leader_test.go:36` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/mdm/challenge/challenge.go:79` | unix-epoch seconds round-trip; in int64 range until year 292e9 (CWE-190) |
| `internal/mdm/challenge/challenge.go:90` | unix-epoch seconds round-trip; in int64 range until year 292e9 (CWE-190) |
| `internal/mdm/challenge/dynamic.go:80` | unix-epoch seconds; in int64 range until year 292e9 (CWE-190) |
| `internal/mdm/challenge/dynamic.go:117` | unix-epoch seconds round-trip (CWE-190) |
| `internal/netsec/relay_egress.go:157` | LookupPort returned 0-65535, checked above (CWE-190) |
| `internal/objectstore/s3.go:405` | page is at most listPageSize (CWE-190) |
| `internal/objectstore/s3.go:487` | limit is at most listPageSize (CWE-190) |
| `internal/observ/trace.go:228` | deliberate byte packing of a trace id (CWE-190) |
| `internal/orchestrator/discovery.go:367` | retained sequence was checked against MaxInt64 before conversion. |
| `internal/orchestrator/main_test.go:74` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/orchestrator/operation_approvals.go:440` | a tombstone version is positive (CHECK version > 0) (CWE-190). |
| `internal/orchestrator/operation_approvals.go:450` | a negative stored version is classified as drift before conversion (CWE-190). |
| `internal/orchestrator/secret_rotation.go:574` | the positive int64 value always fits exactly in uint64 (CWE-190). |
| `internal/orchestrator/tenant_registration_test.go:242` | bounded test sequence. |
| `internal/orchestrator/tenant_registration_test.go:323` | test event sequence is PostgreSQL bigint-bounded. |
| `internal/outboxgc/outboxgc_test.go:37` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/perf/live.go:935` | page size is positive and small (CWE-190) |
| `internal/pqcmigration/cutover.go:198` | bounded above (CWE-190) |
| `internal/projections/application_secret_rebuild_test.go:50` | the binding validator proved this fixture version is positive (CWE-190). |
| `internal/projections/application_secret_rebuild_test.go:76` | the binding validator proved this fixture version is positive (CWE-190). |
| `internal/projections/aud64_test.go:43` | every generated fixture sequence is a positive small integer (CWE-190). |
| `internal/projections/certificate_sct.go:88` | a log timestamp in milliseconds fits int64 (CWE-190) |
| `internal/projections/discovery_declaration_convergence_test.go:432` | migration 0199 constrains the sequence to non-negative bigint values |
| `internal/projections/full_dr_test.go:634` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/projections/projections.go:7566` | checked against MaxInt64 above. |
| `internal/projections/projections.go:7583` | sequence was checked against MaxInt64 before conversion. |
| `internal/projections/projections.go:7596` | checked against MaxInt64 above. |
| `internal/projections/projections.go:7630` | event log sequences are stored as PostgreSQL bigint throughout the projection spine (CWE-190) |
| `internal/projections/projections_test.go:45` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/projections/secret_integrations.go:241` | the explicit bound above proves this event sequence fits PostgreSQL bigint. |
| `internal/projections/secret_integrations.go:248` | the explicit bound above proves this event sequence fits PostgreSQL bigint. |
| `internal/projections/secret_integrations_test.go:659` | embedded JetStream fixture sequences are bounded far below MaxInt64 (CWE-190). |
| `internal/projections/secret_integrations_test.go:812` | fixture sequence is tiny and asserted positive above. |
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
| `internal/protocols/ssh/krl_binary_test.go:29` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/protocols/ssh/ssh.go:519` | SSH wire string length, far under the uint32 bound for certificate fields (CWE-190) |
| `internal/query/adversarial_test.go:51` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/reconcile/stepcasource_test.go:50` | a TCP port from the kernel (CWE-190) |
| `internal/scancollect/cilogs.go:187` | bounded by the archive's own size check below (CWE-190) |
| `internal/secretmigrate/assess.go:354` | bounded by MaxValueBytes (CWE-190) |
| `internal/server/agentchannel_served_test.go:837` | fixture sequences are single-digit seconds (CWE-190). |
| `internal/server/aud65_test.go:37` | fixture sequences are single-digit seconds (CWE-190). |
| `internal/server/audit_archive_download_served_test.go:55` | a test fixture count (CWE-190) |
| `internal/server/backup.go:223` | record counts bounded by the event log (CWE-190) |
| `internal/server/backup.go:390` | record counts bounded by the event log (CWE-190) |
| `internal/server/bundled_pg.go:95` | cfg.Port is checked above and the zero default is 5432 (CWE-190) |
| `internal/server/crypto_risk_report_served_test.go:58` | fixture sequences are single-digit seconds (CWE-190). |
| `internal/server/ct_inclusion.go:162` | a log timestamp after 1970 (CWE-190) |
| `internal/server/ct_inclusion.go:168` | a log timestamp in milliseconds fits int64 (CWE-190) |
| `internal/server/ct_inclusion.go:175` | a log's tree fits int64 (CWE-190) |
| `internal/server/ct_submission.go:449` | positive checked above (CWE-190) |
| `internal/server/managedkeys_pkcs11_served_test.go:47` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/pam_breakglass_served_test.go:180` | a positive clock step in a test (CWE-190) |
| `internal/server/pam_browser.go:337` | offsets within the ring, at most 1 MiB apart (CWE-190) |
| `internal/server/pam_browser_console.go:459` | an opcode's two's-complement bits (CWE-190) |
| `internal/server/pam_browser_console.go:466` | a request id's two's-complement bits (CWE-190) |
| `internal/server/pam_browser_kube.go:185` | a 7-bit length below 126 (CWE-190) |
| `internal/server/pam_browser_kube.go:188` | a 16-bit length under 1<<16 (CWE-190) |
| `internal/server/pam_browser_kube.go:191` | a payload length, never negative (CWE-190) |
| `internal/server/pam_browser_kube_test.go:40` | test frame length below 126 (CWE-190) |
| `internal/server/pam_browser_kube_test.go:43` | test frame length under 1<<16 (CWE-190) |
| `internal/server/pam_browser_kube_test.go:46` | test frame length, never negative (CWE-190) |
| `internal/server/pam_gateway_mongo_served_test.go:106` | a request id's two's-complement bits (CWE-190) |
| `internal/server/pam_gateway_private_ca_served_test.go:71` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/pam_health.go:94` | a positive interval in nanoseconds, never negative (CWE-190) |
| `internal/server/pam_served_test.go:731` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/protocol_mounts.go:1035` | DER lengths of certificates/keys are orders of magnitude under the uint32 bound (CWE-190) |
| `internal/server/protocol_mounts.go:1037` | DER lengths of certificates/keys are orders of magnitude under the uint32 bound (CWE-190) |
| `internal/server/recovery_projection_factory_test.go:173` | event test sequence is PostgreSQL bigint-bounded. |
| `internal/server/revocation.go:446` | value reduced modulo the shard count before conversion (CWE-190) |
| `internal/server/run.go:255` | bounded small ints from config (CWE-190) |
| `internal/server/secret_integrations_outbox.go:1149` | positive int64 is exactly representable as uint64. |
| `internal/server/secret_integrations_outbox.go:1153` | positive int64 is exactly representable as uint64. |
| `internal/server/secret_sync_source_sequence_test.go:56` | this fixture appends exactly two events. |
| `internal/server/secret_sync_source_sequence_test.go:67` | this fixture appends exactly two events. |
| `internal/server/secret_sync_source_sequence_test.go:72` | this fixture appends exactly two events. |
| `internal/server/secrets_rotation_served_test.go:2589` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/server/totp_seed_replace_served_test.go:72` | a positive clock step in a test (CWE-190) |
| `internal/signing/keystore.go:117` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:119` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:121` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:123` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/signing/keystore.go:133` | enum values and set sizes documented bounded <256 in the framing header (CWE-190) |
| `internal/slackapp/socket.go:207` | bounded by maxSocketMessage above (CWE-190) |
| `internal/slackapp/socket.go:231` | n <= 0xFFFF here (CWE-190) |
| `internal/slackapp/socket.go:234` | a length is non-negative (CWE-190) |
| `internal/store/access_bundle_standing_approvals.go:144` | positive by constraint (CWE-190) |
| `internal/store/access_bundles.go:142` | bounded above (CWE-190) |
| `internal/store/acme_dns01.go:292` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/acme_dns01.go:337` | non-negative by construction (CWE-190) |
| `internal/store/acme_upstream_ari.go:312` | JetStream sequence is bounded by PostgreSQL bigint (CWE-190) |
| `internal/store/acme_upstream_ari.go:361` | JetStream sequence is bounded by PostgreSQL bigint (CWE-190) |
| `internal/store/acme_upstream_ari.go:388` | DB CHECK keeps event_sequence positive (CWE-190) |
| `internal/store/adcs_decisions.go:46` | bounded above (CWE-190) |
| `internal/store/adcs_pending_requests.go:54` | bounded above (CWE-190) |
| `internal/store/application_secret_approval_test.go:49` | the binding validator proved this fixture version is positive (CWE-190). |
| `internal/store/archive_legal_hold.go:90` | event sequences fit int64 (CWE-190) |
| `internal/store/archive_legal_hold.go:124` | event sequences fit int64 (CWE-190) |
| `internal/store/archive_legal_hold.go:145` | event sequences fit int64 (CWE-190) |
| `internal/store/archive_legal_hold.go:149` | event sequences fit int64 (CWE-190) |
| `internal/store/archive_legal_hold.go:153` | event sequences fit int64 (CWE-190) |
| `internal/store/archive_legal_hold.go:192` | positive by constraint (CWE-190) |
| `internal/store/assurance_evidence.go:248` | non-negative by construction (CWE-190) |
| `internal/store/audit_anchor.go:47` | tenant-local audit ordinal fits a Postgres bigint (CWE-190) |
| `internal/store/audit_anchor.go:49` | event-log sequence fits a Postgres bigint (CWE-190) |
| `internal/store/audit_anchor.go:96` | the table CHECKs keep both positive (CWE-190) |
| `internal/store/audit_checkpoint.go:52` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/audit_checkpoint.go:86` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/audit_checkpoint.go:116` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/audit_feed.go:426` | PostgreSQL bigint event sequence is non-negative by schema (CWE-190) |
| `internal/store/audit_feed.go:427` | PostgreSQL bigint tenant sequence is non-negative by schema (CWE-190) |
| `internal/store/audit_feed.go:428` | PostgreSQL bigint tenant sequence is non-negative by schema (CWE-190) |
| `internal/store/audit_feed.go:429` | PostgreSQL bigint tenant sequence is non-negative by schema (CWE-190) |
| `internal/store/audit_feed.go:442` | positive PostgreSQL bigint by schema (CWE-190) |
| `internal/store/audit_feed.go:443` | positive PostgreSQL bigint by schema (CWE-190) |
| `internal/store/audit_retention_scope.go:22` | PostgreSQL advisory keys are signed bit patterns. |
| `internal/store/aws_honey_trail.go:76` | bounded above (CWE-190) |
| `internal/store/breakglass_authority_receipt.go:36` | MaxInt64 checked above. |
| `internal/store/breakglass_authority_receipt.go:85` | MaxInt64 checked above. |
| `internal/store/breakglass_authority_receipt.go:128` | MaxInt64 checked above. |
| `internal/store/breakglass_issue_receipt.go:35` | the explicit MaxInt64 bound above prevents narrowing (CWE-190). |
| `internal/store/breakglass_issue_receipt.go:93` | MaxInt64 bound above rejects narrowing (CWE-190). |
| `internal/store/breakglass_issue_receipt.go:136` | MaxInt64 bound above rejects narrowing (CWE-190). |
| `internal/store/ca.go:557` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/ca.go:637` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/ca_rollover_draft.go:45` | event sequences fit int64 (CWE-190) |
| `internal/store/ca_rollover_draft.go:68` | positive by constraint (CWE-190) |
| `internal/store/ca_upstream_standing_approval.go:52` | event sequences fit int64 (CWE-190) |
| `internal/store/ca_upstream_standing_approval.go:64` | event sequences fit int64 (CWE-190) |
| `internal/store/ca_upstream_standing_approval.go:77` | event sequences fit int64 (CWE-190) |
| `internal/store/ca_upstream_standing_approval.go:94` | non-negative by constraint (CWE-190) |
| `internal/store/certificate_der_recovery.go:54` | event sequences fit int64 (CWE-190) |
| `internal/store/certificate_der_recovery.go:68` | positive by constraint (CWE-190) |
| `internal/store/certificate_reprotection_recovery.go:32` | MaxInt64 bound above rejects narrowing (CWE-190). |
| `internal/store/certificate_sct.go:63` | positive by constraint (CWE-190) |
| `internal/store/certificate_sct.go:91` | event sequences fit int64 (CWE-190) |
| `internal/store/certificate_sct.go:104` | event sequences fit int64 (CWE-190) |
| `internal/store/code_signing_key_certificate.go:44` | bounded above (CWE-190) |
| `internal/store/code_signing_transparency.go:51` | bounded above (CWE-190) |
| `internal/store/compliance_report_retention.go:62` | event sequences fit int64 (CWE-190) |
| `internal/store/compliance_report_retention.go:69` | event sequences fit int64 (CWE-190) |
| `internal/store/compliance_report_retention.go:93` | event sequences fit int64 (CWE-190) |
| `internal/store/compliance_report_retention.go:176` | event sequences fit int64 (CWE-190) |
| `internal/store/compliance_report_retention.go:196` | event sequences fit int64 (CWE-190) |
| `internal/store/compliance_report_retention.go:210` | non-negative by constraint (CWE-190) |
| `internal/store/compliance_report_run.go:294` | non-negative by constraint (CWE-190) |
| `internal/store/compliance_report_run.go:312` | event sequence is a positive PostgreSQL bigint. |
| `internal/store/compliance_report_run_lock.go:33` | advisory-lock keys intentionally use all 64 hash bits, including the sign bit. |
| `internal/store/connector_lifecycle.go:468` | JetStream sequence fits PostgreSQL bigint by construction (CWE-190) |
| `internal/store/connector_lifecycle.go:522` | constrained positive PostgreSQL bigint (CWE-190) |
| `internal/store/connector_lifecycle.go:525` | constrained positive PostgreSQL bigint (CWE-190) |
| `internal/store/credential_usage.go:78` | bounded to int64 above (CWE-190) |
| `internal/store/cryptoasset_migration_test.go:73` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/store/deployment_kek_domain.go:153` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/deployment_kek_domain.go:188` | the column holds a non-negative event sequence (CWE-190) |
| `internal/store/discovery.go:205` | JetStream event sequences are stored in PostgreSQL bigint throughout the projection spine (CWE-190) |
| `internal/store/discovery.go:255` | the migration constrains this PostgreSQL bigint to non-negative values (CWE-190) |
| `internal/store/discovery_coverage.go:37` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/discovery_coverage.go:57` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/discovery_coverage.go:81` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/discovery_secret_move.go:103` | bounded to int64 above (CWE-190) |
| `internal/store/discovery_secret_move.go:118` | bounded to int64 above (CWE-190) |
| `internal/store/discovery_segments.go:74` | JetStream event sequences are stored in PostgreSQL bigint throughout the projection spine (CWE-190) |
| `internal/store/discovery_segments.go:107` | the migration constrains this PostgreSQL bigint to non-negative values (CWE-190) |
| `internal/store/discovery_segments.go:138` | the migration constrains this PostgreSQL bigint to non-negative values (CWE-190) |
| `internal/store/discovery_segments.go:199` | the migration constrains this PostgreSQL bigint to non-negative values (CWE-190) |
| `internal/store/dynamic_secret_lease_access.go:171` | bounded to int64 above (CWE-190) |
| `internal/store/endpoint_recovery_check.go:53` | event sequences fit int64 (CWE-190) |
| `internal/store/endpoint_recovery_check.go:85` | event sequences fit int64 (CWE-190) |
| `internal/store/endpoint_recovery_check.go:102` | positive by constraint (CWE-190) |
| `internal/store/endpoint_recovery_check.go:103` | positive by constraint (CWE-190) |
| `internal/store/endpoint_recovery_check.go:146` | a projected event sequence (CWE-190) |
| `internal/store/endpoint_verification.go:172` | event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/endpoint_verification.go:219` | non-negative by construction (CWE-190) |
| `internal/store/endpoint_verification.go:263` | constrained positive database sequence (CWE-190) |
| `internal/store/enrollment_diagnostics.go:95` | JetStream sequence fits positive bigint (CWE-190) |
| `internal/store/enrollment_diagnostics.go:234` | JetStream/PostgreSQL sequences share the signed-bigint storage bound (CWE-190) |
| `internal/store/enrollment_diagnostics.go:275` | JetStream/PostgreSQL sequences share the signed-bigint storage bound (CWE-190) |
| `internal/store/enrollment_diagnostics.go:372` | constrained positive bigint written from a JetStream sequence (CWE-190) |
| `internal/store/external_ca_held.go:52` | bounded above (CWE-190) |
| `internal/store/external_observation.go:83` | event sequences fit int64 (CWE-190) |
| `internal/store/external_observation.go:101` | event sequences fit int64 (CWE-190) |
| `internal/store/external_observation.go:112` | non-negative by constraint (CWE-190) |
| `internal/store/external_observation.go:159` | non-negative by constraint (CWE-190) |
| `internal/store/factory_batches.go:59` | bounded above (CWE-190) |
| `internal/store/federation.go:58` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/incident_closures.go:39` | bounded above (CWE-190) |
| `internal/store/key_compromise_retry.go:25` | bounded above by the MaxInt64 check; the column is a Postgres bigint (CWE-190) |
| `internal/store/key_vault_disables.go:44` | bounded above (CWE-190) |
| `internal/store/listener_sessions.go:45` | bounded by MaxInt64 above. |
| `internal/store/mdm_check_ins.go:45` | bounded above (CWE-190) |
| `internal/store/migration_run.go:52` | JetStream/PostgreSQL event sequence is bounded by bigint (CWE-190) |
| `internal/store/migration_run.go:221` | positive bigint constrained by migration (CWE-190) |
| `internal/store/migration_run.go:245` | positive bigint constrained by migration (CWE-190) |
| `internal/store/migration_run.go:278` | positive bigint constrained by migration (CWE-190) |
| `internal/store/offboard_test.go:45` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `internal/store/operation_approvals.go:298` | the explicit MaxInt64 bound above prevents narrowing (CWE-190). |
| `internal/store/outbox_reconciliation_checkpoint.go:34` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/outbox_reconciliation_conflicts.go:76` | JetStream sequence fits PostgreSQL bigint by construction (CWE-190). |
| `internal/store/ownership_assignment.go:65` | event sequences fit PostgreSQL bigint |
| `internal/store/ownership_readiness.go:205` | event sequences fit PostgreSQL bigint |
| `internal/store/ownership_readiness.go:226` | event sequences fit PostgreSQL bigint |
| `internal/store/ownership_readiness.go:254` | persisted event sequences fit PostgreSQL bigint |
| `internal/store/ownership_readiness.go:312` | database constraint/event writer keeps sequence non-negative |
| `internal/store/pam.go:136` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:740` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:820` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:1076` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection.go:1090` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:191` | event sequence fits the PostgreSQL bigint used by the event log (CWE-190) |
| `internal/store/projection_checkpoint.go:247` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:276` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:331` | log sequence fits PostgreSQL bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:340` | log sequence fits PostgreSQL bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:362` | log sequence fits PostgreSQL bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:369` | log sequence fits PostgreSQL bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:392` | log sequence fits PostgreSQL bigint (CWE-190) |
| `internal/store/projection_checkpoint.go:399` | log sequence fits PostgreSQL bigint (CWE-190) |
| `internal/store/provider_billing_sync.go:75` | bounded by the check above (CWE-190) |
| `internal/store/provider_doc_records.go:56` | bounded by the check above (CWE-190) |
| `internal/store/provider_psa_tickets.go:82` | bounded by the check above (CWE-190) |
| `internal/store/provider_rmm_devices.go:76` | bounded by the check above (CWE-190) |
| `internal/store/rehearsals.go:64` | bounded above (CWE-190) |
| `internal/store/scanned_certificate_chain.go:23` | event sequences fit int64 (CWE-190) |
| `internal/store/secret_projects.go:74` | bounded to int64 above (CWE-190) |
| `internal/store/secret_rotation_schedule.go:257` | checked against MaxInt64 above (CWE-190). |
| `internal/store/secret_rotation_schedule.go:270` | checked against MaxInt64 above (CWE-190). |
| `internal/store/secret_rotation_schedule.go:297` | checked against MaxInt64 above (CWE-190). |
| `internal/store/secret_rotation_schedule.go:310` | checked against MaxInt64 above (CWE-190). |
| `internal/store/secret_rotation_schedule.go:406` | validateBoundSecretRotationScheduleRun rejects values above MaxInt64 (CWE-190). |
| `internal/store/secret_rotation_schedule.go:430` | validateBoundSecretRotationScheduleRun rejects values above MaxInt64 (CWE-190). |
| `internal/store/slack_app.go:52` | bounded above (CWE-190) |
| `internal/store/snapshot.go:943` | the projection sequence is stored in a PostgreSQL bigint throughout this file (CWE-190) |
| `internal/store/snapshot.go:963` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/spiffe_upstream_jwt_key.go:49` | event sequences fit int64 (CWE-190) |
| `internal/store/spiffe_upstream_jwt_key.go:64` | event sequences fit int64 (CWE-190) |
| `internal/store/spiffe_upstream_jwt_key.go:79` | non-negative by constraint (CWE-190) |
| `internal/store/ssh_certificate_revocation.go:28` | bounded by MaxInt64 above. |
| `internal/store/switching_imports.go:117` | bounded above (CWE-190) |
| `internal/store/tenant.go:63` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tenant.go:81` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tenant_custom_role.go:41` | event sequences fit int64 (CWE-190) |
| `internal/store/tenant_custom_role.go:54` | event sequences fit int64 (CWE-190) |
| `internal/store/tenant_custom_role.go:66` | positive by constraint (CWE-190) |
| `internal/store/tenant_key_domain.go:168` | event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190) |
| `internal/store/tsa_certificate.go:41` | event-log sequence fits a Postgres bigint (CWE-190) |
| `internal/store/tsa_certificate.go:76` | the table CHECK keeps it positive (CWE-190) |
| `internal/store/upsert_arbiter_race_test.go:94` | small fixture counters (CWE-190) |
| `internal/store/upsert_arbiter_race_test.go:105` | small fixture counter (CWE-190) |
| `internal/store/upsert_arbiter_race_test.go:220` | small fixture counter (CWE-190) |
| `internal/store/workload_jwt_keys.go:36` | bounded to int64 above (CWE-190) |
| `internal/succession/background/workers_retirement_legacy_test.go:80` | TCP port was checked against [0, 65535] above. |
| `internal/succession/conformance/int20_fullstack_test.go:490` | source sequence was checked against MaxInt64 above (CWE-190). |
| `internal/tenantseal/deployment_keyring.go:217` | a generation is a small positive counter checked by the table (CWE-190) |
| `internal/tenantseal/idempotency.go:96` | length framing of short bounded fields (CWE-190) |
| `internal/tsa/fuzz_test.go:133` | crafted DER length byte for fuzz corpus; truncation is the crafted input (CWE-190) |
| `internal/tsa/fuzz_test.go:135` | crafted DER length byte for fuzz corpus (CWE-190) |
| `internal/tsa/fuzz_test.go:137` | crafted DER length bytes for fuzz corpus (CWE-190) |
| `scripts/perf/cmd/capacitycalibrate/main.go:217` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:244` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:245` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:343` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/soakcapture/main.go:423` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:479` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:675` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:676` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `scripts/perf/cmd/spineburst/main.go:700` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:497` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1252` | bounded process identity comparison (CWE-190) |
| `tools/dodcensus/proof/launched.go:1284` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1385` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1850` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:1887` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:2087` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:2091` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/proof/launched.go:2741` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:193` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:199` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:205` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:212` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:227` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:239` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:248` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/runtime_runner_test.go:258` | bounded fixture/corpus value packing inside a test (CWE-190) |
| `tools/dodcensus/substrate_broker.go:409` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/substrate_broker.go:433` | bounded value packing in a developer tool, not a served binary (CWE-190) |
| `tools/dodcensus/substrate_broker.go:463` | bounded value packing in a developer tool, not a served binary (CWE-190) |

### G117 — CWE-200 Exposure of sensitive information (marshaled secret field) (72 sites)

| Location | Reason |
|---|---|
| `internal/agent/accessgateway/azure_test.go:25` | owned provider-envelope fixture; locked on parse and scratch wiped (CWE-200) |
| `internal/agent/accessgateway/console.go:85` | native federation Session grant; scratch wiped and request serialized from locked bytes (CWE-200) |
| `internal/agent/accessgateway/console_test.go:24` | owned STS-envelope fixture; parsed into locked bytes and scratch wiped (CWE-200) |
| `internal/agent/accessgateway/gcp_test.go:35` | owned provider-envelope fixture; private bytes are locked on parse and scratch is wiped (CWE-200) |
| `internal/agent/accessgateway/gcp_test.go:166` | owned provider-envelope fixture; private bytes are locked on parse and scratch is wiped (CWE-200) |
| `internal/dynsecret/active_directory.go:123` | byte-backed rotated credential is sealed by the existing outbox rotation worker (CWE-200) |
| `internal/dynsecret/active_directory_prepared_json.go:107` | all three secret generations are cleared before marshaling public metadata (CWE-200) |
| `internal/dynsecret/active_directory_prepared_test.go:17` | synthetic byte-backed parser fixture, wiped and never logged (CWE-200) |
| `internal/dynsecret/active_directory_prepared_test.go:31` | synthetic rejected credential fixture, wiped and never logged (CWE-200) |
| `internal/dynsecret/active_directory_prepared_test.go:59` | synthetic byte-backed fuzz/parser seed, never logged (CWE-200) |
| `internal/dynsecret/active_directory_prepared_test.go:75` | synthetic byte-backed fuzz/parser seed, never logged (CWE-200) |
| `internal/dynsecret/active_directory_restore_test.go:41` | byte-backed synthetic credential DTO exercises rejected native recovery; never logged or persisted (CWE-200) |
| `internal/dynsecret/auth0.go:108` | the rotated client secret is this provider's output: the outbox seals it and only the secret's readers open it (CWE-200) |
| `internal/dynsecret/auth0.go:193` | client credentials go to the tenant's token endpoint over the guarded client and are not kept (CWE-200) |
| `internal/dynsecret/aws_cache_users.go:170` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/aws_cache_users.go:201` | the new user's password goes to the MemoryDB API over the guarded client and is not kept (CWE-200) |
| `internal/dynsecret/aws_honeytoken.go:165` | one-time decoy reveal; caller seals or writes and wipes this []byte (CWE-200) |
| `internal/dynsecret/aws_sts.go:203` | this is the reveal-once AWS STS credential payload; the caller seals it before storage (CWE-200) |
| `internal/dynsecret/cassandra.go:179` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/clickhouse.go:131` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/client_secrets.go:183` | the new secret is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/cloudflare.go:127` | the new token is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/convex.go:50` | the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/couchbase.go:145` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/datadog.go:179` | the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/dbt.go:57` | the new token is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/elasticsearch.go:187` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/esxi.go:110` | the rotated host credential; the rotation seals it before storage (CWE-200) |
| `internal/dynsecret/fireworks.go:56` | the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/github_app.go:228` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/hana.go:186` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/ibm_api_connect.go:152` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/ibm_api_connect.go:202` | the platform credentials go to the token endpoint over the guarded client and are not kept (CWE-200) |
| `internal/dynsecret/idp_admin.go:172` | the rotated administrator credential; the rotation seals it before storage (CWE-200) |
| `internal/dynsecret/kafka.go:339` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/ldap.go:329` | the reveal-once LDAP lease credential; the caller seals it before storage (CWE-200) |
| `internal/dynsecret/ldap.go:359` | the staged two-user credential; the rotation seals it before storage (CWE-200) |
| `internal/dynsecret/litellm.go:40` | the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/milvus.go:126` | the new user's password goes to the Milvus API over the guarded client and is not kept (CWE-200) |
| `internal/dynsecret/milvus.go:138` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/mongodb_atlas.go:155` | the new user's password goes to the Atlas Admin API over the guarded client and is not kept (CWE-200) |
| `internal/dynsecret/mongodb_atlas.go:184` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/mssql.go:266` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/mssql.go:321` | the staged credential is this provider's output: the outbox seals it and only an authorized read opens it (CWE-200) |
| `internal/dynsecret/network_api.go:137` | the rotated device credential; the rotation seals it before storage (CWE-200) |
| `internal/dynsecret/network_device.go:125` | the rotated device credential; the rotation seals it before storage (CWE-200) |
| `internal/dynsecret/oauth_client_credentials.go:206` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/openai.go:125` | the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/openrouter.go:59` | the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/oracle.go:262` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/providers_real.go:1637` | the dynamic-secret provider's minted credential payload; returning it is the API (CWE-200) |
| `internal/dynsecret/rabbitmq.go:150` | the new user's password goes to the management API over the guarded client and is not kept (CWE-200) |
| `internal/dynsecret/rabbitmq.go:177` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/redfish.go:104` | the rotated controller credential; the rotation seals it before storage (CWE-200) |
| `internal/dynsecret/snowflake.go:221` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/snowflake_keypair.go:94` | the rotated key pair is this provider's output: the rotation seals it before storage (CWE-200) |
| `internal/dynsecret/supabase.go:53` | the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200) |
| `internal/dynsecret/tailscale.go:155` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/dynsecret/unix_accounts.go:143` | the rotated local-account credential; the rotation seals it before storage (CWE-200) |
| `internal/dynsecret/vcenter_sso.go:133` | the rotated SSO credential; the rotation seals it before storage (CWE-200) |
| `internal/server/dynamic_secret_oracle_lab_test.go:276` | the lab's own initial password, seeded into the test tenant's secret store (CWE-200) |
| `internal/server/pam_breakglass.go:187` | the one-time break-glass release the responder asked for; returned as wiped bytes, never stored (CWE-200) |
| `internal/server/pam_desktop_served_test.go:192` | byte-backed fixture credential goes only to the encrypted secret store and private native pipe (CWE-200) |
| `internal/server/pam_gateway_aws_console_standin_test.go:122` | native federation protocol returns its owned issued sign-in token (CWE-200) |
| `internal/server/pam_gateway_azure_standin_test.go:110` | owned Graph addPassword protocol fixture; secret response bytes are wiped and held locked (CWE-200) |
| `internal/server/pam_gateway_azure_standin_test.go:182` | owned OAuth endpoint returns issued tokens; locked storage and wipeable JSON bytes (CWE-200) |
| `internal/server/pam_gateway_gcp_standin_test.go:186` | the owned OAuth endpoint must return its issued token; locked storage and wipeable JSON bytes (CWE-200) |
| `internal/server/secret_integrations_outbox.go:632` | the result is sealed by DoAtMostOnceEffect and plaintext is wiped after issue (CWE-200) |
| `internal/server/service_account_ad_rollback_served_test.go:179` | byte-backed owned bootstrap sent to the existing sealed-vault API; not logged (CWE-200) |
| `internal/server/service_account_ad_rollback_served_test.go:259` | synthetic byte-backed Unicode predecessor in the owned native fixture, never logged (CWE-200) |
| `internal/server/ssh_certificate_provider.go:111` | the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200) |
| `internal/server/token_exchange.go:98` | the token endpoint's response is the issued token, returned once to the caller that proved the subject token (CWE-200) |

### G118 — CWE-664 Improper lifetime control (goroutine context) (3 sites)

| Location | Reason |
|---|---|
| `internal/events/privacy_erasure_test.go:1555` | test goroutine lifecycle is managed by the test (CWE-664) |
| `internal/server/agenthttprenewal.go:71` | shutdown grace period must outlive the already-canceled parent context (CWE-664) |
| `internal/server/estmtls.go:86` | shutdown grace period must outlive the already-canceled parent context (CWE-664) |

### G122 — CWE-367 Time-of-check time-of-use race (walk callback) (26 sites)

| Location | Reason |
|---|---|
| `deploy/deploycheck_test.go:609` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `deploy/helm/airgap_bundle_test.go:278` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/ai_surface_placement_test.go:27` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/deferred_wipe_guard_test.go:45` | walking the repo's own tree (CWE-22) |
| `docs/docs_test.go:2624` | test walks the repo's own checkout; no hostile symlink exposure (CWE-367) |
| `docs/embedded_postgres_teardown_test.go:46` | walks this repository's own test sources (CWE-22) |
| `docs/est_differential_test.go:190` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_completeness_test.go:280` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:926` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:992` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:4748` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/provenance/authorship_test.go:103` | test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367) |
| `internal/agent/discovery/filesystem.go:61` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/mcpconfig.go:108` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/privatekey.go:74` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/truststore.go:78` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/auditsink/discard_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/crypto/acmekey/production_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/notify/response_buffer_guard_test.go:37` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/backup_test.go:1007` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/protect_correct102_guard_test.go:122` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/scan_annotation_served_test.go:48` | test fixture under t.TempDir (CWE-22) |
| `internal/signing/design_test.go:137` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/managedkeys_test.go:553` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/store/store_isolation_test.go:418` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/store/store_isolation_test.go:466` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |

### G124 — CWE-1004 Sensitive cookie without protective attributes (50 sites)

| Location | Reason |
|---|---|
| `ee/enterpriseauth/scim_served_test.go:224` | explicit plaintext loopback fixture; the production TLS cookie remains Secure and __Host-prefixed (CWE-1004) |
| `ee/provider/oidc_login.go:156` | credential cookie is HttpOnly, host-only, strict, and Secure follows the served TLS mode. |
| `ee/provider/oidc_login.go:165` | non-HttpOnly by design for double-submit CSRF; it is not a credential without the HttpOnly session. |
| `ee/provider/oidc_login.go:331` | deletion preserves the HttpOnly, strict, host-only session policy; Secure is false only in explicit loopback development mode (CWE-614). |
| `ee/provider/oidc_login.go:335` | this non-credential double-submit cookie must remain JavaScript-readable; strict and served-mode Secure still apply (CWE-614). |
| `ee/provider/oidc_login.go:352` | short-lived login state, HttpOnly; Lax so the IdP's top-level GET redirect returns it (CWE-614). |
| `ee/provider/oidc_login.go:359` | expiring login state (CWE-614). |
| `ee/provider/saml_authenticator.go:199` | credential cookie is HttpOnly, host-only, strict, and Secure follows the served TLS mode. |
| `ee/provider/saml_authenticator.go:208` | non-HttpOnly by design for double-submit CSRF; it is not a credential without the HttpOnly session. |
| `ee/provider/saml_authenticator.go:230` | deletion preserves the HttpOnly, strict, host-only session policy; Secure is false only in explicit loopback development mode (CWE-614). |
| `ee/provider/saml_authenticator.go:234` | this non-credential double-submit cookie must remain JavaScript-readable; strict and served-mode Secure still apply (CWE-614). |
| `ee/provider/saml_authenticator.go:338` | short-lived HttpOnly state/request correlation; None is paired with Secure for the required cross-site SAML POST. |
| `ee/provider/saml_authenticator.go:345` | expiry retains HttpOnly/Lax and uses insecure transport only in explicit loopback development mode (CWE-614). |
| `internal/agent/accessgateway/webconsole.go:962` | the browser is on the CLI's plain-http loopback tunnel, so a Secure cookie would never come back; only template-named script cookies pass (CWE-614) |
| `internal/api/auth.go:1240` | short-lived HttpOnly correlation cookies; None is limited to Secure SAML POST state, not authenticated session cookies (CWE-1004) |
| `internal/api/auth.go:1251` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth.go:1275` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth.go:1282` | HttpOnly and SameSite are set; Secure follows the deployment's TLS mode from config, and the CSRF cookie is deliberately script-readable double-submit (SEC-007) (CWE-1004) |
| `internal/api/auth_hardening_test.go:21` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_saml_cookie_test.go:80` | request cookie for the local handler fixture (CWE-1004) |
| `internal/api/auth_saml_cookie_test.go:83` | request cookie for the local handler fixture (CWE-1004) |
| `internal/api/auth_test.go:230` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:231` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:232` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:233` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:287` | explicit loopback-only plaintext development test (CWE-1004) |
| `internal/api/auth_test.go:317` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:318` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:319` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:320` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:467` | test cookie against the test's own local server (CWE-1004) (mismatch) |
| `internal/api/auth_test.go:487` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:488` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:515` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:516` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:545` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:566` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:613` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/auth_test.go:974` | test double-submit CSRF cookie must be JavaScript-readable, with Secure and SameSite set. |
| `internal/api/auth_test.go:1017` | test double-submit CSRF cookie must be JavaScript-readable, with Secure and SameSite set. |
| `internal/api/csrf_test.go:37` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:52` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:53` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:70` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/csrf_test.go:71` | test cookie against the test's own local server (CWE-1004) |
| `internal/api/rate_limit_guard_test.go:50` | test cookie against the test's own local server (CWE-1004) |
| `internal/connector/netscaler/netscaler.go:354` | cookie on an outbound API request; response-cookie attributes do not apply (CWE-1004) |
| `internal/crypto/infratest/webconsole.go:284` | a double-submit CSRF token the page's scripts must read (CWE-1004) |
| `internal/projections/auth_resolver_test.go:170` | test cookie against the test's own local server (CWE-1004) |
| `internal/projections/auth_resolver_test.go:179` | test cookie against the test's own local server (CWE-1004) |

### G201 — CWE-? (unmapped rule) (1 sites)

| Location | Reason |
|---|---|
| `internal/store/migration_content_test.go:4226` | closed test table list above |

### G202 — CWE-? (unmapped rule) (2 sites)

| Location | Reason |
|---|---|
| `internal/dynsecret/discover_accounts.go:131` | fixed column names, no input (CWE-89) |
| `internal/store/migrate.go:678` | a quoted identifier from the migration file, never input (CWE-89) |

### G203 — CWE-? (unmapped rule) (3 sites)

| Location | Reason |
|---|---|
| `ee/whitelabel/email.go:109` | scheme and host validated above; https only (CWE-79) |
| `ee/whitelabel/email.go:126` | raster image data URI with a decodable base64 payload (CWE-79) |
| `internal/assurance/customer_render.go:186` | the logo matched logoDataURI: a base64 PNG, JPEG, GIF or WebP data URI, never script-capable SVG or another scheme (CWE-79). |

### G204 — CWE-78 OS command injection (414 sites)

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
| `clients/signing/cmd/trstctl-ksp-register/signtool_windows_test.go:166` | the Windows SDK's signtool and certutil with test inputs |
| `clients/signing/ksp/module_test.go:132` | compiles the in-repo check program |
| `clients/signing/ksp/module_test.go:139` | runs the program just built |
| `clients/signing/pkcs11/module_test.go:88` | compiles the in-repo check program |
| `clients/signing/pkcs11/module_test.go:91` | runs the program just built |
| `clients/terraform/internal/terraformprovider/provider_tls_test.go:169` | fixed arguments to this test's own executable (CWE-78) |
| `cmd/trstctl-agent/edgeca_pkcs11_softhsm_container_test.go:31` | fixed docker invocation for the acceptance test (CWE-78) |
| `cmd/trstctl-agent/edgeca_pkcs11_softhsm_real_test.go:76` | fixed pkcs11-tool invocation inside the SoftHSM test container (CWE-78) |
| `cmd/trstctl-agent/selfrestart_unix.go:23` | re-exec of this process's OWN executable path with its own args; the binary at that path was just digest-verified against the campaign's pinned sha256 (CWE-78) |
| `cmd/trstctl-agent/sshtrust.go:179` | operator-configured sshd reload command; running it is the feature (CWE-78) |
| `cmd/trstctl-signer/fips_startup_test.go:53` | current local test executable and bounded QA flags |
| `cmd/trstctl/backup_cmd_test.go:40` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `cmd/trstctl/demo.go:151` | binary resolved beside this executable, args are our own config (CWE-78) |
| `deploy/deploycheck_test.go:119` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/deploycheck_test.go:442` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/deploycheck_test.go:452` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/context_size_test.go:20` | fixed repository script; the test-owned directory is a separate argv value, never shell code (CWE-78). |
| `deploy/docker/context_size_test.go:66` | fixed repository script; the test-owned directory is a separate argv value, never shell code (CWE-78). |
| `deploy/docker/dist_test.go:738` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:867` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:1182` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/dist_test.go:1248` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/reproducible_test.go:64` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/docker/reproducible_test.go:97` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/airgap_bundle_test.go:34` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/airgap_bundle_test.go:49` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/airgap_bundle_test.go:111` | test executes a fixed local tool (CWE-78). |
| `deploy/helm/airgap_bundle_test.go:168` | fixed repository script under test. |
| `deploy/helm/airgap_bundle_test.go:232` | fixed stock checksum command over test-owned archive names. |
| `deploy/helm/helm_docs_commands_test.go:48` | executes the repo's own documented helm command under test (CWE-78) |
| `deploy/helm/helm_docs_commands_test.go:113` | executes the repo's own documented helm command under test (CWE-78) |
| `deploy/helm/helm_test.go:1188` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/helm/signer_hsm_test.go:53` | the chart test's own helm template invocation (CWE-78) |
| `deploy/helm/signer_serviceaccount_test.go:30` | the chart test's own helm template invocation (CWE-78) |
| `deploy/kubernetes/manifests_test.go:434` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/kubernetes/manifests_test.go:452` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `deploy/local-oidc/oidc_test.go:112` | node path comes from LookPath and the script is a checked-in test target (CWE-78) |
| `deploy/local-oidc/oidc_test.go:300` | arguments are fixed checked-in scripts (CWE-78) |
| `deploy/local-oidc/oidc_test.go:514` | node path comes from LookPath and the script is a checked-in test target (CWE-78) |
| `docs/claim_applications_test.go:67` | test runs the repository's own committed generator against tempdir fixtures it just wrote itself (CWE-78) |
| `docs/cwe_register_test.go:18` | test runs the repo's own committed generator (CWE-78) |
| `docs/cwe_register_test.go:40` | test runs the repo's own committed generator against a tempdir fixture (CWE-78) |
| `docs/docs_drift_test.go:192` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/fuzz_shim_guard_test.go:384` | the go tool with fixed flags over this repository's own package directories (CWE-78) |
| `docs/lint_failure_test.go:59` | fixed timeout regression over an owned Python child (CWE-78) |
| `docs/lint_failure_test.go:232` | fixed local Make target in an owned test fixture (CWE-78) |
| `docs/lint_gate_test.go:25` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/lint_gate_test.go:39` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `docs/lint_supervision_test.go:19` | fixed supervision regression with owned scanner and child fixtures (CWE-78) |
| `docs/vuln_gate_test.go:44` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/auditcompliance/protected_archive_minio_fixture_test.go:42` | test runs a fixed local tool with the image the operator named (CWE-78) |
| `ee/auditcompliance/protected_archive_minio_fixture_test.go:47` | test removes the container it started (CWE-78) |
| `ee/auditcompliance/protected_archive_minio_fixture_test.go:48` | test inspects the container it started (CWE-78) |
| `ee/enterpriseauth/auth_ldap_served_test.go:142` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/enterpriseauth/auth_ldap_served_test.go:147` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/enterpriseauth/auth_ldap_served_test.go:153` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/enterpriseauth/auth_ldap_served_test.go:170` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/enterpriseauth/auth_ldap_served_test.go:181` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/enterpriseauth/auth_ldap_served_test.go:187` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/enterpriseauth/ldap_writeback_test.go:89` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `ee/enterpriseauth/ntlm.go:112` | operator-pinned absolute helper path from deployment configuration, validated at startup (CWE-78) |
| `ee/managedkeys/signerwiring/softhsm_container_test.go:83` | fixed Docker test-harness operations bounded by a context deadline (CWE-78) |
| `ee/provider/oidc_login_keycloak_test.go:36` | pinned image, local docker client (CWE-78) |
| `ee/provider/oidc_login_keycloak_test.go:81` | pinned image, fixed arguments (CWE-78) |
| `ee/provider/oidc_login_keycloak_test.go:85` | removes the container this test started (CWE-78) |
| `ee/provider/oidc_login_keycloak_test.go:86` | reads this test's container port (CWE-78) |
| `ee/provider/oidc_login_keycloak_test.go:103` | this test's container logs (CWE-78) |
| `internal/agent/decoy/watch_linux_test.go:38` | the test's own decoy path (CWE-78) |
| `internal/agent/desktop/stock_served_test.go:85` | fixed viewer binary and loopback port allocated by this owned listener, no shell or credential arguments (CWE-78) |
| `internal/agent/desktop/stock_served_test.go:92` | test-built public keyboard/window arguments, fixed tool with no shell or upstream credential (CWE-78) |
| `internal/agent/discovery/pkcs11_softhsm_container_test.go:189` | fixed Docker test-harness operations bounded by a context deadline (CWE-78) |
| `internal/agent/discovery/pkcs11_softhsm_real_test.go:41` | fixed test-harness invocation of the OpenSC tool; the module path, token label and PIN come from the container harness environment, not from a request (CWE-78) |
| `internal/agent/relay/adcs_restrictions_windows.go:42` | CWE-78: the Windows SDK supplies System32, certutil.exe and command switches are fixed, and the bounded validated CA selector is one argv value; no shell or credentials are used. |
| `internal/agent/relay/adcsdatabase.go:308` | reviewed SEC-005 argv: fixed action flags built here; the binary is operator-configured and every value is validated as one non-option argument (CWE-78) |
| `internal/agent/relay/adcsdatabase.go:316` | reviewed SEC-005 argv: fixed flags built by this package; the binary is operator-configured and every value is validated as one non-option argument (CWE-78) |
| `internal/agent/relay/native_probe_host_test.go:34` | local stock test executable, fixed arguments. |
| `internal/agent/relay/native_probe_host_test.go:81` | fixed stock command against owned loopback fixtures. |
| `internal/agent/reportstate/local_account_rotation_test.go:290` | current Go test executable with one fixed test selector and an owned public temp root; no shell or credentials (CWE-78) |
| `internal/agent/reportstate/task_execution_test.go:337` | the current Go test executable and one fixed test name, public owned fixture root only, no shell or credential (CWE-78) |
| `internal/agent/secretrender/secretrender.go:745` | operator-configured reload argv from the renderer's own configuration; running it is the feature (CWE-78) |
| `internal/agent/sessionobserve/observer_linux_test.go:101` | the proof's own traffic script, named by the proof runner (CWE-78) |
| `internal/agent/sshkrl/revocations_test.go:92` | fixed ssh-keygen argv over test-owned temp paths |
| `internal/agent/sshtrust/sshd_live_test.go:61` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:153` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:179` | live-sshd test harness validating its own config with the resolved sshd binary (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:188` | HUPs the harness's own child sshd by pid (CWE-78) |
| `internal/agent/sshtrust/sshd_live_test.go:240` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/agent/workloadapi/attest_darwin_test.go:75` | test runs the system nc against its own socket (CWE-78) |
| `internal/agent/workloadapi/attest_linux_test.go:138` | the test re-executes its own binary (CWE-78) |
| `internal/agent/workloadapi/attest_linux_test.go:155` | the system sleep binary (CWE-78) |
| `internal/agentid/delegation/signer_subprocess_test.go:284` | executable and argv are fixed; output is confined to TempDir (CWE-78). |
| `internal/agentid/verify/wasm_parity_test.go:49` | executable and argv are fixed; output is confined to TempDir (CWE-78). |
| `internal/agentid/verify/wasm_parity_test.go:59` | execShim is Go's fixed wasm_exec_node shim and wasmOut is this test's TempDir artifact (CWE-78). |
| `internal/api/headerauth_guard_test.go:34` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/api/headerauth_guard_test.go:39` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/ca/shellca/shellca.go:120` | the shell-CA backend exists to run the operator's configured signing command (CWE-78) |
| `internal/cli/cbom_scan.go:91` | the operator names the scanner and its arguments; running it is the command's purpose (CWE-78) |
| `internal/cli/cli_test.go:2634` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/connector/localops.go:434` | operator-configured local-ops action command; running it is the feature (CWE-78) |
| `internal/connector/wasm/host/host_test.go:44` | fixed toolchain and package; output confined to the temp dir (CWE-78). |
| `internal/crypto/kmswrap/external_kms.go:122` | operator-configured external KMS helper command (CWE-78) |
| `internal/crypto/pfx/alias_test.go:92` | runs the locally installed JDK tool with fixed arguments (CWE-78). |
| `internal/crypto/pfx/alias_test.go:136` | stock JDK import uses disposable test paths and a password file, never a shell or secret argv (CWE-78). |
| `internal/crypto/pfx/certonly_test.go:255` | the test runs the system openssl on its own files (CWE-78) |
| `internal/crypto/possession_openssl_test.go:25` | the test's own openssl binary and fixed arguments (CWE-78) |
| `internal/crypto/pqc_x509_test.go:61` | LookPath-resolved OpenSSL with fixed arguments |
| `internal/crypto/pqc_x509_test.go:70` | LookPath-resolved OpenSSL; arguments are test-owned paths and flags |
| `internal/crypto/ssh_signin_report_windows_test.go:33` | the fixed report script this test proves, run on the test host (CWE-78) |
| `internal/crypto/tlsprobe/openssl.go:104` | trusted absolute local executable; fixed verb/options; no shell or remote command. |
| `internal/crypto/windependents/pool_runtime_windows.go:39` | fixed inbox IIS executable in native System32, read-only operation and validated pool name; no shell/credentials (CWE-78) |
| `internal/crypto/windependents/rotation_native_windows_test.go:279` | exact compiler-output digest verified by the parent; absolute regular lab binary, fixed argv, no shell or credential argument (CWE-78) |
| `internal/decommission/conformance/release_test.go:22` | goBin is derived from runtime.GOROOT and every argument is fixed (CWE-78). |
| `internal/decommission/conformance/release_test.go:416` | fixed argv, no user input (CWE-78) |
| `internal/dynsecret/active_directory_lab_test.go:132` | fixed stock tools and test-owned public directory arguments; password arrives on an inherited pipe, no shell (CWE-78) |
| `internal/dynsecret/active_directory_reset_native_lab_test.go:216` | this exact owned test executable and public fixture references; key material travels only through the anonymous stdin pipe (CWE-78) |
| `internal/dynsecret/active_directory_reset_native_lab_test.go:247` | fixed stock LDAP binary and exact owned DN; only a private inherited pipe carries the password, no argv/environment/plain file (CWE-78) |
| `internal/kmip/independent_verifier_test.go:119` | python is LookPath-resolved and module is a fixed repository verifier path (CWE-78). |
| `internal/kmip/pykmip_client_test.go:49` | fixed docker subcommands with test-owned arguments (CWE-78) |
| `internal/kmip/pykmip_tenants_test.go:46` | fixed docker subcommands with test-owned arguments (CWE-78) |
| `internal/kms/pkcs11/softhsm_container_test.go:193` | fixed Docker test-harness operations bounded by a context deadline (CWE-78) |
| `internal/kms/tpm/swtpm_container_test.go:110` | fixed Docker test-harness operations bounded by a context deadline (CWE-78) |
| `internal/kms/wrapadapter/localstack_signer_test.go:165` | the repository's own signer (CWE-78) |
| `internal/kms/wrapadapter/localstack_signer_test.go:181` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/kms/wrapadapter/localstack_signer_test.go:182` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/kms/wrapadapter/localstack_signer_test.go:201` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/kms/wrapadapter/localstack_signer_test.go:215` | builds the repository's own command (CWE-78) |
| `internal/kms/wrapadapter/softhsm_signer_container_test.go:30` | fixed docker invocation for the acceptance test (CWE-78) |
| `internal/kms/wrapadapter/softhsm_signer_real_test.go:114` | fixed SoftHSM tool inside the test container (CWE-78) |
| `internal/netconfine/netconfine_linux.go:70` | runs the launcher's own command line verbatim, without a shell, inside the confined network (CWE-78) |
| `internal/netconfine/netconfine_linux_test.go:126` | the test re-runs its own binary through Wrap |
| `internal/objectstore/minio_lock_test.go:43` | test runs a fixed local tool with the image the operator named (CWE-78) |
| `internal/objectstore/minio_lock_test.go:48` | test removes the container it started (CWE-78) |
| `internal/objectstore/minio_lock_test.go:49` | test inspects the container it started (CWE-78) |
| `internal/objectstore/minio_lock_test.go:64` | test reads the container it started (CWE-78) |
| `internal/perf/live.go:815` | perf harness building/running the repo's own signer with the go toolchain (CWE-78) |
| `internal/perf/live.go:979` | perf harness building/running the repo's own signer with the go toolchain (CWE-78) |
| `internal/pluginhost/raw_api_boundary_test.go:44` | fixed go build command, literal tag table, owned temp output; no shell or user arguments (CWE-78). |
| `internal/pqc/native_probe_test.go:74` | pinned local stock executable and owned loopback fixture. |
| `internal/pqc/prepared_leaf_openssl_test.go:63` | LookPath-resolved OpenSSL, fixed verbs, loopback and TempDir artifacts. |
| `internal/pqc/prepared_leaf_openssl_test.go:83` | Fixed stock TLS validation command against the owned loopback server. |
| `internal/pqc/pure_x509_openssl_test.go:129` | path is exec.LookPath("openssl") and arguments are fixed (CWE-78). |
| `internal/pqc/pure_x509_openssl_test.go:139` | executable is the LookPath-resolved OpenSSL and test call sites supply fixed verbs plus TempDir paths (CWE-78). |
| `internal/pqc/signer_served_test.go:88` | executable and argv are fixed; output is confined to TempDir (CWE-78). |
| `internal/pqcruntime/spiffe_hybrid_test.go:81` | path is exec.LookPath("openssl") and arguments are fixed (CWE-78). |
| `internal/pqcruntime/spiffe_hybrid_test.go:91` | executable is the LookPath-resolved OpenSSL and call sites supply fixed verbs plus TempDir paths (CWE-78). |
| `internal/projections/server_assembly_test.go:44` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/acme/certbot_client_test.go:240` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/conformance_test.go:116` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/mldsa_csr_test.go:101` | fixed local tool (CWE-78) |
| `internal/protocols/cmp/mldsa_csr_test.go:123` | fixed local tool and tempdir paths (CWE-78) |
| `internal/protocols/cmp/mldsa_csr_test.go:131` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/openssl_client_test.go:48` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/cmp/openssl_client_test.go:114` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/est/differential_test.go:101` | test executes a fixed local tool or fixture it built itself (CWE-78) (-g: get cacerts) |
| `internal/protocols/est/differential_test.go:169` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/est/differential_test.go:196` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/scep/sscep_client_test.go:55` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/scep/sscep_client_test.go:74` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/protocols/ssh/krl_binary_test.go:197` | fixed reference tool and task-owned test files (CWE-78) |
| `internal/protocols/ssh/krl_binary_test.go:289` | fixed reference tool and task-owned test files (CWE-78) |
| `internal/protocols/ssh/krl_binary_test.go:293` | fixed reference tool and task-owned test files (CWE-78) |
| `internal/protocols/ssh/ssh_test.go:66` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/reconcile/conformance/ca_ledgers_e2e_test.go:264` | fixed docker subcommands with test-owned arguments (CWE-78) |
| `internal/reconcile/conformance/ca_ledgers_e2e_test.go:278` | fixed docker cleanup of test-owned resources (CWE-78) |
| `internal/reconcile/conformance/ca_ledgers_e2e_test.go:321` | fixed docker probe of the test's own container (CWE-78) |
| `internal/reconcile/conformance/ca_ledgers_e2e_test.go:432` | fixed docker probe of the test's own container (CWE-78) |
| `internal/reconcile/kmipsource_pykmip_test.go:43` | fixed docker subcommands with test-owned arguments (CWE-78) |
| `internal/reconcile/kmipsource_pykmip_test.go:97` | removes the test's own container (CWE-78) |
| `internal/reconcile/kmipsource_pykmip_test.go:102` | fixed seeding script inside the test's own container (CWE-78) |
| `internal/rpverify/verifier_test.go:369` | fixed argv, no user input (CWE-78) |
| `internal/secretscan/gitdiff.go:169` | fixed git/gitleaks binaries over the operator's own repository (CWE-78) |
| `internal/secretscan/gitdiff_test.go:93` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/secretscan/gitleaks.go:228` | fixed git/gitleaks binaries over the operator's own repository (CWE-78) |
| `internal/secretscan/installer_retry_test.go:96` | the test's own script, against its own server (CWE-78) |
| `internal/secretscan/installer_retry_test.go:192` | the shipped wrapper around the test's own stand-in (CWE-78) |
| `internal/secretscan/move.go:147` | the pinned gitleaks binary over the operator's own checkout (CWE-78) |
| `internal/secretscan/move_test.go:52` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/secretscan/repository.go:247` | fixed git/gitleaks binaries over the operator's own repository (CWE-78) |
| `internal/secretscan/repository_credential_test.go:44` | the local git (CWE-78) |
| `internal/secretscan/repository_credential_test.go:84` | the local git over the test's own repository (CWE-78) |
| `internal/secretscli/secretscli.go:108` | runs the operator's own command line verbatim; injecting secrets into their process is the feature (CWE-78) |
| `internal/server/agent_workload_api_darwin_path_test.go:42` | test builds a fixed local fixture (CWE-78) |
| `internal/server/agent_workload_api_darwin_path_test.go:96` | test runs the client it built (CWE-78) |
| `internal/server/agent_workload_api_gospiffe_test.go:215` | test executes a fixed local fixture (CWE-78) |
| `internal/server/agent_workload_api_stock_clients_test.go:120` | the stock helper on PATH with a config this test wrote (CWE-78) |
| `internal/server/archive_minio_served_test.go:45` | test runs a fixed local tool with the image the operator named (CWE-78) |
| `internal/server/archive_minio_served_test.go:50` | test removes the container it started (CWE-78) |
| `internal/server/archive_minio_served_test.go:51` | test inspects the container it started (CWE-78) |
| `internal/server/audit_export_formats_served_test.go:267` | fixed binary built by this test; arguments are fixed/test-owned paths and enum values (CWE-78) |
| `internal/server/audit_export_formats_served_test.go:292` | fixed repository binary and test-owned destination (CWE-78) |
| `internal/server/audit_feed_lab_p5_test.go:226` | the runner's own lab container (CWE-78) |
| `internal/server/audit_feed_lab_p5_test.go:233` | the runner's own lab container (CWE-78) |
| `internal/server/aws_honeytoken_trail_served_test.go:41` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/backup_test.go:966` | fixed repository binary and test-owned destination (CWE-78) |
| `internal/server/bundled_pg_dependency_test.go:19` | fixed local Go tool and package pattern (CWE-78) |
| `internal/server/ca_hierarchy_pqc_served_test.go:32` | LookPath-resolved OpenSSL with fixed arguments |
| `internal/server/ca_hierarchy_pqc_served_test.go:41` | LookPath-resolved OpenSSL; arguments are test-owned paths and flags |
| `internal/server/cbom_native_served_test.go:166` | resolved stock OpenSSL, fixed arguments and owned loopback fixture paths (CWE-78). |
| `internal/server/cloud_workload_replacement_served_test.go:141` | validated 64-hex owned test container ID and constant stock-client program, separate argv, no shell (CWE-78) |
| `internal/server/codesign_cosign_lab_p9_test.go:67` | the lab runner names the network and the local cosign image (CWE-78) |
| `internal/server/codesign_cosign_rekor_lab_p9l2_test.go:101` | the lab runner names the network and the local cosign image (CWE-78) |
| `internal/server/codesign_ksp_served_p9_test.go:77` | test builds the in-repo provider (CWE-78) |
| `internal/server/codesign_ksp_served_p9_test.go:84` | test compiles the in-repo C caller (CWE-78) |
| `internal/server/codesign_ksp_served_p9_test.go:90` | test runs the caller it just built (CWE-78) |
| `internal/server/codesign_notation_lab_p9_test.go:73` | the lab runner names the verified Notation binary (CWE-78) |
| `internal/server/codesign_pkcs11_lab_p9_test.go:83` | the lab runner names the local tool images (CWE-78) |
| `internal/server/codesign_stock_tools_served_test.go:245` | test builds the in-repo plugin (CWE-78) |
| `internal/server/codesign_stock_tools_served_test.go:262` | test runs the plugin it just built (CWE-78) |
| `internal/server/compliance_report_retention_versions_served_test.go:28` | fixed local Docker tool and approved fixture image (CWE-78) |
| `internal/server/compose_e2e_tls_test.go:245` | exact shipped prefix plus fixed test invocation, only owned loopback listeners (CWE-78). |
| `internal/server/decoy_files_container_lab_q6o1_test.go:44` | docker with the lab's own arguments and the runner's image (CWE-78) |
| `internal/server/decoy_files_container_lab_q6o1_test.go:116` | the lab's own container name (CWE-78) |
| `internal/server/decoy_kubernetes_kind_lab_q6o2_test.go:148` | kind and kubectl with the lab's own arguments (CWE-78) |
| `internal/server/decoy_kubernetes_kind_lab_q6o2_test.go:158` | the lab's own cluster (CWE-78) |
| `internal/server/docker_fixture_command_test.go:20` | fixed Docker test-harness operations bounded by a context deadline (CWE-78) |
| `internal/server/dod_signer_binary_test.go:105` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/dynamic_secret_access_databases_container_test.go:38` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/dynamic_secret_access_served_test.go:360` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/dynamic_secret_totp_lab_test.go:35` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/dynamic_secret_totp_lab_test.go:82` | fixed lab image, arguments built by the test (CWE-78) |
| `internal/server/enrollment_relay_served_test.go:107` | fixed current test binary and fixed test selector (CWE-78) |
| `internal/server/est_libest_served_tls_policy_test.go:71` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/est_mtls_reenroll_served_test.go:143` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/esxi_vcsim_served_test.go:70` | the stock simulator on PATH with fixed arguments (CWE-78) |
| `internal/server/github_action_served_test.go:246` | the test deliberately executes a generated copy of the fixed shipped action script (CWE-78). |
| `internal/server/java_sdk_served_test.go:56` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/java_sdk_served_test.go:60` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/java_sdk_served_test.go:91` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/lab_openldap_test.go:52` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/lab_openldap_test.go:97` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/lab_openldap_test.go:102` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/lab_openldap_test.go:108` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/lab_openldap_test.go:112` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/lab_openldap_test.go:115` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/lab_openldap_test.go:121` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/lab_openldap_test.go:154` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/mcp_authorization_keycloak_test.go:111` | test executes the reference binary it built itself (CWE-78) |
| `internal/server/mcp_authorization_keycloak_test.go:343` | test builds the in-repo reference module (CWE-78) |
| `internal/server/mcp_authorization_keycloak_test.go:358` | test executes the reference binary it built itself (CWE-78) |
| `internal/server/mdm_scep_dynamic_served_test.go:233` | test executes a fixed local tool (CWE-78) |
| `internal/server/mdm_scep_dynamic_served_test.go:247` | test executes a fixed local tool (CWE-78) |
| `internal/server/pam_ad_rotation_served_test.go:171` | fixed stock client, exact owned directory DN and inherited password pipe; no shell (CWE-78) |
| `internal/server/pam_command_clickhouse_served_test.go:68` | stock curl against this test's owned tunnel (CWE-78) |
| `internal/server/pam_command_mongo_served_test.go:72` | stock Mongo shell against this test's owned tunnel (CWE-78) |
| `internal/server/pam_command_mysql_served_test.go:67` | stock client against this test's owned tunnel (CWE-78) |
| `internal/server/pam_command_redis_served_test.go:59` | stock Redis client against this test's owned tunnel (CWE-78) |
| `internal/server/pam_desktop_served_test.go:114` | fixed lab SSH daemon and test-owned configuration; no shell or credential arguments (CWE-78) |
| `internal/server/pam_desktop_served_test.go:397` | stock viewer and port from this owned CLI tunnel; no shell or upstream credential (CWE-78) |
| `internal/server/pam_desktop_served_test.go:406` | fixed tool and test-built public keyboard/window arguments, no shell (CWE-78) |
| `internal/server/pam_desktop_served_test.go:427` | fixed tool on the owned viewer display, no shell (CWE-78) |
| `internal/server/pam_desktop_served_test.go:469` | fixed tool on the owned viewer display, no shell (CWE-78) |
| `internal/server/pam_desktop_served_test.go:504` | generated owned database identifier, fixed local test server/tool, no shell (CWE-78) |
| `internal/server/pam_desktop_served_test.go:515` | drops only the exact database this test created, no shell (CWE-78) |
| `internal/server/pam_discovery_ad_served_test.go:32` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_discovery_ad_served_test.go:47` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_discovery_import_served_test.go:34` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_discovery_served_test.go:71` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_gateway_aws_console_served_test.go:35` | fixed local tool and already-approved fixture image (CWE-78) |
| `internal/server/pam_gateway_aws_console_served_test.go:166` | stock curl is confined to owned loopback gateway/federation fixtures; private body travels on stdin (CWE-78) |
| `internal/server/pam_gateway_aws_served_test.go:35` | fixed local Docker tool and approved fixture image (CWE-78) |
| `internal/server/pam_gateway_aws_served_test.go:196` | fixed command inspects only AWS variables in the test-owned CLI container (CWE-78) |
| `internal/server/pam_gateway_azure_served_test.go:87` | stock curl uses only the test-owned credential-free gateway tunnel (CWE-78) |
| `internal/server/pam_gateway_clickhouse_served_test.go:38` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_gateway_clickhouse_served_test.go:125` | the stock curl against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_fixture_test.go:369` | the stock ssh client against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_gcp_served_test.go:86` | stock curl uses only the test-owned credential-free gateway tunnel (CWE-78) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:171` | the stock kubectl against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:194` | the stock kubectl against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_mongo_served_test.go:31` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_gateway_mongo_served_test.go:68` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_gateway_mongo_served_test.go:142` | the stock mongosh against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_mysql_served_test.go:38` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_gateway_mysql_served_test.go:164` | the stock mysql client against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_redis_served_test.go:28` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_gateway_redis_served_test.go:107` | the stock redis-cli against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_snowflake_served_test.go:101` | stock curl against the test-owned gateway tunnel (CWE-78) |
| `internal/server/pam_gateway_ssh_served_test.go:259` | the stock ssh client against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_ssh_served_test.go:294` | the stock ssh client against the test's own sshd (CWE-78) |
| `internal/server/pam_gateway_ssh_served_test.go:314` | the stock ssh client against the test's own tunnel (CWE-78) |
| `internal/server/pam_health_served_test.go:35` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_recording_served_test.go:196` | the stock ssh client against the test's own tunnel (CWE-78) |
| `internal/server/pam_recording_served_test.go:208` | the stock sftp client against the test's own tunnel (CWE-78) |
| `internal/server/pam_served_test.go:918` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_served_test.go:949` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_signin_served_test.go:43` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_signin_served_test.go:46` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_signin_served_test.go:51` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_signin_served_test.go:68` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_signin_served_test.go:504` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:68` | docker with the lab's own arguments and the runner's image (CWE-78) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:146` | the lab's own container names (CWE-78) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:161` | the lab's own container name (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:323` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:382` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:412` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:531` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:584` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_spiffe_ssh_test.go:599` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:302` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:382` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:401` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:468` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:592` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_tsa_test.go:49` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/protocols_served_tsa_test.go:73` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/python_sdk_served_test.go:82` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/redfish_mockup_served_test.go:79` | the interpreter and checkout the CI lab names, fixed arguments (CWE-78) |
| `internal/server/revocation_openssl_test.go:184` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/sdk_registry_install_served_test.go:239` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/sdk_registry_install_served_test.go:285` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_csi_lab_a238_test.go:44` | the runner's own lab cluster and node (CWE-78) |
| `internal/server/secret_csi_lab_a238_test.go:134` | the runner's own lab cluster (CWE-78) |
| `internal/server/secret_csi_lab_a238_test.go:177` | the runner's own lab cluster (CWE-78) |
| `internal/server/secret_dynamic_lease_rotation_container_test.go:38` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_dynamic_lease_rotation_container_test.go:48` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_dynamic_lease_rotation_container_test.go:49` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_dynamic_lease_rotation_container_test.go:51` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_dynamic_lease_rotation_container_test.go:52` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_dynamic_lease_rotation_container_test.go:60` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_dynamic_lease_rotation_container_test.go:90` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_move_served_test.go:104` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_repository_private_clone_served_test.go:39` | the local git over the test's own repository (CWE-78) |
| `internal/server/secret_repository_private_clone_served_test.go:46` | the local git (CWE-78) |
| `internal/server/secret_repository_private_clone_served_test.go:188` | the local git over the test's own repository (CWE-78) |
| `internal/server/secret_scan_hooks_gitlab_bitbucket_served_test.go:68` | the local git over the test's own repository (CWE-78) |
| `internal/server/secret_scan_hooks_served_test.go:51` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_scan_hooks_served_test.go:59` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_scan_hooks_served_test.go:63` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_ldap_two_user_container_test.go:415` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_ldap_two_user_container_test.go:443` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_mongo_two_user_container_test.go:46` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_mongo_two_user_container_test.go:54` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_mongo_two_user_container_test.go:60` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_mongo_two_user_container_test.go:65` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_mongo_two_user_container_test.go:395` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_mongo_two_user_container_test.go:421` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_mssql_two_user_lab_test.go:253` | fixed tool in the runner's lab container (CWE-78) |
| `internal/server/secret_static_rotation_unix_container_test.go:53` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_unix_container_test.go:56` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_unix_container_test.go:61` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_unix_container_test.go:81` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_unix_container_test.go:91` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_unix_container_test.go:421` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_static_rotation_unix_container_test.go:447` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_sync_signed_targets_served_test.go:135` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/service_account_ad_discovery_served_test.go:24` | fixed stock read-only LDAP client, owned account filter and protected credential reference; no shell or credential argv (CWE-78) |
| `internal/server/service_account_rotation_native_ad_test.go:124` | fixed read-only stock client and independently selected owned account; credential only in an inherited pipe, no shell or credential argv (CWE-78) |
| `internal/server/signer_token_command.go:61` | operator-configured token-helper command (CWE-78) |
| `internal/server/spire_jwt_authorities_container_test.go:50` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/spire_jwt_authorities_container_test.go:286` | test builds the repository's own plugin (CWE-78) |
| `internal/server/spire_jwt_authorities_container_test.go:319` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/spire_jwt_authorities_container_test.go:330` | test removes the container it started (CWE-78) |
| `internal/server/spire_jwt_authorities_container_test.go:333` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/spire_jwt_authorities_container_test.go:392` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/spire_jwt_authorities_container_test.go:434` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/spire_jwt_authorities_container_test.go:443` | test reads its own container's logs (CWE-78) |
| `internal/server/ssh_certificate_lease_served_test.go:62` | test executes a fixed local tool on its own temp files (CWE-78) |
| `internal/server/ssh_krl_adoption_served_test.go:31` | fixed ssh-keygen argv over a test-owned temp path |
| `internal/server/ssh_trust_fleet_openssh_test.go:64` | fixed operations on one owned SSH test container, with allowlisted public paths (CWE-78). |
| `internal/server/ssh_trust_fleet_openssh_test.go:81` | stock SSH against the owned container, with an exact host-key pin and public certificate (CWE-78). |
| `internal/server/ssh_trust_fleet_openssh_test.go:206` | stock reference signing with a disposable fixture key in a private test directory (CWE-78). |
| `internal/server/sshcollection_openssh_test.go:272` | stock client against an exact owned container with strict host identity and a disposable private test key (CWE-78). |
| `internal/server/sshcollection_openssh_test.go:282` | stock-client refusal probe forwards only toward the owned SSH test container, with the same strict host pin (CWE-78). |
| `internal/server/sts_deny_policy_served_test.go:35` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/thirdparty_collect_served_test.go:109` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/token_exchange_lab_m4_test.go:36` | the runner's own lab cluster (CWE-78) |
| `internal/server/token_exchange_lab_m4_test.go:70` | the runner's own lab cluster (CWE-78) |
| `internal/server/vault_compat_served_test.go:178` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/vault_compat_served_test.go:212` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/vault_dynamic_credentials_cloud_test.go:38` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/vault_dynamic_credentials_cloud_test.go:84` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/signing/helpers_test.go:29` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/signing/rewrap_binary_test.go:56` | the test's own freshly built signer binary (CWE-78) |
| `internal/signing/static_test.go:41` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/signing/supervisor.go:46` | spawns the repo's own signer binary; AN-4 child-process mode (CWE-78) |
| `internal/signing/supervisor.go:235` | spawns the repo's own signer binary; AN-4 child-process mode (CWE-78) |
| `internal/succession/conformance/edition_test.go:44` | goBin is derived from runtime.GOROOT and every argument is fixed (CWE-78). |
| `internal/succession/conformance/edition_test.go:128` | fixed argv, no user input (CWE-78) |
| `internal/succession/conformance/int20_fullstack_test.go:1336` | executable/argv are fixed and ldflags contain only this test's base64 public key (CWE-78). |
| `internal/testutil/openssltest/openssltest.go:97` | test-support helper running the system openssl found above; not linked into served binaries (CWE-78) |
| `internal/tsa/http_test.go:48` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/tsa/http_test.go:75` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/tsa/tsa_rfc3161_test.go:128` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `scripts/perf/cmd/perfgate/main_test.go:28` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `scripts/perf/cmd/soakcapture/main_test.go:66` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `scripts/perf/cmd/soakgate/main_test.go:133` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/connector_substrate_test.go:114` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/external_ca_substrate_test.go:168` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/kmip_substrate_test.go:38` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/main.go:322` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/managed_key_manifest_test.go:599` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/managed_key_manifest_test.go:635` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/launched.go:285` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/launched.go:649` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/launched.go:1407` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/launched.go:1443` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/proof.go:331` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1173` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1215` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1299` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/runtime_runner.go:956` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/dodcensus/substrate_broker.go:229` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/pqclab/main.go:361` | developer tool running fixed toolchain commands over the repo (CWE-78) |
| `tools/trstctllint/repo_selftest_test.go:22` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/trstctllint/repo_selftest_test.go:111` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/trstctllint/repo_selftest_test.go:177` | test executes a fixed local tool or fixture it built itself (CWE-78) |

### G301 — CWE-276 Incorrect default permissions (directory) (59 sites)

| Location | Reason |
|---|---|
| `clients/embedded/est_client_test.go:73` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `clients/embedded/est_client_test.go:138` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `clients/embedded/est_client_test.go:199` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/cosign_listener_mtls_test.go:111` | deliberately loose, to prove it is tightened (CWE-276) |
| `cmd/trstctl-trustbundle/main.go:85` | build-time output path named by the image build (CWE-22) |
| `deploy/docker/dist_test.go:1112` | npm fixture tree in t.TempDir; mirrors a real package layout, nothing secret (CWE-276) |
| `ee/provider/oidc_login_keycloak_test.go:74` | the container's keycloak user must read the import directory (CWE-276) |
| `internal/agent/csitrust/driver.go:147` | the volume holds public CA certificates the pod's containers read (CWE-276) |
| `internal/agent/destination/fs_unix_test.go:79` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/discovery/discovery_test.go:270` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/discovery/privatekey_test.go:28` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/sshdiscovery/sshdiscovery_test.go:26` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/sshkrl/install_test.go:117` | intentionally unsafe rollback-directory fixture must be rejected |
| `internal/api/machine_sessions_served_test.go:57` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/api/openapi_golden_test.go:59` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/api/vault_compat_contract_test.go:246` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:173` | non-secret fixture directory in t.TempDir (CWE-22, CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:61` | deliberately loose fixture dir; secretfile must refuse it (CWE-276) |
| `internal/dynsecret/providers_real_test.go:676` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/dynsecret/providers_real_test.go:679` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/dynsecret/providers_real_test.go:682` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/projections/golden_events_test.go:107` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/projections/sshdiscovery_store_test.go:92` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:48` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:69` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:275` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:291` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/cmp/openssl_client_test.go:168` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/scep/sscep_client_test.go:196` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/acme_adcs_upstream_served_test.go:176` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/acme_adcs_upstream_served_test.go:207` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/agentchannel_served_test.go:1553` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/decoy_kubernetes_kind_lab_q6o2_test.go:65` | the kind node reads the lab's audit configuration |
| `internal/server/java_sdk_served_test.go:45` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/mcp_authorization_keycloak_test.go:245` | the container's keycloak user must read the import directory (CWE-276) |
| `internal/server/pam_gateway_private_ca_served_test.go:64` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/pam_served_test.go:724` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:137` | a disposable lab certificate the Envoy container reads |
| `internal/server/protocols_served_stock_clients_test.go:51` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:86` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:733` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:747` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_tsa_test.go:189` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/secret_third_party_scan_served_test.go:154` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/secrets_rotation_served_test.go:2582` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/server.go:3110` | served CA certificate directory; the PEM is public material (CWE-276) |
| `internal/signing/socket_dir_symlink_test.go:24` | the loose mode IS the attack fixture this test defends against (CWE-276) |
| `internal/signing/socket_dir_symlink_test.go:56` | the wide mode IS the precondition this test proves gets narrowed (CWE-276) |
| `internal/tsa/http_test.go:103` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `scripts/perf/cmd/capacitycalibrate/main.go:137` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/perfgate/main.go:52` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/scalegate/main.go:52` | developer tool writing a run receipt; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakcapture/main.go:82` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakgate/main.go:120` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/spineburst/main.go:170` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/dodcensus/main.go:1342` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/pqclab/main.go:455` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/trstctllint/eventsource/eventsource_test.go:98` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/trstctllint/idempotency/idempotency_test.go:238` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-276) |

### G302 — CWE-276 Incorrect default permissions (chmod) (55 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/cosign_listener_mtls_test.go:114` | deliberately loose, to prove it is tightened (CWE-276) |
| `cmd/trstctl-agent/main.go:760` | 0700 on a directory: the execute bit is required to traverse it (CWE-276) |
| `cmd/trstctl-agent/tomcat_reload_test.go:80` | deliberately public disposable password fixture must be rejected before any request (CWE-276). |
| `cmd/trstctl-license/main_test.go:147` | regression fixture deliberately starts with an insecure mode to prove signing repairs it (CWE-276) |
| `cmd/trstctl/ssh_request_file_test.go:49` | deliberately public test fixture must be rejected by the private-file gate |
| `ee/provider/reports_test.go:94` | owner execute is required to traverse this private test directory. |
| `internal/agent/csitrust/driver.go:163` | public CA certificates, read by any container user (CWE-276) |
| `internal/agent/destination/fs_unix_test.go:82` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_unix_test.go:28` | deliberately loosens the fixture key's mode; detecting exactly this is what the test proves (CWE-276) |
| `internal/agent/drift/drift_unix_test.go:53` | deliberately loosens the fixture key's mode; detecting exactly this is what the test proves (CWE-276) |
| `internal/agent/listenersessions/listenersessions_test.go:69` | a test directory restored so TempDir can remove it |
| `internal/agent/relay/selfupgrade.go:224` | the file IS the executable being installed; 0755 is its required mode (CWE-276) |
| `internal/agent/secretrender/replace_windows_test.go:41` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/workloadapi/attest.go:123` | a DIRECTORY, not a file. 0700 is the tightest mode that |
| `internal/cloudentitlements/awsiam/session_file_posix_test.go:21` | deliberate shared-file negative fixture; SessionFile must reject it (CWE-276) |
| `internal/cloudentitlements/bearerhttp/client_test.go:108` | negative fixture proves a public token file is refused (CWE-732) |
| `internal/crypto/mtls/custody_other_test.go:36` | deliberate over-permissive negative fixture (CWE-276) |
| `internal/crypto/samltest/material_test.go:61` | deliberately unsafe test fixture must be refused |
| `internal/crypto/secretfile/custody_unix.go:16` | this is a directory; owner execute is required to traverse it, and 0700 grants nothing to group/other (CWE-276) |
| `internal/crypto/secretfile/custody_unix.go:23` | this is public certificate/trust material; group/other may read it but only the owner may write it (CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:64` | deliberately loose fixture mode; secretfile must refuse it (CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:67` | restores the fixture dir so t.TempDir cleanup can remove it (CWE-276) |
| `internal/objectstore/objectstore_test.go:310` | the test loosens the mode on purpose to prove a world-readable secret file is refused (CWE-276) |
| `internal/server/bundled_pg_start_test.go:30` | adversarial test anchor must be writable to prove the verifier rejects it (CWE-732) |
| `internal/server/bundled_pg_start_test.go:33` | restore the private directory's required execute bit (CWE-732) |
| `internal/server/bundled_pg_start_test.go:114` | the source is read-only, as a mount another user owns would be (CWE-732) |
| `internal/server/bundled_pg_start_test.go:117` | let TempDir remove it (CWE-732) |
| `internal/server/compliance_report_dispatch_served_test.go:40` | owner execute is required to traverse this private test directory. |
| `internal/server/compliance_report_worker_test.go:67` | owner execute is required to traverse this private test directory. |
| `internal/server/compliance_report_worker_test.go:223` | owner execute is required to traverse this private test directory. |
| `internal/server/crypto_risk_report_served_test.go:39` | owner execute is required to traverse this private test directory. |
| `internal/server/customer_assurance_report_served_test.go:59` | owner execute is required to traverse this private test directory. |
| `internal/server/evidence_reports_served_test.go:39` | owner execute is required to traverse this private test directory. |
| `internal/server/external_ca_config_test.go:189` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/managed_key_signer_config.go:27` | 0700 on a directory: the execute bit is required to traverse it (CWE-276) |
| `internal/server/protocols_served_tsa_test.go:198` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/server/report_schedule_name_conflict_served_test.go:33` | owner execute is required to traverse this private test directory. |
| `internal/server/tenant_baseline_served_test.go:61` | owner execute is required to traverse this private test directory. |
| `internal/signing/serve.go:203` | 0700 on a directory: the execute bit is required to traverse it (CWE-276) |
| `internal/signing/socket_dir_symlink_test.go:59` | deliberately widened so enforceExactSocketDirMode has something to tighten (CWE-276) |
| `internal/signing/socket_mode_unix_test.go:206` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/tsa/http_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `tools/dodcensus/proof/artifact_watch_linux_test.go:97` | adversarial mutation fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:869` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:889` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:899` | deliberately unsafe fixture mode (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:932` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:196` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:202` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:219` | private fixture-directory mode is the behavior under test (CWE-276) |
| `tools/dodcensus/runtime_runner_test.go:245` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:157` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:163` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:166` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/substrate_broker_test.go:293` | fixture mode in a test tempdir; the mode is part of the fixture (CWE-276) |

### G304 — CWE-22 Path traversal (file inclusion via variable) (786 sites)

| Location | Reason |
|---|---|
| `clients/embedded/est_client_test.go:81` | test reads its own fixture/tempdir path (CWE-22) |
| `clients/signing/cmd/trstctl-ksp-register/main.go:79` | the administrator names the DLL to install |
| `clients/signing/cmd/trstctl-ksp-register/signtool_windows_test.go:193` | this test binary, an unsigned executable to sign |
| `clients/signing/trstctlsign/client.go:51` | the operator names the token file |
| `clients/signing/trstctlsign/client.go:97` | the operator names the CA bundle |
| `clients/terraform/internal/terraformprovider/client.go:94` | operator-selected public trust bundle (CWE-22) |
| `cmd/trstctl-agent/cosign_attach.go:208` | operator-configured local path from the agent's own config (CWE-22) |
| `cmd/trstctl-agent/csisecrets.go:30` | the operator's --csi-secrets-config (CWE-22) |
| `cmd/trstctl-agent/csisecrets.go:45` | operator-configured CA bundle (CWE-22) |
| `cmd/trstctl-agent/distrust.go:23` | operator-supplied agent flag naming a local distrust list (CWE-22) |
| `cmd/trstctl-agent/edgeca.go:137` | explicit operator file path |
| `cmd/trstctl-agent/edgeca.go:149` | explicit operator file path |
| `cmd/trstctl-agent/edgeca.go:211` | explicit operator file path |
| `cmd/trstctl-agent/edgeca.go:333` | operator-configured local path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/edgeca.go:411` | operator-configured journal path on the agent's own host (CWE-22) |
| `cmd/trstctl-agent/edgeca.go:454` | directory of the operator-selected output, synced after an atomic rename |
| `cmd/trstctl-agent/edgeca.go:477` | operator-configured local path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/edgeca.go:487` | operator-configured local handle path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/edgeca_pkcs11_attest_test.go:43` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_pkcs11_attest_test.go:77` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_pkcs11_softhsm_real_test.go:53` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_pkcs11_softhsm_real_test.go:91` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_provider.go:70` | explicit operator-owned device secret path (CWE-22) |
| `cmd/trstctl-agent/edgeca_test.go:61` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_test.go:122` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_test.go:242` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_test.go:253` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/edgeca_test.go:335` | exact test tempdir sentinel |
| `cmd/trstctl-agent/edgeca_test.go:338` | exact test tempdir output |
| `cmd/trstctl-agent/edgejournal_upload.go:83` | operator-configured journal path on the agent's own host (CWE-22) |
| `cmd/trstctl-agent/edgejournal_upload.go:135` | the agent's own upload record beside its journal (CWE-22) |
| `cmd/trstctl-agent/edgerenew.go:69` | operator-configured delegation certificate path on the agent's own host (CWE-22) |
| `cmd/trstctl-agent/edgerenew.go:125` | explicit operator file path |
| `cmd/trstctl-agent/edgerenew.go:161` | explicit operator file path |
| `cmd/trstctl-agent/edgerenew_test.go:104` | the test's own temp file (CWE-22) |
| `cmd/trstctl-agent/edgerenew_test.go:133` | the test's own temp file (CWE-22) |
| `cmd/trstctl-agent/factory.go:55` | operator-configured local path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/factory.go:70` | operator-configured local path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/factory.go:87` | operator-configured local path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/factory.go:104` | derived from the operator-configured journal path (CWE-22) |
| `cmd/trstctl-agent/factory.go:147` | operator-configured local path from the agent's own flags (CWE-22) |
| `cmd/trstctl-agent/factory_test.go:32` | t.TempDir path (CWE-22) |
| `cmd/trstctl-agent/found_inventory_posture_test.go:17` | a fixed test fixture, named by the test itself (CWE-22) |
| `cmd/trstctl-agent/inventory_hostcrypto.go:76` | operator-configured keystore password file (CWE-22) |
| `cmd/trstctl-agent/main.go:1386` | operator-supplied PIN file path, read at their instruction (CWE-22) |
| `cmd/trstctl-agent/main.go:2056` | operator-named key file (CWE-22) |
| `cmd/trstctl-agent/observe.go:92` | the operator names the capture file on the command line (CWE-22) |
| `cmd/trstctl-agent/pluginruntime.go:217` | operator-supplied trust key path (CWE-22) |
| `cmd/trstctl-agent/pluginruntime.go:477` | operator-supplied runtime configuration path (CWE-22) |
| `cmd/trstctl-agent/pluginruntime.go:504` | operator-supplied public issuer certificate (CWE-22) |
| `cmd/trstctl-agent/pluginruntime.go:534` | operator-supplied public issuer certificate (CWE-22) |
| `cmd/trstctl-agent/relayloop.go:212` | explicit operator-supplied CA path, parsed as public PEM trust only (CWE-22). |
| `cmd/trstctl-agent/role_grant_renewal_test.go:149` | the test's own temp file (CWE-22) |
| `cmd/trstctl-agent/secretrender.go:23` | the operator's --secret-render-config (CWE-22) |
| `cmd/trstctl-agent/secretrender.go:38` | operator-configured CA bundle (CWE-22) |
| `cmd/trstctl-agent/ssh_trust_fleet_policy.go:71` | operator-pinned host-local public CA path (CWE-22). |
| `cmd/trstctl-agent/ssh_trust_fleet_policy.go:168` | resolved operator-pinned executable, read only to bind its public digest (CWE-22). |
| `cmd/trstctl-agent/sshkrl.go:51` | operator-selected public KRL input |
| `cmd/trstctl-agent/sshkrl_test.go:24` | test fixture path created under t.TempDir |
| `cmd/trstctl-agent/sshkrl_test.go:67` | test fixture target under t.TempDir |
| `cmd/trstctl-agent/sshkrl_watch.go:186` | the operator's absolute RevokedKeys path, read back for the receipt |
| `cmd/trstctl-agent/sshkrl_watch.go:237` | operator-selected CA bundle for this exact HTTPS origin |
| `cmd/trstctl-agent/sshkrl_watch_test.go:35` | test-only path under t.TempDir |
| `cmd/trstctl-agent/sshkrl_watch_test.go:86` | test-only target under t.TempDir |
| `cmd/trstctl-agent/sshkrl_watch_test.go:114` | test-only target under t.TempDir |
| `cmd/trstctl-agent/sshkrl_watch_test.go:152` | test-only target under t.TempDir |
| `cmd/trstctl-agent/sshtrust.go:97` | operator-configured local path from the agent's own config (CWE-22) |
| `cmd/trstctl-license/aud56_test.go:35` | licensePath is created inside this test's TempDir (CWE-22). |
| `cmd/trstctl-license/main.go:151` | vendor operator explicitly selects the local CLI output path (CWE-22) |
| `cmd/trstctl-signer/offline.go:117` | fixed public-kit path beneath the operator-selected offline vault (CWE-22) |
| `cmd/trstctl-signer/offline.go:153` | operator-selected local offline input file (CWE-22) |
| `cmd/trstctl-signer/offline.go:181` | operator-selected owner-only custodian key file (CWE-22) |
| `cmd/trstctl-signer/offline.go:185` | operator-selected create-new offline output file (CWE-22) |
| `cmd/trstctl-signer/offline.go:214` | operator-selected public CSR input file (CWE-22) |
| `cmd/trstctl-signer/offline_pcas_test.go:45` | path is under t.TempDir from this test's keygen (CWE-22) |
| `cmd/trstctl-signer/offline_pcas_test.go:177` | test helper reads only t.TempDir fixture paths (CWE-22) |
| `cmd/trstctl-trustbundle/main.go:69` | build-time input named by the image build (CWE-22) |
| `cmd/trstctl-trustbundle/main.go:164` | audit input named by the operator (CWE-22) |
| `cmd/trstctl/backup_cmd_test.go:46` | test reads its own fixture/tempdir path (CWE-22) |
| `cmd/trstctl/backup_cmd_test.go:64` | test reads its own fixture/tempdir path (CWE-22) |
| `cmd/trstctl/backup_cmd_test.go:111` | test reads a fixed repository artifact (CWE-22) |
| `cmd/trstctl/connector.go:155` | the operator names their reviewed public preview file (CWE-22) |
| `cmd/trstctl/connector.go:250` | the operator names their reviewed public preview file (CWE-22) |
| `cmd/trstctl/connector.go:382` | the operator explicitly names the public trust-bundle path (CWE-22) |
| `cmd/trstctl/ee_attach.go:407` | operator-supplied path to their own IdP's JWKS (CWE-22) |
| `cmd/trstctl/ee_attach.go:437` | operator-supplied path to their own IdP's JWKS (CWE-22) |
| `cmd/trstctl/ee_attach.go:447` | operator-configured client secret file (CWE-22) |
| `cmd/trstctl/ee_attach.go:513` | operator-pinned local IdP metadata, validated as configuration. |
| `cmd/trstctl/main.go:471` | the configured public certificate of this process's own listener (CWE-22) |
| `cmd/trstctl/ssh.go:196` | operator-selected local proof file is matched to the checked private regular inode before reading |
| `deploy/demo/aud66_test.go:105` | fixed repository test path (CWE-22) |
| `deploy/demo/demo_test.go:56` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:98` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:212` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:294` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:364` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:462` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:577` | test reads the repo's own workflow (CWE-22) |
| `deploy/deploycheck_test.go:609` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `deploy/deploycheck_test.go:700` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:769` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:860` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:889` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:927` | test reads its own repository source file. |
| `deploy/deploycheck_test.go:1081` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1087` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1093` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1156` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1246` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1429` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/deploycheck_test.go:1673` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/docker/context_size_test.go:28` | fixed filename below this test's private t.TempDir (CWE-22). |
| `deploy/docker/dist_test.go:25` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/docker/dist_test.go:1199` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/docker/reproducible_test.go:35` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/airgap_bundle_test.go:62` | bundle is created inside this test's TempDir (CWE-22). |
| `deploy/helm/airgap_bundle_test.go:69` | bundle is created inside this test's TempDir (CWE-22). |
| `deploy/helm/airgap_bundle_test.go:186` | the call log path is created inside this test's private temporary directory. |
| `deploy/helm/airgap_bundle_test.go:200` | the bundle path is created inside this test's private temporary directory. |
| `deploy/helm/airgap_bundle_test.go:218` | the archive is produced inside this test's private temporary directory. |
| `deploy/helm/airgap_bundle_test.go:278` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `deploy/helm/airgap_bundle_test.go:294` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/airgap_bundle_test.go:340` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/helm_docs_commands_test.go:130` | reads the repo's own docs pages from a walked list (CWE-22) |
| `deploy/helm/helm_test.go:1150` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/helm_test.go:1211` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/helm/signer_hsm_test.go:152` | the test's own golden file (CWE-22) |
| `deploy/iac/iac_test.go:279` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/kubernetes/manifests_test.go:495` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/kubernetes/manifests_test.go:512` | test reads its own fixture/tempdir path (CWE-22) |
| `deploy/local-oidc/oidc_test.go:309` | paths are exact children of t.TempDir (CWE-22) |
| `docs/ai_surface_placement_test.go:27` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/aud56_test.go:62` | name comes from the fixed documentation manifest in this test (CWE-22). |
| `docs/aud58_test.go:15` | name comes from the fixed documentation manifest in this test (CWE-22). |
| `docs/aud65_test.go:18` | name comes from the fixed documentation manifest in this test (CWE-22). |
| `docs/deferred_wipe_guard_test.go:45` | walking the repo's own tree (CWE-22) |
| `docs/docker_acceptance_deadline_test.go:22` | test reads a fixed repository path (CWE-22) |
| `docs/docker_acceptance_deadline_test.go:38` | test reads a fixed repository path (CWE-22) |
| `docs/doctor_doc_test.go:33` | fixed literal list of the repo's own committed doctor sources; no external input reaches this path (CWE-22) |
| `docs/edition_ledger_test.go:83` | test reads the repository's own documentation (CWE-22) |
| `docs/edition_ledger_test.go:116` | test reads the repository's own documentation and console catalog (CWE-22) |
| `docs/embedded_postgres_teardown_test.go:46` | walks this repository's own test sources (CWE-22) |
| `docs/est_differential_test.go:190` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/fuzz_shim_guard_test.go:369` | this repository's own test sources (CWE-22) |
| `docs/nolint_gosec_guard_test.go:90` | test reads a path listed by this repository's own git index (CWE-22) |
| `docs/operational_transfer_test.go:64` | test reads its own fixture/tempdir path (CWE-22) |
| `docs/protect_guards_completeness_test.go:280` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:926` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:992` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/protect_guards_test.go:4748` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `docs/provenance/authorship_test.go:38` | fixed sibling path inside the package's own directory (CWE-22) |
| `docs/provenance/authorship_test.go:103` | test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367) |
| `docs/sdk_registry_claims_test.go:44` | a page in this checkout (CWE-22) |
| `ee/auditcompliance/retention.go:56` | the archive path built above under the operator's archive dir (CWE-22) |
| `ee/auditcompliance/retention_download_test.go:82` | the test's own archive (CWE-22) |
| `ee/auditcompliance/retention_test.go:357` | glob is restricted to this test's private temporary archive directory. |
| `ee/billing/evidence_test.go:150` | test reads repo source files it names itself (CWE-22) |
| `ee/enterpriseauth/scim_config.go:63` | the operator's own configured CA file (CWE-22) |
| `ee/managedkeys/signerwiring/tenantkek.go:80` | path is the signer operator's explicit local configuration file, never remote input (CWE-22). |
| `ee/managedkeys/signerwiring/tenantkek.go:222` | the signer operator's configured wrapped-key file, never remote input (CWE-22). |
| `ee/managedkeys/signerwiring/tenantkek_kms_test.go:69` | the fixture adapter's log in the test tempdir (CWE-22) |
| `ee/managedkeys/signerwiring/wiring.go:144` | path is the signer operator's explicit local configuration file, never remote input (CWE-22). |
| `internal/agent/csisecrets/driver_test.go:259` | the test's own temp file (CWE-22) |
| `internal/agent/csisecrets/driver_test.go:288` | the test's own temp file (CWE-22) |
| `internal/agent/csisecrets/driver_test.go:425` | the test's own temp file (CWE-22) |
| `internal/agent/csisecrets/driver_test.go:660` | the test's own temp file (CWE-22) |
| `internal/agent/csitrust/driver.go:151` | path is the kubelet's target directory joined with a validated file name (CWE-22) |
| `internal/agent/csitrust/driver_test.go:120` | the file the driver wrote under this test's temp dir (CWE-22) |
| `internal/agent/decoy/decoy.go:90` | the agent's own decoy state file (CWE-22) |
| `internal/agent/decoy/decoy.go:137` | an operator-configured decoy path, created exclusively (CWE-22) |
| `internal/agent/decoy/decoy_test.go:28` | the test's own decoy (CWE-22) |
| `internal/agent/decoy/decoy_test.go:46` | the test's own file (CWE-22) |
| `internal/agent/decoy/watch_linux.go:198` | the kernel's process table (CWE-22) |
| `internal/agent/desktop/stock_served_test.go:137` | owned unique task filename under the fixed lab account home (CWE-22) |
| `internal/agent/desktop/stock_served_test.go:154` | exact child PID and fixed metadata filenames created by this test (CWE-22) |
| `internal/agent/destination/destination_test.go:49` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/destination/destination_test.go:53` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/destination/destination_test.go:81` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/destination/destination_test.go:88` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/discovery/cryptolib.go:132` | the agent inventories operator-configured library paths; reading them is the product function (CWE-22) |
| `internal/agent/discovery/cryptolib.go:336` | a file named by the library being inventoried (its OPENSSLDIR or a sibling library) (CWE-22) |
| `internal/agent/discovery/cryptopolicy.go:120` | the host's own crypto policy files under a fixed root (CWE-22) |
| `internal/agent/discovery/filesystem.go:61` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/keystore.go:87` | the agent inventories operator-configured keystore paths; reading them is the product function (CWE-22) |
| `internal/agent/discovery/keystore_jceks_test.go:22` | the test reads its own fixtures (CWE-22) |
| `internal/agent/discovery/mcpconfig.go:108` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/pkcs11_softhsm_container_test.go:93` | the repository's own go.mod under the test's computed repo root (CWE-22) |
| `internal/agent/discovery/privatekey.go:74` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/truststore.go:78` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22, CWE-367) |
| `internal/agent/discovery/truststore.go:191` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/drift/drift.go:150` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/drift/drift_test.go:127` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/drift/drift_test.go:184` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/drift/drift_test.go:209` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/drift/drift_test.go:244` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/listenersessions/proc.go:101` | a fixed proc table under the agent's proc root |
| `internal/agent/listenersessions/proc.go:158` | a fixed proc file under the agent's proc root |
| `internal/agent/listenersessions/proc.go:184` | a fixed proc file under the agent's proc root |
| `internal/agent/mcp_inventory.go:31` | the agent's own state file (CWE-22) |
| `internal/agent/observe/udp_capture_test.go:17` | the test reads its own fixture (CWE-22) |
| `internal/agent/relay/adcsdatabase_test.go:89` | test-owned temp file (CWE-22). |
| `internal/agent/relay/adcsdatabase_test.go:297` | test-owned temp file (CWE-22). |
| `internal/agent/relay/adcsrevoke_test.go:67` | test-owned temp file (CWE-22). |
| `internal/agent/relay/deploy_failure_log.go:84` | the operator's own flag (CWE-22) |
| `internal/agent/relay/deploy_failure_log.go:148` | the operator's own flag (CWE-22) |
| `internal/agent/relay/deploy_failure_log_keep_test.go:72` | the test's own temp file (CWE-22) |
| `internal/agent/relay/host_pqc_predecessor_test.go:47` | test-owned directory (CWE-22) |
| `internal/agent/relay/host_renew_pending.go:144` | validated agent-local state directory |
| `internal/agent/relay/host_renew_pending_replay_test.go:52` | test-owned directory |
| `internal/agent/relay/hostexec.go:148` | operator-supplied profile path, read at their instruction (CWE-22) |
| `internal/agent/relay/hostposture_store_test.go:34` | test-owned directory |
| `internal/agent/relay/hostrollback.go:915` | validated agent-local state directory (CWE-22) |
| `internal/agent/relay/hostrollback_test.go:46` | test-owned temporary directory (CWE-22) |
| `internal/agent/relay/hostrollback_test.go:193` | test-owned state root (CWE-22) |
| `internal/agent/relay/hostrollback_test.go:300` | test-owned state root (CWE-22) |
| `internal/agent/relay/k8ssecret_kind_e2e_test.go:84` | the cluster CA file the kind job exports (CWE-22) |
| `internal/agent/relay/mysql_verification_test.go:177` | p is one of two fixed filenames under t.TempDir, with no external input (CWE-22). |
| `internal/agent/relay/plugin_modules.go:43` | the operator's own approval record beside the agent key (CWE-22) |
| `internal/agent/relay/plugins.go:255` | operator-configured plugin directory (CWE-22) |
| `internal/agent/relay/plugins.go:259` | sibling of an operator-configured module (CWE-22) |
| `internal/agent/relay/plugins.go:271` | sibling of an operator-configured module (CWE-22) |
| `internal/agent/relay/plugins.go:276` | sibling of an operator-configured module (CWE-22) |
| `internal/agent/relay/postgresql_verification_test.go:154` | p is one of two fixed filenames under t.TempDir, with no external input (CWE-22). |
| `internal/agent/relay/recovery_check.go:273` | the host operator's own pinned executable from the host profile (CWE-22) |
| `internal/agent/relay/relay_test.go:675` | certPath is created beneath this test's private t.TempDir, |
| `internal/agent/relay/relay_test.go:1106` | callers pass paths created inside this test package's t.TempDir fixtures (CWE-22). |
| `internal/agent/relay/rollback_test.go:208` | test-owned temporary path (CWE-22) |
| `internal/agent/relay/selfupgrade_test.go:87` | test reads its own tempdir fixture path (CWE-22) |
| `internal/agent/relay/selfupgrade_test.go:152` | test reads its own tempdir fixture path (CWE-22) |
| `internal/agent/relay/selfupgrade_test.go:156` | test reads its own tempdir fixture path (CWE-22) |
| `internal/agent/relay/selfupgrade_test.go:259` | the test reads its own temp fixture (CWE-22) |
| `internal/agent/relay/selfupgrade_test.go:274` | the test reads its own temp fixture (CWE-22) |
| `internal/agent/relay/tomcat_activation_test.go:49` | fixed filenames below t.TempDir, no external input (CWE-22). |
| `internal/agent/relay/trust_distrusted_test.go:17` | a fixed test fixture directory, named by the test itself (CWE-22) |
| `internal/agent/relay/trust_test.go:48` | path is created inside this test's TempDir (CWE-22). |
| `internal/agent/relay/trust_test.go:73` | path is created inside this test's TempDir (CWE-22). |
| `internal/agent/secretinject/secretinject.go:179` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/secretinject/secretinject_test.go:26` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/secretinject/secretinject_test.go:56` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/secretrender/lease_renew_test.go:117` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/lease_reuse_test.go:59` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/lease_test.go:106` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/lease_test.go:130` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/login.go:86` | operator-configured workload credential file (CWE-22) |
| `internal/agent/secretrender/ownership_unix_test.go:78` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/replace_windows_test.go:49` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/replacement_test.go:53` | this test reads only its own temporary renderer destination (CWE-22) |
| `internal/agent/secretrender/replacement_test.go:82` | this test reads only its own temporary renderer destination (CWE-22) |
| `internal/agent/secretrender/restrict_windows_test.go:70` | the test's own file (CWE-22) |
| `internal/agent/secretrender/secretrender.go:398` | the renderer's own state directory and a validated template name (CWE-22) |
| `internal/agent/secretrender/secretrender.go:727` | operator-configured pid file (CWE-22) |
| `internal/agent/secretrender/secretrender.go:819` | a fresh random name beside the configured destination (CWE-22) |
| `internal/agent/secretrender/secretrender.go:861` | the destination's own directory (CWE-22) |
| `internal/agent/secretrender/secretrender.go:908` | operator-configured token file (CWE-22) |
| `internal/agent/secretrender/secretrender_test.go:83` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/secretrender_test.go:142` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/secretrender_test.go:154` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/secretrender_test.go:175` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/secretrender_test.go:230` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/secretrender_test.go:258` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/service_reload_windows_test.go:36` | the owning test's marker file, passed by that test (CWE-22) |
| `internal/agent/secretrender/service_reload_windows_test.go:134` | the test's own temp file (CWE-22) |
| `internal/agent/secretrender/service_reload_windows_test.go:138` | the test's own temp file (CWE-22) |
| `internal/agent/sessionobserve/objects_test.go:46` | the committed probe objects beside the test (CWE-22) |
| `internal/agent/sessionobserve/observer_linux_test.go:40` | the proof traffic's own output (CWE-22) |
| `internal/agent/sessionobserve/observer_linux_test.go:175` | the proof traffic's own output (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:61` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:80` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:97` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:120` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshdiscovery/sshdiscovery.go:144` | the agent inventories operator-configured roots; reading discovered paths is the product function (CWE-22) |
| `internal/agent/sshdiscovery/sshdtrust.go:325` | the agent inventories operator-configured sshd configuration and the public files it names (CWE-22) |
| `internal/agent/sshdiscovery/sshdtrust_test.go:21` | committed test fixture |
| `internal/agent/sshkrl/install.go:304` | read only the derived predecessor in the checked private rollback directory |
| `internal/agent/sshkrl/install.go:338` | syncs only the validated target or private rollback directory |
| `internal/agent/sshkrl/install_test.go:28` | test fixture path created under t.TempDir |
| `internal/agent/sshkrl/install_test.go:128` | test fixture path under t.TempDir |
| `internal/agent/sshkrl/install_unix_test.go:59` | committed test fixture |
| `internal/agent/sshkrl/revocations_test.go:110` | test-created path under t.TempDir |
| `internal/agent/sshtrust/sshd_live_test.go:49` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/sshtrust/sshd_live_test.go:99` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/sshtrust/sshd_live_test.go:149` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agent/sshtrust/sshd_live_test.go:279` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/agentid/delegation/reachtruststore.go:81` | signer-owned floor and validated key ID; open only to fsync the published directory |
| `internal/agentid/orchestrator/reachability_key.go:156` | configured control-plane key directory; open only to fsync the sealed-key publication |
| `internal/api/backpressure_errors_test.go:88` | reads this package's own sources in a test (CWE-22) |
| `internal/api/public_route_abuse_guard_test.go:91` | reads this package's own sources in a test (CWE-22) |
| `internal/api/rogue_certificates_weak_key_test.go:18` | a fixed test fixture directory, named by the test itself (CWE-22) |
| `internal/api/sdk_spec_pinned_test.go:49` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/api/vault_compat_contract_test.go:255` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/auditarchive/reader.go:181` | rebuilt from the configured archive dir, tenant and boundary (CWE-22) |
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
| `internal/backup/objectstore.go:120` | a file inside the operator's own backup set directory (CWE-22) |
| `internal/backup/objectstore.go:207` | a validated name inside the operator's new download directory (CWE-22) |
| `internal/backup/objectstore_test.go:82` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/backup/objectstore_test.go:99` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/adcs/kerberos_lab_test.go:33` | lab password file named by the test environment, never by a request (CWE-22) |
| `internal/ca/capability_evidence_test.go:65` | fixed in-tree proof manifest |
| `internal/ca/external_error_redaction_test.go:62` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/letsencrypt/dnspersist_pebble_test.go:53` | the runner's copy of Pebble's test root (CWE-22) |
| `internal/ca/letsencrypt/revoke_authorized_pebble_test.go:42` | the runner's copy of Pebble's test root (CWE-22) |
| `internal/ca/profilelint/profilelint_test.go:146` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/shellca/shellca.go:104` | operator-configured shell-CA output path; the shell CA is an explicit operator integration (CWE-22) |
| `internal/ca/shellca/shellca_test.go:161` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/cbom/cyclonedx_supplement_test.go:108` | the package's own golden test fixture (CWE-22) |
| `internal/cbom/cyclonedx_test.go:104` | the package's own golden test fixture (CWE-22) |
| `internal/cbom/hostsource/hostsource.go:81` | an authorized, previewed discovery selector; the read is size-bounded below (CWE-22) |
| `internal/cbom/sourcescan/sourcescan.go:148` | a repository the operator named; reading its files is the product function (CWE-22) |
| `internal/cbom/sourcescan/sourcescan.go:680` | a repository the operator named; reading its files is the product function (CWE-22) |
| `internal/cbom/tlssource/tlssource_key_verdict_test.go:19` | a fixed test fixture, named by the test itself (CWE-22) |
| `internal/cli/access_agent.go:136` | the operator names their own attestation payload file (CWE-22) |
| `internal/cli/access_agent_test.go:129` | the file the test's own child wrote in the test's temp dir (CWE-22) |
| `internal/cli/access_connect.go:61` | the operator names their own ticket file (CWE-22) |
| `internal/cli/assurance_verify.go:41` | operator-named local file (CWE-22) |
| `internal/cli/assurance_verify.go:46` | operator-named local file (CWE-22) |
| `internal/cli/audit_verify.go:203` | path is the explicit read-only local artifact selected by this CLI command (CWE-22). |
| `internal/cli/ca_key_wrap.go:66` | operator-named local file (CWE-22) |
| `internal/cli/ca_key_wrap.go:85` | operator-named local file (CWE-22) |
| `internal/cli/ca_key_wrap.go:100` | operator-named local file (CWE-22) |
| `internal/cli/ca_key_wrap_test.go:63` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/cli/cbom_scan_test.go:32` | the test's own temp file (CWE-22) |
| `internal/cli/cbom_verify.go:109` | operator-named local file (CWE-22) |
| `internal/cli/cbom_verify_test.go:61` | a file this test wrote under t.TempDir (CWE-22) |
| `internal/cli/certificate_key_attestation.go:71` | operator-named local file (CWE-22) |
| `internal/cli/certificate_key_attestation.go:81` | operator-named local file (CWE-22) |
| `internal/cli/certificate_key_attestation.go:87` | operator-named local file (CWE-22) |
| `internal/cli/ci_templates_test.go:109` | test reads the repo's own shipped templates (CWE-22) |
| `internal/cli/cli.go:294` | the operator explicitly names the public trust-bundle path (CWE-22) |
| `internal/cli/cli.go:691` | operator-passed local file argument on their own command line (CWE-22) |
| `internal/cli/cli_test.go:2176` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/cli/doctor/doctor_test.go:98` | test reads its own tempdir receipt (CWE-22) |
| `internal/cli/doctor/probes_objectstore_test.go:50` | test reads its own tempdir receipt (CWE-22) |
| `internal/cli/evaluate/cmd.go:92` | operator-named token file (CWE-22) |
| `internal/cli/evaluate/cmd.go:155` | the operator names the public trust-bundle path (CWE-22) |
| `internal/cli/evaluate/cmd.go:222` | operator-named local file (CWE-22) |
| `internal/cli/evaluate/cmd.go:227` | operator-named local file (CWE-22) |
| `internal/cli/pcas_kem_envelope.go:67` | operator-named local file (CWE-22) |
| `internal/cli/pcas_kem_envelope.go:80` | operator-named local file (CWE-22) |
| `internal/cli/report_verify.go:44` | operator-named local file (CWE-22) |
| `internal/cli/report_verify.go:49` | operator-named local file (CWE-22) |
| `internal/cli/report_verify_test.go:90` | the test's own temporary file (CWE-22) |
| `internal/cli/secret_scan_hook_test_cmd.go:48` | the operator names their own secret file (CWE-22) |
| `internal/cli/secret_scan_hook_test_cmd.go:57` | the operator names their own payload file (CWE-22) |
| `internal/cli/switching_import.go:42` | the operator names the export file to read (CWE-22 not applicable) |
| `internal/cloudauth/aws_credential_chain.go:164` | operator- or platform-configured projected token path (CWE-22) |
| `internal/cloudauth/aws_credential_chain.go:223` | platform-configured Pod Identity token path (CWE-22) |
| `internal/cloudauth/azure_token_source.go:83` | operator-configured projected token path (CWE-22) |
| `internal/cloudauth/cloudauth.go:398` | operator-configured projected token path (CWE-22) |
| `internal/cloudauth/gcp_token_source.go:115` | operator-configured projected token path (CWE-22) |
| `internal/cloudhttp/adoption_guard_test.go:127` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/config/config.go:3740` | the config loader reading the operator's own config file (CWE-22) |
| `internal/config/config.go:5099` | operator-configured local file path from deployment config (CWE-22) |
| `internal/config/config.go:5118` | operator-configured local file path from deployment config (CWE-22) |
| `internal/config/object_store.go:165` | the operator's own config file (CWE-22) |
| `internal/connector/device_proof_census_test.go:47` | fixed in-tree path derived from the census (CWE-22) |
| `internal/connector/localops.go:310` | operator-configured local-ops connector path; local file deploy is the feature (CWE-22) |
| `internal/connector/localops.go:402` | clean is confined to operator-approved local roots above (CWE-22) |
| `internal/connector/localops_sync_other.go:10` | path is the parent of an operator-approved local connector target (CWE-22) |
| `internal/connector/wasm/host/gen/main.go:36` | a developer tool reading the module the make target just built (CWE-22). |
| `internal/connector/wasm/host/host_test.go:51` | the file this test just built (CWE-22). |
| `internal/connector/wasm/host/host_test.go:293` | this repository's own connector sources (CWE-22). |
| `internal/crypto/acmekey/production_guard_test.go:44` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/crypto/fsatomic/syncdir_other.go:10` | the caller's own state directory (CWE-22) |
| `internal/crypto/jks/jceks_test.go:27` | the test reads its own fixture (CWE-22) |
| `internal/crypto/kerberos/client_test.go:87` | lab password file named by the test environment, never by a request (CWE-22) |
| `internal/crypto/kerberos/lab_kdc_test.go:30` | lab password file named by the test environment, never by a request (CWE-22) |
| `internal/crypto/mongosignin/mongosignin.go:251` | the session's URI names the CA file on the gateway's host, as a driver's tlsCAFile does (CWE-22) |
| `internal/crypto/mtls/agent.go:215` | operator-configured certificate/key path from deployment config (CWE-22) |
| `internal/crypto/mtls/agent.go:233` | operator-configured certificate/key path from deployment config (CWE-22) |
| `internal/crypto/mtls/server.go:240` | operator-selected public certificate path, validated as a regular file (CWE-22) |
| `internal/crypto/mtls/server.go:336` | operator-selected internal TLS state path, validated as a private regular file (CWE-22) |
| `internal/crypto/mtls/server.go:382` | operator-configured certificate/key path from deployment config (CWE-22) |
| `internal/crypto/mtls/server_test.go:37` | test-owned path under t.TempDir (CWE-22) |
| `internal/crypto/mtls/server_test.go:65` | test-owned path under t.TempDir (CWE-22) |
| `internal/crypto/mtls/server_test.go:93` | test-owned path under t.TempDir (CWE-22) |
| `internal/crypto/mtls/server_test.go:97` | test-owned path under t.TempDir (CWE-22) |
| `internal/crypto/mtls/signer.go:109` | operator-configured peer CA trust anchor path from the signer's own config (CWE-22) |
| `internal/crypto/mtls/signer_test.go:47` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/mtls/syncdir_other.go:10` | parent of a validated internal TLS state path (CWE-22) |
| `internal/crypto/parserfuzz_audit_test.go:269` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/pfx/alias_test.go:139` | reads the stock JDK output inside this test's private temporary directory (CWE-22). |
| `internal/crypto/pfx/certonly_test.go:259` | the test's own file (CWE-22) |
| `internal/crypto/pfx/pfx_test.go:43` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/pfx/pfx_test.go:44` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/crypto/pgsignin/pgsignin.go:233` | the session's DSN names the root file on the gateway's host, as libpq's sslrootcert does (CWE-22) |
| `internal/crypto/possession_openssl_test.go:39` | the test's own temporary file (CWE-22) |
| `internal/crypto/possession_openssl_test.go:81` | the test's own temporary file (CWE-22) |
| `internal/crypto/possession_openssl_test.go:85` | the test's own temporary file (CWE-22) |
| `internal/crypto/possession_test.go:114` | a fixed test fixture, named by the test itself (CWE-22) |
| `internal/crypto/rdp/clipboard_native_test.go:100` | test-owned unique filename beneath fixed lab account home (CWE-22) |
| `internal/crypto/rdp/clipboard_native_test.go:128` | test-owned unique filename (CWE-22) |
| `internal/crypto/rdp/desktop_test.go:85` | exact child PID created by this test, fixed proc metadata file (CWE-22) |
| `internal/crypto/rdp/desktop_test.go:92` | exact child PID created by this test, fixed proc metadata file (CWE-22) |
| `internal/crypto/rdp/desktop_test.go:99` | exact child PID created by this test, fixed proc metadata file (CWE-22) |
| `internal/crypto/rdp/desktop_test.go:138` | test-owned unique filename beneath fixed lab account home (CWE-22) |
| `internal/crypto/rdp/process_linux.go:83` | operator-installed helper; absolute regular protected executable, executed by this open FD (CWE-22) |
| `internal/crypto/samltest/material_test.go:57` | test-owned temporary identity file |
| `internal/crypto/secretfile/secretfile.go:38` | operator-configured local secret path; parents and file mode validated above (CWE-22) |
| `internal/crypto/secretfile/secretfile.go:83` | operator-configured local secret path; O_EXCL + 0600, parents validated above (CWE-22) |
| `internal/crypto/sshkeys/certificate_test.go:20` | committed test fixture |
| `internal/crypto/trust/systemroots.go:99` | audit input: a path resolved inside an exported image filesystem (CWE-22) |
| `internal/crypto/windependents/rotation_native_windows_test.go:114` | fixed public receipt under the exact test-owned protected native task work directory (CWE-22) |
| `internal/crypto/windependents/rotation_native_windows_test.go:187` | same bounded regular lab executable, read only to compare the independently recorded compiler-output digest (CWE-22) |
| `internal/crypto/windependents/services_native_windows_test.go:282` | os.Executable identifies this native test binary; copied code is public, no caller path (CWE-22) |
| `internal/crypto/windependents/services_native_windows_test.go:288` | fixed filename in the exclusively created native protected test directory, O_EXCL refuses substitution (CWE-22) |
| `internal/crypto/windependents/tasks_native_windows_test.go:55` | fixed public nonce under the exact native ProgramData fixture path with validated random suffix; no credential file (CWE-22) |
| `internal/crypto/windependents/tasks_native_windows_test.go:127` | fixed bounded public receipt inside the exclusively created native protected fixture directory, exact path revalidated (CWE-22) |
| `internal/discovery/cloudsecret/generic_entropy_test.go:133` | repository source files under test (CWE-22) |
| `internal/discovery/ctmonitor/ctmonitor_posture_test.go:20` | a fixed test fixture, named by the test itself (CWE-22) |
| `internal/discovery/netscan/chain_observation_test.go:24` | a fixed test fixture, named by the test itself (CWE-22) |
| `internal/discovery/netscan/chain_observation_test.go:53` | a fixed test fixture, named by the test itself (CWE-22) |
| `internal/dynsecret/providers_real_test.go:258` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/eventprotect/verification_keys_file.go:52` | Operator-pinned absolute public trust path is canonicalized outside managed restore roots; only a bounded regular file is read. |
| `internal/events/protect_schema005_guard_test.go:138` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/events/protect_schema005_guard_test.go:157` | fixed repository source anchor, not caller input (CWE-22) |
| `internal/featureparity/catalog.go:94` | fixed repo-relative catalog path read by tools and tests (CWE-22) |
| `internal/featureparity/feature_facet_coverage_test.go:110` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/feature_facet_coverage_test.go:114` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/feature_facet_coverage_test.go:152` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/featureparity/mcp_rest_coverage.go:57` | fixed repo-relative catalog path read by tools and tests (CWE-22) |
| `internal/keyposture/keyposture_test.go:14` | a fixed test fixture directory, named by the test itself (CWE-22) |
| `internal/kmip/pykmip_client_test.go:65` | test-generated TLS material in the test's temp dir (CWE-22) |
| `internal/kmip/pykmip_tenants_test.go:68` | test-generated TLS material in the test's temp dir (CWE-22) |
| `internal/kmip/tenant_router_test.go:230` | test-generated TLS material in the test's temp dir (CWE-22) |
| `internal/kms/wrapadapter/adapter.go:280` | operator-named adapter configuration (CWE-22) |
| `internal/kms/wrapadapter/localstack_signer_test.go:104` | the test's own key store (CWE-22) |
| `internal/kms/wrapadapter/softhsm_signer_real_test.go:74` | the test's own key store (CWE-22) |
| `internal/license/license.go:352` | operator-supplied license file path (CWE-22) |
| `internal/notify/email/smtp_plain_wipe_test.go:131` | this package's own source files (CWE-22) |
| `internal/notify/response_buffer_guard_test.go:37` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/objectstore/config.go:38` | operator-configured CA bundle path (CWE-22) |
| `internal/perf/smoke.go:176` | perf harness reading its own artifact path (CWE-22) |
| `internal/pluginhost/containment_test.go:122` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/pluginhost/provenance_start_test.go:96` | owned canary under t.TempDir (CWE-22). |
| `internal/pluginhost/raw_api_boundary_test.go:30` | fixed repository checksum manifest, no external path input (CWE-22). |
| `internal/pluginhost/raw_architecture_test.go:72` | enumerated Go source in this package only (CWE-22). |
| `internal/pluginhost/reference_plugin_test.go:55` | fixed in-repo reference plugin path (CWE-22) |
| `internal/pluginhost/reference_plugin_test.go:135` | test reads the path it granted (CWE-22) |
| `internal/pluginhost/sandbox_test.go:95` | test reads the fixture path it just granted (CWE-22) |
| `internal/pluginhost/sandbox_test.go:171` | test reads the fixture it created (CWE-22) |
| `internal/pqc/prepared_leaf_openssl_test.go:58` | fixed server.log filename in this test's private TempDir; no user path. |
| `internal/protocols/acme/certbot_client_test.go:178` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:253` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:303` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:308` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:333` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/acme/certbot_client_test.go:352` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/mldsa_csr_test.go:138` | test reads its own tempdir path (CWE-22) |
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
| `internal/protocols/ssh/krl_binary_test.go:315` | test-owned file under t.TempDir |
| `internal/reconcile/awskmssource.go:343` | operator-configured credential file path (CWE-22) |
| `internal/reconcile/casource.go:61` | operator-configured CA certificate bundle path (CWE-22) |
| `internal/reconcile/conformance/ca_ledgers_e2e_test.go:283` | a certificate this test copied out of its own container (CWE-22) |
| `internal/reconcile/conformance/ca_ledgers_e2e_test.go:409` | the test's own copied config (CWE-22) |
| `internal/reconcile/gcpkmssource.go:353` | operator-configured credential file path (CWE-22) |
| `internal/reconcile/kmipsource_pykmip_test.go:63` | test-generated TLS material in the test's temp dir (CWE-22) |
| `internal/reconcile/stepcasource.go:175` | operator-configured step-ca database DSN file (CWE-22) |
| `internal/reconcile/vaultsource.go:411` | operator-configured token file from the reviewed config (CWE-22) |
| `internal/reportarchive/archive.go:250` | fixed reports path under operator archive root; both path IDs and digest are validated UUID/SHA-256 components. |
| `internal/reportarchive/archive.go:269` | directory is constructed under the operator archive root and checked as a private real directory. |
| `internal/scancollect/scancollect.go:203` | a path inside the collection directory, checked by w.path (CWE-22) |
| `internal/scancollect/scancollect_test.go:27` | the test's own temp directory (CWE-22) |
| `internal/secretscan/gitleaks.go:240` | reads the report file this process asked gitleaks to write in its own tempdir (CWE-22) |
| `internal/secretscan/gitleaks.go:341` | path is resolved inside an operator-configured scan root |
| `internal/secretscan/gitleaks.go:545` | the operator's own scanner config, already validated as a path this process was told to use (CWE-22) |
| `internal/secretscan/gitleaks_options_test.go:186` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/secretscan/installer_retry_test.go:107` | the test's own temporary file (CWE-22) |
| `internal/secretscan/installer_retry_test.go:203` | the test's own temporary file (CWE-22) |
| `internal/secretscan/installer_retry_test.go:215` | the test's own temporary file (CWE-22) |
| `internal/secretscan/locate.go:285` | a file inside the operator's reviewed artifact path, checked by exportFile (CWE-22) |
| `internal/secretscan/locate_test.go:14` | test fixture under t.TempDir (CWE-22) |
| `internal/secretscan/repository_credential_test.go:144` | the test's own clone (CWE-22) |
| `internal/secretscan/repository_credential_test.go:147` | the test's own clone (CWE-22) |
| `internal/secretscan/secretscan_test.go:124` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/secretscan/thirdparty.go:110` | operator-owned artifact path from the reviewed source config, bounded by size above (CWE-22) |
| `internal/secretscan/thirdparty.go:114` | operator-owned signature path from the reviewed source config (CWE-22) |
| `internal/secretscan/thirdparty_signature_test.go:47` | test-owned temp path |
| `internal/secretscan/validity/validity.go:191` | confined to the scan's own temporary tree above (CWE-22) |
| `internal/server/agent_roles_served_test.go:535` | path is a t.TempDir fixture (CWE-22). |
| `internal/server/agent_roles_served_test.go:539` | path is a t.TempDir fixture (CWE-22). |
| `internal/server/agent_workload_api_darwin_path_test.go:51` | test reads the binary it just built (CWE-22) |
| `internal/server/agentchannel.go:147` | operator-configured agent CA certificate path from this server's own config (CWE-22) |
| `internal/server/audit_archive_download_served_test.go:167` | the test's own archive (CWE-22) |
| `internal/server/audit_feed_index_template_lab_test.go:50` | the repository's own shipped content (CWE-22) |
| `internal/server/audit_feed_lab_p5_test.go:35` | the runner's lab CA (CWE-22) |
| `internal/server/audit_feed_lab_p5_test.go:106` | the runner's mounted rsyslog output (CWE-22) |
| `internal/server/audit_feed_lab_p5_test.go:160` | the runner's mounted rsyslog output (CWE-22) |
| `internal/server/audit_feed_rsyslog_content_lab_test.go:28` | the runner's lab CA (CWE-22) |
| `internal/server/audit_feed_rsyslog_content_lab_test.go:74` | the runner's lab output file (CWE-22) |
| `internal/server/audit_feed_syslog_mtls_lab_test.go:29` | the runner's lab CA (CWE-22) |
| `internal/server/audit_feed_syslog_mtls_lab_test.go:33` | the runner's lab client certificate and key (CWE-22) |
| `internal/server/audit_feed_syslog_mtls_lab_test.go:83` | the runner's lab output file (CWE-22) |
| `internal/server/backup.go:147` | operator-configured public trust anchor path (CWE-22) |
| `internal/server/backup.go:210` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:381` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:455` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:555` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:820` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:936` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup.go:940` | operator-invoked backup/restore over its own configured directory (CWE-22) |
| `internal/server/backup_reports.go:165` | the restore's own staging tree (CWE-22) |
| `internal/server/backup_reports.go:181` | the restore's own staging tree; names validated above (CWE-22) |
| `internal/server/backup_test.go:388` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/backup_test.go:436` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/backup_test.go:575` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/backup_test.go:1007` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/breakglass.go:173` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/breakglass_material_test.go:67` | test-owned public kit under t.TempDir (CWE-22) |
| `internal/server/bundled_pg_dependency_test.go:32` | fixed repository source path (CWE-22) |
| `internal/server/bundled_pg_dependency_test.go:46` | fixed repository source path (CWE-22) |
| `internal/server/ca_custody_test.go:91` | test-owned path verifies upgrade custody |
| `internal/server/ca_custody_test.go:95` | test-owned path verifies public mirror |
| `internal/server/ca_custody_test.go:226` | test-owned path under t.TempDir verifies fail-closed preservation (CWE-22) |
| `internal/server/ca_custody_test.go:261` | test-owned path under t.TempDir captures the planted mismatch (CWE-22) |
| `internal/server/ca_custody_test.go:269` | same test-owned path proves the mismatch was not overwritten (CWE-22) |
| `internal/server/cbom_cyclonedx_served_test.go:239` | the repository's own fixture path (CWE-22) |
| `internal/server/cmdb_readonly_test.go:126` | test reads repo source files it names itself (CWE-22) |
| `internal/server/code_signing_config.go:96` | operator-configured certificate chain path (CWE-22) |
| `internal/server/codesign_pkcs11_lab_p9_test.go:69` | the lab runner's build output (CWE-22) |
| `internal/server/decoy_files_container_lab_q6o1_test.go:50` | the lab runner's build output (CWE-22) |
| `internal/server/discovery_key_posture_test.go:18` | a fixed test fixture, named by the test itself (CWE-22) |
| `internal/server/distrust_removal_served_test.go:34` | a fixed test fixture, named by the test itself (CWE-22) |
| `internal/server/distrust_removal_served_test.go:38` | a fixed test fixture, named by the test itself (CWE-22) |
| `internal/server/distrust_removal_served_test.go:184` | the test's own temporary file (CWE-22) |
| `internal/server/dod_connector_runtime_test.go:76` | parent-created public CA fixture (CWE-22) |
| `internal/server/dynamic_secret_failure_epoch_guard_test.go:22` | closed sibling-source fixture list. |
| `internal/server/est_mtls_reenroll_served_test.go:150` | test reads its own tempdir path (CWE-22) |
| `internal/server/event_protection_backup_missing_custody_test.go:23` | exact artifact in this test's owned fixture (CWE-22) |
| `internal/server/event_protection_backup_missing_custody_test.go:33` | exact artifact in this test's owned fixture (CWE-22) |
| `internal/server/event_protection_backup_missing_custody_test.go:49` | exact original artifact in this test's owned fixture (CWE-22) |
| `internal/server/event_protection_done_when_test.go:117` | the test's own backup artifact (CWE-22) |
| `internal/server/event_protection_postgres_backup_served_test.go:35` | exact artifact in this test's owned backup directory (CWE-22) |
| `internal/server/external_poller_boundary_test.go:16` | name comes only from the closed literal source-file list above (CWE-22) |
| `internal/server/host_agent_remote_served_test.go:153` | parent-created test fixture path (CWE-22) |
| `internal/server/host_agent_remote_served_test.go:210` | parent-created public fixture (CWE-22) |
| `internal/server/host_agent_remote_served_test.go:419` | test reads its own remote-host fixture (CWE-22) |
| `internal/server/host_agent_remote_served_test.go:810` | test-owned target fixture (CWE-22) |
| `internal/server/host_keystore_credentials_served_test.go:117` | fixed filename inside this test's private TempDir (CWE-22). |
| `internal/server/host_keystore_credentials_served_test.go:166` | fixed filename inside this test's private TempDir (CWE-22). |
| `internal/server/idempotency_protection_wiring_test.go:61` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/kmip_client_registration_served_test.go:163` | test-generated TLS material in the test's temp dir (CWE-22) |
| `internal/server/lab_openldap_test.go:70` | the test's own temp file (CWE-22) |
| `internal/server/machine_session_self_end_served_test.go:207` | the test's own temp file (CWE-22) |
| `internal/server/mcp_authorization_keycloak_test.go:141` | the test's own TempDir audit log (CWE-22) |
| `internal/server/pam_agent_launcher_served_test.go:193` | what the launched agent wrote in the test's temp dir (CWE-22) |
| `internal/server/pam_agent_launcher_served_test.go:197` | what the launched agent wrote in the test's temp dir (CWE-22) |
| `internal/server/pam_desktop_served_test.go:187` | one of two fixed owned native fixture credential paths, selected by the test (CWE-22) |
| `internal/server/pam_desktop_served_test.go:460` | unique owned task file under fixed lab account home (CWE-22) |
| `internal/server/pam_desktop_served_test.go:465` | unique owned task file under fixed lab account home (CWE-22) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:46` | test reads the cluster CA its runner wrote (CWE-22) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:161` | the kubeconfig the CLI wrote for this test (CWE-22) |
| `internal/server/pam_gateway_private_ca_served_test.go:84` | the fixture's own data directory (CWE-22) |
| `internal/server/pam_gateway_served_test.go:228` | the test's own temporary files (CWE-22) |
| `internal/server/pam_gateway_ssh_served_test.go:282` | the test's own temporary files (CWE-22) |
| `internal/server/pam_served_test.go:921` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/plugins.go:199` | operator-configured plugin dir; WASM and signature are verified after the read (CWE-22) |
| `internal/server/plugins.go:203` | operator-configured plugin dir; WASM and signature are verified after the read (CWE-22) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:82` | the lab runner's build output (CWE-22) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:97` | the repository's own fixture (CWE-22) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:117` | the repository's own fixture (CWE-22) |
| `internal/server/protect_correct102_guard_test.go:122` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/server/protocol_mounts.go:755` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/protocol_mounts.go:870` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/protocol_mounts.go:987` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/protocol_mounts.go:1393` | operator-configured trust bundle path (CWE-22) |
| `internal/server/protocols_served_spiffe_ssh_test.go:602` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:228` | test reads its own tempdir fixture (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:232` | test reads its own tempdir fixture (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:326` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:616` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:629` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:763` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:769` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:53` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:193` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:198` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/server/rekor.go:46` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/response_buffer_guard_test.go:63` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/restore_consistency.go:76` | the restored backup set's own event log, under the isolated target (CWE-22) |
| `internal/server/restore_consistency.go:123` | the restored issuing CA certificate under the isolated target (CWE-22) |
| `internal/server/run.go:589` | operator-configured public recovery kit (CWE-22) |
| `internal/server/run.go:1215` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/run.go:1399` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/run.go:1860` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/run_connectors_test.go:89` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/runtime_worker_census_test.go:65` | test reads its own package directory (CWE-22) |
| `internal/server/scan_annotation_served_test.go:48` | test fixture under t.TempDir (CWE-22) |
| `internal/server/sdk_registry_install_served_test.go:330` | the test reads what it downloaded under its own temp dir (CWE-22) |
| `internal/server/sdk_registry_install_served_test.go:348` | the test reads what it installed under its own temp dir (CWE-22) |
| `internal/server/sdk_registry_install_served_test.go:352` | the test reads what it installed under its own temp dir (CWE-22) |
| `internal/server/secret_csi_restart_served_test.go:143` | the test's own temp file (CWE-22) |
| `internal/server/secret_csi_restart_served_test.go:153` | the test's own temp file (CWE-22) |
| `internal/server/secret_integrations.go:476` | the operator's own administrator DSN names this root file on the control plane's host (CWE-22) |
| `internal/server/secret_render_lease_renew_served_test.go:82` | the test's own temp file (CWE-22) |
| `internal/server/secret_render_lease_renew_served_test.go:105` | the test's own temp file (CWE-22) |
| `internal/server/secret_render_lease_renew_served_test.go:135` | the test's own temp file (CWE-22) |
| `internal/server/secret_render_lease_reuse_served_test.go:68` | the test's own temp file (CWE-22) |
| `internal/server/secret_render_lease_reuse_served_test.go:87` | the test's own temp file (CWE-22) |
| `internal/server/secret_render_login_served_test.go:70` | the test's own temp file (CWE-22) |
| `internal/server/secret_render_served_test.go:69` | the test's own temp file or the lab directory the runner created (CWE-22) |
| `internal/server/secret_render_served_test.go:324` | the test's own temp file (CWE-22) |
| `internal/server/secret_render_served_test.go:370` | the test's own temp file (CWE-22) |
| `internal/server/secret_render_served_test.go:382` | the test's own temp file (CWE-22) |
| `internal/server/secret_repository_private_clone_served_test.go:97` | the server's own temporary clone (CWE-22) |
| `internal/server/secret_scan_hooks_gitlab_bitbucket_served_test.go:42` | the server's own temporary clone (CWE-22) |
| `internal/server/secret_third_party_scan_signature_served_test.go:35` | test reads its own tempdir path (CWE-22) |
| `internal/server/serve_test.go:80` | test-owned path under t.TempDir (CWE-22) |
| `internal/server/serve_test.go:81` | test-owned path under t.TempDir (CWE-22) |
| `internal/server/serve_test.go:125` | test-owned path under t.TempDir (CWE-22) |
| `internal/server/server.go:1631` | operator-configured key file path (CWE-22) |
| `internal/server/server.go:3037` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/server.go:3114` | same operator-configured directory as the target certificate (CWE-22) |
| `internal/server/soar_playbooks_served_test.go:62` | the repository's own SOAR pack (CWE-22) |
| `internal/server/soar_playbooks_served_test.go:72` | a playbook the repository's own pack names (CWE-22) |
| `internal/server/ssh_krl_adoption_served_test.go:36` | test-owned KRL path under t.TempDir |
| `internal/server/tenant_key_domain_kms_served_test.go:164` | the fixture adapter's log in the test tempdir (CWE-22) |
| `internal/server/tsa_certificates_served_test.go:87` | the test's own temp file (CWE-22) |
| `internal/server/upgrade_preflight_json_test.go:48` | the package's own golden file (CWE-22) |
| `internal/server/vault_dynamic_credentials_cloud_test.go:156` | test reads the cluster CA its runner wrote (CWE-22) |
| `internal/signing/ceremony_test.go:129` | the test's own temporary journal directory (CWE-22) |
| `internal/signing/design_test.go:30` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/design_test.go:137` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/gated_destruction_journal.go:252` | exact signer-owned journal path. |
| `internal/signing/hardening_contract_test.go:55` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/keyimport.go:95` | path passed the explicit signer-keystore confinement check above (CWE-22) |
| `internal/signing/keystore.go:346` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/signing/keystore.go:428` | path joins a sanitized handle to the signer-owned 0700 keystore (CWE-22). |
| `internal/signing/keystore_test.go:139` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/keystore_test.go:229` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/signing/legacy_migration.go:32` | signer operator supplies the one legacy migration path |
| `internal/signing/managedkeys.go:359` | the signer's own journal directory from its config (CWE-22) |
| `internal/signing/managedkeys.go:754` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/signing/managedkeys.go:897` | the signer's own keystore/journal directory from its config (CWE-22) |
| `internal/signing/managedkeys_test.go:553` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/signing/offline_breakglass.go:290` | path is the signer-owned offline vault journal or kit (CWE-22) |
| `internal/signing/offline_lock_unix.go:14` | fixed lock name under dedicated operator-selected offline vault (CWE-22) |
| `internal/signing/revocation.go:105` | path passed the explicit signer-keystore confinement check above (CWE-22) |
| `internal/signing/rewrap.go:231` | the operator's own key store and its staging copy (CWE-22) |
| `internal/signing/rewrap_binary_test.go:72` | the test's own temp key store (CWE-22) |
| `internal/signing/rewrap_test.go:102` | the test's own temp key store (CWE-22) |
| `internal/spireupstream/plugin.go:381` | operator-configured public CA bundle path (CWE-22) |
| `internal/spireupstream/plugin.go:466` | operator-configured upstream-authority plugin config path (CWE-22) |
| `internal/store/dynamic_secret_lock_order_test.go:124` | fixed sibling path inside this package's own directory (CWE-22) |
| `internal/store/keyset_order_test.go:43` | the package's own source files (CWE-22) |
| `internal/store/migration_safety_test.go:87` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/store/store_isolation_test.go:418` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/store/store_isolation_test.go:466` | test reads its own fixture/tempdir path (CWE-22, CWE-367) |
| `internal/succession/delegation/durable.go:253` | signer-owned keystore directory selected at signer startup; fsync makes the scope rename durable (CWE-22) |
| `internal/succession/minter/spentstore.go:70` | signer-owned custody directory selected at signer startup (CWE-22). |
| `internal/succession/minter/spentstore.go:113` | claim path is signer-owned custody dir plus a fixed SHA-256 hex nonce digest (CWE-22). |
| `internal/supportbundle/supportbundle.go:438` | operator-invoked support bundle collecting its configured files (CWE-22) |
| `internal/supportbundle/supportbundle_test.go:97` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/supportbundle/supportbundle_test.go:101` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/supportbundle/supportbundle_test.go:151` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/telemetry/instanceid.go:21` | fixed instance-id file under the configured data dir (CWE-22) |
| `internal/tenantseal/deployment_rotation.go:395` | operator-configured deployment file paths (CWE-22) |
| `internal/transit/persist.go:271` | the store's own sealed state file (CWE-22) |
| `internal/transit/persist_test.go:118` | reads the test's own sealed keyring file (CWE-22) |
| `internal/tsa/http_test.go:52` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/tsa/http_test.go:107` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/tsa/http_test.go:112` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/tsa/tsa_rfc3161_test.go:136` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/webui/source_digest_test.go:63` | console build inputs inside the repository (CWE-22) |
| `internal/webui/source_digest_test.go:70` | fixed repository path (CWE-22) |
| `scripts/perf/cmd/capacitycalibrate/main.go:350` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `scripts/perf/cmd/soakcapture/main_test.go:72` | test reads its own fixture/tempdir path (CWE-22) |
| `scripts/perf/cmd/soakgate/main.go:130` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `scripts/perf/cmd/soakgate/main_test.go:56` | test reads its own fixture/tempdir path (CWE-22) |
| `scripts/perf/cmd/soakgate/main_test.go:139` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/cbomcoveragedoc/main.go:66` | operator/CI-supplied path to this repo's own generated page (CWE-22) |
| `tools/connectorsupportdoc/main.go:45` | fixed in-tree doc paths (CWE-22) |
| `tools/connectorsupportdoc/main_test.go:25` | fixed in-tree doc paths (CWE-22) |
| `tools/connectorsupportdoc/main_test.go:105` | fixed in-tree documentation contract |
| `tools/dodcensus/artifact.go:85` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/artifact.go:167` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/claims.go:64` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/claims.go:75` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/claims.go:79` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/kubernetes_posture_manifest_test.go:18` | test reads the exact committed runtime-proof source (CWE-22) |
| `tools/dodcensus/main.go:536` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/main_test.go:519` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:538` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:557` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:578` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:603` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:634` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:657` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:706` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/main_test.go:1180` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_closure.go:56` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:149` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:214` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:294` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:320` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:345` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:397` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:408` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:431` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:477` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:664` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/proof/launched.go:420` | gate-owned private directory created above (CWE-22) |
| `tools/dodcensus/proof/launched.go:592` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:1324` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2103` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2217` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2312` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2459` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2538` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/launched.go:2792` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:213` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:322` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:1086` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:1224` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime.go:133` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:154` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:225` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:439` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:1141` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime.go:1495` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:99` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:714` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:853` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner.go:897` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:387` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:535` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:589` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:593` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/dodcensus/secret_integrations_manifest_test.go:126` | test reads the exact committed substrate source (CWE-22) |
| `tools/dodcensus/secret_integrations_manifest_test.go:158` | test reads the exact committed runtime proof source (CWE-22) |
| `tools/dodcensus/shard.go:43` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/dodcensus/shard.go:198` | developer tool reading the shard receipts it is pointed at (CWE-22) |
| `tools/editionledger/main.go:43` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/editionledger/main.go:56` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/featureparityreport/main.go:49` | explicit operator-selected local report output |
| `tools/pqclab/main.go:204` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/pqclab/main.go:269` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/pqclab/main_test.go:49` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/pqclab/main_test.go:53` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/sdkpack/registry/ecosystems.go:79` | this registry directory's own list (CWE-22) |
| `tools/sdkpack/registry/ecosystems.go:167` | the SDK's own pyproject.toml in the checkout (CWE-22) |
| `tools/sdkpack/registry/ecosystems.go:175` | the SDK's own README in the checkout (CWE-22) |
| `tools/sdkpack/registry/ecosystems.go:244` | a wheel in this registry directory (CWE-22) |
| `tools/sdkpack/registry/ecosystems.go:273` | the npm pack output the release script names (CWE-22) |
| `tools/sdkpack/registry/ecosystems.go:305` | this registry directory's own document (CWE-22) |
| `tools/sdkpack/registry/ecosystems.go:397` | the jar and pom the release script built (CWE-22) |
| `tools/sdkpack/registry/handler.go:74` | a fixed directory and an escaped package name with no parent references (CWE-22) |
| `tools/sdkpack/registry/registry.go:61` | a file this tool just wrote under the operator's output directory (CWE-22) |
| `tools/sdkpack/registry/registry.go:99` | the registry directory's own manifest (CWE-22) |
| `tools/sdkpack/registry/registry.go:150` | a tracked file the release script listed (CWE-22) |
| `tools/sdkpack/registry/registry.go:165` | the operator's file list (CWE-22) |
| `tools/sdkpack/registry/registry_test.go:98` | the test reads files it wrote under its own temp dir (CWE-22) |
| `tools/sdkpack/registry/registry_test.go:191` | the test reads files it wrote under its own temp dir (CWE-22) |
| `tools/sdkpack/registry/registry_test.go:290` | the test reads files it wrote under its own temp dir (CWE-22) |
| `tools/sdkpack/registry/registry_test.go:348` | the test reads files it wrote under its own temp dir (CWE-22) |
| `tools/sdkpack/registry/registry_test.go:352` | the test reads files it wrote under its own temp dir (CWE-22) |
| `tools/sdkpack/registry/registry_test.go:356` | the test reads files it wrote under its own temp dir (CWE-22) |
| `tools/siempack/main.go:60` | the operator's own output path (CWE-22) |
| `tools/siempack/main.go:65` | a listed file of the pack (CWE-22) |
| `tools/siempack/main_test.go:30` | test reads the repo's own shipped content (CWE-22) |
| `tools/siempack/main_test.go:105` | test reads the repo's own shipped content (CWE-22) |
| `tools/trstctllint/docs_test.go:75` | test reads its own fixture/tempdir path (CWE-22) |
| `tools/trstctllint/licenseboundary/licenseboundary.go:38` | developer tool reading the repo paths it is pointed at (CWE-22) |
| `tools/trstctllint/upsertarbiter/sites_dump_test.go:30` | test-only maintenance dump to an operator-chosen path (CWE-22) |
| `tools/trstctllint/upsertarbiter/upsertarbiter.go:287` | migration files under the repository store package (CWE-22) |
| `tools/trstctllint/upsertarbiter/upsertarbiter_test.go:66` | test-only baseline dump to a path the operator chose via UPSERTARBITER_BASELINE_OUT (CWE-22) |

### G306 — CWE-276 Incorrect default permissions (file write) (138 sites)

| Location | Reason |
|---|---|
| `clients/signing/cmd/trstctl-ksp-register/main.go:88` | System32 images are world-readable; only administrators write there |
| `cmd/trstctl-agent/bootstrap_token_test.go:231` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/edgeca_test.go:312` | deliberately loose fixture proves atomic replacement tightens the mode |
| `cmd/trstctl-agent/host_profile_census_test.go:19` | fixture executable written by this test (CWE-276) |
| `cmd/trstctl-agent/ssh_trust_fleet_policy_test.go:36` | executable fixture owned by this test; its executable bit is the behavior under test (CWE-276). |
| `cmd/trstctl-agent/ssh_trust_fleet_policy_test.go:50` | replace the owned executable fixture while retaining its mode (CWE-276). |
| `cmd/trstctl-agent/ssh_trust_fleet_policy_test.go:90` | owned executable fixture needed to check error-output suppression (CWE-276). |
| `cmd/trstctl-agent/sshkrl_test.go:58` | public KRL fixture checks the operator's existing mode |
| `cmd/trstctl-agent/sshtrust_test.go:82` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:131` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:158` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:182` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-agent/sshtrust_test.go:224` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `cmd/trstctl-license/main.go:67` | writes the license PUBLIC key/inspection output; public material (CWE-276) |
| `cmd/trstctl-trustbundle/main.go:88` | a public trust bundle at a build-time path (CWE-276) |
| `cmd/trstctl-trustbundle/main.go:96` | build evidence at a build-time path, not a secret (CWE-276) |
| `cmd/trstctl-trustbundle/main.go:185` | audit evidence at an operator path (CWE-276) |
| `cmd/trstctl/backup_cmd_test.go:31` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `deploy/docker/dist_test.go:1115` | non-secret npm fixture manifest in t.TempDir (CWE-276) |
| `deploy/docker/dist_test.go:1118` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `deploy/docker/dist_test.go:1158` | fake npm shim in a test tempdir must be executable (CWE-276) |
| `deploy/helm/airgap_bundle_test.go:149` | the executable is a disposable fake Docker client inside this test's private temporary directory. |
| `docs/lint_gate_test.go:91` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `ee/managedkeys/signerwiring/tenantkek_kms_test.go:61` | fixture script in a test tempdir; the mode is part of the fixture (CWE-276) |
| `ee/provider/oidc_login_keycloak_test.go:77` | lab realm with lab-only credentials, read by the container (CWE-276) |
| `internal/agent/destination/fs_unix_test.go:57` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/discovery/discovery_test.go:273` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/discovery/privatekey_test.go:34` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:26` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:73` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:109` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:169` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_test.go:226` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/drift/drift_unix_test.go:81` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) (world-readable) |
| `internal/agent/relay/adcsdatabase_test.go:52` | a test-owned executable stand-in (CWE-276). |
| `internal/agent/relay/adcsdatabase_test.go:259` | a test-owned executable stand-in (CWE-276). |
| `internal/agent/relay/adcsdecide_test.go:47` | a test-owned executable stand-in (CWE-276). |
| `internal/agent/relay/adcsrevoke_test.go:46` | a test-owned executable stand-in (CWE-276). |
| `internal/agent/relay/recovery_check_test.go:31` | the fixture IS an executable; 0755 is its required mode (CWE-276) |
| `internal/agent/relay/selfupgrade_test.go:35` | the fixture IS an executable; 0755 is its required mode (CWE-276) |
| `internal/agent/secretrender/replace_windows_test.go:26` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/sshdiscovery/sshdiscovery_test.go:29` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/agent/sshkrl/install_test.go:61` | public KRL fixture checks that mode is preserved |
| `internal/agent/sshkrl/install_unix_test.go:27` | a public KRL fixture (committed testdata bytes) written under t.TempDir; sshd lists are world-readable |
| `internal/agent/transport/regen_schema_test.go:43` | committed wire contract fixture, reviewed in the diff (CWE-276) |
| `internal/api/openapi_golden_test.go:62` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/api/vault_compat_contract_test.go:249` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/backup/full_manifest_io_test.go:23` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:241` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:254` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/cbom/hostsource/hostsource_test.go:23` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/cli/cbom_scan_test.go:24` | the stand-in scanner must be executable (CWE-276) |
| `internal/cli/cbom_scan_test.go:41` | executable stand-in (CWE-276) |
| `internal/cli/cli_test.go:2664` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/cli/secret_scan_local.go:137` | a git hook must be executable; 0755 is the working minimum (CWE-276) |
| `internal/connector/localops_test.go:159` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/connector/wasm/host/gen/main.go:52` | a public build artifact at a fixed repository path (CWE-276, CWE-22). |
| `internal/connector/wasm/host/gen/main.go:56` | a public digest at a fixed repository path (CWE-276, CWE-22). |
| `internal/crypto/external_kms_test.go:90` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/crypto/mtls/agent.go:206` | certificate chain PEM is public material; the key is written 0600 separately (CWE-276) |
| `internal/crypto/mtls/signer.go:209` | writes the PUBLIC CA trust anchor bundle; world-readable is intended, no key material (CWE-276) |
| `internal/crypto/mtls/signer.go:322` | writes the PUBLIC leaf certificate chain; the private key beside it is written 0600 (CWE-276) |
| `internal/crypto/secretfile/custody_windows_test.go:36` | public fixture contents (CWE-276) |
| `internal/crypto/secretfile/secretfile_test.go:48` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/crypto/tenantwrap/tenantwrap_test.go:110` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/crypto/tlsprobe/native_fallback_test.go:53` | fixture executable written by this test (CWE-276) |
| `internal/kmip/pykmip_client_test.go:69` | test-named files in the test's temp dir, readable by the container user (CWE-22, CWE-276) |
| `internal/kmip/pykmip_tenants_test.go:72` | test-named files in the test's temp dir, readable by the container user (CWE-22, CWE-276) |
| `internal/projections/cbom_store_test.go:38` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/projections/discovery_store_test.go:93` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/projections/discovery_store_test.go:96` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:225` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/protocols/ssh/ssh_test.go:63` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/reconcile/conformance/ca_ledgers_e2e_test.go:423` | step-ca's lab config, read by the container's user (CWE-276) |
| `internal/reconcile/kmipsource_pykmip_test.go:67` | test-named files in the test's temp dir, readable by the container's server user (CWE-22, CWE-276) |
| `internal/reconcile/kmipsource_pykmip_test.go:80` | a public certificate (CWE-276) |
| `internal/reconcile/kmipsource_pykmip_test.go:90` | test server configuration (CWE-276) |
| `internal/secrets/vault_test.go:147` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/secrets/vault_test.go:180` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/secretscan/gitleaks_options_test.go:72` | executable is an isolated test fixture |
| `internal/secretscan/gitleaks_options_test.go:178` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/secretscan/installer_retry_test.go:183` | a test-owned executable stand-in (CWE-276). |
| `internal/server/adcs_database_collect_served_test.go:42` | a test-owned executable stand-in (CWE-276). |
| `internal/server/adcs_decisions_served_test.go:50` | a test-owned executable stand-in (CWE-276). |
| `internal/server/adcs_pending_requests_served_test.go:103` | a test-owned executable stand-in (CWE-276). |
| `internal/server/adcs_revoke_relay_served_test.go:121` | a test-owned executable stand-in (CWE-276). |
| `internal/server/agent_workload_api_darwin_path_test.go:56` | test copies its own executable fixture (CWE-22) |
| `internal/server/auth_unit_test.go:64` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/cbom_served_test.go:151` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/codesign_cosign_lab_p9_test.go:58` | a public payload, signature and keys the cosign container reads (CWE-22) |
| `internal/server/codesign_cosign_rekor_lab_p9l2_test.go:88` | public payload, signature, bundle and keys the cosign container reads (CWE-22) |
| `internal/server/codesign_pkcs11_lab_p9_test.go:40` | public lab inputs the tool containers read (CWE-22) |
| `internal/server/decoy_files_container_lab_q6o1_test.go:39` | disposable lab inputs the container reads (CWE-22) |
| `internal/server/decoy_kubernetes_kind_lab_q6o2_test.go:70` | disposable lab configuration the kind node reads (CWE-22) |
| `internal/server/dod_connector_runtime_test.go:817` | public CA fixture (CWE-276) |
| `internal/server/host_agent_remote_served_test.go:390` | public CA certificate fixture (CWE-276) |
| `internal/server/host_agent_remote_served_test.go:616` | public CA fixture (CWE-276) |
| `internal/server/lab_openldap_test.go:105` | the container's directory server reads it; the key is a throwaway lab key (CWE-276) |
| `internal/server/mcp_authorization_keycloak_test.go:248` | public realm configuration the container reads (CWE-276) |
| `internal/server/mcp_authorization_keycloak_test.go:252` | public cache configuration the container reads (CWE-276) |
| `internal/server/pam_served_test.go:845` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/pam_served_test.go:857` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:60` | public lab inputs the containers read (CWE-22) |
| `internal/server/protocols_served_spiffe_ssh_test.go:527` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_spiffe_ssh_test.go:581` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:574` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/secrets_scan_served_test.go:27` | isolated executable test fixture |
| `internal/server/secrets_scan_served_test.go:157` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/server.go:3120` | served CA certificate PEM is public material (CWE-276) |
| `internal/server/signer_authorization_test.go:132` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/signer_authorization_test.go:192` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/ssh_certificate_lease_served_test.go:76` | public CA/KRL fixture in a test tempdir (CWE-276) |
| `internal/server/ssh_certificate_lease_served_test.go:107` | a public certificate in a test tempdir (CWE-276) |
| `internal/server/ssh_journey_served_test.go:277` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/server/tenant_key_domain_kms_served_test.go:156` | fixture script in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/signing/keystore_test.go:274` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/signing/signauth_secret_test.go:47` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `internal/testutil/openssltest/openssltest_test.go:14` | fake openssl shim must be executable; 0700 is the minimum that runs (CWE-276) |
| `scripts/gen-terraform-provider-routes/main.go:92` | generated Go source committed to the repo; world-readable by design (CWE-276) |
| `scripts/perf/cmd/capacitycalibrate/main.go:140` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/capacitycalibrate/main_test.go:183` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `scripts/perf/cmd/perfgate/main.go:55` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/scalegate/main.go:55` | developer tool writing a run receipt; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakcapture/main.go:85` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/soakgate/main.go:123` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `scripts/perf/cmd/spineburst/main.go:173` | developer tool writing repo/dist artifacts; the mode is intentional (CWE-276) |
| `tools/dodcensus/proof/artifact_watch_linux_test.go:65` | private test fixture (CWE-276) |
| `tools/dodcensus/proof/artifact_watch_linux_test.go:91` | private test fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:264` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:283` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:313` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:398` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:411` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:432` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/dodcensus/proof/proof_test.go:435` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/editionledger/main.go:65` | a public documentation file (CWE-276) |
| `tools/trstctllint/eventsource/eventsource_test.go:101` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |
| `tools/trstctllint/idempotency/idempotency_test.go:241` | fixture file in a test tempdir; the mode is part of the fixture (CWE-276) |

### G401 — CWE-328 Use of weak hash (20 sites)

| Location | Reason |
|---|---|
| `internal/crypto/certinfo/certinfo.go:421` | display/lookup fingerprint in the industry-standard form; not a security control (CWE-328) |
| `internal/crypto/deviceattest/cvc.go:370` | verifying a CV signature that names SHA-1 (CWE-327) |
| `internal/crypto/jks/jceks.go:68` | the JCEKS integrity digest is SHA-1 by definition; verification only (CWE-328) |
| `internal/crypto/leafca.go:743` | RFC 5280 4.2.1.2 method-1 SKID: an identifier, not integrity (CWE-328) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:379` | mysql_native_password, when the server demands it (CWE-327) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:380` | mysql_native_password (CWE-327) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:381` | mysql_native_password (CWE-327) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:417` | the OAEP hash MySQL servers use (CWE-327) |
| `internal/crypto/opaque_x509.go:274` | RFC 5280 4.2.1.2 method-1 SKID: an identifier, not integrity (CWE-328) |
| `internal/crypto/pgsignin/pgsignin.go:308` | PostgreSQL's md5 password exchange, as the server demands it (CWE-327) |
| `internal/crypto/pgsignin/pgsignin.go:313` | PostgreSQL's md5 password exchange, as the server demands it (CWE-327) |
| `internal/crypto/pgsignin/pgsignin_test.go:166` | the test recomputes PostgreSQL's md5 password exchange (CWE-327) |
| `internal/crypto/pqc_x509.go:96` | key identifier, not integrity (CWE-328) |
| `internal/crypto/thumbprint.go:15` | an identifier a CA API requires, not integrity (CWE-328) |
| `internal/crypto/tsa.go:187` | RFC 5816 ESSCertIDv1 is defined over SHA-1; identifier only, v2 uses SHA-256 (CWE-328) |
| `internal/crypto/tsa_verify.go:115` | RFC 5816 ESSCertIDv1 certificate identifier, not a signature digest (CWE-328) |
| `internal/crypto/uuidv5.go:20` | RFC 4122 UUIDv5 public identifier, not a security digest. |
| `internal/crypto/weakkey/weakkey.go:139` | Debian blocklist entry format, not a security use of SHA-1 (CWE-328) |
| `internal/crypto/weakkey/weakkeytest/rsa.go:51` | Debian blocklist entry format, not a security use of SHA-1 (CWE-328) |
| `internal/crypto/websocket_accept.go:17` | RFC 6455 handshake identifier, not integrity (CWE-328) |

### G402 — CWE-295 Improper certificate validation (InsecureSkipVerify) (9 sites)

| Location | Reason |
|---|---|
| `internal/crypto/mtls/mtls.go:373` | operator-selected lab escape hatch, off by default, and |
| `internal/crypto/mtls/rawclient_test.go:101` | the test server models a KMIP server whose TLS stops at 1.2 (CWE-327) |
| `internal/crypto/mtls/reload_test.go:64` | reload probe of the test's own loopback listener; reads only the served serial, carries no data (CWE-295) |
| `internal/crypto/mtls/server_test.go:251` | test TLS client speaking to the test's own server (CWE-295) |
| `internal/crypto/mtls/tls_floor_test.go:34` | loopback test dial against the test's own self-signed server (CWE-295) |
| `internal/crypto/tlsprobe/native_fallback_test.go:24` | interoperability fixture pins TLS 1.2 to prove the native fallback preserves an existing supported listener. |
| `internal/crypto/tlsprobe/openssl_test.go:59` | negative control: this fixture must reject the TLS 1.3-only native probe. |
| `internal/crypto/tlsprobe/tlsprobe.go:203` | discovery inventories whatever cert is served; the connection is never trusted and never carries data (CWE-295) |
| `internal/crypto/trust/tls_test.go:140` | the test proves the check runs with verification off (CWE-295) |

### G403 — CWE-326 Inadequate encryption strength (RSA key size) (4 sites)

| Location | Reason |
|---|---|
| `internal/crypto/jose/bounds_test.go:52` | deliberately undersized key; the test proves the verifier refuses it (CWE-326) |
| `internal/crypto/keyinspect_test.go:121` | a deliberately weak RSA-1024 key, to prove it is named and rated weak (CWE-326) |
| `internal/crypto/possession_test.go:283` | a throwaway test root key |
| `internal/crypto/weakkey/weakkey_test.go:413` | a deliberately weak RSA-1024 key, to prove it is rated weak (CWE-326) |

### G404 — CWE-338 Cryptographically weak PRNG (36 sites)

| Location | Reason |
|---|---|
| `clients/sdk/go/trstctl/client.go:303` | dedup token bound server-side to the caller's request, not a secret; the SDK stays outside the crypto boundary by design (CRYPTO-101) (CWE-338) |
| `clients/sdk/go/trstctl/client.go:304` | dedup token bound server-side to the caller's request, not a secret; the SDK stays outside the crypto boundary by design (CRYPTO-101) (CWE-338) |
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
| `cmd/trstctl-agent/main.go:940` | reconnect jitter, not a security decision (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:28` | jitter spread, not a security decision (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:61` | jitter spread (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:77` | jitter spread (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:88` | jitter spread (CWE-338) |
| `cmd/trstctl-agent/rotation_schedule_test.go:105` | jitter spread (CWE-338) |
| `internal/agent/k8s/informer.go:208` | reconnect jitter, not a security decision (CWE-338) |
| `internal/cli/cli.go:699` | idempotency-key uniqueness suffix; deliberately outside the AN-3 boundary, not a secret (CWE-338) |
| `internal/crypto/scep_property_test.go:145` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/scep_property_test.go:184` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/sshkeys/property_test.go:100` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/sshkeys/property_test.go:162` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/x509_property_test.go:126` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/crypto/x509_property_test.go:175` | deterministic property-test name, not security randomness (CWE-338) |
| `internal/crypto/x509_property_test.go:196` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/discovery/adcs/membership_paths_test.go:48` | deterministic property-test permutations, never a cryptographic choice (CWE-330). |
| `internal/discovery/cloudsecret/generic_entropy_test.go:18` | a seeded fixture generator: reproducible test data, not a secret (CWE-338) |
| `internal/orchestrator/outbox.go:490` | retry backoff jitter, not a security decision (CWE-338) |
| `internal/protocols/acme/property_test.go:90` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/protocols/acme/property_test.go:144` | deterministic property-test stream, not security randomness (CWE-338) |
| `internal/protocols/ari/ari.go:94` | deterministic per-certificate renewal jitter (int64 seed reinterpreted for the PCG); scheduling spread, not a security decision (CWE-338, CWE-190) |
| `internal/query/adversarial_test.go:223` | test jitter/shuffle, not a security decision (CWE-338) |
| `internal/query/filter_test.go:150` | test shuffle, not a security decision (CWE-338) |
| `internal/server/secret_store_generic_entropy_served_test.go:26` | a seeded fixture generator: reproducible test data, not a secret (CWE-338) |

### G405 — CWE-? (unmapped rule) (1 sites)

| Location | Reason |
|---|---|
| `internal/crypto/pfx/certonly.go:308` | decrypting a legacy file's certificate contents only (CWE-327) |

### G501 — CWE-? (unmapped rule) (2 sites)

| Location | Reason |
|---|---|
| `internal/crypto/pgsignin/pgsignin.go:18` | PostgreSQL's md5 password exchange, used only when the server demands it (CWE-327) |
| `internal/crypto/pgsignin/pgsignin_test.go:7` | the test recomputes PostgreSQL's md5 password exchange (CWE-327) |

### G502 — CWE-? (unmapped rule) (1 sites)

| Location | Reason |
|---|---|
| `internal/crypto/pfx/certonly.go:9` | legacy PKCS#12 files encrypt their certificate contents with 3DES; reading them needs it, and nothing here encrypts (CWE-327) |

### G504 — CWE-? (unmapped rule) (2 sites)

| Location | Reason |
|---|---|
| `internal/secretscan/repository_credential_test.go:11` | test-only stand-in host: serves the local git-http-backend; the toolchain is far past the CVE-2016-5386 fix (CWE-284) |
| `internal/server/secret_repository_private_clone_served_test.go:14` | test-only stand-in host: serves the local git-http-backend; the toolchain is far past the CVE-2016-5386 fix (CWE-284) |

### G505 — CWE-328 Weak hash import (SHA-1) (16 sites)

| Location | Reason |
|---|---|
| `internal/crypto/certinfo/certinfo.go:15` | SHA-1 only for the conventional certificate fingerprint identifier, never integrity (CWE-328) |
| `internal/crypto/deviceattest/cvc.go:11` | a card-verifiable certificate may name ECDSA/RSA with SHA-1; verified only, never produced (CWE-327) |
| `internal/crypto/jks/jceks.go:7` | a JCEKS keystore's integrity digest is defined over SHA-1; this only verifies existing files (CWE-328) |
| `internal/crypto/leafca.go:7` | SHA-1 only for RFC 5280 4.2.1.2 method-1 Subject Key Identifier derivation (CWE-328) |
| `internal/crypto/mysqlsignin/mysqlsignin.go:17` | MySQL's mysql_native_password and the RSA-OAEP padding its servers use (CWE-327) |
| `internal/crypto/opaque_x509.go:14` | SHA-1 only for RFC 5280 4.2.1.2 method-1 Subject Key Identifier derivation (CWE-328) |
| `internal/crypto/otp.go:7` | RFC 6238 TOTP's default HMAC hash, used as an HMAC, not a collision-resistant digest (CWE-327) |
| `internal/crypto/pfx/certonly.go:12` | the PKCS#12 KDF, legacy MACs and PBES2 default PRF are defined over SHA-1; this only verifies and decrypts existing files (CWE-328) |
| `internal/crypto/pqc_x509.go:6` | RFC 5280 4.2.1.2 method-1 key identifiers only (CWE-328) |
| `internal/crypto/thumbprint.go:6` | a certificate's SHA-1 thumbprint is the identifier some CA APIs address it by; it proves nothing (CWE-328) |
| `internal/crypto/tsa.go:20` | RFC 5816 ESSCertIDv1 is defined over SHA-1; identifier only, v2 uses SHA-256 (CWE-328) |
| `internal/crypto/tsa_verify.go:7` | RFC 5816 ESSCertIDv1 certificate identifier, not a signature digest (CWE-328) |
| `internal/crypto/uuidv5.go:6` | RFC 4122 UUIDv5 uses SHA-1 only for a public identity label, never integrity (CWE-328). |
| `internal/crypto/weakkey/weakkey.go:24` | the Debian blocklist format is defined over SHA-1 of the modulus text; not used for security (CWE-328) |
| `internal/crypto/weakkey/weakkeytest/rsa.go:8` | Debian's blocklist format is defined over SHA-1; not a security use (CWE-328) |
| `internal/crypto/websocket_accept.go:6` | RFC 6455 4.2.2 fixes SHA-1 for the WebSocket handshake's accept value: an identifier, not integrity (CWE-328) |

### G602 — CWE-118 Incorrect access of indexable resource (6 sites)

| Location | Reason |
|---|---|
| `internal/auth/tenantmap_test.go:118` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `internal/crypto/ctlog/ctlog_test.go:134` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `internal/crypto/quicinitial/quicinitial.go:145` | i < pnLen <= 4, and the mask is one 16-byte AES block (CWE-129) |
| `internal/projections/graph_api_test.go:268` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `internal/server/issuance_dispatcher_test.go:1481` | fixed-shape test data; the index is in range by construction (CWE-118) |
| `tools/dodcensus/managed_key_closure.go:733` | fixed-shape data inside a developer tool (CWE-118) |

### G702 — CWE-78 OS command injection (taint) (50 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/selfrestart_unix.go:23` | re-exec of this process's OWN executable path with its own args; the binary at that path was just digest-verified against the campaign's pinned sha256 (CWE-78) |
| `ee/auditcompliance/protected_archive_minio_fixture_test.go:42` | test runs a fixed local tool with the image the operator named (CWE-78) |
| `internal/agent/discovery/pkcs11_softhsm_real_test.go:41` | fixed test-harness invocation of the OpenSC tool; the module path, token label and PIN come from the container harness environment, not from a request (CWE-78) |
| `internal/agent/sessionobserve/observer_linux_test.go:101` | the proof's own traffic script, named by the proof runner (CWE-78) |
| `internal/crypto/ssh_signin_report_windows_test.go:33` | the fixed report script this test proves, run on the test host (CWE-78) |
| `internal/crypto/windependents/rotation_native_windows_test.go:279` | exact compiler-output digest verified by the parent; absolute regular lab binary, fixed argv, no shell or credential argument (CWE-78) |
| `internal/netconfine/netconfine_linux.go:70` | runs the launcher's own command line verbatim, without a shell, inside the confined network (CWE-78) |
| `internal/objectstore/minio_lock_test.go:43` | test runs a fixed local tool with the image the operator named (CWE-78) |
| `internal/protocols/est/differential_test.go:101` | test executes a fixed local tool or fixture it built itself (CWE-78) (-g: get cacerts) |
| `internal/server/archive_minio_served_test.go:45` | test runs a fixed local tool with the image the operator named (CWE-78) |
| `internal/server/audit_feed_lab_p5_test.go:226` | the runner's own lab container (CWE-78) |
| `internal/server/audit_feed_lab_p5_test.go:233` | the runner's own lab container (CWE-78) |
| `internal/server/cloud_workload_replacement_served_test.go:141` | validated 64-hex owned test container ID and constant stock-client program, separate argv, no shell (CWE-78) |
| `internal/server/codesign_cosign_lab_p9_test.go:67` | the lab runner names the network and the local cosign image (CWE-78) |
| `internal/server/codesign_cosign_rekor_lab_p9l2_test.go:101` | the lab runner names the network and the local cosign image (CWE-78) |
| `internal/server/codesign_notation_lab_p9_test.go:73` | the lab runner names the verified Notation binary (CWE-78) |
| `internal/server/codesign_pkcs11_lab_p9_test.go:83` | the lab runner names the local tool images (CWE-78) |
| `internal/server/decoy_files_container_lab_q6o1_test.go:44` | docker with the lab's own arguments and the runner's image (CWE-78) |
| `internal/server/decoy_kubernetes_kind_lab_q6o2_test.go:148` | kind and kubectl with the lab's own arguments (CWE-78) |
| `internal/server/est_libest_served_tls_policy_test.go:71` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/est_mtls_reenroll_served_test.go:143` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/pam_command_clickhouse_served_test.go:68` | stock curl against this test's owned tunnel (CWE-78) |
| `internal/server/pam_command_mongo_served_test.go:72` | stock Mongo shell against this test's owned tunnel (CWE-78) |
| `internal/server/pam_command_mysql_served_test.go:67` | stock client against this test's owned tunnel (CWE-78) |
| `internal/server/pam_command_redis_served_test.go:59` | stock Redis client against this test's owned tunnel (CWE-78) |
| `internal/server/pam_gateway_aws_console_served_test.go:166` | stock curl is confined to owned loopback gateway/federation fixtures; private body travels on stdin (CWE-78) |
| `internal/server/pam_gateway_azure_served_test.go:87` | stock curl uses only the test-owned credential-free gateway tunnel (CWE-78) |
| `internal/server/pam_gateway_clickhouse_served_test.go:125` | the stock curl against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_gcp_served_test.go:86` | stock curl uses only the test-owned credential-free gateway tunnel (CWE-78) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:171` | the stock kubectl against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:194` | the stock kubectl against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_mongo_served_test.go:142` | the stock mongosh against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_mysql_served_test.go:164` | the stock mysql client against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_redis_served_test.go:107` | the stock redis-cli against the test's own tunnel (CWE-78) |
| `internal/server/pam_gateway_snowflake_served_test.go:101` | stock curl against the test-owned gateway tunnel (CWE-78) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:68` | docker with the lab's own arguments and the runner's image (CWE-78) |
| `internal/server/protocols_served_stock_clients_test.go:302` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/redfish_mockup_served_test.go:79` | the interpreter and checkout the CI lab names, fixed arguments (CWE-78) |
| `internal/server/revocation_openssl_test.go:184` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/secret_csi_lab_a238_test.go:44` | the runner's own lab cluster and node (CWE-78) |
| `internal/server/secret_csi_lab_a238_test.go:134` | the runner's own lab cluster (CWE-78) |
| `internal/server/secret_csi_lab_a238_test.go:177` | the runner's own lab cluster (CWE-78) |
| `internal/server/secret_dynamic_lease_rotation_container_test.go:60` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `internal/server/ssh_certificate_lease_served_test.go:62` | test executes a fixed local tool on its own temp files (CWE-78) |
| `internal/server/token_exchange_lab_m4_test.go:36` | the runner's own lab cluster (CWE-78) |
| `internal/server/token_exchange_lab_m4_test.go:70` | the runner's own lab cluster (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1173` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1215` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/proof/proof_test.go:1299` | test executes a fixed local tool or fixture it built itself (CWE-78) |
| `tools/dodcensus/runtime_runner.go:956` | developer tool running fixed toolchain commands over the repo (CWE-78) |

### G703 — CWE-22 Path traversal (taint) (164 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl-agent/sshtrust_report_test.go:56` | committed stock KRL fixture bytes written under t.TempDir (CWE-22) |
| `cmd/trstctl-license/main.go:151` | vendor operator explicitly selects the local CLI output path (CWE-22) |
| `cmd/trstctl-trustbundle/main.go:85` | build-time output path named by the image build (CWE-22) |
| `cmd/trstctl-trustbundle/main.go:88` | a public trust bundle at a build-time path (CWE-276) |
| `cmd/trstctl-trustbundle/main.go:96` | build evidence at a build-time path, not a secret (CWE-276) |
| `cmd/trstctl-trustbundle/main.go:164` | audit input named by the operator (CWE-22) |
| `cmd/trstctl-trustbundle/main.go:185` | audit evidence at an operator path (CWE-276) |
| `cmd/trstctl/ssh.go:189` | operator-selected local proof file is checked for regular type and private permissions before reading |
| `cmd/trstctl/ssh.go:196` | operator-selected local proof file is matched to the checked private regular inode before reading |
| `deploy/helm/airgap_bundle_test.go:222` | receiver is a private test directory and name ranges over two fixed archive basenames. |
| `docs/provenance/authorship_test.go:103` | test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367) |
| `ee/auditcompliance/retention_download_test.go:87` | the test's own archive under its t.TempDir (CWE-22) |
| `internal/agent/discovery/keystore_bcfks_test.go:22` | the test writes its fixture into its own t.TempDir() (CWE-22) |
| `internal/agent/discovery/keystore_jceks_test.go:30` | the test writes its fixture into its own t.TempDir() (CWE-22) |
| `internal/agent/discovery/keystore_multikey_test.go:23` | the test writes its fixture into its own t.TempDir() (CWE-22) |
| `internal/agent/observe/capture_linux_test.go:65` | the lab runner names the report path in the test environment, never a request (CWE-22) |
| `internal/agent/observe/capture_linux_test.go:146` | the lab runner names the report path in the test environment, never a request (CWE-22) |
| `internal/agent/relay/host_renew_pending.go:164` | both paths are agent-owned fixed state paths |
| `internal/agent/relay/host_renew_pending.go:224` | derived agent-owned state path |
| `internal/agent/relay/host_renew_pending.go:255` | derived agent-owned state path |
| `internal/agent/relay/host_renew_pending.go:288` | derived agent-owned state path |
| `internal/agent/relay/hostrollback.go:939` | both paths are inside the validated agent-local state directory (CWE-22) |
| `internal/agent/relay/k8ssecret_kind_e2e_test.go:84` | the cluster CA file the kind job exports (CWE-22) |
| `internal/agent/sessionobserve/observer_linux_test.go:132` | the proof names its report path in the environment, never a request (CWE-22) |
| `internal/agent/sshkrl/install.go:279` | staged path is created in the bound target directory by CreateTemp |
| `internal/agent/sshkrl/install.go:280` | target is an absolute operator path bound to sshd's effective RevokedKeys path |
| `internal/agent/sshkrl/install.go:299` | path is a derived predecessor name inside the checked private rollback directory |
| `internal/agent/sshkrl/install.go:304` | read only the derived predecessor in the checked private rollback directory |
| `internal/agent/sshkrl/install.go:328` | target is a derived predecessor name inside the checked private rollback directory |
| `internal/agent/sshkrl/install_unix_test.go:27` | a public KRL fixture (committed testdata bytes) written under t.TempDir; sshd lists are world-readable |
| `internal/agent/sshtrust/sshd_live_test.go:115` | temp file beside the harness-owned sshd config in a test dir (CWE-22) |
| `internal/agent/sshtrust/sshd_live_test.go:131` | atomic replace of the harness-owned sshd config in a test dir (CWE-22) |
| `internal/ca/adcs/kerberos_lab_test.go:33` | lab password file named by the test environment, never by a request (CWE-22) |
| `internal/ca/letsencrypt/dnspersist_pebble_test.go:53` | the runner's copy of Pebble's test root (CWE-22) |
| `internal/ca/letsencrypt/revoke_authorized_pebble_test.go:42` | the runner's copy of Pebble's test root (CWE-22) |
| `internal/ca/profilelint/profilelint_test.go:146` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/profilelint/profilelint_test.go:173` | non-secret fixture directory in t.TempDir (CWE-22, CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:241` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/ca/profilelint/profilelint_test.go:254` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/ca/shellca/shellca_test.go:161` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/ca/shellca/shellca_test.go:182` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/config/config.go:5099` | operator-configured local file path from deployment config (CWE-22) |
| `internal/config/config.go:5118` | operator-configured local file path from deployment config (CWE-22) |
| `internal/connector/wasm/host/gen/main.go:36` | a developer tool reading the module the make target just built (CWE-22). |
| `internal/connector/wasm/host/gen/main.go:52` | a public build artifact at a fixed repository path (CWE-276, CWE-22). |
| `internal/connector/wasm/host/gen/main.go:56` | a public digest at a fixed repository path (CWE-276, CWE-22). |
| `internal/crypto/kerberos/client_test.go:87` | lab password file named by the test environment, never by a request (CWE-22) |
| `internal/crypto/kerberos/lab_kdc_test.go:30` | lab password file named by the test environment, never by a request (CWE-22) |
| `internal/crypto/rdp/process_linux.go:83` | operator-installed helper; absolute regular protected executable, executed by this open FD (CWE-22) |
| `internal/crypto/windependents/rotation_native_windows_test.go:72` | only the parent-created ACL-restricted native fixture directory, before installing the request handler (CWE-22) |
| `internal/crypto/windependents/rotation_native_windows_test.go:96` | validated parent-owned directory plus constant filename; request-derived nonce is validated hex file content only (CWE-22) |
| `internal/crypto/windependents/rotation_native_windows_test.go:183` | explicit local lab artifact reference, required absolute regular non-symlink file and exact build hash below (CWE-22) |
| `internal/crypto/windependents/rotation_native_windows_test.go:187` | same bounded regular lab executable, read only to compare the independently recorded compiler-output digest (CWE-22) |
| `internal/dynsecret/windows_accounts_lab_test.go:45` | runner-provided lab path (CWE-22) |
| `internal/kmip/pykmip_client_test.go:69` | test-named files in the test's temp dir, readable by the container user (CWE-22, CWE-276) |
| `internal/kmip/pykmip_tenants_test.go:72` | test-named files in the test's temp dir, readable by the container user (CWE-22, CWE-276) |
| `internal/pluginhost/raw_api_boundary_test.go:34` | writes fixed manifest name only under the owned t.TempDir (CWE-22). |
| `internal/protocols/acme/certbot_client_test.go:275` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:291` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/acme/certbot_client_test.go:308` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/cmp/openssl_client_test.go:168` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/cmp/openssl_client_test.go:178` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/protocols/est/differential_test.go:166` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:134` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/protocols/scep/sscep_client_test.go:196` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/protocols/scep/sscep_client_test.go:205` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/reconcile/kmipsource_pykmip_test.go:67` | test-named files in the test's temp dir, readable by the container's server user (CWE-22, CWE-276) |
| `internal/secretscan/gitleaks.go:416` | locates the pinned gitleaks binary in known tool dirs (CWE-22) |
| `internal/secretscan/move_test.go:38` | locates the pinned gitleaks binary in known tool dirs (CWE-22) |
| `internal/secretscan/thirdparty_signature_test.go:49` | test-owned temp path |
| `internal/server/agent_workload_api_darwin_path_test.go:51` | test reads the binary it just built (CWE-22) |
| `internal/server/agent_workload_api_darwin_path_test.go:56` | test copies its own executable fixture (CWE-22) |
| `internal/server/audit_archive_download_served_test.go:173` | the test's own archive under its t.TempDir (CWE-22) |
| `internal/server/audit_archive_download_served_test.go:179` | the test's own archive under its t.TempDir (CWE-22) |
| `internal/server/audit_feed_index_template_lab_test.go:50` | the repository's own shipped content (CWE-22) |
| `internal/server/audit_feed_lab_p5_test.go:35` | the runner's lab CA (CWE-22) |
| `internal/server/audit_feed_lab_p5_test.go:106` | the runner's mounted rsyslog output (CWE-22) |
| `internal/server/audit_feed_lab_p5_test.go:160` | the runner's mounted rsyslog output (CWE-22) |
| `internal/server/audit_feed_rsyslog_content_lab_test.go:28` | the runner's lab CA (CWE-22) |
| `internal/server/audit_feed_rsyslog_content_lab_test.go:74` | the runner's lab output file (CWE-22) |
| `internal/server/audit_feed_syslog_mtls_lab_test.go:29` | the runner's lab CA (CWE-22) |
| `internal/server/audit_feed_syslog_mtls_lab_test.go:33` | the runner's lab client certificate and key (CWE-22) |
| `internal/server/audit_feed_syslog_mtls_lab_test.go:83` | the runner's lab output file (CWE-22) |
| `internal/server/backup_reports.go:117` | the staging tree is this backup's own temp directory (CWE-22) |
| `internal/server/codesign_cosign_lab_p9_test.go:58` | a public payload, signature and keys the cosign container reads (CWE-22) |
| `internal/server/codesign_cosign_rekor_lab_p9l2_test.go:88` | public payload, signature, bundle and keys the cosign container reads (CWE-22) |
| `internal/server/codesign_notation_lab_p9_test.go:66` | the lab trust policy in the test's own temp directory (CWE-22) |
| `internal/server/codesign_pkcs11_lab_p9_test.go:40` | public lab inputs the tool containers read (CWE-22) |
| `internal/server/codesign_pkcs11_lab_p9_test.go:69` | the lab runner's build output (CWE-22) |
| `internal/server/compose_e2e_tls_test.go:160` | fixed helper filename below this test's private t.TempDir; source bytes are never a path (CWE-22). |
| `internal/server/compose_e2e_tls_test.go:240` | fixed script filename below this test's private t.TempDir; test call text is file content, never a path (CWE-22). |
| `internal/server/compose_e2e_tls_test.go:398` | fixed invalid.pem filename below this test's private t.TempDir; deliberately invalid public fixture bytes are content only (CWE-22). |
| `internal/server/decoy_files_container_lab_q6o1_test.go:39` | disposable lab inputs the container reads (CWE-22) |
| `internal/server/decoy_files_container_lab_q6o1_test.go:50` | the lab runner's build output (CWE-22) |
| `internal/server/decoy_kubernetes_kind_lab_q6o2_test.go:70` | disposable lab configuration the kind node reads (CWE-22) |
| `internal/server/enrollment_relay_served_test.go:54` | the parent test supplies a freshly created public-CA fixture path to this helper process (CWE-22). |
| `internal/server/pam_agent_launcher_served_test.go:38` | the launched agent writes beside the path its own test named (CWE-22) |
| `internal/server/pam_agent_launcher_served_test.go:47` | the launched agent writes beside the path its own test named (CWE-22) |
| `internal/server/pam_desktop_served_test.go:187` | one of two fixed owned native fixture credential paths, selected by the test (CWE-22) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:46` | test reads the cluster CA its runner wrote (CWE-22) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:161` | the kubeconfig the CLI wrote for this test (CWE-22) |
| `internal/server/pam_gateway_private_ca_served_test.go:88` | the fixture's own data directory (CWE-22) |
| `internal/server/pam_webconsole_served_test.go:513` | the operator-named handshake directory of an opt-in test run, with constant file names (CWE-22) |
| `internal/server/pam_webconsole_served_test.go:517` | the operator-named handshake directory of an opt-in test run, with constant file names (CWE-22) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:60` | public lab inputs the containers read (CWE-22) |
| `internal/server/pqc_posture_two_hosts_lab_a176_test.go:82` | the lab runner's build output (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:316` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:692` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/protocols_served_stock_clients_test.go:733` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:747` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_stock_clients_test.go:769` | test reads its own fixture/tempdir path (CWE-22) |
| `internal/server/protocols_served_tsa_test.go:189` | fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/protocols_served_tsa_test.go:198` | test reads its own fixture/tempdir path (CWE-22, CWE-276) |
| `internal/server/run.go:1215` | operator-configured local file path from deployment config (CWE-22) |
| `internal/server/secret_dynamic_lease_rotation_served_test.go:58` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/secret_render_served_test.go:69` | the test's own temp file or the lab directory the runner created (CWE-22) |
| `internal/server/secret_render_served_test.go:146` | the test's own temp file or the lab directory the runner created (CWE-22) |
| `internal/server/secret_render_served_test.go:222` | the test's own temp file or the lab directory the runner created (CWE-22) |
| `internal/server/secret_render_served_test.go:227` | the test's own temp file or the lab directory the runner created (CWE-22) |
| `internal/server/secret_render_served_test.go:234` | the test's own temp file or the lab directory the runner created (CWE-22) |
| `internal/server/secret_third_party_scan_signature_served_test.go:44` | test-owned temp path |
| `internal/server/secret_third_party_scan_signature_served_test.go:50` | test-owned temp path |
| `internal/server/secrets_scan_served_test.go:324` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/signer_authorization_test.go:192` | fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276) |
| `internal/server/spire_jwt_authorities_container_test.go:314` | test writes into its own temp directory (CWE-22) |
| `internal/server/ssh_krl_adoption_served_test.go:52` | target is a fixed name under t.TempDir, not request-derived |
| `internal/server/ssh_trust_fleet_openssh_test.go:215` | retain the owned generated public certificate beside its fixture key; no external path input (CWE-22). |
| `internal/server/vault_compat_served_test.go:195` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/server/vault_dynamic_credentials_cloud_test.go:156` | test reads the cluster CA its runner wrote (CWE-22) |
| `internal/signing/keyimport.go:120` | path passed the explicit signer-keystore confinement check above (CWE-22) |
| `internal/signing/keystore.go:306` | both absolute paths passed the explicit signer-keystore confinement check above (CWE-22) |
| `internal/signing/keystore.go:317` | tmpPath passed the explicit signer-keystore confinement check above (CWE-22) |
| `internal/signing/keystore.go:454` | path passed the explicit signer-keystore confinement check above (CWE-22) |
| `internal/signing/keystore_test.go:233` | test path inside its own tempdir/checkout (CWE-22) |
| `internal/signing/revocation.go:132` | path passed the explicit signer-keystore confinement check above (CWE-22) |
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
| `tools/dodcensus/main_test.go:1482` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:222` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:302` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:436` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:485` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/managed_key_manifest_test.go:676` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/proof/launched.go:1243` | developer tool probing repo/toolchain paths, not a served binary (CWE-22) |
| `tools/dodcensus/proof/proof.go:98` | developer tool probing repo/toolchain paths, not a served binary (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:218` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:327` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/proof/proof_test.go:1329` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/runtime_runner.go:941` | developer tool probing repo/toolchain paths, not a served binary (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:392` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/dodcensus/runtime_runner_test.go:543` | test path inside its own tempdir/checkout (CWE-22) |
| `tools/sdkpack/registry/ecosystems.go:29` | a path under the operator's registry output directory (CWE-22) |
| `tools/sdkpack/registry/handler.go:74` | a fixed directory and an escaped package name with no parent references (CWE-22) |
| `tools/trstctllint/upsertarbiter/sites_dump_test.go:30` | test-only maintenance dump to an operator-chosen path (CWE-22) |
| `tools/trstctllint/upsertarbiter/upsertarbiter_test.go:66` | test-only baseline dump to a path the operator chose via UPSERTARBITER_BASELINE_OUT (CWE-22) |

### G704 — CWE-918 Server-side request forgery (taint) (49 sites)

| Location | Reason |
|---|---|
| `cmd/trstctl/connector.go:426` | CLI calling the operator-specified connector base URL; their own target (CWE-918) |
| `cmd/trstctl/connector.go:446` | CLI calling the operator-specified connector base URL; their own target (CWE-918) |
| `internal/agent/enrollproxy/proxy.go:207` | the destination host is the operator-configured upstream, |
| `internal/agent/relay/k8ssecret_kind_e2e_test.go:108` | the kind cluster API server the job exports (CWE-918) |
| `internal/agent/relay/k8ssecret_kind_e2e_test.go:117` | the kind cluster API server the job exports (CWE-918) |
| `internal/agent/workloadapi/attest_linux_test.go:29` | the parent test hands its own temporary socket's path to this helper process (CWE-918). |
| `internal/crypto/kerberos/client_test.go:115` | the test's own loopback httptest server (CWE-918) |
| `internal/crypto/kerberos/client_test.go:125` | the test's own loopback httptest server (CWE-918) |
| `internal/crypto/windependents/rotation_native_windows_test.go:131` | both exact listener addresses validated as literal loopback before handler installation; only a validated 16-byte hex nonce varies (CWE-918) |
| `internal/crypto/windependents/rotation_native_windows_test.go:136` | fixed validated loopback origin, bounded client and all redirects refused (CWE-918) |
| `internal/discovery/cloudcert/httpfetch.go:42` | fetches the cloud provider endpoint declared by the operator's discovery source (CWE-918) |
| `internal/dynsecret/clickhouse.go:167` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/couchbase.go:184` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/elasticsearch.go:239` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/esxi.go:160` | the operator's configured host through the pinned, egress-guarded client (CWE-918) |
| `internal/dynsecret/github_app.go:327` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/hosted_api.go:64` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/ibm_api_connect.go:239` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/milvus.go:180` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/mongodb_atlas.go:233` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/mongodb_atlas.go:260` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/network_api.go:158` | the operator's configured device endpoint through the pinned, egress-guarded client (CWE-918) |
| `internal/dynsecret/oauth_client_credentials.go:315` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/providers_real.go:1758` | the authority host is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/rabbitmq.go:240` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/rabbitmq.go:284` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/redfish.go:130` | the operator's configured controller through the pinned, egress-guarded client (CWE-918) |
| `internal/dynsecret/signin_check.go:255` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/snowflake.go:315` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/tailscale.go:197` | the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918) |
| `internal/dynsecret/vcenter_sso.go:222` | the operator's configured appliance through the pinned, egress-guarded client (CWE-918) |
| `internal/dynsecret/vcenter_sso.go:239` | same configured appliance (CWE-918) |
| `internal/netconfine/netconfine_linux_test.go:36` | the probe dials the test's own listeners to show which the confinement lets through |
| `internal/scanannotate/registry_stock_test.go:35` | the loopback stock registry the operator names in TRSTCTL_A174L2_REGISTRY for this env-gated test (CWE-918) |
| `internal/scanannotate/registry_stock_test.go:43` | the loopback stock registry the operator names in TRSTCTL_A174L2_REGISTRY for this env-gated test (CWE-918) |
| `internal/scanannotate/registry_stock_test.go:66` | the loopback stock registry the operator names in TRSTCTL_A174L2_REGISTRY for this env-gated test (CWE-918) |
| `internal/scanannotate/registry_stock_test.go:68` | the loopback stock registry the operator names in TRSTCTL_A174L2_REGISTRY for this env-gated test (CWE-918) |
| `internal/server/audit_feed_index_template_lab_test.go:33` | the runner's own lab search engine (CWE-918) |
| `internal/server/audit_feed_index_template_lab_test.go:38` | the runner's own lab search engine (CWE-918) |
| `internal/server/audit_feed_lab_p5_test.go:53` | the runner's own lab search engine (CWE-918) |
| `internal/server/audit_feed_lab_p5_test.go:60` | the runner's own lab search engine (CWE-918) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:65` | test calls the cluster its runner named (CWE-918) |
| `internal/server/pam_gateway_kubernetes_kind_test.go:71` | test calls the cluster its runner named (CWE-918) |
| `internal/server/secret_render_served_test.go:134` | the test application or the lab nginx on loopback (CWE-918) |
| `internal/server/secret_render_served_test.go:136` | the test application or the lab nginx on loopback (CWE-918) |
| `internal/server/spire_jwt_authorities_container_test.go:242` | test calls its own served harness (CWE-918) |
| `internal/server/vault_dynamic_credentials_cloud_test.go:175` | test calls the cluster its runner named (CWE-918) |
| `internal/server/vault_dynamic_credentials_cloud_test.go:181` | test calls the cluster its runner named (CWE-918) |
| `tools/dodcensus/proof/launched.go:1770` | developer tool calling the endpoint it was pointed at (CWE-918) |

### G705 — CWE-79 Cross-site scripting (taint) (19 sites)

| Location | Reason |
|---|---|
| `ee/provider/reports.go:112` | the exact signed JSON report, sent as an application/json attachment that is never rendered as HTML (CWE-79) |
| `internal/ca/letsencrypt/acmefake/acmefake.go:404` | test-support package compiled only into test binaries (CWE-79) |
| `internal/ca/letsencrypt/acmefake/acmefake.go:558` | test-support package compiled only into test binaries (CWE-79) |
| `internal/ca/letsencrypt/acmefake/acmefake.go:585` | test-support package compiled only into test binaries (CWE-79) |
| `internal/ca/letsencrypt/acmefake/acmefake.go:589` | test-support package compiled only into test binaries (CWE-79) |
| `internal/connector/fortigate/fortigatetest/fortigatetest.go:241` | test-support package compiled only into test binaries (CWE-79) |
| `internal/dns/akamai/akamai_test.go:131` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/dynsecret/access_test.go:83` | test writes fixture bytes to its own local server (CWE-79) |
| `internal/dynsecret/access_test.go:91` | test writes fixture bytes to its own local server (CWE-79) |
| `internal/dynsecret/aws_sts_deny_test.go:69` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/operator/reconcile_test.go:263` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/secretstore/access.go:86` | the secret read API returns the secret by contract; served as octet-stream with nosniff, never an HTML context (CWE-79) |
| `internal/secretstore/access.go:97` | fixed-shape JSON carrying only an integer version, served as application/json with nosniff (CWE-79) |
| `internal/secretstore/access.go:113` | fixed-shape JSON carrying only an integer version, served as application/json with nosniff (CWE-79) |
| `internal/server/dynamic_secret_access_served_test.go:60` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/server/secrets_sync_served_test.go:1101` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/server/secrets_sync_served_test.go:1172` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/server/secrets_sync_served_test.go:1282` | test writes fixture bytes to its own recorder/local server (CWE-79) |
| `internal/server/sts_role_chaining_served_test.go:81` | test writes fixture bytes to its own local server (CWE-79) |

### G709 — CWE-502 Deserialization of untrusted data (taint) (1 sites)

| Location | Reason |
|---|---|
| `internal/connector/paloalto/paloaltotest/paloaltotest.go:579` | test double: the op command decodes into a fixed struct, and encoding/xml resolves no external entities (CWE-502) |

### G710 — CWE-601 Open redirect (taint) (6 sites)

| Location | Reason |
|---|---|
| `clients/sdk/go/trstctl/workloads_test.go:300` | the test's own redirect to its own server; the SDK must refuse to follow it (CWE-601) |
| `ee/enterpriseauth/auth_saml_served_test.go:294` | test IdP redirects to the SP's own SLO URL read from its metadata (CWE-601) |
| `ee/enterpriseauth/auth_saml_served_test.go:375` | test IdP redirects to the ACS it read from the SP's own metadata (CWE-601) |
| `ee/enterpriseauth/oidc_fixture_test.go:48` | test redirect within its own local server (CWE-601) |
| `internal/secretscan/repository_credential_test.go:58` | the test's own redirect to its second stand-in host; the clone must not carry the credential there (CWE-601) |
| `internal/server/auth_served_test.go:66` | test redirect within its own local server (CWE-601) |

