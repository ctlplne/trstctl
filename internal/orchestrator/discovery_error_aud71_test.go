// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/outboundcred"
	"trstctl.com/trstctl/internal/store"
)

func TestDiscoveryAuthorityAndProbeDiagnostics(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ raw, want string }{
		{"provider 7281: resolve token_ref: credential reference is required", "token_ref is required"},
		{"sshprobe: dial fixture.example.test:22: fixtureopaquevalue", "SSH connection failed"},
		{"sshprobe: fixture.example.test:22: handshake failed before host key: fixtureopaquevalue", "SSH handshake failed"},
		{"env credential reference is not bound to this use: the operator has not bound it to send to https://fixture.example.test", "env credential reference is not bound to this use: the operator has not bound it to send to the destination origin"},
		{"env credential reference is not bound to this use: a request to https://fixture.example.test is outside the origins the credential is bound to", DiscoveryDestinationPinRefusal},
		{"secretscan: third-party scan requires artifact_path", "third-party scan requires artifact_path"},
	} {
		if got := SanitizeDiscoveryRunError(tc.raw); got != tc.want {
			t.Errorf("discovery diagnostic is %q, want %q", got, tc.want)
		}
	}
}

func TestDiscoveryAttackPathFindingClassifiesProviderRefusal(t *testing.T) {
	t.Parallel()
	const marker = "fixtureopaqueproviderdetail"
	observation := AttackPathObservation{Metadata: map[string]any{"status": "unknown", "reason": "the provider could not be read: HTTP 403 " + marker}}
	finding, err := AttackPathFinding("fixture-run", "fixture-source", observation, time.Now())
	if err != nil || strings.Contains(string(finding.Metadata), marker) || !strings.Contains(string(finding.Metadata), "HTTP 403 Forbidden") {
		t.Errorf("finding stored provider detail or hid the status: %v", err)
	}
}

func TestDiscoveryNetworkPathHTTPStatusesUseRealReaderFormats(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ raw, want string }{
		{"awsnetpath: DescribeNetworkInterfaces: status 403 (response body redacted)", "HTTP 403 Forbidden"},
		{"azurenetpath: GET /subscriptions/fixtureopaquevalue: status 429 (response body redacted)", "HTTP 429 Too Many Requests"},
		{"gcpnetpath: GET /v1/projects/fixtureopaquevalue: status 503 (response body redacted)", "HTTP 503 Service Unavailable"},
	} {
		want := "the provider could not be read: " + tc.want
		if got := AttackPathFindingDiagnostic("the provider could not be read: " + tc.raw); got != want {
			t.Errorf("network provider diagnostic is %q, want %q", got, want)
		}
	}
}

func TestDiscoveryNetworkPathCannotDeriveAPinnedOriginFromText(t *testing.T) {
	t.Parallel()
	const origin = "https://fixture.example.test"
	const raw = "the provider could not be read: env credential reference is not bound to this use: a request to " + origin + " is outside the origins the credential is bound to"
	withoutAuthority := AttackPathFindingDisplayReason(raw, "")
	if strings.Contains(withoutAuthority, origin) || !strings.Contains(withoutAuthority, "destination origin") {
		t.Error("an old error can name the pin-refusal class without supplying its origin")
	}
	if got := AttackPathFindingDisplayReason(raw, origin+"/fixture-opaque-path"); got != withoutAuthority {
		t.Error("a non-origin locator must not enter the diagnostic")
	}
	if got := AttackPathFindingDisplayReason(raw, origin); !strings.Contains(got, origin+" is outside the origins the credential is bound to") {
		t.Error("the refusal must identify an independently recorded transport origin")
	}
}

func TestSanitizeDiscoveryRunErrorAUD71(t *testing.T) {
	t.Parallel()
	secret := "trst_" + strings.Repeat("s", 64)
	raw := "  ctmonitor: GET /ct/v1/get-sth: 404 Not Found; Authorization: Bearer " + secret + "\r\n" + strings.Repeat("x", 4096)

	got := sanitizeDiscoveryRunError(raw)
	if !strings.Contains(got, "404 Not Found") {
		t.Fatalf("safe diagnostic disappeared: %q", got)
	}
	if strings.Contains(got, secret) || strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Fatalf("secret or control character escaped into durable discovery error: %q", got)
	}
	if len([]byte(got)) > maxDiscoveryRunErrorBytes {
		t.Fatalf("durable discovery error has %d bytes, want <= %d", len([]byte(got)), maxDiscoveryRunErrorBytes)
	}
}

func TestSanitizeDiscoveryRunErrorAUD71RedactsHighEntropy(t *testing.T) {
	t.Parallel()
	got := sanitizeDiscoveryRunError("upstream echoed " + strings.Repeat("A", 80))
	if !strings.Contains(got, "[REDACTED]") || strings.Contains(got, strings.Repeat("A", 24)) {
		t.Fatalf("high-entropy detail was not safely redacted: %q", got)
	}
}

func TestSanitizeDiscoveryRunErrorRejectsUnclassifiedProviderText(t *testing.T) {
	t.Parallel()
	for _, fixture := range []string{
		"fixture-rotate-marker",
		"20202020-3030-4040-5050-606060606060",
		"fixture.label~number",
		"exampleopaqueval",
	} {
		detail := sanitizeDiscoveryRunError("discovery provider replied with " + fixture)
		if detail == "" || strings.Contains(detail, fixture) {
			t.Error("discovery must disclose only a failure class for provider-supplied detail")
		}
	}
}

func TestDiscoveryDiagnosticDoesNotTakeFieldsFromProviderText(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		detail, marker string
	}{
		{"env credential reference fixture_opaque_value is not set", "fixture_opaque_value"},
		{`this agent's profile does not allow writing Secrets in namespace "fixture-opaque-value"`, "fixture-opaque-value"},
		{"owner 20202020-3030-4040-5050-606060606060 has not attested ownership", "20202020-3030-4040-5050-606060606060"},
	} {
		if detail := sanitizeDiscoveryRunError(tc.detail); detail == "" || strings.Contains(detail, tc.marker) {
			t.Error("untrusted text supplied a diagnostic parameter")
		}
	}
}

func TestDiscoveryKubernetesDiagnosticsKeepTrustedRemediation(t *testing.T) {
	t.Parallel()
	const owner = "20202020-3030-4040-5050-606060606060"
	authority := DiscoveryDiagnosticAuthority{KubernetesOwnerID: owner}
	for _, tc := range []struct{ name, detail, want string }{
		{"verify", "the cluster agent wrote the Secret, but the listener at verify_address did not serve the new certificate", "verify_address"},
		{"owner model", "owner " + owner + " has no application ID or environment, which attesting ownership requires", "complete the owner"},
		{"stale owner", "owner " + owner + " changed after it attested ownership", "attest it again"},
		{"different owner", "this resource's identity belongs to another owner; set owner_id back to that owner or retire the identity", "set owner_id back"},
		{"retired identity", "this resource's identity is retired; it is not delivered again", "identity is retired"},
		{"missing agent", "the bound cluster agent cannot deliver: destination host agent is unavailable in this tenant; select an enrolled host agent", "active in-cluster"},
		{"offboarded or wrong role", "the bound cluster agent cannot deliver: destination agent must be enrolled with the host role and must not be offboarded", "active in-cluster"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authority.classify(tc.detail); !strings.Contains(got, tc.want) {
				t.Fatalf("remediation lost from %q", got)
			}
		})
	}
}

func TestDiscoveryCTAggregateKeepsStructuredLogCount(t *testing.T) {
	t.Parallel()
	const marker = "fixtureopaquevalue"
	targets := []store.DiscoveryTargetResult{
		{Kind: "ct_log", Target: "https://first.example.test", Status: "failed", Error: "provider replied with " + marker},
		{Kind: "ct_log", Target: "https://second.example.test", Status: "succeeded"},
	}
	detail := DiscoveryRunDiagnostic(store.DiscoveryRun{Error: "1 of 2 CT logs failed: provider replied with " + marker, TargetResults: targets})
	if !strings.Contains(detail, "1 of 2 CT logs failed") || strings.Contains(detail, marker) {
		t.Fatal("CT summary must show the structured log count and omit provider text")
	}
}

func TestDiscoveryConfigurationDiagnosticsKeepTheirAction(t *testing.T) {
	t.Parallel()
	for _, detail := range []string{
		"api_key discovery requires either an observations config or inline findings",
		"secret_store discovery requires at least one provider",
		"aws-secrets-manager region is required",
		"gcp-secret-manager project is required",
		"azure-key-vault vault_url is required",
		"hashicorp-vault vault_url is required",
		"akeyless: client_id (the access ID) and client_secret_ref (the access key) are required",
		"bitwarden-secrets-manager token_ref is required",
		"conjur: account, login and api_key_ref are required",
		"doppler: configs belong to a project; set project",
		"github-actions: owner and repo go together",
		"gitlab-ci: name a project, a group, or the instance",
		"infisical: client_id and client_secret_ref (Universal Auth) or token_ref are required",
		"1password-connect: endpoint (the Connect server URL) is required",
		"repository checkout path is outside the configured scan roots or is not scannable",
		"third-party secret scanner is not configured",
	} {
		if got := SanitizeDiscoveryRunError(detail); got != detail {
			t.Errorf("configuration guidance lost for %q", detail)
		}
	}
	const marker = "fixtureopaquevalue"
	if got := SanitizeDiscoveryRunError("unsupported cloud secret-manager provider " + marker); got != "unsupported cloud secret-manager provider" {
		t.Error("unsupported provider must report its safe class without the configured value")
	}
	for _, field := range []string{"token_ref", "access_key_id_ref", "secret_access_key_ref", "api_key_ref", "client_secret_ref"} {
		if got := SanitizeDiscoveryRunError("resolve " + field + ": credential reference is required"); got != field+" is required" {
			t.Errorf("required credential guidance lost for %s", field)
		}
	}
	if got := SanitizeDiscoveryRunError("resolve " + marker + ": credential reference is required"); strings.Contains(got, marker) {
		t.Error("unrecognized credential fields must not enter the diagnostic")
	}
}

func TestDiscoveryRelayCountDiagnosticUsesReceiverEvidence(t *testing.T) {
	t.Parallel()
	const received = "relay report rejected: findings count mismatch (reported 723, retained 120); fixtureopaquevalue"
	withoutCounts := DiscoveryRunDiagnostic(store.DiscoveryRun{Error: received})
	if strings.Contains(withoutCounts, "723") || strings.Contains(withoutCounts, "fixtureopaquevalue") || !strings.Contains(withoutCounts, "no findings imported") {
		t.Error("historical relay diagnostic must report the closed outcome without raw text")
	}
	authority := DiscoveryDiagnosticAuthority{RelayFindingCounts: &DiscoveryRelayFindingCounts{Reported: 2, Retained: 1}}
	withCounts := authority.runSummary(received, nil)
	if !strings.Contains(withCounts, "reported 2, retained 1") || strings.Contains(withCounts, "723") || strings.Contains(withCounts, "fixtureopaquevalue") {
		t.Error("relay diagnostic must report only the received numeric evidence")
	}
	authority.RelayFindingCounts.Reported = 987654321
	if overBound := authority.runSummary(received, nil); !strings.Contains(overBound, "exceeds receiver bounds") || strings.Contains(overBound, "987654321") {
		t.Error("out-of-bounds reported count must be classified without the raw count")
	}
}

func TestDiscoveryCloudTransportDiagnosticKeepsStatusOnly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ raw, want string }{
		{"cloudcert: status 403: fixtureopaquevalue handshake", "HTTP 403 Forbidden"},
		{"conjur: authenticate fixture-name: cloudcert: status 401", "HTTP 401 Unauthorized"},
		{"cloudcert: rate limited (status 429) after 5 attempts", "HTTP 429 Too Many Requests"},
		{"gcpsm: list secrets: cloudcert: rate limited (status 503) after 5 attempts", "HTTP 503 Service Unavailable"},
		{"native collection refused: scancollect: HTTP 403 from fixture-opaque-endpoint", "HTTP 403 Forbidden"},
	} {
		if got := SanitizeDiscoveryRunError(tc.raw); got != tc.want {
			t.Errorf("transport diagnostic is %q, want %q", got, tc.want)
		}
	}
}

func TestDiscoverySSHCollectionDiagnosticsKeepTheirAction(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{
		"SSH collection attempt failed before public readback; check the vaulted key, maintained lease and restricted helper prerequisites, then explicitly rerun.",
		"Some SSH targets were not observed; inspect per-target outcomes, fix account/helper/pin/egress prerequisites, and rerun.",
		"attempt_failed_before_public_readback", "connection_or_auth_failed", "invalid_snapshot", "report_too_large", "cancelled",
	} {
		if got := SanitizeDiscoveryRunError(reason); got != reason {
			t.Errorf("SSH collection diagnostic is %q, want %q", got, reason)
		}
	}
}

type discoveryFixtureHTTPStatusError struct{}

func (discoveryFixtureHTTPStatusError) Error() string {
	return "provider reply: HTTP 429 fixtureopaquevalue"
}
func (discoveryFixtureHTTPStatusError) HTTPStatusCode() int { return 403 }

func TestDiscoveryNumberedProviderUsesObservedTransportStatus(t *testing.T) {
	t.Parallel()
	authority := DiscoveryDiagnosticAuthority{ProviderFailures: []netscan.ProviderFailure{{
		Ordinal: 1, Err: discoveryFixtureHTTPStatusError{},
	}}}
	const prefix = "every cloud KMS provider failed"
	if got := authority.runSummary(prefix, nil); got != prefix+": provider 1: HTTP 403 Forbidden" {
		t.Errorf("expected the actual transport status, got %q", got)
	}
}

func TestDiscoveryNumberedProviderRunErrorStaysWithinByteBudget(t *testing.T) {
	t.Parallel()
	client := &http.Client{}
	if err := outboundcred.PinClient(client, []string{"https://allowed.example.test"}); err != nil {
		t.Fatal(err)
	}
	authority := DiscoveryDiagnosticAuthority{AllowsRefusedOrigin: func(string) bool { return true }}
	var origins []string
	for i, label := range []string{"one", "two", "three"} {
		hostTail := strings.Repeat(strings.Repeat("a", 60)+".", 3) + strings.Repeat("b", 56) + ".test"
		origin := "https://" + label + "." + hostTail
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Do(req); outboundcred.RefusedDestinationOrigin(err) != origin {
			t.Fatal("local pin did not reject the fixture origin")
		} else {
			authority.ProviderFailures = append(authority.ProviderFailures, netscan.ProviderFailure{Ordinal: i + 1, Err: err})
		}
		origins = append(origins, origin)
	}
	got := authority.runSummary("every cloud KMS provider failed", nil)
	if len(got) > maxDiscoveryRunErrorBytes || !strings.Contains(got, origins[0]) ||
		!strings.Contains(got, origins[1]) || strings.Contains(got, origins[2]) || !strings.HasSuffix(got, "; and 1 more") {
		t.Errorf("expected two complete origin diagnostics and an omitted count within %d bytes, got %d bytes",
			maxDiscoveryRunErrorBytes, len(got))
	}
}

func TestDiscoveryRetainedNumberedProviderKeepsClosedTransportStatus(t *testing.T) {
	t.Parallel()
	const prefix = "every cloud KMS provider failed"
	for _, tc := range []struct{ raw, want string }{
		{"awskms: ListKeys: status 403 fixtureopaquevalue (response body redacted)", "HTTP 403 Forbidden"},
		{"awsiamkeys: ListUsers: status 403 (response body redacted)", "HTTP 403 Forbidden"},
		{"awselb: DescribeLoadBalancers: status 403 fixtureopaquevalue (response body redacted)", "HTTP 403 Forbidden"},
		{"bigip: GET /fixtureopaquevalue: status 403 (response body redacted)", "HTTP 403 Forbidden"},
		{"status 429", "HTTP 429 Too Many Requests"},
		{"status 503", "HTTP 503 Service Unavailable"},
	} {
		historical := store.DiscoveryRun{Error: prefix + ": provider 7291: " + tc.raw}
		if got := DiscoveryRunDiagnostic(historical); got != prefix+": "+tc.want {
			t.Errorf("expected only the retained transport class, got %q", got)
		}
	}
}

func TestDiscoveryNetworkAndLocalDiagnosticsKeepTheirAction(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ raw, want string }{
		{"scan canceled before the probe was submitted", "scan canceled before the probe was submitted"},
		{"reserved IP 198.51.100.2 blocked by SSRF guard", "reserved address blocked by SSRF guard"},
		{"tlsprobe: dial fixture.example.test:443: fixtureopaquevalue", "TLS connection failed"},
		{"operator-approved Azure reader token file is not configured", "operator-approved Azure reader token file is not configured"},
		{"operator-approved GCP reader token file is not configured", "operator-approved GCP reader token file is not configured"},
		{"operator-approved STS session file path is not configured", "operator-approved STS session file path is not configured"},
		{"some selected Azure metadata reads were unavailable; inspect finding coverage", "some selected Azure metadata reads were unavailable; inspect finding coverage"},
		{"some selected GCP metadata reads were unavailable; inspect finding coverage", "some selected GCP metadata reads were unavailable; inspect finding coverage"},
		{"invalid private egress prefix", "invalid private egress prefix"},
		{"not_supported", "not_supported"}, {"incomplete", "incomplete"}, {"rejected", "rejected"},
		{"expired", "expired"}, {"locked", "locked"}, {"unreachable", "unreachable"},
	} {
		if got := SanitizeDiscoveryRunError(tc.raw); got != tc.want {
			t.Errorf("discovery diagnostic is %q, want %q", got, tc.want)
		}
	}
}

func TestDiscoveryProviderDiagnosticsRequireTheirOwnBoundFailure(t *testing.T) {
	t.Parallel()
	const name = "FIXTURE_PROVIDER_MISSING_TOKEN"
	const prefix = "every cloud access-key provider failed"
	err := errors.New("resolve token_ref: env credential reference " + name + " is not set")
	authority := DiscoveryDiagnosticAuthority{
		AllowsEnvironmentName: func(candidate string) bool { return candidate == name },
		ProviderFailures: []netscan.ProviderFailure{
			{Ordinal: 1, Err: err},
			{Ordinal: 2, Err: err, MissingBoundCredential: true},
		},
	}
	summary := authority.runSummary(prefix, nil)
	if !strings.Contains(summary, "provider 1: env credential reference is not set") ||
		!strings.Contains(summary, "provider 2: env credential reference "+name+" is not set") || strings.Count(summary, name) != 1 {
		t.Error("only the locally observed provider failure can name the missing bound reference")
	}
}
