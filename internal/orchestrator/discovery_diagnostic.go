// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/discovery/k8stls"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/outboundcred"
	"trstctl.com/trstctl/internal/store"
)

var (
	discoveryHTTPStatus     = regexp.MustCompile(`(?:(?:^|: )HTTP(?: status)? | returned |: )([45][0-9]{2})(?:$|[ ;:,])`)
	discoveryCloudStatus    = regexp.MustCompile(`(?:^|: )cloudcert: (?:status |rate limited \(status )([45][0-9]{2})(?:$|:|\) after [1-9][0-9]* attempts$)`)
	discoveryNativeStatus   = regexp.MustCompile(`^native collection refused: scancollect: (?:the provider refused the collection: )?HTTP ([45][0-9]{2}) from `)
	discoveryProviderIndex  = regexp.MustCompile(`^provider [1-9][0-9]{0,3}: `)
	discoveryProviderStatus = regexp.MustCompile(`^(?:(?:awskms|awsiamkeys|awselb): [A-Za-z]+: status ([45][0-9]{2})(?: [A-Za-z0-9_.#-]{1,128})? \(response body redacted\)|bigip: GET [^[:space:]]{1,512}: status ([45][0-9]{2}) \(response body redacted\)|status ([45][0-9]{2}))$`)
	discoveryWeakKeyLimit   = regexp.MustCompile(`^[1-9][0-9]{0,18} distinct RSA keys were left out: one run checks at most [1-9][0-9]{0,18}$`)
	discoveryLegacyCTCount  = regexp.MustCompile(`^[0-9]{1,19} of [0-9]{1,19} CT logs failed(?:: |$)`)
	discoveryUnsetEnv       = regexp.MustCompile(`(?:^|: )env credential reference ([A-Za-z_][A-Za-z0-9_]{0,127}) is not set$`)
	discoveryHost           = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	discoveryNamespace      = regexp.MustCompile(`(?:^|; delivery is not confirmed: )(?:relay: )?(this agent's profile does not allow writing Secrets in namespace "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")$`)
	discoveryOwnerID        = regexp.MustCompile(`^owner ([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}) `)
	discoveryK8sTotal       = regexp.MustCompile(`^[0-9]{1,7} Kubernetes TLS resources? (?:were|was) not delivered(?: \(the first [0-9]{1,7} are listed\))?(?:: |$)`)
)

const discoveryRelayCountMismatch = "relay report rejected: findings count mismatch"
const discoveryOriginPinSuffix = " is outside the origins the credential is bound to"
const DiscoveryDestinationPinRefusal = "env credential reference is not bound to this use: the destination origin" + discoveryOriginPinSuffix

// DiscoveryRelayFindingCounts are the two counts compared by the relay
// receiver before it imports any observation from a signed report.
type DiscoveryRelayFindingCounts struct {
	Reported int
	Retained int
}

// DiscoveryDiagnosticAuthority permits display only of parameters verified
// against this run's bound configuration. Error text alone grants no authority.
type DiscoveryDiagnosticAuthority struct {
	AllowsEnvironmentName    func(string) bool
	AllowsRefusedOrigin      func(string) bool
	KubernetesOwnerID        string
	KubernetesNamespace      string
	KubernetesNamespaces     map[string]string
	KubernetesNotDelivered   int
	KubernetesOutcomesListed int
	ArtifactCleanup          netscan.ArtifactCleanup
	RelayFindingCounts       *DiscoveryRelayFindingCounts
	ProviderFailures         []netscan.ProviderFailure
	WeakKeysOmitted          int
	RefusedOrigins           map[string]string
	refusedOrigin            string
}

// SanitizeDiscoveryRunError classifies a single diagnostic, including rows
// from older releases. Only controlled messages and validated public fields
// reach the operator. A provider's surrounding diagnostic is discarded.
func SanitizeDiscoveryRunError(detail string) string {
	return sanitizeDiscoveryRunError(detail)
}

func sanitizeDiscoveryRunError(detail string) string {
	return DiscoveryDiagnosticAuthority{}.classify(detail)
}

func (authority DiscoveryDiagnosticAuthority) classify(detail string) string {
	if origin := discoveryRefusedOrigin(authority.refusedOrigin); origin != "" {
		return discoveryOriginPinDiagnostic(origin)
	}
	detail = strings.Join(strings.Fields(detail), " ")
	// Historical provider wrappers can identify the error class. Only the
	// worker's structured provider failure conveys an ordinal for display.
	return authority.classifyMessage(strings.TrimPrefix(detail, discoveryProviderIndex.FindString(detail)))
}

func (authority DiscoveryDiagnosticAuthority) classifyMessage(detail string) string {
	switch detail {
	case "", "directory_unreachable", "directory_tls_failed", "directory_authentication_failed",
		"directory_read_failed", "inventory_empty",
		"api_key discovery requires either an observations config or inline findings",
		"cloud_certificate discovery requires at least one provider", "cloud_secret discovery requires at least one provider",
		"secret_store discovery requires at least one provider",
		"aws-secrets-manager region is required", "gcp-secret-manager project is required",
		"azure-key-vault vault_url is required", "hashicorp-vault vault_url is required",
		"aws-acm region is required", "azure-keyvault vault_url is required", "gcp-certmanager project and location are required",
		"aws-ec2 region is required", "gcp-compute project is required", "azure-network subscription_id is required",
		"aws-elbv2 requires a region", "aws-kms requires a region", "f5-bigip requires its management endpoint",
		"cloud_network_path requires at least one provider", "the source is no longer a cloud_network_path source",
		"cloud_access_key discovery requires at least one provider", "cloud_kms_key discovery requires at least one provider",
		"load_balancer_tls discovery requires at least one provider",
		"operator-approved Azure reader token file is not configured", "operator-approved GCP reader token file is not configured",
		"operator-approved STS session file path is not configured", "invalid private egress prefix",
		"some selected Azure metadata reads were unavailable; inspect finding coverage",
		"some selected GCP metadata reads were unavailable; inspect finding coverage",
		"not_supported", "incomplete", "rejected", "expired", "locked", "unreachable", "error",
		"scan canceled before the probe was submitted", "context canceled", "context deadline exceeded",
		"generic_high_entropy needs inspect_content: the generic rule reads values",
		"akeyless: client_id (the access ID) and client_secret_ref (the access key) are required",
		"bitwarden-secrets-manager token_ref is required", "bitwarden-secrets-manager: token_ref (the machine account's access token) is required",
		"conjur api_key_ref is required", "conjur: account, login and api_key_ref are required", "conjur: endpoint is required (the Conjur server URL)",
		"doppler token_ref is required", "doppler: token_ref is required", "doppler: configs belong to a project; set project",
		"github-actions token_ref is required", "github-actions: token_ref is required", "github-actions: owner and repo go together",
		"github-actions: name a repository (owner and repo), an org, or the token owner's Codespaces secrets",
		"github-actions: environments belong to a repository; set owner and repo",
		"github-actions: environments hold Actions secrets only; include actions in stores",
		"gitlab-ci token_ref is required", "gitlab-ci: token_ref is required", "gitlab-ci: name a project, a group, or the instance",
		"infisical: use token_ref or client_id with client_secret_ref, not both",
		"infisical: client_id and client_secret_ref (Universal Auth) or token_ref are required",
		"infisical: environments belong to a project; set project",
		"1password-connect token_ref is required", "1password-connect: token_ref is required",
		"1password-connect: endpoint (the Connect server URL) is required",
		"cloud provider endpoint is required", "ct_log discovery requires the served outbox",
		"secret repository scanner is not configured", "repository credential references are not configured",
		"the repository's credential_ref could not be opened", "the private repository could not be cloned with its credential_ref",
		"repository checkout path is outside the configured scan roots or is not scannable",
		"secret repository scan completed with no findings", "some secret repository findings were rejected",
		"third-party secret scanner is not configured", "third-party secret scan provider is unsupported",
		"credential reference is required",
		"third-party scan requires artifact_path",
		"SSH collection attempt failed before public readback; check the vaulted key, maintained lease and restricted helper prerequisites, then explicitly rerun.",
		"Some SSH targets were not observed; inspect per-target outcomes, fix account/helper/pin/egress prerequisites, and rerun.",
		"attempt_failed_before_public_readback", "connection_or_auth_failed", "invalid_snapshot", "report_too_large", "cancelled",
		"secret scan completed with no findings", "some secret-scan findings were rejected",
		"some agent inventory findings were rejected", "agent inventory report contained no valid findings",
		"third-party secret scan completed with no findings", "some third-party secret findings were rejected",
		"cloud certificate providers returned no certificates", "cloud secret-manager providers returned no certificate secrets":
		return detail
	}
	if total := discoveryK8sTotal.FindString(detail); total != "" {
		if authority.KubernetesNotDelivered == 0 {
			return "Kubernetes TLS resources were not delivered"
		}
		summary := fmt.Sprintf("%d Kubernetes TLS resources were not delivered", authority.KubernetesNotDelivered)
		if authority.KubernetesNotDelivered == 1 {
			summary = "1 Kubernetes TLS resource was not delivered"
		}
		if authority.KubernetesOutcomesListed > 0 {
			summary += fmt.Sprintf(" (the first %d are listed)", authority.KubernetesOutcomesListed)
		}
		if reason := strings.TrimPrefix(detail[len(total):], " "); reason != "" {
			return summary + ": " + authority.classifyDetail(reason)
		}
		return summary
	}
	return authority.classifyDetail(detail)
}

func (authority DiscoveryDiagnosticAuthority) classifyDetail(detail string) string {
	if strings.HasPrefix(detail, "native collection refused:") {
		if match := discoveryNativeStatus.FindStringSubmatch(detail); match != nil {
			return discoveryStatusDiagnostic(match[1])
		}
		return "native collection refused: check the source configuration and provider access, then rerun"
	}
	if stage := discoveryKubernetesDeliveryStage(detail); stage != "" {
		return stage
	}
	// Provider response bodies are arbitrary. Once the shared transport has
	// supplied a status, only that status may determine the class.
	if match := discoveryCloudStatus.FindStringSubmatch(detail); match != nil {
		return discoveryStatusDiagnostic(match[1])
	}
	// Read the observed local failure before considering remote error patterns.
	// A valid environment name can itself contain words such as handshake.
	if match := discoveryUnsetEnv.FindStringSubmatch(detail); match != nil {
		if authority.AllowsEnvironmentName != nil && authority.AllowsEnvironmentName(match[1]) {
			return "env credential reference " + match[1] + " is not set"
		}
		return "env credential reference is not set"
	}
	if detail := discoveryRequiredCredentialField(detail); detail != "" {
		return detail
	}
	switch {
	case detail == "owner_id names no owner in this tenant", detail == k8stls.IdentityOwnerMismatch, detail == k8stls.ListenerVerificationFailure:
		return detail
	case strings.HasPrefix(detail, discoveryRelayCountMismatch):
		return discoveryRelayCountMismatch + "; no findings imported; rerun discovery"
	case strings.Contains(detail, "has not bound it to this tenant"):
		return "env credential reference is not bound to this use: the operator has not bound it to this tenant"
	case strings.Contains(detail, "is outside the origins the credential is bound to"):
		return DiscoveryDestinationPinRefusal
	case strings.Contains(detail, "has not bound it to send to "),
		strings.Contains(detail, "it cannot be sent to that destination:"):
		return "env credential reference is not bound to this use: the operator has not bound it to send to the destination origin"
	case strings.Contains(detail, "unsupported credential reference"):
		return "unsupported credential reference. Use env:NAME"
	case strings.HasPrefix(detail, "unsupported cloud secret-manager provider"):
		return "unsupported cloud secret-manager provider"
	case strings.HasPrefix(detail, "unsupported cloud certificate provider"):
		return "unsupported cloud certificate provider"
	case strings.HasPrefix(detail, "unsupported cloud_network_path provider"):
		return "unsupported cloud_network_path provider"
	case strings.HasPrefix(detail, "unsupported load_balancer_tls provider"):
		return "unsupported load_balancer_tls provider"
	case strings.HasPrefix(detail, "unsupported cloud_kms_key provider"):
		return "unsupported cloud_kms_key provider"
	case strings.HasPrefix(detail, "unsupported cloud_access_key provider"):
		return "unsupported cloud_access_key provider"
	case strings.Contains(detail, "env credential reference is not set"):
		return "env credential reference is not set"
	case strings.Contains(detail, "artifact signature verification refused the scan"):
		return "artifact signature verification refused the scan"
	case detail == "secretscan: third-party scan requires artifact_path":
		return "third-party scan requires artifact_path"
	case strings.HasPrefix(detail, "no in-cluster agent is bound to this source"):
		return "no in-cluster agent is bound to this source. Set cluster_agent_id to the host-role agent and set owner_id."
	case detail == "the bound cluster agent cannot deliver: destination host agent is unavailable in this tenant; select an enrolled host agent",
		detail == "the bound cluster agent cannot deliver: destination agent must be enrolled with the host role and must not be offboarded":
		return "the bound cluster agent cannot deliver. Set cluster_agent_id to an active in-cluster agent with the host role."
	case strings.HasPrefix(detail, "reserved IP ") && strings.HasSuffix(detail, " blocked by SSRF guard"),
		detail == "reserved address blocked by SSRF guard", strings.Contains(detail, "refusing to connect to a non-public address (SSRF guard)"):
		return "reserved address blocked by SSRF guard"
	case strings.HasPrefix(detail, "tlsprobe: dial "), detail == "TLS connection failed":
		return "TLS connection failed"
	case strings.HasPrefix(detail, "tlsprobe: negotiate "), detail == "TLS negotiation failed":
		return "TLS negotiation failed"
	case strings.HasPrefix(detail, "tlsprobe: parse "), detail == "TLS certificate parsing failed":
		return "TLS certificate parsing failed"
	case strings.HasPrefix(detail, "sshprobe: dial "), detail == "SSH connection failed":
		return "SSH connection failed"
	case strings.HasPrefix(detail, "sshprobe: ") && strings.Contains(detail, ": handshake failed before host key:"),
		detail == "SSH handshake failed":
		return "SSH handshake failed"
	}
	if match := discoveryNamespace.FindStringSubmatch(detail); match != nil {
		if strings.HasSuffix(match[1], strconv.Quote(authority.KubernetesNamespace)) {
			return fmt.Sprintf("this agent's profile does not allow writing Secrets in namespace %q", authority.KubernetesNamespace)
		}
		return "the cluster agent's profile does not allow writing Secrets in the configured namespace"
	}
	if reason := authority.ownershipReason(detail); reason != "" {
		return reason
	}
	for _, state := range []State{StateRevoked, StateRetired} {
		reason := fmt.Sprintf("this resource's identity is %s; it is not delivered again", state)
		if detail == reason {
			return reason
		}
	}
	if match := discoveryHTTPStatus.FindStringSubmatch(detail); match != nil {
		return discoveryStatusDiagnostic(match[1])
	}
	if strings.Contains(detail, "handshake") {
		return "TLS handshake failed"
	}
	return discoveryRunErrorWithheld
}

func discoveryOriginPinDiagnostic(origin string) string {
	return "env credential reference is not bound to this use: a request to " + origin + discoveryOriginPinSuffix
}

func discoveryRefusedOrigin(raw string) string {
	if len(raw) > 300 || (!strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://")) {
		return ""
	}
	if origin, err := outboundcred.DestinationOrigin(raw); err == nil && origin == raw {
		return origin
	}
	return ""
}

func discoveryKubernetesDeliveryStage(detail string) string {
	if strings.HasPrefix(detail, "attempt failed on enrolled agent ") {
		_, detail, _ = strings.Cut(detail, "; delivery is not confirmed: ")
	}
	switch detail {
	case transport.RenewInstallFailed, transport.RenewInstallRefusedWrite, transport.RenewInstallFailedConfigTest, transport.RenewInstallFailedReload,
		k8stls.SigningValidityRefused, k8stls.SigningResultUnavailable, transport.RenewRefusedNoPQCProbe:
		return detail
	default:
		return ""
	}
}

func discoveryStatusDiagnostic(number string) string {
	code, _ := strconv.Atoi(number)
	return discoveryHTTPFailure(code)
}

func discoveryHTTPFailure(code int) string {
	if status := http.StatusText(code); code >= 400 && code < 600 && status != "" {
		return fmt.Sprintf("HTTP %d %s", code, status)
	}
	return discoveryRunErrorWithheld
}

func discoveryRequiredCredentialField(detail string) string {
	field, matched := strings.CutSuffix(detail, " is required")
	if !matched {
		return ""
	}
	if localField, wrapped := strings.CutPrefix(field, "resolve "); wrapped {
		field, matched = strings.CutSuffix(localField, ": credential reference")
		if !matched {
			return ""
		}
	}
	switch field {
	case "token_ref", "access_key_id_ref", "secret_access_key_ref", "api_key_ref", "client_secret_ref", "username_ref", "password_ref":
		return field + " is required"
	default:
		return ""
	}
}

func (authority DiscoveryDiagnosticAuthority) ownershipReason(detail string) string {
	match := discoveryOwnerID.FindStringSubmatch(detail)
	if match == nil {
		return ""
	}
	ownerID := ""
	if strings.EqualFold(match[1], authority.KubernetesOwnerID) {
		ownerID = authority.KubernetesOwnerID
	}
	suffix := detail[len(match[0]):]
	switch {
	case strings.HasPrefix(suffix, "has no application ID or environment"):
		return k8stls.OwnershipDeliveryReason(k8stls.OwnerIncomplete, ownerID)
	case strings.HasPrefix(suffix, "changed after it attested ownership"):
		return k8stls.OwnershipDeliveryReason(k8stls.OwnerChanged, ownerID)
	case strings.HasPrefix(suffix, "has not attested ownership"):
		return k8stls.OwnershipDeliveryReason("", ownerID)
	default:
		return ""
	}
}

// DiscoveryRunDiagnostic builds the run's summary from structured outcomes.
// Only the fixed summary prefix is inspected in the old free-text field.
func DiscoveryRunDiagnostic(run store.DiscoveryRun) string {
	detail := run.Error
	// Old scan completions may have combined the fixed scan status with a
	// cleanup error. Render the outcome and discard the old filesystem text.
	primary, note := "", detail
	if before, after, combined := strings.Cut(detail, "; "); combined &&
		(before == "third-party secret scan completed with no findings" || before == "some third-party secret findings were rejected") {
		primary, note = before, after
	}
	switch {
	case note == string(netscan.ArtifactRemoved):
		return withArtifactCleanup(primary, netscan.ArtifactRemoved)
	case strings.HasPrefix(note, string(netscan.ArtifactRemovalFailed)):
		return withArtifactCleanup(primary, netscan.ArtifactRemovalFailed)
	}
	if len(run.TargetResults) == 0 && run.Failed > 0 && run.Failed <= run.Targets {
		if prefix := discoveryLegacyCTCount.FindString(detail); prefix != "" {
			summary := fmt.Sprintf("%d of %d CT logs failed", run.Failed, run.Targets)
			if reason := SanitizeDiscoveryRunError(detail[len(prefix):]); reason != "" {
				summary += ": " + reason
			}
			return summary
		}
	}
	return DiscoveryDiagnosticAuthority{}.runSummary(detail, run.TargetResults)
}

func withArtifactCleanup(detail string, outcome netscan.ArtifactCleanup) string {
	switch outcome {
	case netscan.ArtifactRemoved, netscan.ArtifactRemovalFailed:
		if detail == "" {
			return string(outcome)
		}
		return detail + " (" + string(outcome) + ")"
	default:
		return detail
	}
}

func (authority DiscoveryDiagnosticAuthority) runSummary(detail string, targets []store.DiscoveryTargetResult) string {
	if counts := authority.RelayFindingCounts; counts != nil {
		if counts.Reported < 0 || counts.Reported > segmentscan.MaxTargets || counts.Retained < 0 || counts.Retained > segmentscan.MaxTargets {
			return discoveryRelayCountMismatch + " (count exceeds receiver bounds); no findings imported; rerun discovery"
		}
		return fmt.Sprintf("%s (reported %d, retained %d); no findings imported; rerun discovery", discoveryRelayCountMismatch, counts.Reported, counts.Retained)
	}
	if authority.WeakKeysOmitted > 0 {
		_, summary := WeakKeyAuditOutcome(authority.WeakKeysOmitted)
		return summary
	}
	if discoveryWeakKeyLimit.MatchString(detail) {
		return "some distinct RSA keys were left out because the audit reached its per-run bound"
	}
	for _, prefix := range []string{
		"some load-balancer TLS providers failed", "every load-balancer TLS provider failed",
		"some cloud access-key providers failed", "every cloud access-key provider failed",
		"some cloud KMS providers failed", "every cloud KMS provider failed", "some keys' last use could not be read",
		"cloud network-path provider setup failed",
	} {
		if detail == prefix || strings.HasPrefix(detail, prefix+":") {
			if len(authority.ProviderFailures) == 0 {
				return retainedProviderFailureSummary(prefix, strings.TrimPrefix(detail, prefix))
			}
			return authority.providerFailureSummary(prefix)
		}
	}
	if len(targets) != 0 && targets[0].Kind == "ct_log" {
		if summary := authority.ctLogSummary(targets); summary != "" {
			return summary
		}
	}
	for _, prefix := range []string{
		"some cloud certificate providers failed", "all cloud certificate providers failed",
		"some cloud secret-manager providers failed", "all cloud secret-manager providers failed",
		"some relay discovery probes failed or were blocked", "all relay discovery probes failed or were blocked",
	} {
		if detail == prefix || strings.HasPrefix(detail, prefix+":") {
			return authority.failedTargets(prefix, targets)
		}
	}
	return authority.classify(detail)
}

func retainedProviderFailureSummary(prefix, tail string) string {
	detail, _, _ := strings.Cut(strings.TrimPrefix(tail, ": "), "; ")
	index := discoveryProviderIndex.FindString(detail)
	if index == "" {
		return prefix
	}
	detail = strings.Join(strings.Fields(detail[len(index):]), " ")
	if match := discoveryProviderStatus.FindStringSubmatch(detail); match != nil {
		for _, status := range match[1:] {
			if status != "" {
				return prefix + ": " + discoveryStatusDiagnostic(status)
			}
		}
	}
	return prefix
}

func (authority DiscoveryDiagnosticAuthority) providerFailureSummary(prefix string) string {
	const limit = 3
	summary, listed := prefix, 0
	for _, failure := range authority.ProviderFailures[:min(len(authority.ProviderFailures), limit)] {
		if failure.Ordinal <= 0 || failure.Err == nil {
			continue
		}
		providerAuthority := authority
		if origin := outboundcred.RefusedDestinationOrigin(failure.Err); origin != "" &&
			authority.AllowsRefusedOrigin != nil && authority.AllowsRefusedOrigin(origin) {
			providerAuthority.refusedOrigin = origin
		}
		if !failure.MissingBoundCredential {
			providerAuthority.AllowsEnvironmentName = nil
		}
		var statusError interface{ HTTPStatusCode() int }
		var reason string
		if errors.As(failure.Err, &statusError) {
			reason = discoveryHTTPFailure(statusError.HTTPStatusCode())
		} else {
			reason = providerAuthority.classify(failure.Err.Error())
		}
		separator := ": "
		if listed != 0 {
			separator = "; "
		}
		part := fmt.Sprintf("%sprovider %d: %s", separator, failure.Ordinal, reason)
		// Leave room for the omitted count without cutting an origin in half.
		if len(summary)+len(part)+32 > maxDiscoveryRunErrorBytes {
			break
		}
		summary += part
		listed++
	}
	if listed == 0 {
		return prefix
	}
	if remaining := len(authority.ProviderFailures) - listed; remaining > 0 {
		summary += fmt.Sprintf("; and %d more", remaining)
	}
	return summary
}

func (authority DiscoveryDiagnosticAuthority) ctLogSummary(targets []store.DiscoveryTargetResult) string {
	failed, reason := 0, ""
	for _, target := range targets {
		if target.Kind != "ct_log" {
			return ""
		}
		if target.Status == "failed" {
			failed++
			if reason == "" {
				reason = authority.classify(target.Error)
			}
		}
	}
	if failed == 0 {
		return ""
	}
	summary := fmt.Sprintf("%d of %d CT logs failed", failed, len(targets))
	if reason != "" {
		summary += ": " + reason
	}
	return summary
}

func (authority DiscoveryDiagnosticAuthority) failedTargets(prefix string, targets []store.DiscoveryTargetResult) string {
	var parts []string
	total := 0
	for _, target := range targets {
		switch target.Status {
		case "failed", "blocked", "rejected":
		default:
			continue
		}
		total++
		if len(parts) == 3 {
			continue
		}
		label := publicDiscoveryTarget(target)
		if label == "" {
			continue
		}
		if target.Kind != "cloud_provider" {
			label += " " + target.Status
		}
		targetAuthority := authority
		targetAuthority.refusedOrigin = authority.RefusedOrigins[target.Target]
		if reason := targetAuthority.classify(target.Error); reason != "" {
			label += " (" + reason + ")"
		}
		// Reserve space for the prefix, separators and omitted-target count.
		if len(label) <= (maxDiscoveryRunErrorBytes-len(prefix)-32)/3 {
			parts = append(parts, label)
		}
	}
	if len(parts) == 0 {
		return prefix
	}
	summary := prefix + ": " + strings.Join(parts, "; ")
	if total > len(parts) {
		summary += fmt.Sprintf("; and %d more", total-len(parts))
	}
	return summary
}

func publicDiscoveryTarget(target store.DiscoveryTargetResult) string {
	switch target.Kind {
	case "cloud_provider":
		name, suffix, found := strings.Cut(target.Target, "#")
		if found {
			index, err := strconv.Atoi(suffix)
			if err != nil || index < 2 || strconv.Itoa(index) != suffix {
				return ""
			}
		}
		for _, capability := range sourcecatalog.All().Items {
			for _, provider := range capability.Providers {
				if provider.ID == name {
					return target.Target
				}
			}
		}
		return "unrecognized provider"
	case "network", "ssh":
		host, port, err := net.SplitHostPort(target.Target)
		if err != nil || (net.ParseIP(host) == nil && !discoveryHost.MatchString(host)) {
			return ""
		}
		number, err := strconv.Atoi(port)
		if err == nil && number >= 1 && number <= 65535 && strconv.Itoa(number) == port {
			return target.Target
		}
	}
	return ""
}
