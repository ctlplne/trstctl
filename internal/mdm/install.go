// SPDX-License-Identifier: BUSL-1.1

package mdm

import "strings"

// EvaluateCertificateInstallation compares one exact signer-minted serial with
// one device's provider-attributed certificate observations. It never treats a
// device join, registration state, profile assignment, or correlation id as an
// install result.
func EvaluateCertificateInstallation(device Device, issuedSerial string) (Outcome, string) {
	want := canonicalCertificateSerial(issuedSerial)
	if want == "" {
		return OutcomeUnknown, "This SCEP transaction has no signer-minted certificate serial to compare; inspect its issuance failure before evaluating installation."
	}
	if !device.InstallObserved {
		return OutcomeUnknown, device.InstallDetail
	}
	for _, certificate := range device.Certificates {
		if canonicalCertificateSerial(certificate.SerialNumber) != want {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(certificate.Status))
		source := device.MDM + " certificate evidence"
		if certificate.PolicyID != "" {
			source += " for profile " + certificate.PolicyID
		}
		switch status {
		case "active", "valid", "installed", "issued", "compliant":
			return OutcomeOK, source + " contains the exact issued serial " + issuedSerial + " with status " + certificate.Status + "."
		case "revoked", "expired", "invalid", "failed", "error", "removed":
			return OutcomeFailed, source + " contains the exact issued serial " + issuedSerial + " but reports status " + certificate.Status + "; inspect the provider profile and re-enroll only after resolving that state."
		default:
			shown := certificate.Status
			if strings.TrimSpace(shown) == "" {
				shown = "not supplied"
			}
			return OutcomeUnknown, source + " contains the exact issued serial " + issuedSerial + " but its status is " + shown + "; verify the provider's certificate-status vocabulary before claiming success."
		}
	}
	return OutcomeFailed, device.MDM + " completed certificate evidence for this device but did not contain the exact issued serial " + issuedSerial + "; verify profile assignment, force a device check-in, and inspect the provider's SCEP delivery error."
}

// canonicalCertificateSerial removes representation-only differences providers
// commonly add to an X.509 hexadecimal serial. It does not perform substring,
// decimal, device-name, or case-folded free-text matching.
func canonicalCertificateSerial(value string) string {
	value = strings.TrimSpace(value)
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			out.WriteRune(r)
		case r >= 'a' && r <= 'f':
			out.WriteRune(r)
		case r >= 'A' && r <= 'F':
			out.WriteRune(r + ('a' - 'A'))
		case r == ':' || r == '-' || r == ' ':
			continue
		default:
			return ""
		}
	}
	serial := strings.TrimLeft(out.String(), "0")
	if serial == "" && out.Len() > 0 {
		return "0"
	}
	return serial
}
