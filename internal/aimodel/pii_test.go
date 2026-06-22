package aimodel

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// piiShape is one realistic personal/identifying datum embedded in a plausible
// prompt line. The pii column is the substring that MUST NOT survive PII-aware
// egress when the policy is default-private (PRIVACY-005). Unlike the SURFACE-004
// secret shapes, these are NOT high-entropy: a dotted hostname, an email, an IP,
// or an OIDC/SPIFFE subject sails straight past the secret redactor and the
// residual-entropy gate, so the optional cloud model would otherwise receive the
// owner's identity, the workload's SPIFFE ID, the certificate subject's CN, etc.
type piiShape struct {
	name   string
	prompt string
	pii    string // the personal/identifying substring that must be gone after PII redaction
}

// piiProbeShapes is the PRIVACY-005 acceptance wall: the personal/identifying
// shapes a rowSummary or RCA evidence line can carry into a prompt — certificate
// subjects (CN/SANs), graph node names, owner emails, SPIFFE/OIDC subjects, and
// raw IPs/hostnames. Each must be redacted (or the send blocked) under the
// default-private policy before any cloud egress.
var piiProbeShapes = []piiShape{
	{
		name:   "owner_email",
		prompt: "the owner of payments-tls is alice.smith@corp.example.com please investigate",
		pii:    "alice.smith@corp.example.com",
	},
	{
		name:   "ipv4_address",
		prompt: "the renewal failed on host 203.0.113.42 at noon",
		pii:    "203.0.113.42",
	},
	{
		name:   "ipv6_address",
		prompt: "the endpoint 2001:db8:85a3::8a2e:370:7334 returned a timeout",
		pii:    "2001:db8:85a3::8a2e:370:7334",
	},
	{
		name:   "spiffe_subject",
		prompt: "the workload identity is spiffe://prod.example.org/ns/payments/sa/api and it expired",
		pii:    "spiffe://prod.example.org/ns/payments/sa/api",
	},
	{
		name:   "oidc_subject_url",
		prompt: "the federated subject https://accounts.google.com/sub/108273645 lost access",
		pii:    "https://accounts.google.com/sub/108273645",
	},
	{
		name:   "fqdn_hostname",
		prompt: "certificate subject is svc-api.payments.prod.internal and it is stuck",
		pii:    "svc-api.payments.prod.internal",
	},
	{
		name:   "person_name_owner",
		prompt: "the owner is Alice Johnson and the credential is unrotated",
		pii:    "Alice Johnson",
	},
}

// TestPIIRedactorRedactsPersonalData is the PRIVACY-005 acceptance wall: under the
// default-private policy (AllowPII=false), every personal/identifying shape is
// removed by the PII-aware egress redactor and a redaction marker is left in its
// place. It FAILS before the fix (DefaultRedactor preserves emails/hostnames/IPs/
// subjects/names by design) and PASSES after the PII layer is added.
func TestPIIRedactorRedactsPersonalData(t *testing.T) {
	red := PIIRedactor(PIIPolicy{}) // zero value = default-private (redact)
	for _, c := range piiProbeShapes {
		t.Run(c.name, func(t *testing.T) {
			out := red(c.prompt)
			if strings.Contains(out, c.pii) {
				t.Errorf("PII %q SURVIVED PII-aware redaction\n  in:  %s\n  out: %s", c.pii, c.prompt, out)
			}
			if !strings.Contains(out, "[REDACTED") {
				t.Errorf("no redaction marker in output for %q\n  out: %s", c.name, out)
			}
		})
	}
}

// TestPIIAdapterRedactsBeforeEgress proves the served path: an Adapter built with
// the default-private PII policy redacts every PII shape BEFORE the model (the
// cloud egress boundary) ever sees the prompt. The captured model must never have
// observed the raw email/IP/SPIFFE/hostname/name.
func TestPIIAdapterRedactsBeforeEgress(t *testing.T) {
	for _, c := range piiProbeShapes {
		t.Run(c.name, func(t *testing.T) {
			cm := &captureModel{name: "cloud"}
			a := NewWithPII(cm, nil, PIIPolicy{}) // default-private
			if _, err := a.Reason(context.Background(), c.prompt); err != nil {
				t.Fatalf("Reason errored on PII prompt: %v", err)
			}
			if strings.Contains(cm.seen, c.pii) {
				t.Errorf("PII %q reached the model egress boundary:\n  seen: %s", c.pii, cm.seen)
			}
		})
	}
}

// TestPIIBlockMode proves the fail-closed alternative: when the policy is set to
// block (not redact) on PII, the send is refused entirely rather than egressing a
// partially-redacted prompt, and the model receives nothing.
func TestPIIBlockMode(t *testing.T) {
	cm := &captureModel{name: "cloud"}
	a := NewWithPII(cm, nil, PIIPolicy{Block: true})
	_, err := a.Reason(context.Background(), "owner alice.smith@corp.example.com is affected")
	if !errors.Is(err, ErrPIIBlocked) {
		t.Fatalf("Reason should refuse a PII prompt in block mode, got err=%v", err)
	}
	if cm.seen != "" {
		t.Errorf("model received material despite the PII block gate: %q", cm.seen)
	}
}

// TestPIIAllowlistConsent proves the explicit-consent path: when AllowPII is true
// (an operator deliberately consented to personal-data egress in config), PII is
// preserved and reaches the model unchanged. Default-private means off; this is
// the opt-in.
func TestPIIAllowlistConsent(t *testing.T) {
	cm := &captureModel{name: "cloud"}
	a := NewWithPII(cm, nil, PIIPolicy{AllowPII: true})
	const prompt = "owner alice.smith@corp.example.com on svc-api.prod.internal"
	if _, err := a.Reason(context.Background(), prompt); err != nil {
		t.Fatalf("Reason errored with AllowPII=true: %v", err)
	}
	if !strings.Contains(cm.seen, "alice.smith@corp.example.com") {
		t.Errorf("AllowPII=true should preserve PII for egress, model saw: %q", cm.seen)
	}
}

// TestPIIRedactorPreservesProse: the PII layer must not destroy a normal incident
// question with no personal data in it. Plain words, identity-state vocabulary, and
// short ids stay intact (otherwise RCA answers become useless).
func TestPIIRedactorPreservesProse(t *testing.T) {
	red := PIIRedactor(PIIPolicy{})
	cases := []string{
		"what is the blast radius of the payments certificate?",
		"identity id 7f3a is in state requested; explain the transition",
		"the renewal failed at 2026-06-14T10:00:00Z and the queue rejected it",
	}
	for _, c := range cases {
		out := red(c)
		if out != c {
			t.Errorf("ordinary prose was altered by the PII layer:\n  in:  %s\n  out: %s", c, out)
		}
	}
}

// TestPIIComposesWithSecretRedaction proves the two boundaries stack: a prompt
// carrying BOTH a secret and PII has the secret stripped by DefaultRedactor AND
// the PII stripped by the PII layer when both run through the Adapter.
func TestPIIComposesWithSecretRedaction(t *testing.T) {
	cm := &captureModel{name: "cloud"}
	a := NewWithPII(cm, nil, PIIPolicy{})
	const prompt = "owner bob@corp.example.com set password=hunter2horsebattery on 198.51.100.7"
	if _, err := a.Reason(context.Background(), prompt); err != nil {
		t.Fatalf("Reason errored: %v", err)
	}
	for _, leak := range []string{"bob@corp.example.com", "hunter2horsebattery", "198.51.100.7"} {
		if strings.Contains(cm.seen, leak) {
			t.Errorf("material %q reached the model boundary:\n  seen: %s", leak, cm.seen)
		}
	}
}
