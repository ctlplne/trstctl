// SPDX-License-Identifier: MPL-2.0

package custody_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/custody"
)

// The custody vocabulary (epic B5). What is being tested is not that the words
// are right but that the GAPS read as gaps — a custody line that sounds
// confident about facts nobody recorded is worse than no line, because an
// auditor will believe it.

// TestUnrecordedSaysSoRatherThanReassuring is the property the whole package
// exists for.
func TestUnrecordedSaysSoRatherThanReassuring(t *testing.T) {
	summary := custody.Record{}.Summary()
	if !strings.Contains(strings.ToLower(summary), "not recorded") {
		t.Fatalf("an unrecorded custody summary does not say so: %q", summary)
	}
	// It must not accidentally read like any of the reassuring answers.
	for _, phrase := range []string{"never held", "cannot leave", "non-exportable"} {
		if strings.Contains(strings.ToLower(summary), phrase) {
			t.Errorf("an unrecorded summary contains the reassuring phrase %q: %q", phrase, summary)
		}
	}
	if (custody.Record{}).Recorded() {
		t.Error("an empty record reports itself as recorded")
	}
}

// TestControlPlaneOriginIsStatedPlainly: a credential on the deprecated path is
// one an operator should plan to replace, and they cannot plan for what the
// summary softens.
func TestControlPlaneOriginIsStatedPlainly(t *testing.T) {
	r := custody.Record{Origin: custody.OriginControlPlane, Storage: custody.StorageLockedMemory}
	summary := r.Summary()
	if !r.ControlPlaneHeldKey() {
		t.Fatal("a control-plane origin does not report that the control plane held the key")
	}
	if !strings.Contains(summary, "CONTROL PLANE") {
		t.Errorf("the deprecated path is not stated plainly: %q", summary)
	}
	// And it must not claim the reassuring thing the requester path claims.
	if strings.Contains(summary, "never held it") {
		t.Errorf("the control-plane summary claims the key was never held: %q", summary)
	}
}

// TestRequesterOriginAnswersTheAuditorsFirstQuestion.
func TestRequesterOriginAnswersTheAuditorsFirstQuestion(t *testing.T) {
	r := custody.Record{Origin: custody.OriginRequester}
	if r.ControlPlaneHeldKey() {
		t.Fatal("a requester-generated key reports the control plane held it")
	}
	if !strings.Contains(r.Summary(), "never held it") {
		t.Errorf("the requester summary does not answer the first question: %q", r.Summary())
	}
}

// TestHostAgentNamesTheMachineWhenItCan: "a host agent made it" is less useful
// than naming which one, and an auditor follows up on the specific.
func TestHostAgentNamesTheMachineWhenItCan(t *testing.T) {
	named := custody.Record{Origin: custody.OriginHostAgent, GeneratedBy: "edge-agent-01"}
	if !strings.Contains(named.Summary(), "edge-agent-01") {
		t.Errorf("a named host agent is not in the summary: %q", named.Summary())
	}
	anonymous := custody.Record{Origin: custody.OriginHostAgent}
	if strings.Contains(anonymous.Summary(), "the agent  on") {
		t.Errorf("an unnamed agent produced a malformed summary: %q", anonymous.Summary())
	}
}

// TestPartialCustodySaysOnlyWhatIsKnown: recording an origin without a storage
// class must not invent one.
func TestPartialCustodySaysOnlyWhatIsKnown(t *testing.T) {
	r := custody.Record{Origin: custody.OriginRequester}
	summary := r.Summary()
	for _, invented := range []string{"locked", "file", "token", "exportable"} {
		if strings.Contains(strings.ToLower(summary), invented) {
			t.Errorf("a record with only an origin invented %q: %q", invented, summary)
		}
	}
}

// TestVocabularyIsClosed: every value the database will accept is one this
// package recognizes, and nothing else is.
func TestVocabularyIsClosed(t *testing.T) {
	for _, v := range []custody.KeyOrigin{
		custody.OriginRequester, custody.OriginHostAgent, custody.OriginDevice,
		custody.OriginControlPlane, custody.OriginSigner, custody.OriginUnrecorded,
	} {
		if !custody.ValidOrigin(v) {
			t.Errorf("declared origin %q is not valid", v)
		}
	}
	if custody.ValidOrigin("somewhere") {
		t.Error("an unknown origin was accepted")
	}
	if custody.ValidStorage("a drawer") {
		t.Error("an unknown storage class was accepted")
	}
	if custody.ValidExportability("maybe") {
		t.Error("an unknown exportability was accepted")
	}
}
