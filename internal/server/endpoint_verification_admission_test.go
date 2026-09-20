// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestVerificationAdmissionRetainsShippingNormalizationAndFailureSemantics(t *testing.T) {
	want := relay.EndpointExpectation{EndpointID: "bound", Address: " 127.0.0.1:5432 ", ServerName: " db.example.test ", Fingerprint: strings.Repeat("AA:", 31) + "AA", DNSNames: []string{" DB.EXAMPLE.TEST. "}, ChainFingerprints: []string{strings.Repeat("BB:", 31) + "BB"}}
	intent, err := json.Marshal(relay.EndpointVerifyIntent{Endpoints: []relay.EndpointExpectation{want}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	valid := transport.ProbeTranscript{Address: strings.TrimSpace(want.Address), ServerName: strings.TrimSpace(want.ServerName), Vantage: transport.VantageRelay, ExpectedFingerprint: strings.Repeat("aa", 32), ExpectedSANDigest: transport.SANSetDigest(want.DNSNames), ExpectedChainDigest: transport.ChainDigest(want.ChainFingerprints), Error: "controlled refusal", ObservedAtUnix: now}
	check := func(tr transport.ProbeTranscript) error {
		payload, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: want.EndpointID, Transcript: tr}}})
		if err != nil {
			return err
		}
		_, err = validateEndpointVerificationReport(intent, string(payload), transport.SweepDigest(append(tr.Canonical(), '\n')))
		return err
	}
	if err := check(valid); err != nil {
		t.Fatalf("shipping normalization/refusal was rejected: %v", err)
	}
	unparseable := valid
	unparseable.Reached = true
	unparseable.Error = "unparseable peer"
	unparseable.Mismatch = certinfo.MismatchFingerprint
	unparseable.ChainBytes = 200
	if err := check(unparseable); err != nil {
		t.Fatalf("truthful unparseable-peer observation was rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*transport.ProbeTranscript)
	}{
		{"invented-dates", func(tr *transport.ProbeTranscript) { tr.NotAfterUnix = now + 60 }},
		{"changed-names", func(tr *transport.ProbeTranscript) { tr.ExpectedSANDigest = "" }},
		{"changed-chain", func(tr *transport.ProbeTranscript) { tr.ExpectedChainDigest = "" }},
		{"clean-without-peer", func(tr *transport.ProbeTranscript) { tr.Reached = true; tr.Error = "" }},
		{"clean-with-other-peer", func(tr *transport.ProbeTranscript) {
			tr.Reached = true
			tr.Error = ""
			tr.ObservedFingerprint = strings.Repeat("c", 64)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := valid
			tc.mutate(&bad)
			if err := check(bad); err == nil {
				t.Fatal("contradictory observation was accepted")
			}
		})
	}
}

func TestDeploymentVerificationReadsSealedRoutingBeforeLegacyFields(t *testing.T) {
	wrapped := sealedConnectorDeployPayload{Format: connectorDeploySealedFormat, Version: 1, Connector: "postgresql", Target: "owned-db", TargetID: "owned-target", Fingerprint: strings.Repeat("a", 64), TargetConfig: json.RawMessage(`{"verify_address":"127.0.0.1:5432","verify_server_name":"db.example.test"}`)}
	payload, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	got, rollback := deployIntentForVerificationReceipt(payload)
	if rollback || got.TargetID != wrapped.TargetID || got.Fingerprint != wrapped.Fingerprint || got.VerifyAddress != "127.0.0.1:5432" || got.VerifyServerName != "db.example.test" {
		t.Fatalf("sealed routing lost its verification binding: %+v", got)
	}
}

func TestDeploymentVerificationReadsUnsealedTargetConfig(t *testing.T) {
	payload := []byte(`{"connector":"postgresql","target":"owned-db","target_id":"owned-target","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_config":{"verify_address":"127.0.0.1:5432","verify_server_name":"db.example.test"}}`)
	got, rollback := deployIntentForVerificationReceipt(payload)
	if rollback || got.VerifyAddress != "127.0.0.1:5432" || got.VerifyServerName != "db.example.test" {
		t.Fatalf("unsealed routing lost its verification binding: %+v", got)
	}
}

func TestDeploymentVerificationReadsRollbackTargetConfig(t *testing.T) {
	payload := []byte(`{"connector":"nginx","target":"owned-host","target_id":"owned-target","predecessor_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_config":{"verify_address":"127.0.0.1:443","verify_server_name":"host.example.test"}}`)
	got, rollback := deployIntentForVerificationReceipt(payload)
	if !rollback || got.VerifyAddress != "127.0.0.1:443" || got.VerifyServerName != "host.example.test" {
		t.Fatalf("rollback routing lost its verification binding: %+v", got)
	}
}
