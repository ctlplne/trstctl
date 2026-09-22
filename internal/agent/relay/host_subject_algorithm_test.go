// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqc"
)

// This exercises the actual host executor up to its signing RPC. A deliberate
// refusal stops before installation; it is key-selection/custody proof only.
func TestHostRenewalUsesReviewedSubjectAlgorithm(t *testing.T) {
	for _, algorithm := range []string{"", string(crypto.ECDSAP256), string(pqc.MLDSA44), string(pqc.MLDSA65), string(pqc.MLDSA87), "unsupported"} {
		t.Run(algorithm, func(t *testing.T) {
			dir := t.TempDir()
			ch := &renewChannel{signErr: errors.New("stop before deployment")}
			ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
				Connector: "nginx", Target: "host", SubjectCommonName: "api.example.test", SubjectDNSNames: []string{"api.example.test"},
				TargetConfig: renewTargetConfig(t, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")),
			})}
			// Write the public wire field independently of the executor struct so
			// this regression also detects old agents silently ignoring it.
			var payload map[string]any
			if err := json.Unmarshal(ch.jobs[0].Payload, &payload); err != nil {
				t.Fatal(err)
			}
			payload["subject_key_algorithm"] = algorithm
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			ch.jobs[0].Payload = encoded
			if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, connector.LocalOpsConfig{AllowedRoots: []string{dir}}, 1, 60); err != nil {
				t.Fatal(err)
			}
			if algorithm == "unsupported" {
				if ch.signCalls != 0 {
					t.Fatal("unsupported algorithm silently selected another key")
				}
				return
			}
			if ch.signCalls != 1 || len(ch.signed) != 1 {
				t.Fatalf("sign calls = %d", ch.signCalls)
			}
			csr := ch.signed[0]
			if bytes.Contains(csr, []byte("PRIVATE KEY")) || ch.redeemed != 0 {
				t.Fatal("host subject generation requested or exposed private material")
			}
			if algorithm == "" || algorithm == string(crypto.ECDSAP256) {
				info, err := crypto.InspectCSR(csr)
				if err != nil || info.KeyAlgorithm != "ECDSA" || info.KeyBits != 256 {
					t.Fatalf("legacy subject changed: %v", err)
				}
				return
			}
			info, recognized, err := pqc.ParsePureMLDSACSR(csr)
			if err != nil || !recognized || info.KeyAlgorithm != algorithm || info.CommonName != "api.example.test" || len(info.DNSNames) != 1 || info.DNSNames[0] != "api.example.test" {
				t.Fatalf("requested algorithm or names changed: %+v %v", info, err)
			}
		})
	}
}
