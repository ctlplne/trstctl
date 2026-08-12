// SPDX-License-Identifier: MPL-2.0

package transport_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/plugincensus"
)

type censusSigner struct{ statement []byte }

func (s *censusSigner) SignStatement(statement []byte) ([]byte, error) {
	s.statement = append([]byte(nil), statement...)
	return []byte("detached-signature"), nil
}

func TestSignedPluginCensusBindsIdentityMetadataAndTime(t *testing.T) {
	signer := &censusSigner{}
	plugins := []plugincensus.Entry{{
		Name: "partner", Digest: "sha256:" + sixtyFour("a"), Publisher: "sha256:" + sixtyFour("b"),
		ExecutionContext: plugincensus.ExecutionContextNetworkRelayWASM,
		Grants:           []plugincensus.Grant{{Capability: "net.dial", Constraints: []string{"appliance.internal:443"}}},
	}}
	report, err := transport.SignedPluginCensus(signer, "tenant-a", "relay-a", plugins, 1786550400)
	if err != nil {
		t.Fatalf("sign plugin census: %v", err)
	}
	if !bytes.Equal(report.Signature, []byte("detached-signature")) || len(signer.statement) == 0 {
		t.Fatalf("signed report = %+v statement=%q", report, signer.statement)
	}
	original := append([]byte(nil), signer.statement...)
	mutated := plugincensus.Statement{
		TenantID: "tenant-a", AgentCommonName: "relay-a", Plugins: report.Plugins, IssuedAtUnix: report.IssuedAtUnix,
	}
	mutated.Plugins[0].Grants[0].Constraints[0] = "other.internal:443"
	canonical, err := mutated.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, canonical) {
		t.Fatal("changing an effective constraint did not change the signed statement")
	}
}

func sixtyFour(v string) string {
	var out string
	for range 64 {
		out += v
	}
	return out
}
