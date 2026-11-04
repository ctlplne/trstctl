// SPDX-License-Identifier: BUSL-1.1

package letsencrypt_test

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// alwaysValidSolver answers dns-01 without publishing anything: the runner
// starts Pebble with PEBBLE_VA_ALWAYS_VALID=1, so the order and authorization
// flow is Pebble's own while DNS publication stays P1's proven path.
type alwaysValidSolver struct{}

func (alwaysValidSolver) SolvableChallenges() []string { return []string{acmekey.ChallengeDNS01} }

func (alwaysValidSolver) Solve(context.Context, acmekey.ChallengeRequest) (func(context.Context) error, error) {
	return nil, nil
}

// N10 against Pebble 2.10.1, the CI-pinned ACME CA (runners/n10-pebble-proof.sh).
// trstctl's account obtains authorizations for every name of a certificate
// another account requested, and the revocation it then sends identifies that
// certificate: Pebble finds it and refuses the account, because Pebble
// implements only the issuing-account rule of RFC 8555 §7.6 (its WFE marks the
// authorized-account rule unimplemented). The issuing account revokes the same bytes.
func TestRevokeWithAuthorizationsAgainstPebbleN10(t *testing.T) {
	directory, caFile := os.Getenv("TRSTCTL_N10_PEBBLE_DIRECTORY"), os.Getenv("TRSTCTL_N10_PEBBLE_CA_FILE")
	if directory == "" || caFile == "" {
		t.Skip("set TRSTCTL_N10_PEBBLE_DIRECTORY and TRSTCTL_N10_PEBBLE_CA_FILE (runners/n10-pebble-proof.sh)")
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 G703 -- the runner's copy of Pebble's test root (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	ctx := context.Background()
	other, err := newAccountPlugin(t, directory, client, alwaysValidSolver{})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"rogue.n10.test", "www.rogue.n10.test"}
	issued, err := other.Issue(ctx, ca.IssueRequest{TenantID: "someone-else", CSR: buildCSR(t, names[0], names), DNSNames: names})
	if err != nil {
		t.Fatalf("another account's issuance: %v", err)
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	trstctl, err := newAccountPlugin(t, directory, client, alwaysValidSolver{})
	if err != nil {
		t.Fatal(err)
	}
	err = trstctl.RevokeWithAuthorizations(ctx, "tenant-a", block.Bytes, 1)
	if err == nil || !strings.Contains(err.Error(), "does not accept trstctl's account") {
		t.Fatalf("revocation by an authorized account = %v; want Pebble's refusal of the account", err)
	}
	located := false
	for cause := error(err); cause != nil; cause = errors.Unwrap(cause) {
		located = located || strings.Contains(cause.Error(), "is not associated with account")
	}
	if !located {
		t.Fatalf("Pebble did not identify the certificate from its bytes: %v", err)
	}
	if err := other.Revoke(ctx, ca.RevokeRequest{CertificatePEM: issued.CertificatePEM, ReasonCode: 1}); err != nil {
		t.Fatalf("the issuing account's revocation of the same certificate: %v", err)
	}
}
