package acme_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// TestACMEOnlyReturnExistingNoAccount is the INTEROP-010 acceptance: a newAccount
// with onlyReturnExisting=true for a key with no registered account MUST be rejected
// with 400 accountDoesNotExist (RFC 8555 §7.3.1). The real x/crypto/acme client
// surfaces this as GetReg(ctx, "") (it sends onlyReturnExisting). Pre-fix newAccount
// ignored the flag and CREATED an account, so GetReg wrongly succeeded.
func TestACMEOnlyReturnExistingNoAccount(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.DefaultValidators()))
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// No account has been registered for this key: GetReg ("look up existing
	// account, do not create") must fail with accountDoesNotExist.
	_, err = client.GetReg(ctx, "")
	if err == nil {
		t.Fatal("GetReg with onlyReturnExisting succeeded for an unregistered key — the server created an account (INTEROP-010)")
	}
	var aerr *xacme.Error
	if errors.As(err, &aerr) {
		if aerr.ProblemType != "urn:ietf:params:acme:error:accountDoesNotExist" {
			t.Errorf("GetReg returned problem %q, want accountDoesNotExist", aerr.ProblemType)
		}
	} else {
		t.Logf("GetReg returned non-ACME error (acceptable as long as it is a rejection): %v", err)
	}

	// After a real registration, onlyReturnExisting returns the SAME account.
	acct, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	existing, err := client.GetReg(ctx, "")
	if err != nil {
		t.Fatalf("GetReg after registration failed: %v", err)
	}
	if existing.URI != acct.URI {
		t.Errorf("onlyReturnExisting returned a different account: %q != %q", existing.URI, acct.URI)
	}
}

// TestACMEDirectoryMetaIsRich is the INTEROP-010 directory-meta acceptance: when the
// server is configured with DirectoryMeta, the directory advertises website,
// caaIdentities, and externalAccountRequired (RFC 8555 §7.1.1), which the real
// x/crypto/acme client surfaces via Discover(). Pre-fix meta carried only
// termsOfService.
func TestACMEDirectoryMetaIsRich(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	srv := acmesrv.New(builtin, acmesrv.DefaultValidators()).WithDirectoryMeta(acmesrv.DirectoryMeta{
		TermsOfService:          "https://ca.example/tos",
		Website:                 "https://ca.example",
		CAAIdentities:           []string{"ca.example"},
		ExternalAccountRequired: true,
	})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if dir.Website != "https://ca.example" {
		t.Errorf("directory website = %q, want https://ca.example", dir.Website)
	}
	if len(dir.CAA) != 1 || dir.CAA[0] != "ca.example" {
		t.Errorf("directory caaIdentities = %v, want [ca.example]", dir.CAA)
	}
	if !dir.ExternalAccountRequired {
		t.Error("directory does not advertise externalAccountRequired")
	}
	if dir.Terms != "https://ca.example/tos" {
		t.Errorf("directory terms = %q, want https://ca.example/tos", dir.Terms)
	}
}

// TestACMEExternalAccountRequiredRejectsBareRegistration is the INTEROP-010 EAB
// acceptance: when the CA advertises externalAccountRequired, a newAccount that
// CREATES an account but carries no externalAccountBinding must be rejected
// (RFC 8555 §7.3.4). The x/crypto/acme client's plain Register sends no EAB, so it
// must fail against an EAB-required server.
func TestACMEExternalAccountRequiredRejectsBareRegistration(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	srv := acmesrv.New(builtin, acmesrv.DefaultValidators()).WithDirectoryMeta(acmesrv.DirectoryMeta{
		ExternalAccountRequired: true,
	})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(context.Background(), &xacme.Account{}, xacme.AcceptTOS); err == nil {
		t.Fatal("a bare registration (no externalAccountBinding) was accepted by an EAB-required CA (INTEROP-010)")
	}
}
