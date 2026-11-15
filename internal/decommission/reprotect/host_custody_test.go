// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

// openCustodyTestStore starts an embedded PostgreSQL with the schema.
func openCustodyTestStore(t *testing.T) *corestore.Store {
	t.Helper()
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	if port <= 0 || port > math.MaxUint16 {
		t.Fatalf("invalid embedded PostgreSQL port %d", port)
	}
	pgDir := filepath.Join(t.TempDir(), "postgres")
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(uint32(port)). // #nosec G115 -- port was checked against the uint16 maximum above (CWE-190)
		RuntimePath(filepath.Join(pgDir, "rt")).DataPath(filepath.Join(pgDir, "data")).
		BinariesPath(filepath.Join(pgDir, "bin")).Logger(io.Discard).StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		t.Fatalf("start PostgreSQL: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })
	st, err := corestore.Open(ctx, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate PostgreSQL: %v", err)
	}
	return st
}

// TestHostReprotectionKeyCustodyFollowsThePredecessorTPMO1L1: a CA
// re-protection runs through the host's TPM exactly when its predecessor's
// recorded custody is the device-bound claim a host agent's TPM attestation
// proved. A certificate whose key a host agent's TPM attested asks for key
// custody "tpm"; one an ACME client's device attested, and one whose key is a
// host file, ask for none; and a job whose key custody differs from its
// predecessor's, either way, is refused at signing.
func TestHostReprotectionKeyCustodyFollowsThePredecessorTPMO1L1(t *testing.T) {
	ctx := context.Background()
	st := openCustodyTestStore(t)
	const tenant = "6f2c9d4e-1b7a-4c3e-9a5d-2e8f0b1c7d31"
	if err := st.UpsertTenant(ctx, corestore.Tenant{TenantID: tenant, Name: "TPM-O1-L1 custody"}); err != nil {
		t.Fatal(err)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "TPM-O1-L1 predecessor CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	record := func(name, origin, storage string) corestore.Certificate {
		t.Helper()
		subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer subject.Destroy()
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}}, subject)
		if err != nil {
			t.Fatal(err)
		}
		leafDER, err := crypto.SignLeafFromCSR(caDER, ca, csr, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		info, err := certinfo.Inspect(leafDER)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := st.UpsertCertificate(ctx, corestore.Certificate{TenantID: tenant, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer,
			Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, CertificateDER: leafDER, CertificatePEM: crypto.EncodeCertificatePEM(leafDER),
			KeyOrigin: origin, KeyStorage: storage, Status: "active"})
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	attest := func(cert corestore.Certificate, source string) corestore.Certificate {
		t.Helper()
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return st.ApplyCertificateDeviceCustodyTx(ctx, tx, tenant, cert.Fingerprint, "web-agent", corestore.CertificateKeyAttestation{
				EventID: "evt-" + source, Source: source, Format: "tpm-webauthn", Credential: []byte("credential"), Binding: []byte("binding"),
				PublicKeySHA256: []byte("public"), AttestationCertificateSHA256: []byte("aik"), TrustedRootsSHA256: []byte("roots"), VerifiedAt: time.Now().UTC()})
		}); err != nil {
			t.Fatal(err)
		}
		got, err := st.GetCertificate(ctx, tenant, cert.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	tpmHeld := attest(record("tpm.tpm-o1-l1.test", "requester", ""), projections.CertificateDeviceAttestationSourceHostAgentTPM)
	acmeDevice := attest(record("acme.tpm-o1-l1.test", "requester", ""), projections.CertificateDeviceAttestationSourceACME)
	fileKey := record("file.tpm-o1-l1.test", "host_agent", "file")
	for _, tc := range []struct {
		name string
		cert corestore.Certificate
		want string
	}{
		{"a host agent's TPM-held key", tpmHeld, hostKeyCustodyTPM},
		{"an ACME client's device-attested key", acmeDevice, ""},
		{"a host file key", fileKey, ""},
	} {
		got, err := hostReprotectKeyCustody(ctx, st, tenant, tc.cert)
		if err != nil || got != tc.want {
			t.Errorf("%s: custody %q, %v; want %q", tc.name, got, err, tc.want)
		}
		if err := verifyHostReprotectCustody(ctx, st, tenant, tc.cert, hostReprotectIntent{KeyCustody: tc.want}); err != nil {
			t.Errorf("%s: its own custody was refused: %v", tc.name, err)
		}
		other := hostKeyCustodyTPM
		if tc.want == hostKeyCustodyTPM {
			other = ""
		}
		if err := verifyHostReprotectCustody(ctx, st, tenant, tc.cert, hostReprotectIntent{KeyCustody: other}); err == nil ||
			!strings.Contains(err.Error(), "is not the predecessor's") {
			t.Errorf("%s: a job asking for custody %q was not refused: %v", tc.name, other, err)
		}
	}
}
