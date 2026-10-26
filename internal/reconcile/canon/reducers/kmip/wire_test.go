// SPDX-License-Identifier: BUSL-1.1

package kmip_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	servedkmip "trstctl.com/trstctl/internal/kmip"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers/kmip"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers/kmip/kmiptest"
)

func endpointFor(t *testing.T, srv *kmiptest.Server, maxObjects int) *kmip.WireEndpoint {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		if errs := srv.Errors(); len(errs) > 0 {
			t.Errorf("the client sent requests the served parser refuses: %v", errs)
		}
	})
	go srv.Serve(server)
	return kmip.NewWireEndpoint(client, maxObjects)
}

func testCertificateDER(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := crypto.SelfSignedCACert(key, "KMIP Observed CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A124: Locate pages through every identifier with Maximum Items and Offset
// Items, and Get Attributes maps each object's KMIP enumerations onto what the
// reducer records. A certificate's issuer and serial come from its value; no
// key value is ever requested.
func TestWireEndpointLocatesEveryObjectAndMapsItsAttributes(t *testing.T) {
	created := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	certDER := testCertificateDER(t)
	srv := kmiptest.New()
	srv.Add("key-aes", kmiptest.Object{ObjectType: kmiptest.ObjectTypeSymmetricKey, Algorithm: kmiptest.AlgorithmAES,
		Length: 256, State: kmiptest.StateActive, Initial: created})
	srv.Add("cert-ca", kmiptest.Object{ObjectType: kmiptest.ObjectTypeCertificate, Algorithm: kmiptest.AlgorithmECDSA,
		Length: 256, State: kmiptest.StateActive, Initial: created, CertificateDER: certDER})
	srv.Add("tmpl-old", kmiptest.Object{ObjectType: kmiptest.ObjectTypeTemplate, State: kmiptest.StatePreActive})
	for i := 0; i < 998; i++ {
		srv.Add(fmt.Sprintf("bulk-%04d", i), kmiptest.Object{ObjectType: kmiptest.ObjectTypeSymmetricKey, State: kmiptest.StateActive})
	}
	ep := endpointFor(t, srv, 0)
	ctx := context.Background()
	ids, err := ep.Locate(ctx, "tenant-a")
	if err != nil || len(ids) != 1001 || ids[0] != "key-aes" || ids[1000] != "bulk-0997" {
		t.Fatalf("locate = %d ids, %v", len(ids), err)
	}
	if got := fmt.Sprint(srv.Offsets()); got != "[0 500 1000]" {
		t.Fatalf("locate offsets = %v, want three pages", got)
	}

	key, err := ep.GetAttributes(ctx, "key-aes")
	if err != nil || key.ObjectType != kmip.ObjectTypeSymmetricKey || key.Algorithm != "AES" || key.LengthBits != 256 ||
		key.State != kmip.StateActive || !key.InitialDate.Equal(created) {
		t.Fatalf("symmetric key = %+v, %v", key, err)
	}
	cert, err := ep.GetAttributes(ctx, "cert-ca")
	wantIssuer, wantSerial, _ := crypto.CertificateIssuerAndSerial(certDER)
	if err != nil || cert.ObjectType != kmip.ObjectTypeCertificate || string(cert.IssuerNameDER) != string(wantIssuer) ||
		cert.SerialHex != wantSerial || !strings.Contains(cert.SubjectDN, "KMIP Observed CA") {
		t.Fatalf("certificate = %+v, %v", cert, err)
	}
	if _, err := ep.GetAttributes(ctx, "tmpl-old"); !errors.Is(err, kmip.ErrUnmappedObjectType) {
		t.Fatalf("a template = %v, want ErrUnmappedObjectType", err)
	}
	if srv.KeyValueReads() != 0 {
		t.Fatalf("the endpoint asked for %d key values", srv.KeyValueReads())
	}
}

// An observation never becomes a partial inventory: more objects than the cap,
// a server that ignores Offset Items, a refused operation and an answer to
// another operation each fail it.
func TestWireEndpointFailsClosed(t *testing.T) {
	ctx := context.Background()
	fill := func(srv *kmiptest.Server) *kmiptest.Server {
		for i := 0; i < 600; i++ {
			srv.Add(fmt.Sprintf("k-%03d", i), kmiptest.Object{ObjectType: kmiptest.ObjectTypeSymmetricKey, State: kmiptest.StateActive})
		}
		return srv
	}
	if _, err := endpointFor(t, fill(kmiptest.New()), 550).Locate(ctx, "tenant-a"); !errors.Is(err, kmip.ErrTooManyObjects) {
		t.Fatalf("locate over the cap = %v, want ErrTooManyObjects", err)
	}
	repeating := fill(kmiptest.New())
	repeating.IgnoreOffset = true
	if _, err := endpointFor(t, repeating, 0).Locate(ctx, "tenant-a"); err == nil || !strings.Contains(err.Error(), "Offset Items") {
		t.Fatalf("a server repeating pages = %v, want an Offset Items failure", err)
	}
	refusing := fill(kmiptest.New())
	refusing.Refuse = servedkmip.OperationLocate
	if _, err := endpointFor(t, refusing, 0).Locate(ctx, "tenant-a"); err == nil || !strings.Contains(err.Error(), "refused by the test server") {
		t.Fatalf("a refused locate = %v, want the server's message", err)
	}
	confused := fill(kmiptest.New())
	confused.WrongOperation = true
	if _, err := endpointFor(t, confused, 0).Locate(ctx, "tenant-a"); err == nil {
		t.Fatal("an answer to another operation was accepted")
	}
}
