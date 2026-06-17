package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestProtocolTransportKeyPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	t.Cleanup(wrapper.Destroy)
	keyFile := filepath.Join(dir, "protocol-ra.key")

	first := &Server{}
	raCert1, raKey1, err := first.protocolTransportKey(keyFile, wrapper)
	if err != nil {
		t.Fatalf("first protocolTransportKey: %v", err)
	}
	t.Cleanup(func() { secret.Wipe(raKey1) })
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("sealed RA key was not written: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("sealed RA key mode = %o, want 0600", got)
	}

	clientCert, clientKey, csrDER := newSCEPClient(t, "cached-scep-client")
	reqDER, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, raCert1, "cached-ra-txn")
	if err != nil {
		t.Fatalf("build SCEP request with cached RA cert: %v", err)
	}

	restarted := &Server{}
	raCert2, raKey2, err := restarted.protocolTransportKey(keyFile, wrapper)
	if err != nil {
		t.Fatalf("restart protocolTransportKey: %v", err)
	}
	t.Cleanup(func() { secret.Wipe(raKey2) })
	if !bytes.Equal(raCert1, raCert2) {
		t.Fatal("restart loaded a different RA certificate; cached SCEP GetCACert clients would fail")
	}
	if !bytes.Equal(raKey1, raKey2) {
		t.Fatal("restart loaded a different RA key; SCEP/CMP responses would not match cached RA material")
	}
	parsed, err := crypto.ParseSCEPRequest(reqDER, raCert2, raKey2)
	if err != nil {
		t.Fatalf("cached SCEP request did not decrypt after restart: %v", err)
	}
	if !bytes.Equal(parsed.CSRDER, csrDER) {
		t.Fatal("cached SCEP request decrypted to the wrong CSR after restart")
	}
}

func TestProtocolTransportKeyRequiresSealedStore(t *testing.T) {
	_, _, err := (&Server{}).protocolTransportKey(filepath.Join(t.TempDir(), "protocol-ra.key"), nil)
	if err == nil {
		t.Fatal("protocolTransportKey without a KEK must fail closed")
	}
	if !strings.Contains(err.Error(), "KEK") {
		t.Fatalf("protocolTransportKey error should explain the missing KEK, got %v", err)
	}
}
