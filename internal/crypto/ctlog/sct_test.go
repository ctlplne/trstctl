// SPDX-License-Identifier: BUSL-1.1

package ctlog_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
)

func submit(t *testing.T, log *ctlogtest.Server, endpoint string, chain ...[]byte) ctlog.SCT {
	t.Helper()
	var encoded []string
	for _, der := range chain {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(der))
	}
	body, _ := json.Marshal(map[string]any{"chain": encoded})
	resp, err := http.Post(log.URL()+endpoint, "application/json", bytes.NewReader(body)) // #nosec G107 -- loopback test log (CWE-918)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s = %d %s", endpoint, resp.StatusCode, raw)
	}
	sct, err := ctlog.ParseSCT(raw)
	if err != nil {
		t.Fatal(err)
	}
	return sct
}

func get(t *testing.T, target string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(target) // #nosec G107 -- loopback test log (CWE-918)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func signedTreeHead(t *testing.T, log *ctlogtest.Server) ctlog.SignedTreeHead {
	t.Helper()
	_, raw := get(t, log.URL()+"/ct/v1/get-sth")
	sth, err := ctlog.ParseSignedTreeHead(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctlog.VerifySignedTreeHead(sth, log.PublicKeyDER()); err != nil {
		t.Fatalf("signed tree head: %v", err)
	}
	return sth
}

func proof(t *testing.T, log *ctlogtest.Server, leafHash []byte, treeSize uint64) (int, ctlog.InclusionProof) {
	t.Helper()
	status, raw := get(t, log.URL()+"/ct/v1/get-proof-by-hash?hash="+url.QueryEscape(base64.StdEncoding.EncodeToString(leafHash))+
		"&tree_size="+strconv.FormatUint(treeSize, 10))
	if status != http.StatusOK {
		return status, ctlog.InclusionProof{}
	}
	p, err := ctlog.ParseInclusionProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	return status, p
}

// A213: an SCT verifies against the log key over the exact RFC 6962 entry,
// for a certificate and for a precertificate, and the leaf it names is proven
// included under a signed tree head at every position of a growing tree.
func TestSCTsVerifyAndTheirEntriesAreProvenIncluded(t *testing.T) {
	log := ctlogtest.NewSigningServer()
	defer log.Close()
	var leafHashes [][]byte
	for i := range 6 {
		der, _, err := ctlogtest.IssueCert("ct-" + strconv.Itoa(i) + ".example")
		if err != nil {
			t.Fatal(err)
		}
		sct := submit(t, log, "/ct/v1/add-chain", der)
		leafHash, err := ctlog.VerifySCT(sct, log.PublicKeyDER(), [][]byte{der}, false)
		if err != nil {
			t.Fatalf("certificate SCT %d: %v", i, err)
		}
		leafHashes = append(leafHashes, leafHash)
	}
	precert, issuer, err := ctlogtest.IssuePrecert("pre.example", "pre.example")
	if err != nil {
		t.Fatal(err)
	}
	sct := submit(t, log, "/ct/v1/add-pre-chain", precert, issuer)
	preHash, err := ctlog.VerifySCT(sct, log.PublicKeyDER(), [][]byte{precert, issuer}, true)
	if err != nil {
		t.Fatalf("precertificate SCT: %v", err)
	}
	leafHashes = append(leafHashes, preHash)
	sth := signedTreeHead(t, log)
	if sth.TreeSize != uint64(len(leafHashes)) {
		t.Fatalf("tree size = %d, want %d", sth.TreeSize, len(leafHashes))
	}
	for i, leafHash := range leafHashes {
		status, p := proof(t, log, leafHash, sth.TreeSize)
		if status != http.StatusOK || p.LeafIndex != uint64(i) {
			t.Fatalf("proof %d = %d index %d", i, status, p.LeafIndex)
		}
		if err := ctlog.VerifyInclusion(leafHash, p.LeafIndex, sth.TreeSize, p.AuditPath, sth.RootHash); err != nil {
			t.Fatalf("inclusion of entry %d: %v", i, err)
		}
	}
	wrongRoot := append([]byte(nil), sth.RootHash...)
	wrongRoot[0] ^= 1
	_, p := proof(t, log, leafHashes[3], sth.TreeSize)
	if err := ctlog.VerifyInclusion(leafHashes[3], p.LeafIndex, sth.TreeSize, p.AuditPath, wrongRoot); err == nil {
		t.Fatal("an inclusion proof verified against another root")
	}
	if err := ctlog.VerifyInclusion(leafHashes[2], p.LeafIndex, sth.TreeSize, p.AuditPath, sth.RootHash); err == nil {
		t.Fatal("one entry's proof verified another entry")
	}
	tampered := sth
	tampered.TreeSize++
	if err := ctlog.VerifySignedTreeHead(tampered, log.PublicKeyDER()); err == nil {
		t.Fatal("a tree head whose size was changed verified")
	}
}

// A corrupted SCT signature, an SCT checked against another log's key, and an
// SCT checked against another certificate are each refused.
func TestBadSCTsAreRefused(t *testing.T) {
	corrupt := ctlogtest.NewSigningServer(ctlogtest.WithCorruptSCTs())
	defer corrupt.Close()
	der, _, err := ctlogtest.IssueCert("bad.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctlog.VerifySCT(submit(t, corrupt, "/ct/v1/add-chain", der), corrupt.PublicKeyDER(), [][]byte{der}, false); err == nil {
		t.Fatal("a corrupted SCT signature verified")
	}
	good := ctlogtest.NewSigningServer()
	defer good.Close()
	other := ctlogtest.NewSigningServer()
	defer other.Close()
	sct := submit(t, good, "/ct/v1/add-chain", der)
	if _, err := ctlog.VerifySCT(sct, other.PublicKeyDER(), [][]byte{der}, false); err == nil {
		t.Fatal("an SCT verified against another log's key")
	}
	another, _, err := ctlogtest.IssueCert("another.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctlog.VerifySCT(sct, good.PublicKeyDER(), [][]byte{another}, false); err == nil {
		t.Fatal("an SCT verified for another certificate")
	}
}

// A precertificate SCT checked without its issuer, or with a certificate that
// did not issue it, is not verifiable from that chain rather than bad.
func TestPrecertificateSCTsNeedTheirIssuer(t *testing.T) {
	log := ctlogtest.NewSigningServer()
	defer log.Close()
	precert, issuer, err := ctlogtest.IssuePrecert("pre-issuer.example", "pre-issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	sct := submit(t, log, "/ct/v1/add-pre-chain", precert, issuer)
	if _, err := ctlog.VerifySCT(sct, log.PublicKeyDER(), [][]byte{precert}, true); !errors.Is(err, ctlog.ErrNotVerifiable) {
		t.Fatalf("precertificate SCT without its issuer: %v; want not verifiable", err)
	}
	_, otherIssuer, err := ctlogtest.IssuePrecert("other.example", "other.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctlog.VerifySCT(sct, log.PublicKeyDER(), [][]byte{precert, otherIssuer}, true); !errors.Is(err, ctlog.ErrNotVerifiable) {
		t.Fatalf("precertificate SCT with another issuer: %v; want not verifiable", err)
	}
}

// Before the log merges an entry, the proof request finds nothing; after,
// the entry is proven under the newer tree head.
func TestInclusionFollowsTheMerge(t *testing.T) {
	log := ctlogtest.NewSigningServer(ctlogtest.WithDelayedMerge())
	defer log.Close()
	der, _, err := ctlogtest.IssueCert("later.example")
	if err != nil {
		t.Fatal(err)
	}
	leafHash, err := ctlog.VerifySCT(submit(t, log, "/ct/v1/add-chain", der), log.PublicKeyDER(), [][]byte{der}, false)
	if err != nil {
		t.Fatal(err)
	}
	if sth := signedTreeHead(t, log); sth.TreeSize != 0 {
		t.Fatalf("an unmerged entry is in the tree: size %d", sth.TreeSize)
	}
	if status, _ := proof(t, log, leafHash, 0); status != http.StatusNotFound {
		t.Fatalf("proof before merge = %d, want 404", status)
	}
	log.Merge()
	sth := signedTreeHead(t, log)
	status, p := proof(t, log, leafHash, sth.TreeSize)
	if status != http.StatusOK {
		t.Fatalf("proof after merge = %d", status)
	}
	if err := ctlog.VerifyInclusion(leafHash, p.LeafIndex, sth.TreeSize, p.AuditPath, sth.RootHash); err != nil {
		t.Fatalf("inclusion after merge: %v", err)
	}
}
