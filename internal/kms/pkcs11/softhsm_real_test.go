// SPDX-License-Identifier: MPL-2.0

//go:build pkcs11cgo && cgo

package pkcs11_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/pkcs11"
)

func TestSoftHSMRealBindingGenerateSign(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, and TRSTCTL_SOFTHSM_USER_PIN are required")
	}

	sess, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
		ModulePath:     modulePath,
		TokenLabel:     tokenLabel,
		UserPIN:        []byte(userPIN),
		KeyLabelPrefix: "trstctl-kms03",
	})
	if err != nil {
		t.Fatalf("open SoftHSM module session: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	b := pkcs11.New(sess)
	if err := crypto.ConformBackend(b, []crypto.Algorithm{crypto.RSA2048}); err != nil {
		t.Fatalf("SoftHSM PKCS#11 backend failed conformance: %v", err)
	}
	t.Log("SOFTHSM_PKCS11_OK")
}

func TestSoftHSMEdgeCAHandleSurvivesSessionRestart(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, and TRSTCTL_SOFTHSM_USER_PIN are required")
	}
	open := func(t *testing.T) pkcs11.Session {
		t.Helper()
		sess, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
			ModulePath: modulePath, TokenLabel: tokenLabel, UserPIN: []byte(userPIN), KeyLabelPrefix: "trstctl-edge-aud26",
		})
		if err != nil {
			t.Fatalf("open SoftHSM edge session: %v", err)
		}
		return sess
	}

	ctx := context.Background()
	firstSession := open(t)
	firstBackend := pkcs11.New(firstSession)
	handle, csrDER, err := crypto.GenerateEdgeCAKeyHandleAndCSR(
		ctx, "aud26-softhsm-edge-generation-1", "softhsm edge CA", crypto.RSA2048, firstBackend,
	)
	if err != nil {
		_ = firstSession.Close()
		t.Fatalf("create edge CA in SoftHSM: %v", err)
	}
	raw, err := json.Marshal(handle)
	if err != nil {
		_ = firstSession.Close()
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "private_key") {
		_ = firstSession.Close()
		t.Fatalf("public edge handle contains private material: %s", raw)
	}
	if err := firstSession.Close(); err != nil {
		t.Fatalf("close first SoftHSM session: %v", err)
	}

	parentSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parentSigner.Destroy)
	parent, err := crypto.SelfSignedHierarchyCA(parentSigner, crypto.HierarchyCAProfile{
		CommonName: "SoftHSM edge parent", MaxPathLen: 1, TTL: 24 * time.Hour,
		PermittedDNSDomains: []string{"edge.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := crypto.MintDelegatedEdgeCAFromCSR(parent.CertificateDER, parentSigner, csrDER, crypto.EdgeCARequest{
		CommonName: "softhsm edge CA", PermittedDNSDomains: []string{"edge.example.test"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	secondSession := open(t)
	t.Cleanup(func() { _ = secondSession.Close() })
	leaf, err := crypto.IssueEdgeLeafWithKeyHandle(ctx, delegation.CertificatePEM, handle, pkcs11.New(secondSession), crypto.EdgeLeafRequest{
		CommonName: "db.edge.example.test", TTL: 10 * time.Minute,
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("issue after reopening SoftHSM session: %v", err)
	}
	if _, err := crypto.InspectEdgeReportedLeaf(delegation.CertificateDER, leaf.CertificateDER); err != nil {
		t.Fatalf("reopened token did not sign the edge leaf: %v", err)
	}
	t.Logf("SOFTHSM_EDGE_CA_OK handle=%s", handle.KeyID)
}
