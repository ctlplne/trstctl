package saml

import (
	"bytes"
	"encoding/pem"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// signedAssertion builds and signs a SAML assertion, returning the assertion XML
// and the PEM-encoded signing certificate.
func signedAssertion(t *testing.T, audience string, notBefore, notOnOrAfter time.Time) ([]byte, []byte) {
	t.Helper()
	ks := dsig.RandomKeyStoreForTest()
	_, certDER, err := ks.GetKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	a := etree.NewElement("Assertion")
	a.CreateAttr("xmlns", "urn:oasis:names:tc:SAML:2.0:assertion")
	a.CreateAttr("ID", "_assertion1")
	a.CreateAttr("Version", "2.0")
	a.CreateElement("Subject").CreateElement("NameID").SetText("alice@example.com")
	cond := a.CreateElement("Conditions")
	cond.CreateAttr("NotBefore", notBefore.UTC().Format(time.RFC3339))
	cond.CreateAttr("NotOnOrAfter", notOnOrAfter.UTC().Format(time.RFC3339))
	cond.CreateElement("AudienceRestriction").CreateElement("Audience").SetText(audience)
	attr := a.CreateElement("AttributeStatement").CreateElement("Attribute")
	attr.CreateAttr("Name", "role")
	attr.CreateElement("AttributeValue").SetText("operator")

	ctx := dsig.NewDefaultSigningContext(ks)
	ctx.IdAttribute = "ID"
	signed, err := ctx.SignEnveloped(a)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	xml, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return xml, certPEM
}

func TestValidateAcceptsSignedAssertion(t *testing.T) {
	now := time.Now()
	xml, certPEM := signedAssertion(t, "certctl-sp", now.Add(-time.Minute), now.Add(time.Hour))
	v, err := NewValidator("certctl-sp", certPEM)
	if err != nil {
		t.Fatal(err)
	}
	a, err := v.Validate(xml)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if a.Subject != "alice@example.com" {
		t.Errorf("subject = %q, want alice@example.com", a.Subject)
	}
	if a.Audience != "certctl-sp" {
		t.Errorf("audience = %q, want certctl-sp", a.Audience)
	}
	if got := a.Attributes["role"]; len(got) != 1 || got[0] != "operator" {
		t.Errorf("attributes = %v, want role=[operator]", a.Attributes)
	}
}

func TestValidateRejectsTamperedAssertion(t *testing.T) {
	now := time.Now()
	xml, certPEM := signedAssertion(t, "certctl-sp", now.Add(-time.Minute), now.Add(time.Hour))
	tampered := bytes.Replace(xml, []byte("alice@example.com"), []byte("mallory@evil.example"), 1)
	v, _ := NewValidator("certctl-sp", certPEM)
	if _, err := v.Validate(tampered); err == nil {
		t.Error("Validate accepted a tampered assertion")
	}
}

func TestValidateRejectsUntrustedSigner(t *testing.T) {
	now := time.Now()
	xml, _ := signedAssertion(t, "certctl-sp", now.Add(-time.Minute), now.Add(time.Hour))
	_, otherPEM := signedAssertion(t, "certctl-sp", now.Add(-time.Minute), now.Add(time.Hour))
	v, _ := NewValidator("certctl-sp", otherPEM) // trusts a different cert
	if _, err := v.Validate(xml); err == nil {
		t.Error("Validate accepted an assertion signed by an untrusted key")
	}
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	now := time.Now()
	xml, certPEM := signedAssertion(t, "other-sp", now.Add(-time.Minute), now.Add(time.Hour))
	v, _ := NewValidator("certctl-sp", certPEM)
	if _, err := v.Validate(xml); err == nil {
		t.Error("Validate accepted an assertion for the wrong audience")
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	now := time.Now()
	xml, certPEM := signedAssertion(t, "certctl-sp", now.Add(-2*time.Hour), now.Add(-time.Hour))
	v, _ := NewValidator("certctl-sp", certPEM)
	if _, err := v.Validate(xml); err == nil {
		t.Error("Validate accepted an expired assertion")
	}
}
