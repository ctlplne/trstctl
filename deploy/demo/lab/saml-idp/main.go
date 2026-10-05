// SPDX-License-Identifier: BUSL-1.1

// saml-idp is a loopback-only SAML partner-lab actor. It authenticates one
// explicitly configured disposable identity without a password. It is not an
// operator-facing production identity provider.
package main

import (
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"trstctl.com/trstctl/internal/crypto/samltest"
)

type labIDP struct {
	spEntityID string
	spMetadata string
	session    *saml.Session
}

var labAttributeName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]*$`)

type labAttributes []saml.Attribute

func (a *labAttributes) String() string { return fmt.Sprintf("%d attributes", len(*a)) }

func (a *labAttributes) Set(raw string) error {
	name, value, ok := strings.Cut(raw, "=")
	if !ok || !labAttributeName.MatchString(name) || value == "" || name == "email" || name == "tenant" {
		return errors.New("attribute must be a nonempty name=value other than email or tenant")
	}
	for _, existing := range *a {
		if existing.Name == name {
			return fmt.Errorf("duplicate lab attribute %q", name)
		}
	}
	*a = append(*a, saml.Attribute{Name: name, FriendlyName: name, Values: []saml.AttributeValue{{Type: "xs:string", Value: value}}})
	return nil
}

func (a labAttributes) SAML() []saml.Attribute { return []saml.Attribute(a) }

func (l *labIDP) GetSession(http.ResponseWriter, *http.Request, *saml.IdpAuthnRequest) *saml.Session {
	session := *l.session
	session.CreateTime = time.Now()
	session.ExpireTime = session.CreateTime.Add(time.Hour)
	return &session
}

func (l *labIDP) GetServiceProvider(_ *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	if entityID != l.spEntityID {
		return nil, os.ErrNotExist
	}
	raw, err := os.ReadFile(l.spMetadata)
	if err != nil {
		return nil, err
	}
	return samlsp.ParseMetadata(raw)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18481", "loopback listener")
	identityFile := flag.String("identity-file", "", "owner-only persistent lab IdP certificate and signing key PEM")
	metadataFile := flag.String("metadata-file", "", "path for public IdP metadata XML")
	spMetadataFile := flag.String("sp-metadata-file", "", "path for trusted trstctl SP metadata XML")
	spEntityID := flag.String("sp-entity-id", "", "exact trstctl SP entity ID")
	subject := flag.String("subject", "", "disposable lab identity subject")
	email := flag.String("email", "", "disposable lab identity email")
	tenant := flag.String("tenant", "", "task tenant ID in signed assertion")
	var attributes labAttributes
	flag.Var(&attributes, "attribute", "additional signed name=value claim; repeat for local roles and MFA")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("saml-idp requires an explicit loopback IP listener")
	}
	if *identityFile == "" || *metadataFile == "" || *spMetadataFile == "" || *spEntityID == "" || *subject == "" || *email == "" || *tenant == "" {
		log.Fatal("identity-file, metadata-file, sp-metadata-file, sp-entity-id, subject, email, and tenant are required")
	}
	if filepath.Clean(*identityFile) == filepath.Clean(*metadataFile) {
		log.Fatal("identity-file and public metadata-file must be different")
	}
	if _, err := url.ParseRequestURI(*spEntityID); err != nil {
		log.Fatalf("invalid SP entity ID: %v", err)
	}
	key, cert, err := samltest.LoadOrCreateIdentityProviderMaterial(*identityFile, *spEntityID)
	if err != nil {
		log.Fatalf("load local IdP signing material: %v", err)
	}
	base := "http://" + *addr
	metadataURL, _ := url.Parse(base + "/metadata")
	ssoURL, _ := url.Parse(base + "/sso")
	now := time.Now()
	actor := &labIDP{
		spEntityID: *spEntityID,
		spMetadata: *spMetadataFile,
		session: &saml.Session{
			ID: *subject, CreateTime: now, ExpireTime: now.Add(8 * time.Hour),
			Index: *subject + "-lab", NameID: *subject, UserEmail: *email,
			CustomAttributes: append([]saml.Attribute{
				{Name: "email", FriendlyName: "email", Values: []saml.AttributeValue{{Type: "xs:string", Value: *email}}},
				{Name: "tenant", FriendlyName: "tenant", Values: []saml.AttributeValue{{Type: "xs:string", Value: *tenant}}},
			}, attributes.SAML()...),
		},
	}
	idp := &saml.IdentityProvider{
		Certificate: cert, Key: key,
		MetadataURL: *metadataURL, SSOURL: *ssoURL,
		ServiceProviderProvider: actor, SessionProvider: actor,
	}
	metadata, err := xml.MarshalIndent(idp.Metadata(), "", "  ")
	if err != nil {
		log.Fatalf("marshal IdP metadata: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*metadataFile), 0o700); err != nil {
		log.Fatalf("create metadata directory: %v", err)
	}
	if err := os.WriteFile(*metadataFile, metadata, 0o600); err != nil {
		log.Fatalf("write IdP metadata: %v", err)
	}
	if err := os.Chmod(*metadataFile, 0o600); err != nil {
		log.Fatalf("protect IdP metadata: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metadata", idp.ServeMetadata)
	mux.HandleFunc("GET /sso", idp.ServeSSO)
	mux.HandleFunc("POST /sso", idp.ServeSSO)
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("loopback SAML IdP listening on %s", *addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(fmt.Errorf("serve local IdP: %w", err))
	}
}
