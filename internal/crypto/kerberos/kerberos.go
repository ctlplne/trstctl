// SPDX-License-Identifier: BUSL-1.1

// Package kerberos keeps Kerberos/GSSAPI (SPNEGO) ticket verification behind
// the internal cryptography boundary (AN-3), the way samlsp keeps XMLDSig
// there. Callers configure a service keytab and get an HTTP handler that
// drives the Negotiate challenge and hands them a verified Identity; they
// never touch ticket decryption, encryption types or keytab keys.
package kerberos

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Config is the service-side material for accepting Kerberos logins.
type Config struct {
	// KeytabFile holds the service principal's long-term keys (for example
	// HTTP/trstctl.example.com@EXAMPLE.COM), exported from the KDC.
	KeytabFile string
	// ServicePrincipal pins which keytab principal may be the ticket's
	// service; empty accepts any principal the keytab holds.
	ServicePrincipal string
	// Realm, when set, admits only clients from that realm.
	Realm string
	// MaxClockSkew bounds authenticator and ticket time checks; zero uses the
	// Kerberos default of five minutes.
	MaxClockSkew time.Duration
}

// Identity is the verified subject of a Kerberos login.
type Identity struct {
	// Principal is user@REALM as the KDC authenticated it.
	Principal string
	Username  string
	Realm     string
	// GroupSIDs are the Active Directory group SIDs from the ticket's PAC,
	// when the KDC is AD and included one; an MIT KDC yields none.
	GroupSIDs []string
	AuthTime  time.Time
}

// Service accepts SPNEGO/Kerberos logins for one keytab.
type Service struct {
	kt       *keytab.Keytab
	settings []func(*service.Settings)
	realm    string
}

// New loads the keytab and validates the configuration; it fails closed on a
// missing or empty keytab.
func New(cfg Config) (*Service, error) {
	path := strings.TrimSpace(cfg.KeytabFile)
	if path == "" {
		return nil, errors.New("kerberos: keytab_file is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("kerberos: keytab_file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("kerberos: keytab_file must be a regular file")
	}
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, fmt.Errorf("kerberos: load keytab: %w", err)
	}
	return NewFromKeytab(kt, cfg)
}

// NewFromKeytab builds a service from an already-parsed keytab; tests and
// in-process provisioning use it.
func NewFromKeytab(kt *keytab.Keytab, cfg Config) (*Service, error) {
	if kt == nil || len(kt.Entries) == 0 {
		return nil, errors.New("kerberos: the keytab holds no service keys")
	}
	settings := []func(*service.Settings){service.DecodePAC(true)}
	if spn := strings.TrimSpace(cfg.ServicePrincipal); spn != "" {
		found := false
		for _, entry := range kt.Entries {
			name := strings.Join(entry.Principal.Components, "/")
			if strings.EqualFold(name, spn) || strings.EqualFold(name+"@"+entry.Principal.Realm, spn) {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("kerberos: the keytab holds no key for service principal %q", spn)
		}
		settings = append(settings, service.KeytabPrincipal(spn))
	}
	if cfg.MaxClockSkew > 0 {
		settings = append(settings, service.MaxClockSkew(cfg.MaxClockSkew))
	}
	return &Service{kt: kt, settings: settings, realm: strings.TrimSpace(cfg.Realm)}, nil
}

// Handler returns the HTTP handler for a login route: without a Negotiate
// token it answers 401 with the Negotiate challenge; with one it verifies the
// ticket against the keytab and calls next with the Identity. A client from a
// realm other than the configured one is refused after verification.
func (s *Service) Handler(next func(http.ResponseWriter, *http.Request, Identity)) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := goidentity.FromHTTPRequestContext(r)
		if id == nil || !id.Authenticated() || id.UserName() == "" {
			http.Error(w, "Unauthorised.", http.StatusUnauthorized)
			return
		}
		identity := Identity{
			Username: id.UserName(), Realm: id.Domain(), AuthTime: id.AuthTime(),
			GroupSIDs: append([]string(nil), id.AuthzAttributes()...),
		}
		identity.Principal = identity.Username + "@" + identity.Realm
		if s.realm != "" && !strings.EqualFold(identity.Realm, s.realm) {
			http.Error(w, "Unauthorised.", http.StatusUnauthorized)
			return
		}
		next(w, r, identity)
	})
	return spnego.SPNEGOKRB5Authenticate(inner, s.kt, s.settings...)
}
