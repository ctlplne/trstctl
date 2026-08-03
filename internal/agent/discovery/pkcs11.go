// SPDX-License-Identifier: MPL-2.0

package discovery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// PKCS#11 tokens as a discovery source (epic C1).
//
// The last of the three kinds the collector boundary declared and the binary did
// not build. HSMs and smart cards hold the certificates an organization cares
// most about and inventories least — the ones whose keys cannot be copied, which
// is exactly why nobody has a list of them.
//
// Metadata only. This reads CKA_VALUE from objects of class CKO_CERTIFICATE.
// It never touches CKO_PRIVATE_KEY, never calls C_Sign, and never asks a token
// to export anything. A PKCS#11 private key is normally CKA_EXTRACTABLE=false
// and could not leave the token even if asked; this code does not ask.
//
// The session is READ-ONLY and, by default, unauthenticated: certificate objects
// on most tokens are public (CKA_PRIVATE=false) and readable without a login.
// A PIN is accepted for tokens that hide them, and it is taken from a FILE, never
// a flag — the agent binary already refuses inline bootstrap tokens on the
// grounds that process arguments expose credentials, and a token PIN is no
// different.

// ErrPKCS11Unsupported is returned by a build that cannot load a PKCS#11 module.
//
// It is an error rather than an empty result, for the same reason the Windows
// source fails rather than reporting nothing: an operator must never be told
// their token estate is clean by a binary that could not look. The default
// agent build is cgo-free — a deliberate choice, because a statically linked
// agent is what makes a fleet rollout predictable — and PKCS#11 requires cgo to
// dlopen a vendor module. A build without it says so.
var ErrPKCS11Unsupported = errors.New("discovery: this agent build cannot load PKCS#11 modules (built without cgo)")

// PKCS11Config names the token to inventory.
type PKCS11Config struct {
	// ModulePath is the vendor PKCS#11 shared object (softhsm2.so,
	// libykcs11.so, opensc-pkcs11.so). Required: there is no sensible default,
	// and guessing one would mean loading whatever happened to be installed.
	ModulePath string
	// TokenLabel selects one token by label. Empty means every token the module
	// presents, which is the right default for an operator who does not yet know
	// what is in the slot.
	TokenLabel string
	// UserPIN is read from a file by the caller and held as bytes (AN-8). Empty
	// means no login: public certificate objects are read, private ones are not
	// visible, and that is reported honestly rather than as an empty token.
	UserPIN []byte
}

// pkcs11Reader is the platform call this source depends on, declared as an
// interface so the source's behaviour is testable in a build with no PKCS#11
// module present, and so the cgo surface stays in exactly one build-tagged file.
type pkcs11Reader interface {
	readTokens(ctx context.Context, cfg PKCS11Config) (map[string][]byte, error)
}

// PKCS11Source inventories the certificate objects on one or more tokens.
type PKCS11Source struct {
	cfg    PKCS11Config
	reader pkcs11Reader
}

// NewPKCS11CertSource returns a source over the configured module.
func NewPKCS11CertSource(cfg PKCS11Config) *PKCS11Source {
	return &PKCS11Source{cfg: cfg, reader: platformPKCS11Reader()}
}

// Kind names the source.
func (s *PKCS11Source) Kind() string { return SourcePKCS11 }

// Discover reads every certificate object the session can see.
//
// An object whose CKA_VALUE does not parse is skipped — tokens hold objects this
// does not understand, and one of them must not cost the inventory of the rest.
// A failure to load the module, open a session, or log in is an error: an
// unreadable token reported as empty is the false-clean result this epic exists
// to remove.
func (s *PKCS11Source) Discover(ctx context.Context) ([]Found, error) {
	if strings.TrimSpace(s.cfg.ModulePath) == "" {
		return nil, errors.New("discovery: PKCS#11 inventory needs a module path")
	}
	if s.reader == nil {
		return nil, ErrPKCS11Unsupported
	}
	blobs, err := s.reader.readTokens(ctx, s.cfg)
	if err != nil {
		return nil, err
	}
	labels := make([]string, 0, len(blobs))
	for label := range blobs {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	out := make([]Found, 0, len(labels))
	for _, label := range labels {
		info, err := certinfo.Inspect(blobs[label])
		if err != nil {
			continue
		}
		out = append(out, Found{
			Source: SourcePKCS11,
			// The token and object label locate the finding, so an operator can
			// walk to the slot. The module path is deliberately NOT in the
			// location: it is a host filesystem path, it differs per host for the
			// same physical token, and it would make the same certificate look
			// like two different findings across a fleet.
			Location: label,
			Cert:     info,
		})
	}
	return out, nil
}

// trimSpacePadding removes the fixed-width space padding PKCS#11 uses for
// labels. It lives on this side of the build tag so both readers agree.
func trimSpacePadding(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), " \x00")
}

// pkcs11ObjectLabel builds the stable per-object locator the reader keys on.
func pkcs11ObjectLabel(tokenLabel, objectLabel string, index int) string {
	token := strings.TrimSpace(tokenLabel)
	if token == "" {
		token = "token"
	}
	object := strings.TrimSpace(objectLabel)
	if object == "" {
		// An unlabelled certificate object is common on smart cards. The index
		// keeps two of them distinguishable within a token.
		object = fmt.Sprintf("object-%d", index)
	}
	return "pkcs11:" + token + "/" + object
}
