// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// The Windows certificate store as a discovery source (epic C1).
//
// The collector boundary declared a windows-store kind from the start and the
// served API advertised it, but the agent binary built no enumerator: an
// operator with a Windows estate — IIS bindings, service accounts, machine
// certificates, the population most likely to expire unnoticed because nobody
// owns it — read that panel and concluded it was inventoried. It was not. C1a
// stopped the false advertisement by removing the kind from the shipped census.
// This ships the enumerator so it can go back on, for the right reason.
//
// Metadata only, like every other agent source. The store is opened read-only
// and only the certificate blob of each context is read. The private key
// associated with a Windows certificate — whether in the CNG/CAPI software
// store, a TPM, or a smart card — is never touched: there is no call here that
// exports one, and on a well-configured host most are non-exportable anyway.
// What crosses the agent channel is what crosses it for every other source:
// subject, issuer, serial, fingerprint, validity, and where it was found.

// Windows store names an operator can inventory. These are the physical store
// names the platform defines; anything else is refused rather than passed to the
// API, so a typo cannot become a silent empty result that reads as "clean".
const (
	// WindowsStoreMy is the personal store: certificates this machine or user
	// holds a key for. The one that matters most for expiry.
	WindowsStoreMy = "MY"
	// WindowsStoreRoot is the trusted root store.
	WindowsStoreRoot = "ROOT"
	// WindowsStoreCA is the intermediate certification authority store.
	WindowsStoreCA = "CA"
	// WindowsStoreTrustedPublisher holds publishers trusted for code signing.
	WindowsStoreTrustedPublisher = "TRUSTEDPUBLISHER"
	// WindowsStoreWebHosting is where IIS keeps site certificates on newer
	// Windows Server builds. Omitting it would miss exactly the estate an
	// operator most wants inventoried.
	WindowsStoreWebHosting = "WEBHOSTING"
)

// ErrWindowsStoreUnsupported is returned when the Windows certificate store is
// asked for on a platform that has none. It is deliberately an error rather than
// an empty result: an empty inventory reads as "nothing to find", and telling a
// Linux operator their Windows estate is clean would be the same false comfort
// this epic exists to remove.
var ErrWindowsStoreUnsupported = errors.New("discovery: the Windows certificate store is not available on this platform")

// WindowsStoreNames lists the stores this build can inventory, in the order the
// agent enumerates them.
func WindowsStoreNames() []string {
	return []string{
		WindowsStoreMy,
		WindowsStoreWebHosting,
		WindowsStoreCA,
		WindowsStoreRoot,
		WindowsStoreTrustedPublisher,
	}
}

// ValidWindowsStoreName reports whether name is a store this build enumerates.
// Comparison is case-insensitive because operators write "My" and "my" and the
// platform does not care either.
func ValidWindowsStoreName(name string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(name))
	for _, known := range WindowsStoreNames() {
		if known == normalized {
			return true
		}
	}
	return false
}

// WindowsStoreLocation selects which of the two certificate hierarchies to read.
type WindowsStoreLocation string

const (
	// WindowsLocationLocalMachine is the machine-wide hierarchy. This is where
	// service and IIS certificates live, and it is what an agent running as a
	// service should inventory.
	WindowsLocationLocalMachine WindowsStoreLocation = "local-machine"
	// WindowsLocationCurrentUser is the hierarchy of the account the agent runs
	// as. Useful on workstations; usually near-empty for a service account.
	WindowsLocationCurrentUser WindowsStoreLocation = "current-user"
)

// ValidWindowsStoreLocation reports whether location is one this build reads.
func ValidWindowsStoreLocation(location WindowsStoreLocation) bool {
	return location == WindowsLocationLocalMachine || location == WindowsLocationCurrentUser
}

// windowsCertReader is the platform call this source depends on, declared as an
// interface so the source's behavior — normalization, skipping, error handling
// — is testable on every platform, and so the syscall surface stays in exactly
// one file behind a build tag.
//
// It returns the DER blob of each certificate keyed by a stable per-context
// label, so two certificates in one store cannot collide.
type windowsCertReader interface {
	readStore(ctx context.Context, location WindowsStoreLocation, store string) (map[string][]byte, error)
}

// WindowsStoreSource inventories one Windows certificate store.
type WindowsStoreSource struct {
	location WindowsStoreLocation
	store    string
	reader   windowsCertReader
}

// NewWindowsCertStoreSource returns a source over one store in one hierarchy.
//
// It is constructed with the platform reader for this build: a real crypt32
// reader on Windows, and one that fails with ErrWindowsStoreUnsupported
// everywhere else. The agent binary calls this; the guard in
// docs/agent_advertised_capability_test.go proves it does.
func NewWindowsCertStoreSource(location WindowsStoreLocation, store string) *WindowsStoreSource {
	return &WindowsStoreSource{
		location: location,
		store:    strings.ToUpper(strings.TrimSpace(store)),
		reader:   platformWindowsCertReader(),
	}
}

// Kind names the source.
func (s *WindowsStoreSource) Kind() string { return SourceWindowsCert }

// Discover reads every certificate in the store.
//
// A context whose blob does not parse as a certificate is skipped rather than
// failing the pass: a Windows store can hold objects this does not understand,
// and one of them must not cost an operator the inventory of everything else in
// the store. A failure to OPEN the store is an error, because that is a
// source-level failure — an unreadable store reported as empty would be the
// false-clean result this epic exists to prevent.
func (s *WindowsStoreSource) Discover(ctx context.Context) ([]Found, error) {
	if !ValidWindowsStoreLocation(s.location) {
		return nil, fmt.Errorf("discovery: unknown Windows store location %q", s.location)
	}
	if !ValidWindowsStoreName(s.store) {
		return nil, fmt.Errorf("discovery: unknown Windows certificate store %q", s.store)
	}
	if s.reader == nil {
		return nil, ErrWindowsStoreUnsupported
	}
	blobs, err := s.reader.readStore(ctx, s.location, s.store)
	if err != nil {
		return nil, err
	}
	labels := make([]string, 0, len(blobs))
	for label := range blobs {
		labels = append(labels, label)
	}
	// Stable order so two passes over an unchanged store produce identical
	// reports, and an operator diffing them sees only real change.
	sort.Strings(labels)

	out := make([]Found, 0, len(labels))
	for _, label := range labels {
		info, err := certinfo.Inspect(blobs[label])
		if err != nil {
			continue
		}
		// The finding is located by the certificate's own fingerprint, not by
		// its position in the store. Position shifts whenever anything is added
		// or removed, which would make every pass look like wholesale change to
		// an operator diffing two inventories; the fingerprint is stable and
		// unique, and it is the same identifier the rest of the inventory keys
		// on. The reader's index label is only a placeholder for cases where a
		// blob does not parse and is skipped anyway.
		locator := info.SHA256Fingerprint
		if locator == "" {
			locator = label
		}
		out = append(out, Found{
			Source:   SourceWindowsCert,
			Location: string(s.location) + "/" + s.store + "/" + locator,
			Cert:     info,
		})
	}
	// Fingerprint order, so the report is deterministic regardless of the order
	// the platform walked the store in.
	sort.Slice(out, func(i, j int) bool { return out[i].Location < out[j].Location })
	return out, nil
}
