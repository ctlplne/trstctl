// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"errors"
	googleuuid "github.com/google/uuid"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto"
)

const MaxRotationManifestPageBytes = 64 << 10

// RotationManifestHeader freezes public admission authority before recording
// ordered pages. A complete manifest and its later queue remain separate facts.
// No credential, credential reference or human free text belongs in these hashes.
type RotationManifestHeader struct {
	Version         int                 `json:"version"`
	ID              string              `json:"id"`
	Account         AccountBinding      `json:"account"`
	SecretName      string              `json:"secret_name"`
	ExpectedVersion int                 `json:"expected_version"`
	ProviderBinding string              `json:"provider_binding"`
	Mode            string              `json:"mode,omitempty"`
	Reconcile       *ReconcilePrincipal `json:"reconcile,omitempty"`
	CreatedAt       time.Time           `json:"created_at"`
	ExpiresAt       time.Time           `json:"expires_at"`
}

// RotationManifestHost references an exact signed scan, without repeating its
// native object arrays in every page. Admission must verify that canonical scan.
type RotationManifestHost struct {
	Binding         HostBinding `json:"binding"`
	InventoryRunID  string      `json:"inventory_run_id"`
	InventoryDigest string      `json:"inventory_digest"`
	ObservedAt      time.Time   `json:"observed_at"`
}
type RotationManifestEntry struct {
	Host    RotationManifestHost `json:"host"`
	Ref     DependentRef         `json:"ref"`
	ProbeID string               `json:"probe_id"`
}

// Each page extends one header-bound chain. The final seal must additionally
// prove global reference uniqueness, host completeness and current admission.
type RotationManifestPage struct {
	Version        int                     `json:"version"`
	ID             string                  `json:"id"`
	HeaderDigest   string                  `json:"header_digest"`
	Number         int64                   `json:"page_number"`
	PreviousDigest string                  `json:"previous_digest"`
	Hosts          []RotationManifestHost  `json:"hosts"`
	Entries        []RotationManifestEntry `json:"entries"`
	Digest         string                  `json:"digest"`
}

func (h RotationManifestHeader) Validate() error {
	if h.Version != 1 || !canonicalID(h.ID) || h.Account.Validate() != nil || h.ExpectedVersion < 1 || !rotationDigestValid(h.ProviderBinding) || h.CreatedAt.IsZero() || !h.ExpiresAt.After(h.CreatedAt) || h.ExpiresAt.After(h.CreatedAt.Add(RotationInventoryMaxAge)) {
		return errors.New("service dependents: exact manifest account, provider, vault generation and review window required")
	}
	if err := validateRotationSecretName(h.SecretName); err != nil {
		return err
	}
	return (RotationIntent{Mode: h.Mode, Reconcile: h.Reconcile, Plan: RotationPlan{Account: h.Account}}).validateMode()
}
func (h RotationManifestHeader) Digest() (string, error) {
	if err := h.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl.service-dependent.manifest-header.v1\x00"), raw...)), nil
}
func validateRotationSecretName(name string) error {
	if len(name) == 0 || len(name) > 512 || strings.TrimSpace(name) != name || !utf8.ValidString(name) {
		return errors.New("service dependents: exact application secret reference required")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("service dependents: invalid application secret reference")
		}
	}
	return nil
}
func (host RotationManifestHost) Validate(h RotationManifestHeader) error {
	if host.Binding.Validate() != nil || !host.Binding.Enabled || host.Binding.Account != h.Account || !canonicalID(host.InventoryRunID) || !rotationDigestValid(host.InventoryDigest) || host.ObservedAt.IsZero() || host.ObservedAt.Before(h.CreatedAt.Add(-RotationInventoryMaxAge)) || host.ObservedAt.After(h.CreatedAt.Add(time.Minute)) || !host.ObservedAt.Add(RotationInventoryMaxAge).After(h.CreatedAt) {
		return errors.New("service dependents: manifest host has another or stale native scan")
	}
	return nil
}
func (entry RotationManifestEntry) Validate(h RotationManifestHeader) error {
	if err := entry.Host.Validate(h); err != nil {
		return err
	}
	host := entry.Host
	ref := entry.Ref
	if ref.AgentID != host.Binding.AgentID || (ref.Family != "services" && ref.Family != "tasks" && ref.Family != "iis") || len(ref.Name) == 0 || len(ref.Name) > 4096 || !utf8.ValidString(ref.Name) || !validProbeID(entry.ProbeID) {
		return errors.New("service dependents: exact native reference and local useful-work probe required")
	}
	for _, r := range ref.Name {
		if unicode.IsControl(r) {
			return errors.New("service dependents: invalid native reference")
		}
	}
	return nil
}
func NewRotationManifestPage(h RotationManifestHeader, number int64, previousDigest string, entries []RotationManifestEntry) (RotationManifestPage, error) {
	hosts := make([]RotationManifestHost, 0)
	seen := make(map[string]bool)
	for _, entry := range entries {
		if !seen[entry.Ref.AgentID] {
			hosts = append(hosts, entry.Host)
			seen[entry.Ref.AgentID] = true
		}
	}
	return NewRotationManifestPageWithHosts(h, number, previousDigest, hosts, entries)
}
func NewRotationManifestPageWithHosts(h RotationManifestHeader, number int64, previousDigest string, hosts []RotationManifestHost, entries []RotationManifestEntry) (RotationManifestPage, error) {
	headerDigest, err := h.Digest()
	if err != nil {
		return RotationManifestPage{}, err
	}
	page := RotationManifestPage{Version: 1, ID: h.ID, HeaderDigest: headerDigest, Number: number, PreviousDigest: previousDigest, Hosts: append([]RotationManifestHost(nil), hosts...), Entries: append([]RotationManifestEntry(nil), entries...)}
	page.Digest, err = page.contentDigest()
	if err != nil {
		return RotationManifestPage{}, err
	}
	if err := page.Validate(h); err != nil {
		return RotationManifestPage{}, err
	}
	return page, nil
}
func (p RotationManifestPage) contentDigest() (string, error) {
	p.Digest = ""
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	// Reserve the final digest's encoded bytes inside the per-page wire budget.
	if len(raw)+64 > MaxRotationManifestPageBytes {
		return "", errors.New("service dependents: manifest page exceeds bounded wire size")
	}
	return crypto.SHA256Hex(append([]byte("trstctl.service-dependent.manifest-page.v1\x00"), raw...)), nil
}
func (p RotationManifestPage) Validate(h RotationManifestHeader) error {
	headerDigest, err := h.Digest()
	if err != nil {
		return err
	}
	if p.Version != 1 || p.ID != h.ID || p.HeaderDigest != headerDigest || p.Number < 0 || p.Number == math.MaxInt64 || !rotationDigestValid(p.PreviousDigest) || len(p.Hosts) == 0 || p.Number == 0 && p.PreviousDigest != headerDigest {
		return errors.New("service dependents: exact manifest header and predecessor required")
	}
	digest, err := p.contentDigest()
	if err != nil {
		return err
	}
	if digest != p.Digest {
		return errors.New("service dependents: manifest page digest differs")
	}
	seen := make(map[string]bool, len(p.Entries))
	hosts := make(map[string]RotationManifestHost)
	for _, host := range p.Hosts {
		if err := host.Validate(h); err != nil {
			return err
		}
		if _, found := hosts[host.Binding.AgentID]; found {
			return errors.New("service dependents: duplicate manifest host declaration")
		}
		hosts[host.Binding.AgentID] = host
	}
	for _, entry := range p.Entries {
		if err := entry.Validate(h); err != nil {
			return err
		}
		first, found := hosts[entry.Ref.AgentID]
		if !found || first.Binding != entry.Host.Binding || first.InventoryRunID != entry.Host.InventoryRunID || first.InventoryDigest != entry.Host.InventoryDigest || !first.ObservedAt.Equal(entry.Host.ObservedAt) {
			return errors.New("service dependents: native entry differs from declared host source")
		}
		key := dependentKey(entry.Ref)
		if seen[key] {
			return errors.New("service dependents: duplicate native reference in manifest page")
		}
		seen[key] = true
	}
	return nil
}
func ValidateRotationManifestLink(h RotationManifestHeader, page RotationManifestPage, previous *RotationManifestPage) error {
	if err := page.Validate(h); err != nil {
		return err
	}
	if previous == nil {
		if page.Number != 0 {
			return errors.New("service dependents: manifest chain is missing its first page")
		}
		return nil
	}
	if err := previous.Validate(h); err != nil {
		return err
	}
	if page.Number != previous.Number+1 || page.PreviousDigest != previous.Digest {
		return errors.New("service dependents: manifest page skips or replaces its predecessor")
	}
	return nil
}
func DecodeRotationManifestPage(h RotationManifestHeader, raw []byte) (RotationManifestPage, error) {
	if !utf8.Valid(raw) {
		return RotationManifestPage{}, errors.New("service dependents: UTF-8 manifest JSON required")
	}
	var page RotationManifestPage
	if err := decodeInventoryJSON(raw, MaxRotationManifestPageBytes, &page); err != nil {
		return page, err
	}
	return page, page.Validate(h)
}

// A seal is a constant-size commitment to the entire ordered chain. Validation
// of these scalar fields does not prove completeness: admission must derive its
// counts and expiry from all canonical pages and the exact selected host set.
type RotationManifestSeal struct {
	Version      int       `json:"version"`
	ID           string    `json:"id"`
	HeaderDigest string    `json:"header_digest"`
	PageCount    int64     `json:"page_count"`
	EntryCount   int64     `json:"entry_count"`
	HostCount    int64     `json:"host_count"`
	TailDigest   string    `json:"tail_digest"`
	ExpiresAt    time.Time `json:"expires_at"`
	Digest       string    `json:"digest"`
}

func NewRotationManifestSeal(h RotationManifestHeader, tail RotationManifestPage, entries, hosts int64, expires time.Time) (RotationManifestSeal, error) {
	if err := tail.Validate(h); err != nil {
		return RotationManifestSeal{}, err
	}
	if entries < int64(len(tail.Entries)) || hosts < int64(len(tail.Hosts)) || tail.Number == 0 && (entries != int64(len(tail.Entries)) || hosts != int64(len(tail.Hosts))) {
		return RotationManifestSeal{}, errors.New("service dependents: sealed counts differ from the retained page")
	}
	seal := RotationManifestSeal{Version: 1, ID: h.ID, HeaderDigest: tail.HeaderDigest, PageCount: tail.Number + 1, EntryCount: entries, HostCount: hosts, TailDigest: tail.Digest, ExpiresAt: expires.UTC()}
	var err error
	seal.Digest, err = seal.contentDigest()
	if err != nil {
		return RotationManifestSeal{}, err
	}
	if err := seal.Validate(h); err != nil {
		return RotationManifestSeal{}, err
	}
	return seal, nil
}
func (s RotationManifestSeal) contentDigest() (string, error) {
	s.Digest = ""
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl.service-dependent.manifest-seal.v1\x00"), raw...)), nil
}
func (s RotationManifestSeal) Validate(h RotationManifestHeader) error {
	digest, err := h.Digest()
	if err != nil {
		return err
	}
	if s.Version != 1 || s.ID != h.ID || s.HeaderDigest != digest || s.PageCount < 1 || s.EntryCount < 1 || s.HostCount < 1 || !rotationDigestValid(s.TailDigest) || !s.ExpiresAt.After(h.CreatedAt) || s.ExpiresAt.After(h.ExpiresAt) {
		return errors.New("service dependents: complete manifest counts, tail and expiry required")
	}
	want, err := s.contentDigest()
	if err != nil {
		return err
	}
	if want != s.Digest {
		return errors.New("service dependents: whole-account manifest seal differs")
	}
	return nil
}

func RotationManifestHeaderSourceID(tenantID, id string) string {
	return googleuuid.NewSHA1(googleuuid.NameSpaceOID, []byte("trstctl.service-dependent.manifest-header-source.v1\x00"+tenantID+"\x00"+id)).String()
}
func RotationManifestPageSourceID(tenantID, id string, number int64) string {
	return googleuuid.NewSHA1(googleuuid.NameSpaceOID, []byte("trstctl.service-dependent.manifest-page-source.v1\x00"+tenantID+"\x00"+id+"\x00"+strconv.FormatInt(number, 10))).String()
}
func RotationManifestSealSourceID(tenantID, id string) string {
	return googleuuid.NewSHA1(googleuuid.NameSpaceOID, []byte("trstctl.service-dependent.manifest-seal-source.v1\x00"+tenantID+"\x00"+id)).String()
}

// RotationManifestPageInput contains only public review data. The server derives
// page identity and digest; a supplied digest cannot stand in for reading it.
type RotationManifestPageInput struct {
	HeaderDigest   string                  `json:"header_digest"`
	PreviousDigest string                  `json:"previous_digest"`
	Hosts          []RotationManifestHost  `json:"hosts,omitempty"`
	Entries        []RotationManifestEntry `json:"entries,omitempty"`
}

func DecodeRotationManifestPageInput(raw []byte) (RotationManifestPageInput, error) {
	if !utf8.Valid(raw) {
		return RotationManifestPageInput{}, errors.New("service dependents: UTF-8 manifest JSON required")
	}
	var value RotationManifestPageInput
	if err := decodeInventoryJSON(raw, MaxRotationManifestPageBytes, &value); err != nil {
		return value, err
	}
	if !rotationDigestValid(value.HeaderDigest) || !rotationDigestValid(value.PreviousDigest) || len(value.Hosts) == 0 && len(value.Entries) == 0 {
		return value, errors.New("service dependents: bounded host/entry page and exact header/previous digest required")
	}
	return value, nil
}
func (input RotationManifestPageInput) Page(header RotationManifestHeader, number int64) (RotationManifestPage, error) {
	digest, err := header.Digest()
	if err != nil {
		return RotationManifestPage{}, err
	}
	if input.HeaderDigest != digest {
		return RotationManifestPage{}, errors.New("service dependents: native review header differs")
	}
	if len(input.Hosts) == 0 {
		return NewRotationManifestPage(header, number, input.PreviousDigest, input.Entries)
	}
	return NewRotationManifestPageWithHosts(header, number, input.PreviousDigest, input.Hosts, input.Entries)
}

func RotationManifestReferenceDigest(ref DependentRef) string {
	return crypto.SHA256Hex([]byte("trstctl.service-dependent.manifest-native-ref.v1\x00" + ref.AgentID + "\x00" + ref.Family + "\x00" + ref.Name))
}
