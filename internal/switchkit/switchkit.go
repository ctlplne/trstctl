// SPDX-License-Identifier: BUSL-1.1

// Package switchkit reads another certificate-management product's exports
// and maps them onto trstctl (A265). It describes formats, never products: an
// export is CSV with a header row or JSON, and a column map renames the
// export's own headers onto the fields below. Every input row gets exactly
// one outcome, so nothing an export carried is dropped without a reason.
package switchkit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Format names the export shape this package reads.
const Format = "trstctl.switching-export/v1"

// Fields are the canonical fields an export row may carry.
var Fields = []string{
	"certificate_pem", "fingerprint_sha256", "common_name", "sans", "serial", "issuer", "not_after",
	"folder", "application", "owner_email", "owner_name", "renewal_managed", "renewal_window_days",
	"key_algorithm", "endpoints",
}

// Limits on one export.
const (
	MaxRows  = 50000
	MaxBytes = 20 << 20
)

// Outcomes a row can have.
const (
	OutcomeMapped         = "mapped"
	OutcomeMappedWithGaps = "mapped_with_gaps"
	OutcomeDuplicate      = "duplicate"
	OutcomeUnparseable    = "unparseable"
	OutcomeExpired        = "expired"
)

// Row is one export row after the column map, before mapping.
type Row struct {
	Number int
	Fields map[string]string
}

// Mapped is one row's outcome and what it maps to.
type Mapped struct {
	Row          int       `json:"row"`
	Outcome      string    `json:"outcome"`
	Gaps         []string  `json:"gaps,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	DuplicateOf  int       `json:"duplicate_of,omitempty"`
	Fingerprint  string    `json:"fingerprint_sha256,omitempty"`
	CommonName   string    `json:"common_name,omitempty"`
	SANs         []string  `json:"sans,omitempty"`
	Serial       string    `json:"serial,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	KeyAlgorithm string    `json:"key_algorithm,omitempty"`
	Folder       string    `json:"folder,omitempty"`
	Application  string    `json:"application,omitempty"`
	OwnerEmail   string    `json:"owner_email,omitempty"`
	OwnerName    string    `json:"owner_name,omitempty"`
	OwnerID      string    `json:"owner_id,omitempty"`
	Endpoints    []string  `json:"endpoints,omitempty"`
	RenewalDays  int       `json:"renewal_window_days,omitempty"`
	HasPEM       bool      `json:"has_pem"`
	// DER is the certificate's own bytes when the export carried them.
	DER []byte `json:"-"`
	// KnownCertificateID is the inventory certificate a mapped row already
	// is: applying links the row to it and never rewrites it.
	KnownCertificateID string `json:"known_certificate_id,omitempty"`
}

// FolderPolicy is a folder's renewal settings, proposed as a profile.
type FolderPolicy struct {
	Folder       string   `json:"folder"`
	Profile      string   `json:"profile"`
	Rows         int      `json:"rows"`
	RenewalDays  int      `json:"renewal_window_days,omitempty"`
	KeyAlgorithm string   `json:"key_algorithm,omitempty"`
	Conflicts    []string `json:"conflicts,omitempty"`
}

// OwnerMatch is an owner the export names for one application group: an
// existing one, or one to create. An owner is one email in one application
// group, so the application view groups its certificates.
type OwnerMatch struct {
	Email       string `json:"email"`
	Name        string `json:"name,omitempty"`
	Application string `json:"application,omitempty"`
	OwnerID     string `json:"owner_id,omitempty"`
	Create      bool   `json:"create"`
	Rows        int    `json:"rows"`
}

// OwnerKey is how an owner is matched: its email (any case) in its
// application group.
func OwnerKey(email, application string) string {
	return strings.ToLower(strings.TrimSpace(email)) + "\x00" + strings.TrimSpace(application)
}

// Report is the mapping report: every row's outcome, and what the export's
// folders, owners and application groups become.
type Report struct {
	Format       string         `json:"format"`
	Rows         int            `json:"rows"`
	Counts       map[string]int `json:"counts"`
	GapCounts    map[string]int `json:"gap_counts"`
	Items        []Mapped       `json:"items"`
	Folders      []FolderPolicy `json:"folders"`
	Owners       []OwnerMatch   `json:"owners"`
	Applications []string       `json:"applications"`
	// Known counts the mapped rows already in the inventory.
	Known  int    `json:"known"`
	Digest string `json:"digest"`
}

// MarkKnown records which mapped rows are already in the inventory
// (fingerprint → certificate ID) and binds that into the digest, so an import
// applies against the inventory that was reviewed.
func (r *Report) MarkKnown(known map[string]string) {
	r.Known = 0
	for i := range r.Items {
		m := &r.Items[i]
		m.KnownCertificateID = ""
		if m.Outcome != OutcomeMapped && m.Outcome != OutcomeMappedWithGaps {
			continue
		}
		if id, ok := known[m.Fingerprint]; ok {
			m.KnownCertificateID = id
			r.Known++
		}
	}
	r.Digest = digest(*r)
}

// ExistingOwners maps an OwnerKey to an owner ID in the tenant.
type ExistingOwners map[string]string

// Parse reads an export (CSV or JSON, detected from its first byte) through
// columnMap (export header → canonical field; a header already named after a
// field needs no entry).
func Parse(data []byte, columnMap map[string]string) ([]Row, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("switchkit: export is larger than %d bytes", MaxBytes)
	}
	for header, field := range columnMap {
		if !validField(field) {
			return nil, fmt.Errorf("switchkit: column map sends %q to unknown field %q", header, field)
		}
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("switchkit: export is empty")
	}
	var rows []Row
	var err error
	if trimmed[0] == '[' || trimmed[0] == '{' {
		rows, err = parseJSON(trimmed, columnMap)
	} else {
		rows, err = parseCSV(trimmed, columnMap)
	}
	if err != nil {
		return nil, err
	}
	if len(rows) > MaxRows {
		return nil, fmt.Errorf("switchkit: export has %d rows, more than %d", len(rows), MaxRows)
	}
	return rows, nil
}

func validField(f string) bool {
	for _, known := range Fields {
		if f == known {
			return true
		}
	}
	return false
}

func canonical(header string, columnMap map[string]string) string {
	if f, ok := columnMap[header]; ok {
		return f
	}
	h := strings.ToLower(strings.TrimSpace(header))
	h = strings.NewReplacer(" ", "_", "-", "_").Replace(h)
	if validField(h) {
		return h
	}
	return ""
}

func parseCSV(data []byte, columnMap map[string]string) ([]Row, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("switchkit: read CSV header: %w", err)
	}
	fields := make([]string, len(header))
	for i, h := range header {
		fields[i] = canonical(h, columnMap)
	}
	var rows []Row
	// A CSV row is numbered by the line it starts on (the header is line 1),
	// so an operator finds it in the file even past a quoted line break.
	for {
		record, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A malformed line is a row with a reason, not a stop: later rows
			// still count.
			line := 0
			var parseErr *csv.ParseError
			if errors.As(err, &parseErr) {
				line = parseErr.StartLine
			}
			if line <= 0 {
				line = len(rows) + 2
			}
			rows = append(rows, Row{Number: line, Fields: map[string]string{"_error": err.Error()}})
			continue
		}
		line, _ := r.FieldPos(0)
		row := Row{Number: line, Fields: map[string]string{}}
		for i, value := range record {
			if i < len(fields) && fields[i] != "" && strings.TrimSpace(value) != "" {
				row.Fields[fields[i]] = strings.TrimSpace(value)
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func parseJSON(data []byte, columnMap map[string]string) ([]Row, error) {
	var items []map[string]any
	if data[0] == '{' {
		var wrapped struct {
			Certificates []map[string]any `json:"certificates"`
		}
		if err := json.Unmarshal(data, &wrapped); err != nil {
			return nil, fmt.Errorf("switchkit: read JSON export: %w", err)
		}
		items = wrapped.Certificates
	} else if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("switchkit: read JSON export: %w", err)
	}
	rows := make([]Row, 0, len(items))
	for i, item := range items {
		row := Row{Number: i + 1, Fields: map[string]string{}}
		for key, value := range item {
			field := canonical(key, columnMap)
			if field == "" {
				continue
			}
			switch v := value.(type) {
			case string:
				row.Fields[field] = strings.TrimSpace(v)
			case float64:
				row.Fields[field] = strconv.FormatFloat(v, 'f', -1, 64)
			case bool:
				row.Fields[field] = strconv.FormatBool(v)
			case []any:
				var parts []string
				for _, p := range v {
					if s, ok := p.(string); ok && strings.TrimSpace(s) != "" {
						parts = append(parts, strings.TrimSpace(s))
					}
				}
				row.Fields[field] = strings.Join(parts, ",")
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

var hexFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("not_after %q is not a date", s)
}

// normalizeFolder turns "a\b / c" into "a/b/c".
func normalizeFolder(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '\\' })
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "/")
}

var profileUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// ProfileName is the profile a folder's policy is proposed as.
func ProfileName(folder string) string {
	name := strings.Trim(profileUnsafe.ReplaceAllString(strings.ToLower(strings.ReplaceAll(folder, "/", "-")), "-"), "-")
	if name == "" {
		name = "root"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	return "switched-" + name
}

// Map gives every row exactly one outcome and works out the folders, owners
// and application groups the export carries.
func Map(rows []Row, existing ExistingOwners, now time.Time) Report {
	report := Report{Format: Format, Rows: len(rows), Counts: map[string]int{}, GapCounts: map[string]int{},
		Items: make([]Mapped, 0, len(rows))}
	seen := map[string]int{}
	folders := map[string]*FolderPolicy{}
	owners := map[string]*OwnerMatch{}
	apps := map[string]bool{}
	for _, row := range rows {
		m := mapRow(row, now)
		if m.Outcome == "" {
			if first, dup := seen[m.Fingerprint]; dup {
				m.Outcome, m.DuplicateOf, m.Reason = OutcomeDuplicate, first, fmt.Sprintf("the same certificate as row %d", first)
			} else {
				seen[m.Fingerprint] = row.Number
			}
		}
		if m.Outcome == "" {
			if m.Folder != "" {
				f := folders[m.Folder]
				if f == nil {
					f = &FolderPolicy{Folder: m.Folder, Profile: ProfileName(m.Folder), RenewalDays: m.RenewalDays, KeyAlgorithm: m.KeyAlgorithm}
					folders[m.Folder] = f
				}
				f.Rows++
				if m.RenewalDays != 0 && f.RenewalDays != 0 && m.RenewalDays != f.RenewalDays {
					f.Conflicts = appendOnce(f.Conflicts, fmt.Sprintf("renewal window %d or %d days", f.RenewalDays, m.RenewalDays))
					m.Gaps = append(m.Gaps, "folder has conflicting renewal settings")
				} else if f.RenewalDays == 0 {
					f.RenewalDays = m.RenewalDays
				}
				if m.KeyAlgorithm != "" && f.KeyAlgorithm != "" && !strings.EqualFold(m.KeyAlgorithm, f.KeyAlgorithm) {
					f.Conflicts = appendOnce(f.Conflicts, fmt.Sprintf("key algorithm %s or %s", f.KeyAlgorithm, m.KeyAlgorithm))
				} else if f.KeyAlgorithm == "" {
					f.KeyAlgorithm = m.KeyAlgorithm
				}
			} else {
				m.Gaps = append(m.Gaps, "no folder policy")
			}
			if m.OwnerEmail != "" {
				key := OwnerKey(m.OwnerEmail, m.Application)
				o := owners[key]
				if o == nil {
					o = &OwnerMatch{Email: m.OwnerEmail, Name: m.OwnerName, Application: m.Application}
					if id, ok := existing[key]; ok {
						o.OwnerID = id
					} else {
						o.Create = true
					}
					owners[key] = o
				}
				o.Rows++
				m.OwnerID = o.OwnerID
			} else {
				m.Gaps = append(m.Gaps, "no owner")
			}
			if m.Application != "" {
				apps[m.Application] = true
			} else {
				m.Gaps = append(m.Gaps, "no application")
			}
			if len(m.Endpoints) == 0 {
				m.Gaps = append(m.Gaps, "no endpoint")
			}
			m.Outcome = OutcomeMapped
			if len(m.Gaps) > 0 {
				m.Outcome = OutcomeMappedWithGaps
			}
		}
		report.Counts[m.Outcome]++
		for _, g := range m.Gaps {
			report.GapCounts[g]++
		}
		report.Items = append(report.Items, m)
	}
	for _, f := range folders {
		report.Folders = append(report.Folders, *f)
	}
	sort.Slice(report.Folders, func(i, j int) bool { return report.Folders[i].Folder < report.Folders[j].Folder })
	for _, o := range owners {
		report.Owners = append(report.Owners, *o)
	}
	sort.Slice(report.Owners, func(i, j int) bool {
		if report.Owners[i].Email != report.Owners[j].Email {
			return report.Owners[i].Email < report.Owners[j].Email
		}
		return report.Owners[i].Application < report.Owners[j].Application
	})
	for a := range apps {
		report.Applications = append(report.Applications, a)
	}
	sort.Strings(report.Applications)
	report.Digest = digest(report)
	return report
}

func appendOnce(list []string, v string) []string {
	for _, have := range list {
		if have == v {
			return list
		}
	}
	return append(list, v)
}

// mapRow reads one row's certificate facts; Outcome stays empty for a row
// that is usable so far.
func mapRow(row Row, now time.Time) Mapped {
	m := Mapped{Row: row.Number}
	f := row.Fields
	if msg, bad := f["_error"]; bad {
		m.Outcome, m.Reason = OutcomeUnparseable, msg
		return m
	}
	m.Folder = normalizeFolder(f["folder"])
	m.Application = f["application"]
	m.OwnerEmail, m.OwnerName = f["owner_email"], f["owner_name"]
	m.KeyAlgorithm = f["key_algorithm"]
	if days, err := strconv.Atoi(f["renewal_window_days"]); err == nil && days > 0 && days <= 365 {
		m.RenewalDays = days
	}
	for _, e := range splitList(f["endpoints"]) {
		if host, port, err := net.SplitHostPort(e); err == nil && host != "" && port != "" {
			m.Endpoints = append(m.Endpoints, net.JoinHostPort(strings.ToLower(host), port))
		} else {
			m.Gaps = append(m.Gaps, "endpoint "+e+" is not host:port")
		}
	}
	if raw := f["certificate_pem"]; raw != "" {
		block, _ := pem.Decode([]byte(strings.ReplaceAll(raw, `\n`, "\n")))
		if block == nil || block.Type != "CERTIFICATE" {
			m.Outcome, m.Reason = OutcomeUnparseable, "certificate_pem is not a PEM certificate"
			return m
		}
		info, err := certinfo.Inspect(block.Bytes)
		if err != nil {
			m.Outcome, m.Reason = OutcomeUnparseable, "certificate_pem does not parse: "+err.Error()
			return m
		}
		m.HasPEM, m.DER = true, block.Bytes
		m.Fingerprint = info.SHA256Fingerprint
		m.CommonName, m.SANs = info.CommonName, info.DNSNames
		m.Serial, m.Issuer, m.NotAfter = strings.ToLower(info.SerialNumber), info.Issuer, info.NotAfter.UTC()
		if m.KeyAlgorithm == "" {
			m.KeyAlgorithm = info.KeyAlgorithm
		}
		if given := normalizeFingerprint(f["fingerprint_sha256"]); given != "" && given != m.Fingerprint {
			m.Gaps = append(m.Gaps, "the export's fingerprint disagrees with its certificate")
		}
	} else {
		m.Fingerprint = normalizeFingerprint(f["fingerprint_sha256"])
		if !hexFingerprint.MatchString(m.Fingerprint) {
			m.Outcome, m.Reason = OutcomeUnparseable, "a row needs certificate_pem or a SHA-256 fingerprint"
			return m
		}
		m.CommonName, m.SANs = f["common_name"], splitList(f["sans"])
		m.Serial, m.Issuer = strings.ToLower(strings.ReplaceAll(f["serial"], ":", "")), f["issuer"]
		if raw := f["not_after"]; raw != "" {
			t, err := parseTime(raw)
			if err != nil {
				m.Outcome, m.Reason = OutcomeUnparseable, err.Error()
				return m
			}
			m.NotAfter = t
		} else {
			m.Gaps = append(m.Gaps, "no expiry")
		}
	}
	if !m.NotAfter.IsZero() && !m.NotAfter.After(now) {
		m.Outcome, m.Reason = OutcomeExpired, "expired "+m.NotAfter.Format(time.RFC3339)
	}
	return m
}

// digest binds the report's rows and outcomes, so an import applies exactly
// what was reviewed.
func digest(r Report) string {
	var b strings.Builder
	b.WriteString(r.Format + "\x00" + strconv.Itoa(r.Rows) + "\x00")
	for _, m := range r.Items {
		for _, part := range []string{strconv.Itoa(m.Row), m.Outcome, m.Fingerprint, m.Folder, m.Application,
			strings.ToLower(m.OwnerEmail), m.OwnerID, strings.Join(m.Endpoints, ","), strings.Join(m.Gaps, ","), m.KnownCertificateID} {
			b.WriteString(part + "\x00")
		}
	}
	return "sha256:" + crypto.SHA256Hex([]byte(b.String()))
}
