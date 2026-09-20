// SPDX-License-Identifier: BUSL-1.1

package adcs

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AD CS certificate-database ingestion (epic F4).
//
// Today trstctl sees only what it asked for. An enterprise CA has been issuing
// for years through native auto-enrollment, and every one of those certificates
// is invisible here — so an inventory that claims to cover the estate is
// counting the fraction trstctl happened to request.
//
// The disposition values below are AD CS's own (certutil's Disposition column).
// They are mapped rather than stored raw, because an inventory that speaks two
// vocabularies makes every query a translation exercise; but the mapping keeps
// PENDING distinct from FAILED and both distinct from REVOKED, which the
// obvious two-state "is it good" collapse would lose.

// DBDisposition is AD CS's view of one row in its certificate database.
type DBDisposition string

const (
	// DispositionIssued: the CA issued it and has not revoked it.
	DispositionIssued DBDisposition = "issued"
	// DispositionPending: a request awaiting a CA manager's approval. NOT a
	// failure — somebody has to act, and a pending request rendered as failed
	// makes an operator re-submit rather than go and approve.
	DispositionPending DBDisposition = "pending"
	// DispositionRevoked: issued and later revoked.
	DispositionRevoked DBDisposition = "revoked"
	// DispositionDenied: a CA manager refused it. Distinct from pending because
	// re-submitting a denied request is how people annoy their CA team, and
	// distinct from failed because a human decided.
	DispositionDenied DBDisposition = "denied"
	// DispositionFailed: the CA could not process it at all.
	DispositionFailed DBDisposition = "failed"
	// DispositionUnknown: a disposition code this build does not recognise.
	// Microsoft adds codes; mapping an unseen one onto "failed" would report
	// healthy certificates as broken.
	DispositionUnknown DBDisposition = "unknown"
)

// DBRow is one certificate-database row, reduced to what inventory needs.
type DBRow struct {
	RequestID   int
	Serial      string
	Subject     string
	Template    string
	Disposition DBDisposition
	NotBefore   time.Time
	NotAfter    time.Time
	// RevokedAt is set only for revoked rows. Nil on an issued row means "not
	// revoked"; it is never used to mean "we did not look".
	RevokedAt *time.Time
	// Requester is the account that asked. It is how an operator finds the
	// owner of a certificate nobody in trstctl requested.
	Requester string
}

// MapDisposition turns an AD CS disposition code into our vocabulary.
//
// The numeric codes are the ones certutil reports. Anything else is UNKNOWN,
// never failed: Microsoft adds codes, and a build that guessed "failure" would
// report healthy certificates as broken the first time it met a new one.
func MapDisposition(code int) DBDisposition {
	switch code {
	case 20:
		return DispositionIssued
	case 21:
		return DispositionRevoked
	case 9:
		return DispositionPending
	case 31:
		return DispositionDenied
	case 30:
		return DispositionFailed
	default:
		return DispositionUnknown
	}
}

// ParseDBRow reads one certutil-style row.
//
// Deliberately tolerant about columns it does not know and strict about the
// ones it does: an AD CS estate's certutil output varies by version and by the
// -restrict the operator used, and a parser that demanded an exact shape would
// work on the developer's lab and nowhere else.
func ParseDBRow(fields map[string]string) (DBRow, error) {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := fields[k]; ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	idRaw := get("RequestID", "Request ID", "RequestId")
	if idRaw == "" {
		// Without a request id a row cannot be reconciled against anything, and
		// an unreconcilable row in inventory is a row that inflates coverage.
		return DBRow{}, fmt.Errorf("adcs: certificate-database row has no request id")
	}
	id, err := strconv.Atoi(strings.TrimSpace(idRaw))
	if err != nil {
		return DBRow{}, fmt.Errorf("adcs: request id %q is not a number: %w", idRaw, err)
	}
	row := DBRow{
		RequestID: id,
		Serial:    strings.ToLower(strings.ReplaceAll(get("SerialNumber", "Serial Number"), " ", "")),
		Subject:   get("CommonName", "Common Name", "Subject"),
		Template:  get("CertificateTemplate", "Certificate Template", "Template"),
		Requester: get("Request.RequesterName", "RequesterName", "Requester"),
	}
	dispRaw := get("Request.Disposition", "Disposition")
	if code, err := strconv.Atoi(dispRaw); err == nil {
		row.Disposition = MapDisposition(code)
	} else {
		row.Disposition = DispositionUnknown
	}
	row.NotBefore = parseDBTime(get("NotBefore"))
	row.NotAfter = parseDBTime(get("NotAfter"))
	if t := parseDBTime(get("Request.RevokedWhen", "RevokedWhen")); !t.IsZero() {
		row.RevokedAt = &t
	}
	return row, nil
}

// dbTimeLayouts are the formats certutil emits across locales and versions.
var dbTimeLayouts = []string{
	time.RFC3339,
	"2006-01-02 15:04:05",
	"1/2/2006 3:04 PM",
	"1/2/2006 15:04",
}

// parseDBTime returns the zero time when nothing parses.
//
// Zero means UNPARSED, and callers must not treat it as "expired long ago" —
// an unparseable NotAfter is a gap in what we can see, not a certificate that
// ran out in year zero. The distinction matters because the obvious use of this
// field is an expiry sweep.
func parseDBTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range dbTimeLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// DBSummary counts a database ingestion by disposition.
//
// Every disposition is counted separately. A single "certificates found" number
// would hide that half of them are pending somebody's approval, which is the
// one thing an operator ingesting a CA database actually needs to see.
type DBSummary struct {
	Issued   int
	Pending  int
	Revoked  int
	Denied   int
	Failed   int
	Unknown  int
	Unparsed int
	Total    int
}

// Summarize counts rows by disposition.
func Summarize(rows []DBRow) DBSummary {
	var s DBSummary
	for _, r := range rows {
		s.Total++
		switch r.Disposition {
		case DispositionIssued:
			s.Issued++
		case DispositionPending:
			s.Pending++
		case DispositionRevoked:
			s.Revoked++
		case DispositionDenied:
			s.Denied++
		case DispositionFailed:
			s.Failed++
		default:
			s.Unknown++
		}
		if r.NotAfter.IsZero() && r.Disposition == DispositionIssued {
			// An issued certificate whose expiry we could not read is a gap in
			// visibility, not a healthy row. Counted so the ingestion cannot
			// claim complete coverage it does not have.
			s.Unparsed++
		}
	}
	return s
}
