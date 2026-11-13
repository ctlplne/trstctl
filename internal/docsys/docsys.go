// SPDX-License-Identifier: BUSL-1.1

// Package docsys holds the documentation-system clients of the Provider
// plane (MSP-14 onward): each mapped customer's certificate inventory and
// expiry dates kept in one documentation record under the customer's own
// organization, updated when the inventory changes and linking back to
// trstctl. A client only translates: the core decides which customer a
// record belongs to and renders its content from that customer's inventory
// alone.
package docsys

import (
	"context"
	"errors"
	"html"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// MaxRows bounds the certificates a record lists; the rest are counted.
const MaxRows = 500

// Certificate is one certificate a record lists.
type Certificate struct {
	Subject  string
	SANs     []string
	Issuer   string
	Serial   string
	NotAfter *time.Time
	Location string
}

// Content is what a record holds: its title, the inventory as an HTML table,
// the count, the next expiry, the link back to trstctl, and a digest over
// all of it, so an unchanged inventory writes nothing.
type Content struct {
	Title      string
	HTML       string
	Count      int
	NextExpiry *time.Time
	Link       string
	Digest     string
}

// Render builds a customer's record from its certificates (active ones,
// soonest expiry first); total is how many the customer has, of which at
// most MaxRows are listed. consoleURL is trstctl's console base URL.
func Render(customer string, certs []Certificate, total int, consoleURL string) Content {
	sorted := append([]Certificate(nil), certs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i].NotAfter, sorted[j].NotAfter
		switch {
		case a == nil:
			return false
		case b == nil:
			return true
		default:
			return a.Before(*b)
		}
	})
	if len(sorted) > MaxRows {
		sorted = sorted[:MaxRows]
	}
	if total < len(sorted) {
		total = len(sorted)
	}
	link := strings.TrimRight(strings.TrimSpace(consoleURL), "/") + "/certificates"
	var b strings.Builder
	b.WriteString(`<p>Certificates trstctl manages for ` + html.EscapeString(customer) + `: ` + strconv.Itoa(total) + `.`)
	if total > len(sorted) {
		b.WriteString(` The ` + strconv.Itoa(len(sorted)) + ` that expire soonest are listed.`)
	}
	b.WriteString(` <a href="` + html.EscapeString(link) + `">Open the inventory in trstctl</a>.</p>`)
	b.WriteString(`<table><thead><tr><th>Subject</th><th>Names</th><th>Issuer</th><th>Serial</th><th>Expires</th><th>Location</th></tr></thead><tbody>`)
	var next *time.Time
	for _, c := range sorted {
		expires := "unknown"
		if c.NotAfter != nil {
			expires = c.NotAfter.UTC().Format("2006-01-02")
			if next == nil {
				at := c.NotAfter.UTC()
				next = &at
			}
		}
		names := c.SANs
		more := ""
		if len(names) > 3 {
			more = " (+" + strconv.Itoa(len(names)-3) + " more)"
			names = names[:3]
		}
		b.WriteString(`<tr><td>` + html.EscapeString(c.Subject) + `</td><td>` + html.EscapeString(strings.Join(names, ", ")+more) +
			`</td><td>` + html.EscapeString(c.Issuer) + `</td><td>` + html.EscapeString(c.Serial) + `</td><td>` + expires +
			`</td><td>` + html.EscapeString(c.Location) + `</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	content := Content{Title: "trstctl certificates", HTML: b.String(), Count: total, NextExpiry: next, Link: link}
	nextText := ""
	if next != nil {
		nextText = next.Format(time.RFC3339)
	}
	content.Digest = crypto.SHA256Hex([]byte(content.Title + "\x00" + content.HTML + "\x00" + strconv.Itoa(total) + "\x00" + nextText + "\x00" + link))
	return content
}

// Client is what the Provider plane needs from a documentation system.
type Client interface {
	// Find returns the ID of the record titled title under the
	// organization, if there is one.
	Find(ctx context.Context, orgID, title string) (string, bool, error)
	// Create writes a new record under the organization and returns its ID.
	Create(ctx context.Context, orgID string, content Content) (string, error)
	// Update replaces the content of a record under the organization.
	Update(ctx context.Context, orgID, recordID string, content Content) error
}

// ErrBeforeWrite marks a failure proven before anything reached the
// documentation system (a lookup, a sign-in, a refusal of the request).
var ErrBeforeWrite = errors.New("docsys: refused before anything was written")

// ErrRefused marks the documentation system's definitive refusal of a write.
var ErrRefused = errors.New("docsys: the documentation system refused the write")

// ErrRecordGone marks an update of a record the documentation system no
// longer has (deleted there); the core creates it again.
var ErrRecordGone = errors.New("docsys: the record no longer exists")
