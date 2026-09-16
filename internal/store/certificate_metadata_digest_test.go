// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

func TestCertificateMetadataBatchDigestKeepsStoredFormat(t *testing.T) {
	base := eventspec.Event{ID: "digest <&> \n\u2028", Type: "certificate.recorded", TenantID: "ABCDEF00-ABCD-4ABC-8ABC-ABCDEFABCDEF",
		Time: time.Date(2026, 9, 15, 12, 13, 14, 123456789, time.FixedZone("offset", -4*3600)), Sequence: math.MaxUint64}
	d := newCertificateMetadataDigester()
	for _, payload := range [][]byte{nil, {}, []byte("\x00\xff\n<&>"), bytes.Repeat([]byte("public-certificate"), 1024)} {
		for _, actor := range []*eventspec.Actor{nil, {}, {Subject: "operator <&>\x00\xff", Roles: []string{}}, {Subject: "operator", Roles: []string{"reader", "writer"}}} {
			e := base
			e.Data, e.Actor = payload, actor
			// This is the established on-disk receipt contract, independently
			// normalized before either production digest helper is called.
			canonical := e
			canonical.TenantID = strings.ToLower(base.TenantID)
			canonical.Time = base.Time.UTC()
			canonical.Sequence, canonical.SchemaVersion = 0, eventspec.DefaultSchemaVersion
			raw, err := json.Marshal(canonical)
			if err != nil {
				t.Fatal(err)
			}
			want := crypto.SHA256Hex(raw)
			got, err := d.digest(e)
			single, singleErr := certificateMetadataEventDigest(e)
			if err != nil || singleErr != nil || got != want || single != want {
				t.Fatalf("receipt encoding changed: batch=%q single=%q want=%q errors=%v/%v", got, single, want, err, singleErr)
			}
		}
	}
	// Reusing a buffer after a rejected envelope must not hash earlier bytes or
	// leave the encoder permanently unusable for a later valid envelope.
	for _, bad := range []eventspec.Event{{TenantID: "invalid"}, {TenantID: base.TenantID, Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		if got, err := d.digest(bad); err == nil || got != "" {
			t.Fatalf("invalid envelope received a digest: %q %v", got, err)
		}
		want, err := certificateMetadataEventDigest(base)
		got, gotErr := d.digest(base)
		if err != nil || gotErr != nil || got != want {
			t.Fatalf("invalid envelope poisoned later digest: %v/%v", err, gotErr)
		}
	}
}

func BenchmarkCertificateMetadataDigest(b *testing.B) {
	e := eventspec.Event{ID: "metadata-digest", Type: "certificate.recorded", TenantID: "abcdef00-abcd-4abc-8abc-abcdefabcdef",
		Time: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC), Data: bytes.Repeat([]byte("public-certificate"), 512)}
	for _, name := range []string{"stored-format", "reused-buffer"} {
		b.Run(name, func(b *testing.B) {
			d := newCertificateMetadataDigester()
			b.ReportAllocs()
			for b.Loop() {
				var digest string
				var err error
				if name == "stored-format" {
					digest, err = certificateMetadataEventDigest(e)
				} else {
					digest, err = d.digest(e)
				}
				if err != nil || len(digest) != 64 {
					b.Fatalf("digest failed: %v", err)
				}
			}
		})
	}
}
