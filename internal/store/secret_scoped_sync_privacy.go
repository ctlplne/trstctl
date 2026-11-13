// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
)

// Scoped syncs and privacy (A237-L5). A scoped sync's secret names — its
// source and destination prefixes, and each managed key's destination key
// and source name — are structured paths, and a segment of one can be a
// person's identity (a home folder, a per-person key). An erasure rewrites
// such a segment to the subject's placeholder in the scoped-sync events (their
// subject_token rules) and in these rows, so a rebuild from the rewritten
// events reaches the same rows. A segment is bounded as the event rewrite
// bounds a subject token: letters, numbers, '_', '.' and '@' continue it, any
// other rune ends it. The definition's name is a slug and stays as written.

// isScopedSyncPrivacyTokenRune mirrors the event rewrite's token runes.
func isScopedSyncPrivacyTokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '.' || r == '@'
}

// scopedSyncSubjectPattern is a PostgreSQL regular expression matching the
// raw subject as a complete token, for selecting the rows that hold it.
func scopedSyncSubjectPattern(subject string) string {
	var b strings.Builder
	for _, r := range subject {
		if r < utf8.RuneSelf && !unicode.IsLetter(r) && !unicode.IsDigit(r) || r >= utf8.RuneSelf && !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return `(^|[^[:alnum:]_.@])` + b.String() + `($|[^[:alnum:]_.@])`
}

// replaceScopedSyncSubjectSpans replaces each span of value that is exactly
// the erased subject — known only by its reference — and bounded like a
// subject token, with the placeholder. A span starts where a token starts and
// ends where one ends, so a subject that holds separators ("jean-luc") is
// found as the event rewrite finds it.
func replaceScopedSyncSubjectSpans(tenantID, subjectRef, placeholder, value string) (string, bool) {
	if value == "" {
		return value, false
	}
	var starts, ends []int
	inside := false
	for i, r := range value {
		token := isScopedSyncPrivacyTokenRune(r)
		if token && !inside {
			starts = append(starts, i)
		}
		if !token && inside {
			ends = append(ends, i)
		}
		inside = token
	}
	if inside {
		ends = append(ends, len(value))
	}
	var out strings.Builder
	cursor, changed := 0, false
	for _, start := range starts {
		if start < cursor {
			continue
		}
		for _, end := range ends {
			if end <= start {
				continue
			}
			span := value[start:end]
			if privacy.IsPlaceholder(span) || privacy.SubjectRef(tenantID, span) != subjectRef {
				continue
			}
			out.WriteString(value[cursor:start])
			out.WriteString(placeholder)
			cursor, changed = end, true
			break
		}
	}
	if !changed {
		return value, false
	}
	out.WriteString(value[cursor:])
	return out.String(), true
}

// scopedSyncPrivacyMatch is the SQL condition, on definition s, that one of
// its secret names holds the subject ($2 is the subject's token pattern).
const scopedSyncPrivacyMatch = `(s.source_prefix ~ $2 OR s.destination_prefix ~ $2
	OR EXISTS (SELECT 1 FROM secret_scoped_sync_keys k
	            WHERE k.tenant_id = s.tenant_id AND k.sync_id = s.id AND (k.remote_key ~ $2 OR k.source_name ~ $2))
	OR EXISTS (SELECT 1 FROM secret_scoped_sync_deletes d
	            WHERE d.tenant_id = s.tenant_id AND d.sync_id = s.id AND d.remote_key ~ $2))`

func scopedSyncPrivacySelectorQueries(tenantID, subject string) []privacyReadModelQuery {
	return []privacyReadModelQuery{{
		table: "secret_scoped_syncs",
		sql: `SELECT s.id::text, ''::text, 0 FROM secret_scoped_syncs s
		       WHERE s.tenant_id = $1 AND ` + scopedSyncPrivacyMatch + `
		       ORDER BY s.id`,
		args: []any{tenantID, scopedSyncSubjectPattern(subject)},
	}}
}

func scopedSyncPrivacyExportQueries(tenantID, subject string) []privacyReadModelQuery {
	return []privacyReadModelQuery{{
		table: "secret_scoped_syncs",
		sql: `SELECT s.id::text, ''::text,
		             jsonb_build_object(
		               'name', s.name, 'source_prefix', s.source_prefix, 'target', s.target,
		               'destination_prefix', s.destination_prefix,
		               'keys', COALESCE((SELECT jsonb_agg(jsonb_build_object('remote_key', k.remote_key, 'source_name', k.source_name)
		                                          ORDER BY k.remote_key)
		                                   FROM secret_scoped_sync_keys k
		                                  WHERE k.tenant_id = s.tenant_id AND k.sync_id = s.id
		                                    AND (k.remote_key ~ $2 OR k.source_name ~ $2)), '[]'::jsonb))::text,
		             s.created_at
		        FROM secret_scoped_syncs s
		       WHERE s.tenant_id = $1 AND ` + scopedSyncPrivacyMatch + `
		       ORDER BY s.id`,
		args: []any{tenantID, scopedSyncSubjectPattern(subject)},
	}}
}

// eraseScopedSyncPrivacyRows rewrites the erased subject's segments in each
// selected definition's prefixes, its managed keys and its queued deletes.
func eraseScopedSyncPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	rewrite := func(value string) (string, bool) {
		return replaceScopedSyncSubjectSpans(tenantID, subjectRef, placeholder, value)
	}
	for _, id := range readModelIDs(selectors, "secret_scoped_syncs") {
		var source, destination string
		err := tx.QueryRow(ctx,
			`SELECT source_prefix, destination_prefix FROM secret_scoped_syncs
			  WHERE tenant_id = $1 AND id::text = $2 FOR UPDATE`, tenantID, id).Scan(&source, &destination)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		newSource, a := rewrite(source)
		newDestination, b := rewrite(destination)
		if a || b {
			if _, err := tx.Exec(ctx,
				`UPDATE secret_scoped_syncs SET source_prefix = $3, destination_prefix = $4
				  WHERE tenant_id = $1 AND id::text = $2`, tenantID, id, newSource, newDestination); err != nil {
				return err
			}
		}
		if err := eraseScopedSyncKeyPrivacyRows(ctx, tx, tenantID, id, rewrite); err != nil {
			return err
		}
		if err := eraseScopedSyncDeletePrivacyRows(ctx, tx, tenantID, id, rewrite); err != nil {
			return err
		}
	}
	return nil
}

func eraseScopedSyncKeyPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, syncID string, rewrite func(string) (string, bool)) error {
	rows, err := tx.Query(ctx,
		`SELECT remote_key, source_name FROM secret_scoped_sync_keys
		  WHERE tenant_id = $1 AND sync_id::text = $2 ORDER BY remote_key FOR UPDATE`, tenantID, syncID)
	if err != nil {
		return err
	}
	type key struct{ remote, source, newRemote, newSource string }
	var changed []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.remote, &k.source); err != nil {
			rows.Close()
			return err
		}
		var a, b bool
		k.newRemote, a = rewrite(k.remote)
		k.newSource, b = rewrite(k.source)
		if a || b {
			changed = append(changed, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, k := range changed {
		if _, err := tx.Exec(ctx,
			`UPDATE secret_scoped_sync_keys SET remote_key = $4, source_name = $5
			  WHERE tenant_id = $1 AND sync_id::text = $2 AND remote_key = $3`,
			tenantID, syncID, k.remote, k.newRemote, k.newSource); err != nil {
			return err
		}
	}
	return nil
}

func eraseScopedSyncDeletePrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, syncID string, rewrite func(string) (string, bool)) error {
	rows, err := tx.Query(ctx,
		`SELECT id::text, remote_key FROM secret_scoped_sync_deletes
		  WHERE tenant_id = $1 AND sync_id::text = $2 ORDER BY id FOR UPDATE`, tenantID, syncID)
	if err != nil {
		return err
	}
	type del struct{ id, newRemote string }
	var changed []del
	for rows.Next() {
		var id, remote string
		if err := rows.Scan(&id, &remote); err != nil {
			rows.Close()
			return err
		}
		if newRemote, ok := rewrite(remote); ok {
			changed = append(changed, del{id, newRemote})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, d := range changed {
		if _, err := tx.Exec(ctx,
			`UPDATE secret_scoped_sync_deletes SET remote_key = $3 WHERE tenant_id = $1 AND id::text = $2`,
			tenantID, d.id, d.newRemote); err != nil {
			return err
		}
	}
	return nil
}
