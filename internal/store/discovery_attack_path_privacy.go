// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

const discoveryRefusedOriginPrivacySelector = "discovery_attack_path_refused_origins"

type discoveryFindingPrivacyMatch struct {
	record         PrivacyReadModelRecord
	findingMatches bool
	originMatches  bool
}

// A refused origin follows the event's free-text policy. SQL narrows the
// candidates. The same token check as history avoids matching a substring of
// someone else's hostname, and records whether other finding fields matched.
func selectDiscoveryFindingPrivacy(ctx context.Context, tx pgx.Tx, tenantID, subject string, includeData bool) ([]discoveryFindingPrivacyMatch, error) {
	rows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT id, run_id, kind, ref, metadata, triage_status, triage_actor, triage_reason, triaged_at, discovered_at,
			       attack_path_refused_origin,
			       (triage_actor = $2 OR position($2 in triage_reason) > 0 OR `+discoveryPrivacyJSONStringMatch("metadata", "$2")+`) AS finding_matches
			  FROM discovery_findings
			 WHERE tenant_id = $1
		)
		SELECT id::text, run_id::text, discovered_at, attack_path_refused_origin, finding_matches,
		       CASE WHEN $3::boolean THEN jsonb_build_object(
		          'kind', kind, 'ref', ref, 'metadata',
		          CASE WHEN kind <> 'nhi-attack-path' OR jsonb_typeof(metadata) <> 'object' THEN metadata
		               WHEN metadata->>'reason' LIKE 'the provider could not be read: %'
		               THEN jsonb_set(metadata - 'credential_refused_origin', '{reason}', to_jsonb('the provider could not be read'::text))
		               ELSE metadata - 'credential_refused_origin' END,
		          'triage_status', triage_status, 'triage_actor', triage_actor,
		            'triage_reason', triage_reason, 'triaged_at', triaged_at, 'attack_path_refused_origin', attack_path_refused_origin)::text
		            ELSE '' END
		  FROM candidates
		 WHERE finding_matches OR position($2 in attack_path_refused_origin) > 0
		 ORDER BY id`, tenantID, subject, includeData)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []discoveryFindingPrivacyMatch
	for rows.Next() {
		match := discoveryFindingPrivacyMatch{record: PrivacyReadModelRecord{Table: "discovery_findings"}}
		var origin string
		r := &match.record
		if err := rows.Scan(&r.ID, &r.ParentID, &r.At, &origin, &match.findingMatches, &r.Data); err != nil {
			return nil, err
		}
		match.originMatches = events.PrivacyFreeTextContainsSubject(origin, subject)
		if match.findingMatches || match.originMatches {
			result = append(result, match)
		}
	}
	return result, rows.Err()
}

func eraseDiscoveryRefusedOriginPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID string, selectors []PrivacyReadModelSelector) error {
	selected := readModelChildSelectors(selectors, discoveryRefusedOriginPrivacySelector)
	if len(selected) == 0 {
		return nil
	}
	ids, runs := make([]string, 0, len(selected)), make([]string, 0, len(selected))
	for _, row := range selected {
		ids, runs = append(ids, row.ID), append(runs, row.ParentID)
	}
	// Clear only the selected observation. Surviving triage facts and later
	// observations have their own selectors, or no erasure at all.
	_, err := tx.Exec(ctx, `UPDATE discovery_findings f
		SET attack_path_refused_origin = ''
		FROM unnest($2::uuid[], $3::uuid[]) AS selected(id, run_id)
		WHERE f.tenant_id = $1 AND f.id = selected.id AND f.run_id = selected.run_id`, tenantID, ids, runs)
	return err
}
