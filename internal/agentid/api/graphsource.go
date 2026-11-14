// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"time"

	"trstctl.com/trstctl/internal/agentid/delegation"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/graph"
	corestore "trstctl.com/trstctl/internal/store"
)

// graphSource hands the access graph each chain-bound credential with the
// signed delegation chain it was issued under (Q4-L4): who delegated to whom,
// the subject the credential was issued to, and what the leaf record passes
// on. It reads the AGID store; the graph never does.
type graphSource struct {
	repo *agidstore.Repo
}

// NewGraphSource returns the access graph's reader of AGID chains.
func NewGraphSource(core *corestore.Store) graph.AgentChainSource {
	return graphSource{repo: agidstore.New(core)}
}

func (s graphSource) AgentChains(ctx context.Context, tenantID string, limit int) ([]graph.AgentChain, bool, error) {
	rows, more, err := s.repo.ListIssuanceChains(ctx, tenantID, limit)
	if err != nil {
		return nil, false, err
	}
	out := make([]graph.AgentChain, 0, len(rows))
	for _, row := range rows {
		c := graph.AgentChain{
			CredentialID: row.Issuance.CredentialID, SubjectID: row.Issuance.SubjectID,
			NotBefore: unixTime(row.Issuance.NotBefore), NotAfter: unixTime(row.Issuance.NotAfter),
			Revoked: row.Revoked, ChainBroken: row.Broken,
		}
		for _, rec := range row.Chain {
			c.Links = append(c.Links, graph.AgentDelegationLink{
				DelegatorID: rec.DelegatorID, DelegateID: rec.DelegateID,
				NotBefore: unixTime(rec.NotBefore), NotAfter: unixTime(rec.NotAfter),
			})
		}
		if len(row.Chain) > 0 {
			// What the leaf record passes on is in its signed body; a body that
			// does not read leaves the credential with no grant rather than a
			// guessed one.
			var leaf delegation.RecordEnvelope
			if json.Unmarshal(row.Chain[len(row.Chain)-1].Encoded, &leaf) != nil {
				c.ChainBroken = true
			} else {
				c.Tools, c.Scopes = leaf.Record.Authority.Tools, leaf.Record.Authority.Scopes
				for _, r := range leaf.Record.Authority.Resources {
					c.Resources = append(c.Resources, graph.AgentChainResource{Kind: r.Kind, Value: r.Value})
				}
			}
		}
		out = append(out, c)
	}
	return out, more, nil
}

// unixTime maps the AGID store's Unix seconds to a time; 0 is unset.
func unixTime(seconds int64) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
}
