// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

type preflightCAAResolver struct {
	records map[string][]acmesrv.CAARecord
	err     error
}

func (r preflightCAAResolver) LookupCAA(_ context.Context, name string) ([]acmesrv.CAARecord, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.records[name], nil
}

func TestCAAPolicyCheckReturnsOperatorEvidence(t *testing.T) {
	tests := []struct {
		name               string
		domain             string
		wildcard           bool
		issuer             string
		resolver           acmesrv.CAAResolver
		wantCheck          string
		wantStatus         string
		wantGoverning      string
		wantRelevantTag    string
		wantAllowed        []string
		wantRecordCount    int
		wantRecommendation string
	}{
		{
			name:   "no CAA is visibly unrestricted",
			domain: "api.example.test", issuer: "trstctl.example",
			resolver:  preflightCAAResolver{records: map[string][]acmesrv.CAARecord{}},
			wantCheck: "pass", wantStatus: "unrestricted", wantRelevantTag: "issue",
			wantRecommendation: `api.example.test CAA 0 issue "trstctl.example"`,
		},
		{
			name:   "allowed issuer exposes governing records",
			domain: "api.example.test", issuer: "trstctl.example",
			resolver: preflightCAAResolver{records: map[string][]acmesrv.CAARecord{
				"example.test": {{Flag: 0, Tag: "issue", Value: "trstctl.example; account=7"}},
			}},
			wantCheck: "pass", wantStatus: "allowed", wantGoverning: "example.test", wantRelevantTag: "issue",
			wantAllowed: []string{"trstctl.example"}, wantRecordCount: 1,
		},
		{
			name:   "denied issuer includes an exact safe record change",
			domain: "api.example.test", issuer: "trstctl.example",
			resolver: preflightCAAResolver{records: map[string][]acmesrv.CAARecord{
				"example.test": {{Flag: 0, Tag: "issue", Value: "other.ca"}},
			}},
			wantCheck: "fail", wantStatus: "denied", wantGoverning: "example.test", wantRelevantTag: "issue",
			wantAllowed: []string{"other.ca"}, wantRecordCount: 1,
			wantRecommendation: `example.test CAA 0 issue "trstctl.example"`,
		},
		{
			name:   "DNS error fails closed without inventing a record change",
			domain: "api.example.test", issuer: "trstctl.example",
			resolver:  preflightCAAResolver{err: errors.New("servfail")},
			wantCheck: "fail", wantStatus: "lookup_failed", wantGoverning: "api.example.test", wantRelevantTag: "issue",
		},
		{
			name:   "wildcard uses issuewild",
			domain: "*.example.test", wildcard: true, issuer: "trstctl.example",
			resolver: preflightCAAResolver{records: map[string][]acmesrv.CAARecord{
				"example.test": {
					{Flag: 0, Tag: "issue", Value: "trstctl.example"},
					{Flag: 0, Tag: "issuewild", Value: "wildcard.ca"},
				},
			}},
			wantCheck: "fail", wantStatus: "denied", wantGoverning: "example.test", wantRelevantTag: "issuewild",
			wantAllowed: []string{"wildcard.ca"}, wantRecordCount: 2,
			wantRecommendation: `example.test CAA 0 issuewild "trstctl.example"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check, evidence := caaPolicyCheck(context.Background(), tt.resolver, tt.domain, tt.wildcard, tt.issuer)
			if check.Status != tt.wantCheck || evidence.Status != tt.wantStatus {
				t.Fatalf("check=%+v evidence=%+v, want check %q evidence %q", check, evidence, tt.wantCheck, tt.wantStatus)
			}
			if evidence.Source != "authoritative_live_dns" || !evidence.FailClosed {
				t.Fatalf("evidence=%+v, want authoritative live DNS and fail_closed", evidence)
			}
			if evidence.GoverningName != tt.wantGoverning || evidence.RelevantTag != tt.wantRelevantTag {
				t.Fatalf("evidence=%+v, want governing %q relevant tag %q", evidence, tt.wantGoverning, tt.wantRelevantTag)
			}
			if len(evidence.Records) != tt.wantRecordCount {
				t.Fatalf("records=%+v, want %d", evidence.Records, tt.wantRecordCount)
			}
			if strings.Join(evidence.AllowedIssuers, ",") != strings.Join(tt.wantAllowed, ",") {
				t.Fatalf("allowed issuers=%v, want %v", evidence.AllowedIssuers, tt.wantAllowed)
			}
			if tt.wantRecommendation == "" {
				if len(evidence.RecommendedRecords) != 0 {
					t.Fatalf("recommended records=%v, want none", evidence.RecommendedRecords)
				}
			} else if len(evidence.RecommendedRecords) != 1 || evidence.RecommendedRecords[0] != tt.wantRecommendation {
				t.Fatalf("recommended records=%v, want [%s]", evidence.RecommendedRecords, tt.wantRecommendation)
			}
			if len(evidence.RecoverySteps) == 0 {
				t.Fatal("every policy state must explain the next safe step")
			}
		})
	}
}

func TestCAAPolicyCheckExplainsMissingIssuerConfiguration(t *testing.T) {
	check, evidence := caaPolicyCheck(context.Background(), nil, "example.test", false, "")
	if check.Status != "skipped" || evidence.Status != "not_configured" || evidence.Source != "authoritative_live_dns" {
		t.Fatalf("check=%+v evidence=%+v", check, evidence)
	}
	if len(evidence.RecoverySteps) == 0 || !strings.Contains(evidence.RecoverySteps[0], "CAA issuer domain") {
		t.Fatalf("recovery steps=%v, want configuration guidance", evidence.RecoverySteps)
	}
}
