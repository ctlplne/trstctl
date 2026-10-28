// SPDX-License-Identifier: BUSL-1.1

package projections

import "time"

// Keep historical single-schedule payloads closed when schema two names schedules.
type privacySyncIntentV1 struct {
	System             string `json:"system"`
	InstanceURL        string `json:"instance_url"`
	TokenRef           string `json:"token_ref"`
	SNTable            string `json:"sn_table,omitempty"`
	JiraProject        string `json:"jira_project,omitempty"`
	Query              string `json:"query,omitempty"`
	SubjectField       string `json:"subject_field"`
	ProfileField       string `json:"profile_field"`
	RequesterField     string `json:"requester_field,omitempty"`
	JustificationField string `json:"justification_field,omitempty"`
	PageLimit          int    `json:"page_limit"`
	SweepID            string `json:"sweep_id"`
	Cursor             string `json:"cursor,omitempty"`
	ReadCount          int    `json:"read_count"`
	ExpectedCount      *int   `json:"expected_count,omitempty"`
}

type privacyTicketIntakeConfiguredV1 struct {
	System             string   `json:"system"`
	InstanceURL        string   `json:"instance_url"`
	TokenRef           string   `json:"token_ref"`
	SNTable            string   `json:"sn_table,omitempty"`
	JiraProject        string   `json:"jira_project,omitempty"`
	Query              string   `json:"query,omitempty"`
	SubjectField       string   `json:"subject_field"`
	ProfileField       string   `json:"profile_field"`
	RequesterField     string   `json:"requester_field,omitempty"`
	JustificationField string   `json:"justification_field,omitempty"`
	IntervalSeconds    int      `json:"interval_seconds"`
	Enabled            bool     `json:"enabled"`
	AllowPrivate       bool     `json:"allow_private_endpoint,omitempty"`
	PrivateCIDRs       []string `json:"private_egress_cidrs,omitempty"`
}

type privacyTicketIntakeSweepDispatchedV1 struct {
	Intent       privacySyncIntentV1 `json:"intent"`
	DispatchedAt time.Time           `json:"dispatched_at"`
}

type privacyTicketIntakeSweepPageObservedV1 struct {
	Intent        privacySyncIntentV1  `json:"intent"`
	ObservedAt    time.Time            `json:"observed_at"`
	SourceRefs    []string             `json:"source_refs"`
	ReadCount     int                  `json:"read_count"`
	ExpectedCount *int                 `json:"expected_count,omitempty"`
	Complete      bool                 `json:"complete"`
	NextCursor    string               `json:"next_cursor,omitempty"`
	Eligible      int                  `json:"eligible"`
	Skipped       int                  `json:"skipped"`
	NextIntent    *privacySyncIntentV1 `json:"next_intent,omitempty"`
}

type privacyTicketIntakeSweepFailedV1 struct {
	System   string    `json:"system"`
	SweepID  string    `json:"sweep_id"`
	Cursor   string    `json:"cursor,omitempty"`
	FailedAt time.Time `json:"failed_at"`
	Detail   string    `json:"detail"`
}
