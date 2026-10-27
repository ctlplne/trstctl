// SPDX-License-Identifier: BUSL-1.1

// Package cryptorisk builds the cryptographic risk report: every weak,
// distrusted or quantum-vulnerable key the tenant has inventoried or discovered,
// with what depends on it, the transition deadline that applies, and the
// migration plan or action that addresses it, in the order to act on, with what
// changed since the previous report. Build is pure: the API layer reads the
// inputs under the caller's tenant and passes them in.
package cryptorisk

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cryptoreadiness"
)

// Format names the report.
const Format = "trstctl.crypto-risk-report/v1"

// Coverage says what a report can and cannot see.
const Coverage = "The report covers the certificates trstctl holds or has discovered and the crypto assets " +
	"discovery has inventoried. Hosts, stores and endpoints no agent or scan has reached are not covered, and a " +
	"key with no recorded dependents may be one nothing has scanned around, not one nothing depends on."

// CNSA20Note says what the report does not encode for national security systems.
const CNSA20Note = "CNSA 2.0 milestones for national security systems are not encoded in this report; " +
	"check NSA's CNSA 2.0 guidance for the dates that apply to such a system."

// Exposure values.
const (
	ExposureDistrusted        = "distrusted"
	ExposureWeak              = "weak"
	ExposureQuantumVulnerable = "quantum_vulnerable"
	ExposureOutOfPolicy       = "out_of_policy"
)

// Distrust names the distrust-list entry a key is, or chains to.
type Distrust struct {
	Entry string `json:"entry"`
	How   string `json:"how"`
}

// Dependents is what depends on a key: from the crypto-readiness graph for a
// crypto asset, from the blast radius for a certificate.
type Dependents struct {
	Count  int            `json:"count"`
	ByKind map[string]int `json:"by_kind"`
	// Names lists the first dependents by name, for the reader.
	Names  []string `json:"names"`
	Source string   `json:"source"`
}

// PlanAction is one migration-campaign action bound to the key's crypto asset.
type PlanAction struct {
	CampaignID string    `json:"campaign_id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Wave       string    `json:"wave,omitempty"`
	Deadline   time.Time `json:"deadline"`
	Stale      bool      `json:"stale"`
}

// Plan is what addresses a key: its campaign actions, or the recommended next
// step when there are none.
type Plan struct {
	Actions     []PlanAction `json:"actions"`
	Recommended string       `json:"recommended,omitempty"`
}

// Item is one key in the report.
type Item struct {
	Key            string     `json:"key"`
	Kind           string     `json:"kind"`
	Subject        string     `json:"subject"`
	Algorithm      string     `json:"algorithm"`
	KeyBits        int        `json:"key_bits,omitempty"`
	Exposures      []string   `json:"exposures"`
	Reasons        []string   `json:"reasons,omitempty"`
	Distrust       *Distrust  `json:"distrust,omitempty"`
	Dependents     Dependents `json:"dependents"`
	Owners         []string   `json:"owners"`
	Deadline       Deadline   `json:"deadline"`
	Plan           Plan       `json:"plan"`
	Priority       int        `json:"priority"`
	PriorityReason string     `json:"priority_reason"`
	EvidenceIDs    []string   `json:"evidence_ids"`
}

// Summary counts the report's items.
type Summary struct {
	Items             int `json:"items"`
	Distrusted        int `json:"distrusted"`
	Weak              int `json:"weak"`
	QuantumVulnerable int `json:"quantum_vulnerable"`
	ReplaceNow        int `json:"replace_now"`
	Deprecated        int `json:"deprecated"`
	Upcoming          int `json:"upcoming"`
	WithPlan          int `json:"with_plan"`
	WithoutPlan       int `json:"without_plan"`
}

// Change is one item whose value moved between periods.
type Change struct {
	Key  string `json:"key"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Changes compares the report with the previous period's.
type Changes struct {
	Comparable          bool       `json:"comparable"`
	Note                string     `json:"note,omitempty"`
	PreviousGeneratedAt *time.Time `json:"previous_generated_at,omitempty"`
	Added               []string   `json:"added"`
	Resolved            []string   `json:"resolved"`
	PriorityChanged     []Change   `json:"priority_changed"`
	DeadlineChanged     []Change   `json:"deadline_changed"`
	PlanChanged         []Change   `json:"plan_changed"`
}

// Report is the cryptographic risk report.
type Report struct {
	Format      string    `json:"format"`
	TenantID    string    `json:"tenant_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Sources     []string  `json:"sources"`
	Coverage    string    `json:"coverage"`
	CNSA20      string    `json:"cnsa_2_0"`
	Summary     Summary   `json:"summary"`
	Items       []Item    `json:"items"`
	// Truncated says more keys qualified than the report lists (Limit).
	Truncated bool `json:"truncated,omitempty"`
	// InputLimit says the inputs were read only in part, and which.
	InputLimit string  `json:"input_limit,omitempty"`
	Changes    Changes `json:"changes"`
}

// Asset is a crypto inventory asset's recorded detail, which the graph node does
// not carry.
type Asset struct {
	ID                     string
	Kind                   string
	Location               string
	Algorithm              string
	KeyBits                int
	Strength               string
	QuantumVulnerable      bool
	OutOfPolicy            bool
	Reasons                []string
	CertificateFingerprint string
}

// Certificate is one rated certificate.
type Certificate struct {
	ID          string
	Subject     string
	Issuer      string
	Serial      string
	Fingerprint string
	Algorithm   string
	KeyBits     int
	WeakReasons []string
	Distrust    *Distrust
	Dependents  Dependents
}

// Inputs is what Build joins.
type Inputs struct {
	TenantID     string
	Now          time.Time
	Readiness    cryptoreadiness.Dataset
	Assets       []Asset
	Certificates []Certificate
	// Previous is the previous period's report, when one was read and verified.
	Previous *Report
	// PreviousNote says why no previous report is compared, when Previous is nil.
	PreviousNote string
	// Limit bounds the listed items; 0 lists every one.
	Limit int
	// InputLimit says which inputs were read only in part.
	InputLimit string
}

// recommendedPlan is the next step for a crypto asset nothing addresses yet;
// certificatePlan for a certificate.
const (
	recommendedPlan = "start a crypto-readiness action for this asset, or a PQC migration plan, and assign its owner"
	certificatePlan = "replace the certificate: renew it through its lifecycle identity (claim it as a managed identity first if it has none), or plan its re-issue"
)

// Build makes the report.
func Build(in Inputs) Report {
	r := Report{
		Format: Format, TenantID: in.TenantID, GeneratedAt: in.Now.UTC(),
		Sources: []string{IR8547Source}, Coverage: Coverage, CNSA20: CNSA20Note, Items: []Item{},
		InputLimit: in.InputLimit,
	}
	readiness := map[string]cryptoreadiness.Item{}
	for _, it := range in.Readiness.Items {
		readiness[it.Asset.ID] = it
	}
	certByFingerprint := map[string]int{}
	var items []Item
	for _, c := range in.Certificates {
		item, ok := certificateItem(c, in.Now)
		if !ok {
			continue
		}
		if fp := strings.ToLower(c.Fingerprint); fp != "" {
			certByFingerprint[fp] = len(items)
		}
		items = append(items, item)
	}
	for _, a := range in.Assets {
		row, hasRow := readiness["crypto:"+a.ID]
		// A certificate's own key asset joins its certificate item: one key, one row.
		if idx, ok := certByFingerprint[strings.ToLower(a.CertificateFingerprint)]; ok && a.CertificateFingerprint != "" {
			joinAsset(&items[idx], a, row, hasRow)
			continue
		}
		item, ok := assetItem(a, row, hasRow, in.Now)
		if ok {
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return lessPriority(items[i], items[j]) })
	for i := range items {
		items[i].Priority, items[i].PriorityReason = i+1, rankReasonOf(items[i])
		r.Summary.add(items[i])
	}
	r.Changes = changes(items, in.Previous, in.PreviousNote)
	if in.Limit > 0 && len(items) > in.Limit {
		items, r.Truncated = items[:in.Limit], true
	}
	r.Items = items
	return r
}

func certificateItem(c Certificate, now time.Time) (Item, bool) {
	weak := len(c.WeakReasons) > 0
	deadline := DeadlineFor(c.Algorithm, c.KeyBits, weak || c.Distrust != nil, now)
	exposures := []string{}
	if c.Distrust != nil {
		exposures = append(exposures, ExposureDistrusted)
	}
	if weak {
		exposures = append(exposures, ExposureWeak)
	}
	if deadline.DisallowedAfter != 0 || (deadline.Status == DeadlineReplaceNow && keyFamily(c.Algorithm) != "unknown" && keyFamily(c.Algorithm) != "post_quantum" && keyFamily(c.Algorithm) != "symmetric") {
		exposures = append(exposures, ExposureQuantumVulnerable)
	}
	if len(exposures) == 0 {
		return Item{}, false
	}
	reasons := append([]string(nil), c.WeakReasons...)
	if c.Distrust != nil {
		reasons = append(reasons, fmt.Sprintf("on the distrust list: %s (matched by %s)", c.Distrust.Entry, c.Distrust.How))
		deadline.Rule = "distrusted: replace now"
	}
	return Item{
		Key: "certificate:" + c.ID, Kind: "certificate", Subject: c.Subject, Algorithm: c.Algorithm, KeyBits: c.KeyBits,
		Exposures: exposures, Reasons: reasons, Distrust: c.Distrust, Dependents: normDependents(c.Dependents),
		Owners: []string{}, Deadline: deadline, Plan: Plan{Actions: []PlanAction{}, Recommended: certificatePlan},
		EvidenceIDs: evidence("certificate:"+c.ID, fingerprintRef(c.Fingerprint)),
	}, true
}

func assetItem(a Asset, row cryptoreadiness.Item, hasRow bool, now time.Time) (Item, bool) {
	weak := a.Strength == "weak"
	deadline := DeadlineFor(a.Algorithm, a.KeyBits, weak, now)
	exposures := []string{}
	if weak {
		exposures = append(exposures, ExposureWeak)
	}
	if a.QuantumVulnerable {
		exposures = append(exposures, ExposureQuantumVulnerable)
	}
	if a.OutOfPolicy {
		exposures = append(exposures, ExposureOutOfPolicy)
	}
	if len(exposures) == 0 {
		return Item{}, false
	}
	item := Item{
		Key: "crypto:" + a.ID, Kind: "crypto_asset", Subject: firstNonEmpty(a.Location, a.Kind), Algorithm: a.Algorithm, KeyBits: a.KeyBits,
		Exposures: exposures, Reasons: append([]string(nil), a.Reasons...), Owners: []string{},
		Deadline: deadline, Plan: Plan{Actions: []PlanAction{}}, EvidenceIDs: evidence("crypto_asset:" + a.ID),
	}
	item.Dependents, item.Owners, item.Plan = readinessParts(row, hasRow)
	return item, true
}

// joinAsset folds a certificate's own key asset into the certificate's item:
// the asset's readiness dependents, owners and plan, and its exposures.
func joinAsset(item *Item, a Asset, row cryptoreadiness.Item, hasRow bool) {
	deps, owners, plan := readinessParts(row, hasRow)
	if deps.Count > item.Dependents.Count {
		item.Dependents = deps
	}
	item.Owners = owners
	if len(plan.Actions) > 0 {
		item.Plan = plan
	}
	if a.OutOfPolicy && !contains(item.Exposures, ExposureOutOfPolicy) {
		item.Exposures = append(item.Exposures, ExposureOutOfPolicy)
	}
	item.EvidenceIDs = evidence(append(item.EvidenceIDs, "crypto_asset:"+a.ID)...)
}

func readinessParts(row cryptoreadiness.Item, hasRow bool) (Dependents, []string, Plan) {
	deps := Dependents{ByKind: map[string]int{}, Names: []string{}, Source: "crypto_readiness"}
	plan := Plan{Actions: []PlanAction{}}
	owners := []string{}
	if !hasRow {
		plan.Recommended = recommendedPlan
		return deps, owners, plan
	}
	for _, d := range row.Dependents {
		deps.Count++
		deps.ByKind[string(d.Node.Kind)]++
		if len(deps.Names) < 10 {
			deps.Names = append(deps.Names, firstNonEmpty(d.Node.Name, d.Node.ID))
		}
	}
	owners = append(owners, row.Owners...)
	for _, a := range row.Actions {
		plan.Actions = append(plan.Actions, PlanAction{
			CampaignID: a.CampaignID, Name: a.Name, Status: a.Status, Wave: a.Wave, Deadline: a.Deadline, Stale: a.Stale,
		})
	}
	if len(plan.Actions) == 0 {
		plan.Recommended = recommendedPlan
	}
	return deps, owners, plan
}

func normDependents(d Dependents) Dependents {
	if d.ByKind == nil {
		d.ByKind = map[string]int{}
	}
	if d.Names == nil {
		d.Names = []string{}
	}
	if d.Source == "" {
		d.Source = "blast_radius"
	}
	return d
}

// rank orders exposures: a distrusted key first, then a weak one, then by how
// soon its deadline falls.
func rank(it Item) int {
	switch {
	case contains(it.Exposures, ExposureDistrusted):
		return 0
	case contains(it.Exposures, ExposureWeak):
		return 1
	case it.Deadline.Status == DeadlineReplaceNow:
		return 2
	case it.Deadline.Status == DeadlineDeprecated:
		return 3
	case it.Deadline.DeprecatedAfter != 0:
		return 4
	case it.Deadline.DisallowedAfter != 0:
		return 5
	default:
		return 6
	}
}

var rankReason = []string{
	"distrusted: browsers and clients refuse it",
	"weak key: replace now",
	"past or outside its IR 8547 deadline: replace now",
	"deprecated under IR 8547: disallowed after 2035",
	"112-bit strength: deprecated after 2030",
	"quantum-vulnerable: disallowed after 2035",
	"out of policy",
}

func lessPriority(a, b Item) bool {
	if rank(a) != rank(b) {
		return rank(a) < rank(b)
	}
	if a.Dependents.Count != b.Dependents.Count {
		return a.Dependents.Count > b.Dependents.Count
	}
	return a.Key < b.Key
}

func (s *Summary) add(it Item) {
	s.Items++
	if contains(it.Exposures, ExposureDistrusted) {
		s.Distrusted++
	}
	if contains(it.Exposures, ExposureWeak) {
		s.Weak++
	}
	if contains(it.Exposures, ExposureQuantumVulnerable) {
		s.QuantumVulnerable++
	}
	switch it.Deadline.Status {
	case DeadlineReplaceNow:
		s.ReplaceNow++
	case DeadlineDeprecated:
		s.Deprecated++
	case DeadlineUpcoming:
		s.Upcoming++
	}
	if len(it.Plan.Actions) > 0 {
		s.WithPlan++
	} else {
		s.WithoutPlan++
	}
}

// changes compares every qualifying item, listed or not, with the previous
// report's listed items.
func changes(items []Item, previous *Report, note string) Changes {
	c := Changes{Added: []string{}, Resolved: []string{}, PriorityChanged: []Change{}, DeadlineChanged: []Change{}, PlanChanged: []Change{}}
	if previous == nil {
		c.Note = firstNonEmpty(note, "no previous report to compare with")
		return c
	}
	c.Comparable = true
	at := previous.GeneratedAt
	c.PreviousGeneratedAt = &at
	if previous.Truncated {
		c.Note = "the previous report listed only its first items; keys beyond them are compared as added"
	}
	before := map[string]Item{}
	for _, it := range previous.Items {
		before[it.Key] = it
	}
	now := map[string]bool{}
	for _, it := range items {
		now[it.Key] = true
		old, ok := before[it.Key]
		if !ok {
			c.Added = append(c.Added, it.Key)
			continue
		}
		if rankReasonOf(old) != rankReasonOf(it) {
			c.PriorityChanged = append(c.PriorityChanged, Change{Key: it.Key, From: rankReasonOf(old), To: rankReasonOf(it)})
		}
		if old.Deadline.Status != it.Deadline.Status || old.Deadline.Rule != it.Deadline.Rule {
			c.DeadlineChanged = append(c.DeadlineChanged, Change{Key: it.Key, From: old.Deadline.Status + ": " + old.Deadline.Rule, To: it.Deadline.Status + ": " + it.Deadline.Rule})
		}
		if planState(old) != planState(it) {
			c.PlanChanged = append(c.PlanChanged, Change{Key: it.Key, From: planState(old), To: planState(it)})
		}
	}
	for _, it := range previous.Items {
		if !now[it.Key] {
			c.Resolved = append(c.Resolved, it.Key)
		}
	}
	sort.Strings(c.Added)
	sort.Strings(c.Resolved)
	return c
}

func rankReasonOf(it Item) string { return rankReason[rank(it)] }

func planState(it Item) string {
	if len(it.Plan.Actions) == 0 {
		return "no plan"
	}
	parts := make([]string, 0, len(it.Plan.Actions))
	for _, a := range it.Plan.Actions {
		parts = append(parts, a.CampaignID+"="+a.Status)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func fingerprintRef(fp string) string {
	if strings.TrimSpace(fp) == "" {
		return ""
	}
	return "fingerprint:" + strings.ToLower(fp)
}

func evidence(ids ...string) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
