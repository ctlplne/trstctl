// SPDX-License-Identifier: BUSL-1.1

// Package editionledger builds the product, edition and qualification ledger
// (A253) from the license table (internal/license) and the feature map
// (internal/featureparity). Every edition and qualification statement in the
// docs resolves to it: docs/editions-ledger.json and docs/editions-ledger.md
// are rendered here, and so are the marked blocks in README.md and
// docs/editions.md; the docs guard fails when any of them drifts.
package editionledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/featureparity"
	"trstctl.com/trstctl/internal/license"
)

// Format names this ledger's shape.
const Format = "trstctl.edition-ledger.v1"

// Ledger is the generated truth about what each edition contains and what
// the product has qualified.
type Ledger struct {
	Format        string        `json:"format"`
	Product       Product       `json:"product"`
	Editions      []Edition     `json:"editions"`
	Features      []FeatureRow  `json:"features"`
	CoreFamilies  []string      `json:"core_families"`
	Qualification Qualification `json:"qualification"`
}

// Product is the licensing shape every edition shares.
type Product struct {
	Name               string `json:"name"`
	CoreLicense        string `json:"core_license"`
	CoreConversion     string `json:"core_conversion"`
	ClientsLicense     string `json:"clients_license"`
	CommercialMaterial string `json:"commercial_material"`
	Activation         string `json:"activation"`
	FIPS               string `json:"fips"`
}

// Edition is one tier: its features (inherited ones included), use rights
// and deployment entitlement.
type Edition struct {
	Tier         string   `json:"tier"`
	Name         string   `json:"name"`
	Features     []string `json:"features"`
	Rights       []string `json:"rights"`
	Environments string   `json:"environments"`
}

// FeatureRow is one license-table feature and the editions that carry it.
type FeatureRow struct {
	Feature  string   `json:"feature"`
	Name     string   `json:"name"`
	Tier     string   `json:"tier"`
	Editions []string `json:"editions"`
}

// Qualification is the feature map's served state, row by row.
type Qualification struct {
	Rows          int                 `json:"rows"`
	ByServedState map[string]int      `json:"by_served_state"`
	Items         []QualificationItem `json:"items"`
}

// QualificationItem is one feature map row's state.
type QualificationItem struct {
	FeatureID   string `json:"feature_id"`
	Feature     string `json:"feature"`
	ServedState string `json:"served_state"`
}

// Build assembles the ledger.
func Build() (Ledger, error) {
	catalog, err := featureparity.LoadEmbedded()
	if err != nil {
		return Ledger{}, err
	}
	l := Ledger{
		Format: Format,
		Product: Product{
			Name: "trstctl", CoreLicense: "BUSL-1.1", CoreConversion: "MPL-2.0, four years after each release",
			ClientsLicense: "MPL-2.0", CommercialMaterial: "ee/ (proprietary, ee/LICENSE)",
			Activation: "an offline Ed25519-signed license", FIPS: "artifact-gated (make fips-build), never a runtime license gate",
		},
		CoreFamilies:  license.CoreFamilies(),
		Qualification: Qualification{ByServedState: map[string]int{}},
	}
	for _, tier := range license.Tiers() {
		e := Edition{Tier: string(tier), Name: license.TierDisplay(tier), Features: []string{}, Rights: []string{}}
		for _, f := range license.EffectiveTierFeatures(tier) {
			e.Features = append(e.Features, license.FeatureDisplay(f))
		}
		for _, r := range license.TierRights(tier) {
			e.Rights = append(e.Rights, license.RightDisplay(r))
		}
		e.Environments = "unmetered"
		if tier != license.TierCommunity {
			e.Environments = fmt.Sprintf("1 production + %d signed non-production deployment slots", license.BundledNonProductionDeployments)
		}
		l.Editions = append(l.Editions, e)
	}
	for _, f := range license.AllFeatures() {
		row := FeatureRow{Feature: string(f), Name: license.FeatureDisplay(f), Tier: string(license.FeatureTier(f)), Editions: []string{}}
		for _, tier := range license.Tiers() {
			for _, have := range license.EffectiveTierFeatures(tier) {
				if have == f {
					row.Editions = append(row.Editions, license.TierDisplay(tier))
				}
			}
		}
		l.Features = append(l.Features, row)
	}
	for _, item := range catalog.Items {
		l.Qualification.Items = append(l.Qualification.Items, QualificationItem{
			FeatureID: item.FeatureID, Feature: item.Feature, ServedState: item.ServedState,
		})
		l.Qualification.ByServedState[item.ServedState]++
	}
	sort.Slice(l.Qualification.Items, func(i, j int) bool {
		return featureOrder(l.Qualification.Items[i].FeatureID) < featureOrder(l.Qualification.Items[j].FeatureID)
	})
	l.Qualification.Rows = len(l.Qualification.Items)
	return l, nil
}

func featureOrder(id string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(id, "F"))
	if err != nil {
		return 1 << 30
	}
	return n
}

// JSON is docs/editions-ledger.json.
func (l Ledger) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func (l Ledger) edition(tier license.Tier) Edition {
	byTier := make(map[string]Edition, len(l.Editions))
	for _, e := range l.Editions {
		byTier[e.Tier] = e
	}
	return byTier[string(tier)]
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// rights is the plain-language account of what each edition lets you do.
func (l Ledger) rights() string {
	var b strings.Builder
	free, ent, prov := l.edition(license.TierCommunity), l.edition(license.TierEnterprise), l.edition(license.TierProvider)
	fmt.Fprintf(&b, "- **%s.** Run the core in production for yourself: the Business Source License's Additional Use Grant permits it, "+
		"no signed license is needed, and deployments are %s. Each release becomes MPL-2.0 four years after it is published.\n", free.Name, free.Environments)
	fmt.Fprintf(&b, "- **%s.** Adds %s, activated by %s. You %s; the license covers %s.\n",
		ent.Name, joinAnd(ent.Features), l.Product.Activation, joinAnd(ent.Rights), ent.Environments)
	fmt.Fprintf(&b, "- **%s.** Everything in %s, plus %s, and the rights to %s for your customers. "+
		"The license covers %s per Provider control plane.\n",
		prov.Name, ent.Name, joinAnd(prov.Features[len(ent.Features):]), joinAnd(prov.Rights[1:]), prov.Environments)
	fmt.Fprintf(&b, "- **In every edition.** %s attach in every build and take no license gate; multi-tenancy, the crypto boundary, "+
		"audit and export, and the offline license verifier stay in the core. FIPS is %s.\n", joinAnd(l.CoreFamilies), l.Product.FIPS)
	return b.String()
}

// Markdown is docs/editions-ledger.md.
func (l Ledger) Markdown() string {
	var b strings.Builder
	b.WriteString("# Edition and qualification ledger\n\n")
	b.WriteString("<!-- Generated by `go run ./tools/editionledger` from internal/license and the feature map. Do not edit by hand. -->\n\n")
	fmt.Fprintf(&b, "trstctl's core is source-available under %s (it converts to %s); the client libraries under `clients/` are %s; "+
		"commercial Enterprise and Provider features are %s, activated by %s.\n\n",
		l.Product.CoreLicense, l.Product.CoreConversion, l.Product.ClientsLicense, l.Product.CommercialMaterial, l.Product.Activation)
	b.WriteString("## What each edition lets you do\n\n")
	b.WriteString(l.rights())
	b.WriteString("\n## Editions\n\n| Edition | Features | Use rights | Deployments |\n|---|---|---|---|\n")
	for _, e := range l.Editions {
		features := "the core"
		if len(e.Features) > 0 {
			features = "the core, plus " + strings.Join(e.Features, ", ")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", e.Name, features, strings.Join(e.Rights, ", "), e.Environments)
	}
	b.WriteString("\n## Licensed features\n\n| Feature | Name | Granted by | Editions |\n|---|---|---|---|\n")
	for _, f := range l.Features {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", f.Feature, f.Name, license.TierDisplay(license.Tier(f.Tier)), strings.Join(f.Editions, ", "))
	}
	fmt.Fprintf(&b, "\n## Qualification\n\n%d feature map rows. ", l.Qualification.Rows)
	b.WriteString("By served state: " + countList(l.Qualification.ByServedState) + ". A row's detail, evidence and limits are in " +
		"[current limitations](limitations.md) and its feature page.\n\n")
	b.WriteString("| Row | Feature | Served state |\n|---|---|---|\n")
	for _, item := range l.Qualification.Items {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", item.FeatureID, strings.ReplaceAll(item.Feature, "|", "/"), item.ServedState)
	}
	return b.String()
}

func countList(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		name := k
		if name == "" {
			name = "unset"
		}
		parts = append(parts, fmt.Sprintf("%s %d", name, m[k]))
	}
	return strings.Join(parts, ", ")
}

// buyerMatrix is docs/editions.md's buyer matrix. Its edition cells come from
// the license table; the other rows are the product's packaging lines.
func (l Ledger) buyerMatrix() string {
	free, ent, prov := l.edition(license.TierCommunity), l.edition(license.TierEnterprise), l.edition(license.TierProvider)
	rows := [][4]string{
		{"Buyer", "Organization operating trstctl for itself", "Organization needing the commercial feature set", "MSP operating or reselling trstctl-backed services to customers"},
		{"Primary billing unit", "None", "Per control-plane deployment", "Negotiated managed-customer band"},
		{"Core protocols", "ACME, EST, SCEP, CMP, SPIFFE, SSH CA, TSA", "Included", "Included"},
		{"Tenant isolation", "PostgreSQL RLS and event spine", "Included", "Included; shared multi-tenant control plane is the normal shape"},
		{"Patent-pending families and PQC", "Included: PCAS, agent delegation, reconciliation, VDEC, and post-quantum cryptography attach in every build", "Included", "Included"},
		{"Remediation", "Incident response and guided remediation, subject to authorization and configured targets", "Included", "Included"},
		{"Enterprise features", "Not included", upperFirst(joinAnd(ent.Features)), "All Enterprise features"},
		{"Provider operations", "Not included", "Not included", upperFirst(joinAnd(prov.Features[len(ent.Features):]))},
		{"Product motion and commercial `ee/` rights", "Self-hosted core under BUSL-1.1", "Self-hosted commercial feature set", "Self-host, managed service, and resale of the commercial feature set"},
		{"Deployment flexibility", "Customer operated", "Customer operated", "Shared control plane or dedicated customer deployments"},
		{"Commercial terms", "No license fee", "Not yet published", "Not yet published"},
		{"Environment entitlement", free.Name + " deployments are unmetered", upperFirst(ent.Environments), "Same bundle per licensed Provider control plane"},
	}
	var b strings.Builder
	b.WriteString("| Packaging line | Free | Enterprise | Provider / MSP |\n|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r[0], r[1], r[2], r[3])
	}
	return strings.TrimRight(b.String(), "\n")
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Blocks are the generated passages other pages carry between
// <!-- edition-ledger:begin NAME --> and <!-- edition-ledger:end NAME -->.
func (l Ledger) Blocks() map[string]string {
	ent, prov := l.edition(license.TierEnterprise), l.edition(license.TierProvider)
	return map[string]string{
		"readme-editions": fmt.Sprintf("Enterprise adds %s. Provider / MSP adds %s on top of every Enterprise feature, with the rights to %s. "+
			"See the [edition and qualification ledger](docs/editions-ledger.md).", joinAnd(ent.Features),
			joinAnd(prov.Features[len(ent.Features):]), joinAnd(prov.Rights[1:])),
		"editions-rights":       strings.TrimRight(l.rights(), "\n"),
		"editions-buyer-matrix": l.buyerMatrix(),
	}
}

// ReplaceBlocks rewrites every marked block in page; it fails on an unknown or
// unterminated block.
func ReplaceBlocks(page []byte, blocks map[string]string) ([]byte, error) {
	var out bytes.Buffer
	rest := page
	for {
		i := bytes.Index(rest, []byte("<!-- edition-ledger:begin "))
		if i < 0 {
			out.Write(rest)
			return out.Bytes(), nil
		}
		headerEnd := bytes.Index(rest[i:], []byte("-->"))
		if headerEnd < 0 {
			return nil, fmt.Errorf("editionledger: unterminated block marker")
		}
		name := strings.TrimSpace(string(rest[i+len("<!-- edition-ledger:begin ") : i+headerEnd]))
		body, ok := blocks[name]
		if !ok {
			return nil, fmt.Errorf("editionledger: unknown block %q", name)
		}
		endMarker := []byte("<!-- edition-ledger:end " + name + " -->")
		j := bytes.Index(rest[i:], endMarker)
		if j < 0 {
			return nil, fmt.Errorf("editionledger: block %q has no end marker", name)
		}
		out.Write(rest[:i+headerEnd+3])
		out.WriteString("\n" + body + "\n")
		out.Write(endMarker)
		rest = rest[i+j+len(endMarker):]
	}
}
