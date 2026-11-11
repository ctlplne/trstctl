// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LIC-1 (owner note 2026-11-11): the core license's grant was tightened. These
// guards hold the result: the Business Source License's own text stays SPDX's
// word for word, both LICENSE copies are one file, every summary of the grant
// uses the same words, the old carve-out is gone from the repository, the
// license FAQ is published, and the contribution and security contacts agree.

// spdxBUSL11 is SPDX's canonical BUSL-1.1 text (license-list-data): the
// license's title, copyright line, Terms and Covenants of Licensor. Only the
// parameters above it (the Additional Use Grant, Change Date and Change
// License) are the Licensor's to write; Covenant 4 forbids modifying the rest.
const spdxBUSL11 = `Business Source License 1.1

License text copyright © 2017 MariaDB Corporation Ab, All Rights Reserved.
"Business Source License" is a trademark of MariaDB Corporation Ab.

Terms

The Licensor hereby grants you the right to copy, modify, create derivative
works, redistribute, and make non-production use of the Licensed Work. The
Licensor may make an Additional Use Grant, above, permitting limited
production use.

Effective on the Change Date, or the fourth anniversary of the first publicly
available distribution of a specific version of the Licensed Work under this
License, whichever comes first, the Licensor hereby grants you rights under
the terms of the Change License, and the rights granted in the paragraph
above terminate.

If your use of the Licensed Work does not comply with the requirements
currently in effect as described in this License, you must purchase a
commercial license from the Licensor, its affiliated entities, or authorized
resellers, or you must refrain from using the Licensed Work.

All copies of the original and modified Licensed Work, and derivative works
of the Licensed Work, are subject to this License. This License applies
separately for each version of the Licensed Work and the Change Date may vary
for each version of the Licensed Work released by Licensor.

You must conspicuously display this License on each original or modified copy
of the Licensed Work. If you receive the Licensed Work in original or
modified form from a third party, the terms and conditions set forth in this
License apply to your use of that work.

Any use of the Licensed Work in violation of this License will automatically
terminate your rights under this License for the current and all other
versions of the Licensed Work.

This License does not grant you any right in any trademark or logo of
Licensor or its affiliates (provided that you may use a trademark or logo of
Licensor as expressly required by this License).

TO THE EXTENT PERMITTED BY APPLICABLE LAW, THE LICENSED WORK IS PROVIDED ON
AN “AS IS” BASIS. LICENSOR HEREBY DISCLAIMS ALL WARRANTIES AND CONDITIONS,
EXPRESS OR IMPLIED, INCLUDING (WITHOUT LIMITATION) WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND
TITLE.

MariaDB hereby grants you permission to use this License’s text to license
your works, and to refer to it using the trademark “Business Source License”,
as long as you comply with the Covenants of Licensor below.

Covenants of Licensor

In consideration of the right to use this License’s text and the “Business
Source License” name and trademark, Licensor covenants to MariaDB, and to all
other recipients of the licensed work to be provided by Licensor:

1. To specify as the Change License the GPL Version 2.0 or any later version,
   or a license that is compatible with GPL Version 2.0 or a later version,
   where “compatible” means that software provided under the Change License can
   be included in a program with software provided under GPL Version 2.0 or a
   later version. Licensor may specify additional Change Licenses without
   limitation.

2. To either: (a) specify an additional grant of rights to use that does not
   impose any additional restriction on the right granted in this License, as
   the Additional Use Grant; or (b) insert the text “None”.

3. To specify a Change Date.

4. Not to modify this License in any other way.`

// licenseWords collapses whitespace and straightens quotes, so re-wrapping or
// a quote style cannot fake a difference and a changed word cannot hide.
func licenseWords(s string) []string {
	s = strings.NewReplacer("\u201c", `"`, "\u201d", `"`, "\u2018", "'", "\u2019", "'").Replace(s)
	return strings.Fields(s)
}

func bslBody(t *testing.T, path string) string {
	t.Helper()
	body := read(t, path)
	start := strings.Index(body, "Business Source License 1.1\n\nLicense text copyright")
	const last = "4. Not to modify this License in any other way."
	end := strings.Index(body, last)
	if start < 0 || end < start {
		t.Fatalf("%s has no Business Source License body from its title to Covenant 4", path)
	}
	return body[start : end+len(last)]
}

func TestLicenseBSLTermsAndCovenantsAreTheSPDXTextLIC1(t *testing.T) {
	want := licenseWords(spdxBUSL11)
	for _, path := range []string{"../LICENSE", "../deploy/splunk/trstctl/LICENSE"} {
		got := licenseWords(bslBody(t, path))
		for i := 0; i < len(got) || i < len(want); i++ {
			if i >= len(got) || i >= len(want) || got[i] != want[i] {
				context := func(words []string) string {
					return strings.Join(words[max(0, i-6):min(len(words), i+6)], " ")
				}
				t.Errorf("%s: the Business Source License text differs from SPDX's BUSL-1.1 at word %d:\n  LICENSE: …%s…\n  SPDX:    …%s…\n"+
					"only the Additional Use Grant, Change Date and Change License are ours to write (Covenant 4)", path, i, context(got), context(want))
				break
			}
		}
	}
	if read(t, "../LICENSE") != read(t, "../deploy/splunk/trstctl/LICENSE") {
		t.Error("deploy/splunk/trstctl/LICENSE is not a byte copy of LICENSE; the Splunk app ships the core license as it is")
	}
}

// The grant in LICENSE, and the one sentence every summary of it uses.
const coreGrantSummary = "Run the core in production for your organization, its affiliates, and its employees and staff contractors: " +
	"the Business Source License's Additional Use Grant permits it, no signed license is needed, and deployments are unmetered. " +
	"A provider may do one-off setup work in a customer's own deployment; running trstctl for others as a hosted or managed " +
	"service needs a Provider license. Keep the trstctl name and attribution visible."

func TestCoreGrantIsTheTightenedGrantEverywhereLIC1(t *testing.T) {
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	license := flat(read(t, "../LICENSE"))
	for _, want := range []string{
		`"Hosted Service" means`, `"Managed Service" means`, `"Project Services" means`, `"Customer Infrastructure" means`,
		`"Affiliate" means`, `"Competing Product" means`, "Powered by trstctl", "A version published earlier keeps the grant it was published with.",
		"contact certctl LLC at licensing@trstctl.com",
	} {
		if !strings.Contains(license, want) {
			t.Errorf("LICENSE does not carry the tightened grant: missing %q", want)
		}
	}
	for _, path := range []string{"../README.md", "../CONTRIBUTING.md", "editions.md", "editions-ledger.md"} {
		if !strings.Contains(flat(read(t, path)), coreGrantSummary) {
			t.Errorf("%s does not summarize the core grant in the agreed words:\n%s", path, coreGrantSummary)
		}
	}
	// The old carve-out let a provider run the free core as a customer's
	// service provider; nothing in the repository may still say so.
	oldGrant := []string{
		"as that customer's service provider",
		"operating the licensed work on a customer's own deployment",
		"run the core in production for yourself",
	}
	// Root-scoped: the walk cannot follow a link out of the repository.
	root, err := os.OpenRoot("..")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	repo := root.FS()
	err = fs.WalkDir(repo, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch d.Name() {
		case ".git", "node_modules", "dist", ".site", "bin":
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 || path == "docs/license_grant_test.go" {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".md", ".go", ".ts", ".tsx", ".txt", ".yml", ".yaml", ".json", ".html", ".py", ".sh", "":
		default:
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 8<<20 {
			return err
		}
		raw, err := fs.ReadFile(repo, path)
		if err != nil {
			return err
		}
		text := strings.ToLower(flat(string(raw)))
		for _, phrase := range oldGrant {
			if strings.Contains(text, phrase) {
				t.Errorf("%s still states the old core grant (%q)", path, phrase)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLicenseFAQIsPublishedAndLinkedLIC1(t *testing.T) {
	if _, err := os.Stat("license-faq.md"); err != nil {
		t.Fatalf("docs/license-faq.md is missing: %v", err)
	}
	nav := read(t, "../mkdocs.yml")
	if !strings.Contains(nav, "      - Editions: editions.md\n      - License FAQ: license-faq.md\n") {
		t.Error("mkdocs.yml must list License FAQ under Start here, right after Editions")
	}
	for _, path := range []string{"../README.md", "editions.md"} {
		if !strings.Contains(read(t, path), "license-faq.md)") {
			t.Errorf("%s does not link the License FAQ", path)
		}
	}
}

// README, CONTRIBUTING.md and NOTICE say one thing about contributions: none
// are accepted now; issues and security reports are welcome.
func TestReadmeAgreesWithContributingOnContributionsLIC1(t *testing.T) {
	flat := func(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }
	readme, contributing, notice := flat(read(t, "../README.md")), flat(read(t, "../CONTRIBUTING.md")), flat(read(t, "../NOTICE"))
	for path, body := range map[string]string{"README.md": readme, "CONTRIBUTING.md": contributing, "NOTICE": notice} {
		if !strings.Contains(body, "not accepting contributions") {
			t.Errorf("%s does not say the project is not accepting contributions", path)
		}
		if !strings.Contains(body, "issue") || (!strings.Contains(body, "security reports") && !strings.Contains(body, "security.md")) {
			t.Errorf("%s does not welcome issues and security reports (or point them to SECURITY.md)", path)
		}
	}
	for _, workflow := range []string{"git commit -s", "developer certificate of origin", "signed cla", "requires a signed"} {
		if strings.Contains(readme, workflow) {
			t.Errorf("README.md still advertises a contribution workflow (%q) that CONTRIBUTING.md and NOTICE say does not exist", workflow)
		}
	}
}

func TestSecurityReportsGoToTheProjectMailboxLIC1(t *testing.T) {
	for _, path := range []string{"../SECURITY.md", "security/reporting.md"} {
		body := read(t, path)
		if !strings.Contains(body, "security@trstctl.com") {
			t.Errorf("%s does not name security@trstctl.com", path)
		}
		if strings.Contains(strings.ToLower(body), "@gmail.com") {
			t.Errorf("%s still lists a personal email address for security reports", path)
		}
	}
}
