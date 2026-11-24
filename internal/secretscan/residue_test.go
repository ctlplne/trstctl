// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// P6-L5: a later look at a moved value's history finds every commit that
// still holds it on any branch, and none once a history rewrite has removed
// them; a value the history never held has no residue, and a directory with
// no history is ErrNoHistory, not "no residue".
func TestHistoryResidueOfFollowsAHistoryRewriteP6L5(t *testing.T) {
	bin := p6Gitleaks(t)
	repo, git := p6Repo(t, map[string]string{"app.env": "APP=payments\nSLACK_TOKEN=" + p6Token + "\n"})
	git("add", "app.env")
	git("commit", "-q", "-m", "config")
	leak := git("rev-parse", "HEAD")
	git("checkout", "-q", "-b", "feature")
	if err := os.WriteFile(filepath.Join(repo, "copy.env"), []byte("TOKEN="+p6Token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "copy.env")
	git("commit", "-q", "-m", "copy")
	branchLeak := git("rev-parse", "HEAD")
	git("checkout", "-q", "main")

	runner := NewGitleaksRunner(bin)
	runner.AllowedRoots = []string{t.TempDir()} // the operator's roots need not cover it
	other := []byte(strings.Join([]string{"xoxb", "999999999999", "999999999999", "zyxwvutsrqponmlkjihgfedc"}, "-"))
	residue, err := runner.HistoryResidueOf(t.Context(), repo, [][]byte{[]byte(p6Token), other})
	if err != nil {
		t.Fatal(err)
	}
	commits := map[string]bool{}
	for _, loc := range residue[0] {
		commits[loc.Commit] = true
		if loc.RuleID == "" || loc.File == "" || loc.Line < 1 {
			t.Fatalf("residue location = %+v", loc)
		}
	}
	if !commits[leak] || !commits[branchLeak] || len(residue[1]) != 0 {
		t.Fatalf("residue = %+v, want the leak commit on main and the one on feature, and nothing for the other value", residue)
	}

	// Rewrite: main starts again without the token and feature is deleted.
	git("checkout", "-q", "--orphan", "rewritten")
	git("rm", "-q", "-f", "app.env")
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("APP=payments\nSLACK_TOKEN=${secret.slack}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "app.env")
	git("commit", "-q", "-m", "config without the token")
	git("branch", "-D", "main", "feature")
	git("branch", "-m", "main")
	residue, err = runner.HistoryResidueOf(t.Context(), repo, [][]byte{[]byte(p6Token)})
	if err != nil || len(residue[0]) != 0 {
		t.Fatalf("after the rewrite residue = %+v, %v; want none", residue, err)
	}
	if _, err := runner.HistoryResidueOf(t.Context(), t.TempDir(), [][]byte{[]byte(p6Token)}); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("a directory with no history: %v", err)
	}
}

// P6-L5: a shallow single-branch clone is deepened to every branch's full
// history, so the re-check sees what the clone alone could not.
func TestDeepenCloneFetchesEveryBranchsHistoryP6L5(t *testing.T) {
	origin, git := p6Repo(t, map[string]string{"a.txt": "one\n"})
	git("add", "a.txt")
	git("commit", "-q", "-m", "one")
	first := git("rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(origin, "a.txt"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("commit", "-q", "-am", "two")
	git("branch", "side", first)
	clone := filepath.Join(t.TempDir(), "clone")
	if out, err := exec.Command("git", "clone", "-q", "--no-tags", "--depth", "1", "--branch", "main", "--", "file://"+origin, clone).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("shallow clone: %v %s", err, out)
	}
	at := func(args ...string) string {
		out, _ := exec.Command("git", append([]string{"-C", clone}, args...)...).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		return strings.TrimSpace(string(out))
	}
	if at("rev-parse", "--is-shallow-repository") != "true" {
		t.Fatal("the clone is not shallow to begin with")
	}
	// Serve the same history through the local Git smart-HTTPS backend. The
	// production fetch refuses file://; this fixture explicitly grants only
	// its own loopback /32 and still exercises a real Git history fetch.
	hosted := filepath.Join(t.TempDir(), "hosted")
	if err := os.MkdirAll(hosted, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "clone", "--bare", "--", origin, filepath.Join(hosted, "repo.git")).CombinedOutput(); err != nil { // #nosec G204 -- local Git over this test's own repository (CWE-78)
		t.Fatalf("host history: %v %s", err, out)
	}
	host := newGitStandIn(t, hosted, "fixture", "fixture", "")
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: host.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSL_CAINFO", ca)
	cfg := RepositoryScanConfig{CloneURL: host.srv.URL + "/repo.git"}
	cred := &RepositoryCredential{Username: "fixture", Secret: []byte("fixture")}
	egress := RepositoryCloneEgress{allowPrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	target := RepositoryTarget{Path: clone, Mode: "clone_url", Cleanup: func() {}, Egress: egress}
	if err := DeepenClone(t.Context(), target, cfg, cred); err != nil {
		t.Fatal(err)
	}
	if at("rev-parse", "--is-shallow-repository") != "false" || at("rev-parse", "refs/remotes/origin/side") != first {
		t.Fatalf("after deepening: shallow %q, side %q", at("rev-parse", "--is-shallow-repository"), at("rev-parse", "refs/remotes/origin/side"))
	}
	if err := DeepenClone(t.Context(), target, cfg, cred); err != nil {
		t.Fatalf("deepening a complete clone again: %v", err)
	}
	if err := DeepenClone(t.Context(), RepositoryTarget{Path: t.TempDir(), Mode: "checkout_path"}, RepositoryScanConfig{}, nil); err != nil {
		t.Fatalf("a checkout_path target is used as it is: %v", err)
	}
}
