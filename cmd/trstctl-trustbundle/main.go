// SPDX-License-Identifier: BUSL-1.1

// Command trstctl-trustbundle builds and checks the trust bundle every trstctl
// image ships (eMudhra incident, October 2026). It is a thin front for
// internal/crypto/trust: `filter` turns the pinned Alpine ca-certificates
// bundle (an .apk or a PEM file) into the bundle minus the shipped distrust
// list, `probe` performs handshakes with the system roots so a build can
// record which integration endpoints still verify, and `list` prints the
// shipped list.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/trust"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-trustbundle:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: trstctl-trustbundle filter|probe|list|audit")
	}
	switch args[0] {
	case "filter":
		return runFilter(args[1:])
	case "probe":
		return runProbe(args[1:])
	case "list":
		return runList(args[1:])
	case "audit":
		return runAudit(args[1:])
	default:
		return fmt.Errorf("unknown command %q (filter, probe, list, audit)", args[0])
	}
}

func runFilter(args []string) error {
	fs := flag.NewFlagSet("filter", flag.ContinueOnError)
	in := fs.String("in", "", "input bundle: an Alpine ca-certificates-bundle .apk or a PEM file")
	out := fs.String("out", "", "output PEM bundle path")
	report := fs.String("report", "", "optional JSON report path (kept subjects and dropped certificates)")
	expect := fs.Int("expect", 0, "fail unless exactly this many certificates are kept (0 = no check)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *out == "" {
		return errors.New("filter needs -in and -out")
	}
	data, err := os.ReadFile(*in) // #nosec G304 -- build-time input named by the image build (CWE-22)
	if err != nil {
		return err
	}
	if strings.HasSuffix(*in, ".apk") {
		if data, err = trust.BundleFromAPK(data); err != nil {
			return err
		}
	}
	res, err := trust.FilterBundle(data, trust.Shipped())
	if err != nil {
		return err
	}
	if *expect > 0 && res.Kept != *expect {
		return fmt.Errorf("kept %d certificates, expected %d (dropped %d)", res.Kept, *expect, len(res.Dropped))
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil { // #nosec G703 G301 -- build-time output path named by the image build (CWE-22)
		return err
	}
	if err := os.WriteFile(*out, res.Bundle, 0o644); err != nil { // #nosec G306 G703 -- a public trust bundle at a build-time path (CWE-276)
		return err
	}
	if *report != "" {
		body, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*report, append(body, '\n'), 0o644); err != nil { // #nosec G306 G703 -- build evidence at a build-time path, not a secret (CWE-276)
			return err
		}
	}
	fmt.Printf("kept %d certificates, dropped %d (distrust list %s)\n", res.Kept, len(res.Dropped), trust.Shipped().Updated())
	for _, d := range res.Dropped {
		fmt.Printf("  dropped %s (%s)\n", d.Subject, d.Entry)
	}
	return nil
}

func runProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "per-endpoint handshake deadline")
	strict := fs.Bool("strict", false, "exit non-zero when any endpoint fails")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("probe needs at least one host[:port]")
	}
	failed := 0
	enc := json.NewEncoder(os.Stdout)
	for _, target := range fs.Args() {
		res := trust.Probe(context.Background(), target, trust.Shipped(), nil, *timeout)
		if !res.OK {
			failed++
		}
		if err := enc.Encode(res); err != nil {
			return err
		}
	}
	if *strict && failed > 0 {
		return fmt.Errorf("%d endpoint(s) failed", failed)
	}
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	l := trust.Shipped()
	fmt.Printf("shipped distrust list updated %s, %d entries\n", l.Updated(), l.Len())
	for _, e := range l.Entries() {
		fmt.Printf("%-13s %s spki %s\n", e.Kind, e.Name, e.SPKISHA256)
	}
	return nil
}

// audit (Part 3): the certificates Go would load as system roots from an
// exported image filesystem, compared with Mozilla's websites trust list and
// the distrust list; exit 1 on any failing finding, warnings do not fail.
func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	root := fs.String("root", "", "exported image filesystem root (docker export / docker cp)")
	mozilla := fs.String("mozilla", "", "Mozilla websites trust list, PEM (CCADB IncludedRootsPEMTxt?TrustBitsInclude=Websites)")
	report := fs.String("report", "", "optional JSON report path")
	label := fs.String("label", "", "image name for the report")
	var env envFlags
	fs.Var(&env, "env", "image environment entry KEY=VALUE (repeat; SSL_CERT_FILE/SSL_CERT_DIR are checked)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *root == "" || *mozilla == "" {
		return errors.New("audit needs -root and -mozilla")
	}
	mozPEM, err := os.ReadFile(*mozilla) // #nosec G304 G703 -- audit input named by the operator (CWE-22)
	if err != nil {
		return err
	}
	roots, err := trust.SystemRootsLike(*root, env.m)
	if err != nil {
		return err
	}
	findings, err := trust.Audit(roots, mozPEM, trust.Shipped())
	if err != nil {
		return err
	}
	out := struct {
		Image    string               `json:"image,omitempty"`
		Roots    int                  `json:"roots"`
		Sources  []string             `json:"sources"`
		Skipped  int                  `json:"skipped_pem_blocks"`
		Findings []trust.AuditFinding `json:"findings"`
	}{Image: *label, Roots: len(roots.Roots), Sources: roots.Sources, Skipped: roots.Skipped, Findings: findings}
	if *report != "" {
		body, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(*report, append(body, '\n'), 0o644); err != nil { // #nosec G306 G703 -- audit evidence at an operator path (CWE-276)
			return err
		}
	}
	fails := 0
	fmt.Printf("%s: Go loads %d roots from %s\n", *label, len(roots.Roots), strings.Join(roots.Sources, ", "))
	for _, f := range findings {
		if f.Level == "fail" {
			fails++
		}
		fmt.Printf("  %s %s: %s\n", f.Level, f.Subject, f.Reason)
	}
	if fails > 0 {
		return fmt.Errorf("%d failing finding(s)", fails)
	}
	return nil
}

type envFlags struct{ m map[string]string }

func (e *envFlags) String() string { return "" }
func (e *envFlags) Set(v string) error {
	if e.m == nil {
		e.m = map[string]string{}
	}
	k, val, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("env entry %q is not KEY=VALUE", v)
	}
	e.m[k] = val
	return nil
}
