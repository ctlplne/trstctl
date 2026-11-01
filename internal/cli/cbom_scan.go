// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/sourcescan"
)

// cbom scan-source and cbom scan-image (X6) produce a CycloneDX CBOM on this
// machine, offline, for 'cbom import': scan-source reads a repository's code
// for its crypto uses; scan-image runs a CBOM scanner the operator installed
// (cbomkit-theia) against an image, directory or archive. Neither sends
// anything anywhere.

const cbomScanOutputLimit = 64 << 20

func cbomScanSourceUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl cbom scan-source <directory> [--out <file>]")
	_, _ = fmt.Fprintln(w, "\nFinds where a repository's code uses cryptography (Go through its syntax tree; Java and Python through the")
	_, _ = fmt.Fprintln(w, "JCA and pyca/cryptography calls): RSA and its key size, ECDH and ECDSA curves, 3DES, RC4, MD5, SHA-1 and more,")
	_, _ = fmt.Fprintln(w, "each with its file and line. Writes a CycloneDX CBOM; nothing is executed or sent.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl cbom scan-source ./payments --out payments.cdx.json")
	_, _ = fmt.Fprintln(w, "         trstctl cbom import --source source:payments -f payments.cdx.json")
}

func runCBOMScanSource(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cbom scan-source", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "write the CBOM to this file instead of stdout")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return 2
	}
	if len(fs.Args()) != 1 {
		_, _ = fmt.Fprintln(stderr, "error: give exactly one directory")
		return 2
	}
	uses, err := sourcescan.Scan(ctx, fs.Args()[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if len(uses) == 0 {
		_, _ = fmt.Fprintln(stderr, "no crypto use found; nothing to import")
		return 1
	}
	doc, err := sourcescan.CBOM(uses, uuid.NewString())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return writeCBOM(doc, *out, stdout, stderr, fmt.Sprintf("%d crypto uses", len(uses)))
}

func cbomScanImageUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl cbom scan-image --scanner <cbomkit-theia> [--out <file>] -- <scanner arguments>")
	_, _ = fmt.Fprintln(w, "\nRuns the CBOM scanner you installed against an image, a directory or an archive, offline, checks that what it")
	_, _ = fmt.Fprintln(w, "wrote is a CycloneDX CBOM with crypto in it, and writes it for 'cbom import --source image:<reference>'.")
	_, _ = fmt.Fprintln(w, "trstctl never downloads the scanner; the arguments after -- go to it unchanged.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl cbom scan-image --scanner /usr/local/bin/cbomkit-theia --out app.cdx.json -- dir ./rootfs")
	_, _ = fmt.Fprintln(w, "         trstctl cbom import --source image:registry.example/app:1.4 -f app.cdx.json")
}

func runCBOMScanImage(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cbom scan-image", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scanner := fs.String("scanner", "", "path to the CBOM scanner (cbomkit-theia)")
	out := fs.String("out", "", "write the CBOM to this file instead of stdout")
	timeout := fs.Duration("timeout", 10*time.Minute, "stop the scanner after this long")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*scanner) == "" || len(fs.Args()) == 0 {
		_, _ = fmt.Fprintln(stderr, "error: --scanner and the scanner's arguments after -- are required")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, *scanner, fs.Args()...) // #nosec G204 -- the operator names the scanner and its arguments; running it is the command's purpose (CWE-78)
	var output bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &output, left: cbomScanOutputLimit}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: the scanner failed: %v\n", err)
		return 1
	}
	doc := bytes.TrimSpace(output.Bytes())
	bom, err := cbom.ParseCycloneDXImport(doc, "image:scan", cbom.DefaultPolicy())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: the scanner's output is not a CBOM trstctl can import: %v\n", err)
		return 1
	}
	return writeCBOM(doc, *out, stdout, stderr, fmt.Sprintf("%d components, %d crypto findings", bom.Components, len(bom.Findings)))
}

func writeCBOM(doc []byte, out string, stdout, stderr io.Writer, summary string) int {
	if out == "" {
		_, _ = stdout.Write(append(doc, '\n'))
	} else if err := os.WriteFile(out, append(doc, '\n'), 0o600); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stderr, "CBOM written: "+summary)
	return 0
}

// limitedWriter refuses output past its limit instead of buffering it.
type limitedWriter struct {
	w    io.Writer
	left int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.left {
		return 0, fmt.Errorf("scanner output exceeds %d bytes", cbomScanOutputLimit)
	}
	l.left -= int64(len(p))
	return l.w.Write(p)
}

// reorderFlags lets flags follow the positional directory.
func reorderFlags(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			if !strings.Contains(args[i], "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, args[i])
	}
	return append(flags, positional...)
}
