// SPDX-License-Identifier: BUSL-1.1

// Command siempack builds the SIEM content packs for the trstctl audit feeds
// (P5-L5) into deterministic archives: the same sources give the same bytes,
// so a pack can be checked against its digest.
//
//	siempack --pack elastic --repo . --out bin/trstctl-elastic-content.tar.gz
//	siempack --pack rsyslog --repo . --out bin/trstctl-rsyslog-content.tar.gz
package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// pack is one content pack: its archive's top directory and its files.
type pack struct {
	Name  string
	Dir   string
	Files []string
}

// packs lists every shipped pack. A file is listed by name, so a stray file in
// the directory never enters an archive.
var packs = map[string]pack{
	"elastic": {Name: "trstctl-elastic-content", Dir: "deploy/elastic",
		Files: []string{"README.md", "trstctl-audit-index-template.json", "trstctl-audit-pipeline.json"}},
	"rsyslog": {Name: "trstctl-rsyslog-content", Dir: "deploy/rsyslog",
		Files: []string{"README.md", "trstctl-audit.conf"}},
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "siempack:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("siempack", flag.ContinueOnError)
	name := fs.String("pack", "", "elastic or rsyslog")
	repo := fs.String("repo", ".", "the checkout the pack's files are read from")
	out := fs.String("out", "", "the archive to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, ok := packs[*name]
	if !ok || *out == "" {
		return errors.New("usage: siempack --pack elastic|rsyslog --repo DIR --out FILE")
	}
	f, err := os.Create(*out) // #nosec G304 -- the operator's own output path (CWE-22)
	if err != nil {
		return err
	}
	if err := write(f, p, func(file string) ([]byte, error) {
		return os.ReadFile(filepath.Join(*repo, p.Dir, file)) // #nosec G304 -- a listed file of the pack (CWE-22)
	}); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// write archives p as gzip-compressed USTAR: a directory entry, then each
// listed file in name order, every entry at mtime 0 and owner 0, files 0644.
func write(w io.Writer, p pack, read func(string) ([]byte, error)) error {
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: p.Name + "/", Mode: 0o755, Format: tar.FormatUSTAR}); err != nil {
		return err
	}
	files := slices.Clone(p.Files)
	slices.Sort(files)
	for _, file := range files {
		if file != path.Base(file) || strings.HasPrefix(file, ".") {
			return fmt.Errorf("pack %s lists %q, not a plain file name", p.Name, file)
		}
		content, err := read(file)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: p.Name + "/" + file, Mode: 0o644,
			Size: int64(len(content)), Format: tar.FormatUSTAR}); err != nil {
			return err
		}
		if _, err := tw.Write(content); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
