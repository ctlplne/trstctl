// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/auditsink"
)

// P5-L5: each SIEM content pack builds byte for byte the same from the same
// sources, holds exactly its listed files (0644, mtime 0, owner 0) under its
// own directory, and the rsyslog receiver keeps exactly the messages the
// syslog feed writes.
func TestContentPacksAreDeterministicAndCompleteP5L5(t *testing.T) {
	repo := filepath.Join("..", "..")
	for name, p := range packs {
		read := func(file string) ([]byte, error) {
			return os.ReadFile(filepath.Join(repo, p.Dir, file)) // #nosec G304 -- test reads the repo's own shipped content (CWE-22)
		}
		var first, second bytes.Buffer
		if err := write(&first, p, read); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := write(&second, p, read); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) {
			t.Fatalf("%s: two builds differ", name)
		}
		gz, err := gzip.NewReader(bytes.NewReader(first.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		if !gz.ModTime.IsZero() || gz.Name != "" {
			t.Fatalf("%s: gzip header carries %v %q", name, gz.ModTime, gz.Name)
		}
		tr := tar.NewReader(gz)
		var entries []string
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if !h.ModTime.Equal(time.Unix(0, 0)) || h.Uid != 0 || h.Gid != 0 {
				t.Fatalf("%s: %s has mtime %v owner %d/%d", name, h.Name, h.ModTime, h.Uid, h.Gid)
			}
			entries = append(entries, h.Name)
			if h.Typeflag != tar.TypeReg {
				continue
			}
			if h.Mode != 0o644 {
				t.Fatalf("%s: %s mode %o", name, h.Name, h.Mode)
			}
			got, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			want, err := read(strings.TrimPrefix(h.Name, p.Name+"/"))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s: %s differs from its source (%v)", name, h.Name, err)
			}
		}
		want := []string{p.Name + "/"}
		files := slices.Clone(p.Files)
		slices.Sort(files)
		for _, file := range files {
			want = append(want, p.Name+"/"+file)
		}
		if !slices.Equal(entries, want) {
			t.Fatalf("%s: entries %v, want %v", name, entries, want)
		}
	}
	if err := write(io.Discard, pack{Name: "x", Files: []string{"../escape"}}, func(string) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("a pack listing a path outside its directory was written")
	}

	// The rsyslog receiver filters on the APP-NAME and MSGID the feed writes.
	var framed bytes.Buffer
	if err := auditsink.WriteCollectorBatch(&framed, auditsink.FeedBatch{
		BatchID: "b1", DestinationID: "d1", Provider: auditsink.ProviderSyslog, EndpointURL: "syslog+tls://r.example.test",
		StartSequence: 7, EndSequence: 7, ChainHead: "c7",
		Records: []auditchain.Record{{Sequence: 7, ID: "r7", Type: "owner.created", TenantID: "t1", Time: time.Unix(1, 0)}},
	}); err != nil {
		t.Fatal(err)
	}
	_, message, ok := strings.Cut(framed.String(), " ")
	if !ok || !strings.Contains(message, " - trstctl - trstctl-audit - {") {
		t.Fatalf("the feed's message %q no longer has APP-NAME trstctl and MSGID trstctl-audit", message)
	}
	conf, err := os.ReadFile(filepath.Join(repo, "deploy", "rsyslog", "trstctl-audit.conf")) // #nosec G304 -- test reads the repo's own shipped content (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`$programname == "trstctl"`, `$msgid == "trstctl-audit"`, `module(load="mmjsonparse")`, `StreamDriver.Mode="1"`} {
		if !strings.Contains(string(conf), want) {
			t.Fatalf("the rsyslog receiver lacks %s", want)
		}
	}
}

// P5-L3: the RELP receiver content keeps the same messages as the TLS one,
// takes RELP on TLS only, and ends a session on a message over RELP's 128 KiB
// instead of truncating it (a truncated record would be acknowledged).
func TestRsyslogRELPReceiverContentP5L3(t *testing.T) {
	if !slices.Contains(packs["rsyslog"].Files, "trstctl-audit-relp.conf") {
		t.Fatal("the rsyslog pack does not ship the RELP receiver")
	}
	conf, err := os.ReadFile(filepath.Join("..", "..", "deploy", "rsyslog", "trstctl-audit-relp.conf")) // #nosec G304 -- test reads the repo's own shipped content (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`$programname == "trstctl"`, `$msgid == "trstctl-audit"`, `module(load="mmjsonparse")`, `module(load="imrelp")`,
		`tls="on"`, `maxDataSize="128k"`, `oversizeMode="abort"`, `global(maxMessageSize="128k")`,
	} {
		if !strings.Contains(string(conf), want) {
			t.Fatalf("the RELP receiver lacks %s", want)
		}
	}
}
