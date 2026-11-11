// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Q6-L4: a decoy secret's value is bait, and an operator may plant it in a
// repository as a lure. A scan that finds it there has found the known decoy,
// not a leak. The scanners report where a secret is, never what it is, so the
// match is made where the value already is: the lines around a finding in the
// scanned tree are compared, in memory, with the tenant's live decoy values,
// and both are wiped. Nothing about a scanned value is kept.

// KnownValue is a value the tenant planted on purpose: a live decoy secret.
type KnownValue struct {
	ID, Name string
	Value    []byte
}

// MinKnownValueBytes is the shortest value matched; a shorter one would
// match ordinary text.
const MinKnownValueBytes = 8

// KnownDecoyRiskScore is the risk of a scan finding that holds a live decoy's
// value: the bait where it was put, not a leak.
const KnownDecoyRiskScore = 10

// maxFindingContextFile bounds how much of a finding's file is read.
const maxFindingContextFile = 4 << 20

var errOutsideScannedTree = errors.New("secretscan: the finding's file is outside the scanned tree")

// WipeKnownValues wipes every known value's bytes.
func WipeKnownValues(known []KnownValue) {
	for i := range known {
		secret.Wipe(known[i].Value)
	}
}

// MatchKnownValue reports which known value appears on a finding's line or
// the lines beside it, read from the scanned tree without leaving it.
func MatchKnownValue(root, file string, line int, known []KnownValue) (KnownValue, bool) {
	if len(known) == 0 || line < 1 || strings.TrimSpace(root) == "" {
		return KnownValue{}, false
	}
	text, err := readFindingContext(root, file, line, 1)
	if err != nil {
		return KnownValue{}, false
	}
	defer secret.Wipe(text)
	for _, k := range known {
		if len(k.Value) >= MinKnownValueBytes && bytes.Contains(text, k.Value) {
			return k, true
		}
	}
	return KnownValue{}, false
}

// readFindingContext reads span lines either side of line in file, a path
// in or under root. The file is opened through root, so neither a relative
// path nor a link leads out of the scanned tree.
func readFindingContext(root, file string, line, span int) ([]byte, error) {
	root = filepath.Clean(root)
	rel := filepath.Clean(file)
	if filepath.IsAbs(rel) {
		r, err := filepath.Rel(root, rel)
		if err != nil {
			return nil, errOutsideScannedTree
		}
		rel = r
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errOutsideScannedTree
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	f, err := dir.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFindingContextFile))
	if err != nil {
		secret.Wipe(data)
		return nil, err
	}
	defer secret.Wipe(data)
	lines := bytes.Split(data, []byte("\n"))
	from, to := line-1-span, line+span
	if from < 0 {
		from = 0
	}
	if to > len(lines) {
		to = len(lines)
	}
	if from >= to {
		return nil, errors.New("secretscan: the finding's line is not in the file")
	}
	return append([]byte(nil), bytes.Join(lines[from:to], []byte("\n"))...), nil
}
