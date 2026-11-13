// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// A172-L1: a leaked secret whose value is one of the credential shapes a
// secret-store scan recognizes is matched to the stored copies of that
// credential by fingerprint. As with a planted decoy (Q6-L4), the scanners
// report where a secret is, never what it is, so the finding's line is read
// from the scanned tree, matched in memory and wiped by the caller.

// FindingLine is a finding's line read from the scanned tree, with the lines
// after it that a multi-line credential (a PEM block) may run on to. Text is
// a copy the caller wipes; the finding's own line is Text[:LineEnd].
type FindingLine struct {
	Text    []byte
	LineEnd int
}

// ReadFindingLine reads line and up to following lines after it from file, a
// path in or under root, opened through root so neither a relative path nor
// a link leads out of the scanned tree.
func ReadFindingLine(root, file string, line, following int) (FindingLine, error) {
	if line < 1 || following < 0 || strings.TrimSpace(root) == "" {
		return FindingLine{}, errors.New("secretscan: the finding names no line in a scanned tree")
	}
	data, err := readScannedFile(root, file)
	if err != nil {
		return FindingLine{}, err
	}
	defer secret.Wipe(data)
	start, end, lineEnd, ok := lineSpan(data, line, line+following)
	if !ok {
		return FindingLine{}, errors.New("secretscan: the finding's line is not in the file")
	}
	text := make([]byte, end-start)
	copy(text, data[start:end])
	return FindingLine{Text: text, LineEnd: lineEnd}, nil
}

// lineSpan is where lines first..last (1-based, last clamped to the file)
// lie in data, without their final newline, and where the first one ends,
// measured from start. ok is false when the file has fewer lines than first.
func lineSpan(data []byte, first, last int) (start, end, firstLen int, ok bool) {
	pos := 0
	for n := 1; n < first; n++ {
		i := bytes.IndexByte(data[pos:], '\n')
		if i < 0 {
			return 0, 0, 0, false
		}
		pos += i + 1
	}
	start = pos
	for n := first; n <= last; n++ {
		i := bytes.IndexByte(data[pos:], '\n')
		if i < 0 {
			end = len(data)
			if n == first {
				firstLen = end - start
			}
			return start, end, firstLen, true
		}
		if n == first {
			firstLen = i
		}
		end = pos + i
		pos += i + 1
	}
	return start, end, firstLen, true
}
