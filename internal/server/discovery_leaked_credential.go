// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/secretscan"
)

// leakedCredentialFollowingLines bounds how far past a finding's line a
// credential that starts on it may run: a PEM private key of 8192 bits is
// about a hundred lines.
const leakedCredentialFollowingLines = 128

// leakedCredential is the credential a leaked secret's line holds (A172-L1).
// The line is read from the scanned tree, matched with the rules a
// secret-store value is matched with, and wiped; the credential is
// fingerprinted as a stored copy of it is, so the leak and every stored copy
// share a fingerprint and the findings list reaches both. With columns (as
// gitleaks reports them) the credential is the one the scanner's match
// covers; without them, the only credential that starts on the line. ok is
// false when the line cannot be read from the scanned tree (a leak found only
// in history), holds no recognized credential, or holds several the
// scanner's position cannot tell apart.
func leakedCredential(root string, f secretscan.Finding) (cloudsecret.Credential, bool) {
	line, err := secretscan.ReadFindingLine(root, f.File, f.Line, leakedCredentialFollowingLines)
	if err != nil {
		return cloudsecret.Credential{}, false
	}
	defer secret.Wipe(line.Text)
	found := cloudsecret.CredentialsStartingIn(line.Text, 0, line.LineEnd)
	if f.Column <= 0 {
		if len(found) == 1 {
			return found[0].Credential, true
		}
		return cloudsecret.Credential{}, false
	}
	lo, hi := leakedCredentialWindow(f, line.LineEnd)
	var best cloudsecret.LocatedCredential
	bestOverlap, ties := 0, 0
	for _, c := range found {
		overlap := min(c.End, hi) - max(c.Start, lo)
		switch {
		case overlap > bestOverlap:
			best, bestOverlap, ties = c, overlap, 0
		case overlap > 0 && overlap == bestOverlap:
			ties++
		}
	}
	if bestOverlap == 0 || ties > 0 {
		return cloudsecret.Credential{}, false
	}
	return best.Credential, true
}

// leakedCredentialWindow is the byte range [lo, hi) of the finding's line
// the scanner's match covers. Gitleaks reports a match's columns one or two
// past its 0-based start and one past its end depending on the line, so the
// window opens two before the reported start column and closes at the
// reported end column: wide enough for either, and still clear of a
// credential one separator away. A match that runs onto later lines covers
// the rest of the first line.
func leakedCredentialWindow(f secretscan.Finding, lineEnd int) (int, int) {
	lo := max(f.Column-2, 0)
	hi := f.EndColumn
	if f.EndLine > f.Line || hi > lineEnd {
		hi = lineEnd
	}
	if hi <= lo {
		hi = lo + 1
	}
	return lo, hi
}
