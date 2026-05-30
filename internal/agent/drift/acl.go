package drift

import "strings"

// broadPrincipals are the SDDL account identifiers — well-known aliases and their
// numeric SIDs — that represent broad, non-administrative access. A sensitive
// credential (Watched.Restricted) granting any of them access is a permission
// loosening: the Windows analog of a private key going world-readable on POSIX.
var broadPrincipals = map[string]string{
	"WD":           "Everyone",
	"S-1-1-0":      "Everyone",
	"AU":           "Authenticated Users",
	"S-1-5-11":     "Authenticated Users",
	"BU":           "Users",
	"S-1-5-32-545": "Users",
	"AN":           "Anonymous",
	"S-1-5-7":      "Anonymous",
}

// sddlAllowsBroad reports whether the DACL of an SDDL security descriptor grants
// access to a broad principal via an allow ACE, returning the principal's name.
// It parses only the DACL (D:) section and ignores deny ACEs and the SACL, so a
// deny on Everyone is correctly not treated as loosening.
//
// This is the platform-independent decision behind Windows ACL drift detection;
// the Windows code feeds it the real descriptor's SDDL (so this logic is unit
// tested on every platform, not only where it runs).
func sddlAllowsBroad(sddl string) (string, bool) {
	for _, ace := range daclACEs(sddl) {
		fields := strings.Split(ace, ";")
		if len(fields) < 6 {
			continue
		}
		if !isAllowACE(fields[0]) {
			continue
		}
		if strings.TrimSpace(fields[2]) == "" {
			continue // an ACE granting no rights is not access
		}
		if name, ok := broadPrincipals[strings.TrimSpace(fields[5])]; ok {
			return name, true
		}
	}
	return "", false
}

// daclACEs returns the bodies (without the surrounding parentheses) of the ACEs
// in the DACL (D:) section of an SDDL string.
func daclACEs(sddl string) []string {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return nil
	}
	dacl := sddl[i+2:]
	// The DACL runs until the SACL section (S:), if any. SIDs are written
	// "S-1-..." (no colon), so "S:" unambiguously marks the SACL.
	if j := strings.Index(dacl, "S:"); j >= 0 {
		dacl = dacl[:j]
	}

	var aces []string
	for {
		open := strings.IndexByte(dacl, '(')
		if open < 0 {
			break
		}
		shut := strings.IndexByte(dacl[open:], ')')
		if shut < 0 {
			break
		}
		aces = append(aces, dacl[open+1:open+shut])
		dacl = dacl[open+shut+1:]
	}
	return aces
}

// isAllowACE reports whether an SDDL ACE type string is an access-allowed type
// (plain or callback). Deny types (D, XD, ZD) are not.
func isAllowACE(aceType string) bool {
	switch strings.TrimSpace(aceType) {
	case "A", "XA", "ZA":
		return true
	default:
		return false
	}
}
