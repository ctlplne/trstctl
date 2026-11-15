// SPDX-License-Identifier: BUSL-1.1

package hostsource

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/cbom"
)

// Product defaults (X2-L7). A host-config scan reports what each statement in
// a file says; a protocol or key-exchange group a product reaches only
// through its built-in default went unreported. With the product's version
// from the host's package database, the scan now reports that default too,
// marked config_source "default" and naming the package and version whose
// default it is. A version the table does not cover, or a host whose package
// database the scan does not read (RPM), claims nothing.
//
// The table, each row from the product's own documentation:
//   - HAProxy: TLSv1.2 is the default minimum since 2.2 (the HAProxy 2.2
//     announcement; its SSL deployment FAQ); before 2.2 HAProxy set none and
//     OpenSSL 1.1.1 allowed TLSv1.0. HAProxy sets no key-exchange groups, so
//     the linked OpenSSL's defaults apply.
//   - Envoy, a downstream (listener) TLS context: TLSv1_0 through 1.21 and
//     TLSv1_2 from 1.22 (its versioned common.proto references); default
//     curves X25519 and P-256 from 1.22 through 1.41. A BoringSSL FIPS build
//     uses P-256 alone, which a configuration file does not show: the scan
//     claims the non-FIPS default.
//   - OpenSSL: TLS below 1.2 works only at security level 0 since 3.1 (the
//     3.1 release notes), so a configuration without MinProtocol allows
//     TLSv1.2 and later unless its CipherString sets @SECLEVEL=0; 3.0 and
//     earlier allow TLSv1.0. The default groups lead with the hybrid
//     X25519MLKEM768 since 3.5 (the 3.5 release notes) and with X25519
//     before.
// A group finding names the first group of the product's default list: what
// a current client negotiates.

var defaultPackageDatabases = []string{"/var/lib/dpkg/status", "/lib/apk/db/installed"}

// maxPackageDatabaseBytes bounds how much of a package database a scan reads.
const maxPackageDatabaseBytes = 64 << 20

// defaultPackages are the packages whose versions decide a default.
var defaultPackages = map[string]bool{
	"haproxy": true, "envoy": true, "getenvoy-envoy": true,
	"libssl3t64": true, "libssl3": true, "libssl1.1": true, "openssl": true,
}

type installedPackage struct{ name, version string }

// packageVersions is what the host's package databases record for
// defaultPackages: dpkg's status file (installed packages only) and apk's
// installed database.
type packageVersions map[string]string

func readPackageVersions(paths []string) packageVersions {
	out := packageVersions{}
	for _, path := range paths {
		file, err := os.Open(path) // #nosec G304 -- a fixed system package database, or a test's (CWE-22)
		if err != nil {
			continue
		}
		readPackageDatabase(io.LimitReader(file, maxPackageDatabaseBytes), out)
		_ = file.Close()
	}
	return out
}

// readPackageDatabase reads dpkg status paragraphs (Package:, Status:,
// Version:) or apk installed records (P:, V:), blank-line separated.
func readPackageDatabase(r io.Reader, out packageVersions) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var name, version string
	installed := true
	flush := func() {
		if name != "" && version != "" && installed && defaultPackages[name] {
			out[name] = version
		}
		name, version, installed = "", "", true
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == "":
			flush()
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		case strings.HasPrefix(line, "Status: "):
			installed = strings.HasSuffix(strings.TrimSpace(line), " installed")
		case strings.HasPrefix(line, "P:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "P:"))
		case strings.HasPrefix(line, "V:"):
			version = strings.TrimSpace(strings.TrimPrefix(line, "V:"))
		}
	}
	flush()
}

// first returns the first of names the host has, with its version.
func (p packageVersions) first(names ...string) (installedPackage, bool) {
	for _, n := range names {
		if v, ok := p[n]; ok {
			return installedPackage{name: n, version: v}, true
		}
	}
	return installedPackage{}, false
}

func (i installedPackage) String() string { return i.name + " " + i.version }

var leadingVersion = regexp.MustCompile(`^(\d+(?:\.\d+){0,2})`)

// versionAtLeast compares a package version's leading numbers (an epoch and
// any packaging suffix are ignored: "1:3.0.13-0ubuntu3", "3.5.9-r0",
// "1.30.1.p0.gabc") with want. A version without leading numbers is never
// at least anything.
func versionAtLeast(version string, want ...int) bool {
	if _, rest, ok := strings.Cut(version, ":"); ok {
		version = rest
	}
	m := leadingVersion.FindString(version)
	if m == "" {
		return false
	}
	var have []int
	for _, part := range strings.Split(m, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return false
		}
		have = append(have, n)
	}
	for i, w := range want {
		h := 0
		if i < len(have) {
			h = have[i]
		}
		if h != w {
			return h > w
		}
	}
	return true
}

func libssl(pkgs packageVersions) (installedPackage, bool) {
	return pkgs.first("libssl3t64", "libssl3", "libssl1.1", "openssl")
}

// opensslDefaultGroup is the first group of an OpenSSL release's default list.
func opensslDefaultGroup(lib installedPackage) string {
	if versionAtLeast(lib.version, 3, 5) {
		return "X25519MLKEM768"
	}
	if versionAtLeast(lib.version, 1, 1, 0) {
		return "X25519"
	}
	return ""
}

func defaultFinding(path, library string, pkg installedPackage) cbom.Finding {
	return cbom.Finding{Kind: cbom.AssetHostConfig, Location: path, Library: library,
		ConfigSource: cbom.ConfigSourceDefault, ProductVersion: pkg.String()}
}

// parseDefaults reports the defaults one file leaves in force: a HAProxy
// configuration with a TLS listener or server whose minimum or groups no
// statement sets, an Envoy listener TLS context without a minimum or curves,
// or an OpenSSL configuration without MinProtocol or Groups. pkgs is called
// only for such a file.
func parseDefaults(path string, data []byte, pkgs func() packageVersions) []cbom.Finding {
	lines := logicalLines(data)
	switch {
	case isHAProxyTLS(lines):
		return haproxyDefaults(path, lines, pkgs())
	case strings.Contains(string(data), "DownstreamTlsContext"):
		return envoyDefaults(path, string(data), pkgs())
	case isOpenSSLConfig(path, lines):
		return opensslDefaults(path, lines, pkgs())
	}
	return nil
}

func isHAProxyTLS(lines []string) bool {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && (strings.EqualFold(fields[0], "bind") || strings.EqualFold(fields[0], "server") ||
			strings.EqualFold(fields[0], "default-server")) && hasToken(fields, "ssl") {
			return true
		}
	}
	return false
}

// haproxyDefaults: a side (listeners, or servers HAProxy connects to) takes
// the default minimum when one of its TLS lines states none and no
// ssl-default-<side>-options does, and the linked OpenSSL's groups when one
// states no curves and no ssl-default-<side>-curves does.
func haproxyDefaults(path string, lines []string, pkgs packageVersions) []cbom.Finding {
	type side struct{ globalMin, globalCurves, lineWithoutMin, lineWithoutCurves bool }
	sides := map[string]*side{"bind": {}, "server": {}}
	statesMin := func(options []string) bool {
		for _, o := range options {
			o = strings.ToLower(o)
			if o == "ssl-min-ver" || (strings.HasPrefix(o, "force-") && haproxyVersion(strings.TrimPrefix(o, "force-")) != "") {
				return true
			}
		}
		return false
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		switch key {
		case "ssl-default-bind-options", "ssl-default-server-options":
			if statesMin(fields[1:]) {
				sides[strings.TrimSuffix(strings.TrimPrefix(key, "ssl-default-"), "-options")].globalMin = true
			}
		case "ssl-default-bind-curves", "ssl-default-server-curves":
			sides[strings.TrimSuffix(strings.TrimPrefix(key, "ssl-default-"), "-curves")].globalCurves = true
		case "bind", "server", "default-server":
			if !hasToken(fields, "ssl") {
				continue
			}
			s := sides["bind"]
			if key != "bind" {
				s = sides["server"]
			}
			s.lineWithoutMin = s.lineWithoutMin || !statesMin(fields[1:])
			s.lineWithoutCurves = s.lineWithoutCurves || !hasToken(fields, "curves")
		}
	}
	var out []cbom.Finding
	needMin, needGroups := false, false
	for _, s := range sides {
		needMin = needMin || (s.lineWithoutMin && !s.globalMin)
		needGroups = needGroups || (s.lineWithoutCurves && !s.globalCurves)
	}
	if hap, ok := pkgs.first("haproxy"); ok && needMin {
		f := defaultFinding(path, "haproxy", hap)
		f.Protocol = "TLSv1.0"
		if versionAtLeast(hap.version, 2, 2) {
			f.Protocol = "TLSv1.2"
		}
		out = append(out, f)
	}
	if lib, ok := libssl(pkgs); ok && needGroups {
		if group := opensslDefaultGroup(lib); group != "" {
			f := defaultFinding(path, "haproxy", lib)
			f.Algorithm = group
			out = append(out, f)
		}
	}
	return out
}

// envoyDefaults: more listener TLS contexts than stated minimums means one
// takes the default minimum; no ecdh_curves means the default curves.
func envoyDefaults(path, data string, pkgs packageVersions) []cbom.Finding {
	envoy, ok := pkgs.first("envoy", "getenvoy-envoy")
	if !ok {
		return nil
	}
	var out []cbom.Finding
	if strings.Count(data, "DownstreamTlsContext") > strings.Count(data, "tls_minimum_protocol_version") {
		f := defaultFinding(path, "envoy", envoy)
		f.Protocol = "TLSv1.0"
		if versionAtLeast(envoy.version, 1, 22) {
			f.Protocol = "TLSv1.2"
		}
		out = append(out, f)
	}
	if !strings.Contains(data, "ecdh_curves") && versionAtLeast(envoy.version, 1, 22) && !versionAtLeast(envoy.version, 1, 42) {
		f := defaultFinding(path, "envoy", envoy)
		f.Algorithm = "X25519"
		out = append(out, f)
	}
	return out
}

func isOpenSSLConfig(path string, lines []string) bool {
	if filepath.Base(path) == "openssl.cnf" {
		return true
	}
	for _, line := range lines {
		if name, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(name) == "openssl_conf" {
			return true
		}
	}
	return false
}

// opensslDefaults: no MinProtocol leaves the library's minimum (TLSv1.0
// again at @SECLEVEL=0), and no Groups or Curves its default groups.
func opensslDefaults(path string, lines []string, pkgs packageVersions) []cbom.Finding {
	lib, ok := libssl(pkgs)
	if !ok {
		return nil
	}
	min, groups, seclevel0 := false, false, false
	for _, line := range lines {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(name) {
		case "MinProtocol":
			min = true
		case "Groups", "Curves":
			groups = true
		case "CipherString":
			seclevel0 = seclevel0 || strings.Contains(strings.ReplaceAll(value, " ", ""), "@SECLEVEL=0")
		}
	}
	var out []cbom.Finding
	if !min {
		f := defaultFinding(path, "openssl-config", lib)
		f.Protocol = "TLSv1.0"
		if versionAtLeast(lib.version, 3, 1) && !seclevel0 {
			f.Protocol = "TLSv1.2"
		}
		out = append(out, f)
	}
	if group := opensslDefaultGroup(lib); !groups && group != "" {
		f := defaultFinding(path, "openssl-config", lib)
		f.Algorithm = group
		out = append(out, f)
	}
	return out
}
