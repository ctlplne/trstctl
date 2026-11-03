// SPDX-License-Identifier: BUSL-1.1

package connector

import "testing"

// Owner decision 2026-11-02 (item 2g a): a host connector's file grant names
// the target's directory, which for a Windows target is a drive path; path.Dir
// alone turned C:\certs\site.pem into ".", and the agent refused the grant.
func TestTargetDirKeepsWindowsDrivePathsAndPOSIXPaths(t *testing.T) {
	for in, want := range map[string]string{
		`C:\ProgramData\nginx\certs\site.pem`: `C:\ProgramData\nginx\certs`,
		`d:/tomcat/conf/keystore.p12`:         `d:/tomcat/conf`,
		`C:\site.pem`:                         `C:\`,
		`C:/site.pem`:                         `C:/`,
		`C:\certs\\site.pem`:                  `C:\certs`,
		`/etc/nginx/ssl/site.pem`:             `/etc/nginx/ssl`,
		`/site.pem`:                           `/`,
		`relative/site.pem`:                   `relative`,
		`site.pem`:                            `.`,
		`1:\site.pem`:                         `.`,
	} {
		if got := TargetDir(in); got != want {
			t.Errorf("TargetDir(%q) = %q, want %q", in, got, want)
		}
	}
}
