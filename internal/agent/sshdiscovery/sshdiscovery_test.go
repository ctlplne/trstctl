package sshdiscovery_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/sshdiscovery"
	"trstctl.com/trstctl/internal/sshinv"
)

const (
	edPub  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt alice@laptop"
	edFP   = "SHA256:eg0upccGdZXXLvQU+nKO1PwItOw1TX8CCe3NwH6DnLE"
	rsaPub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSbBngQfJXUR/uxoZhueA+cT9DxWHyP/Ep3x0F7WNKMuSpWcaDtR7MBkqLJNN77yaSOQQMLXDGuGmo+YSEKQlYYJHkErYNvfr7JY8BesxdVcK7RIxIaNhZu1x/HgzTAT+Xv6nK/xJjIpXJA5HIsaFE80bX+nihU3WHt9p+wpWG0TWzB1xTFwjCa2dz1Fzc+ljpU0u638ox7e4bRImwlI9eSEisy6yp23xGY8Ql+3IUOvBxv7i/9RBWGLTMndEXQDYsQQw9q2++Ht1hD/vBOIoUKQu7s3K9PsF5sEByELh1h3koK6EIm6XBZf+HItJF/Hy8FlizE7Ru+faFunRDFGxz deploy-bot"
	rsaFP  = "SHA256:/3eye22EwjZtPODlHAMNnBpNuhcIE2rc5oJWbyTw5cU"
	ecPub  = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCTRiePj3JSBO27Q7RQcNOhLFvuJVqXzGAJAradHGDPH3fXi2KBp0c2FK8o5YYdngfTuUexh06+qAZXDqkxVmbY="
	ecFP   = "SHA256:Qqg49fPYXEb9soSN6Ebjr/udvM1M5Cm5cmUEC1T81qg"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func byFingerprint(found []sshinv.Found) map[string]sshinv.Found {
	out := map[string]sshinv.Found{}
	for _, f := range found {
		out[f.Fingerprint] = f
	}
	return out
}

// The agent inventories every kind of on-host SSH material and flags standing
// access and orphaned grants.
func TestDiscoverInventoriesAllSSHMaterial(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc", "ssh")
	home := filepath.Join(root, "home", "alice", ".ssh")
	caPath := filepath.Join(etc, "ca.pub")

	write(t, filepath.Join(etc, "ssh_host_ed25519_key.pub"), edPub+"\n") // host key
	write(t, filepath.Join(home, "id_rsa.pub"), rsaPub+"\n")             // user key
	// authorized_keys: one owned grant (alice@laptop) + one unattributable (no comment).
	write(t, filepath.Join(home, "authorized_keys"), edPub+"\n"+ecPub+"\n")
	write(t, filepath.Join(home, "known_hosts"), "github.com "+edPub+"\n")
	write(t, caPath, rsaPub+"\n")
	write(t, filepath.Join(etc, "sshd_config"), "# config\nPermitRootLogin no\nTrustedUserCAKeys "+caPath+"\n")

	src := sshdiscovery.New(sshdiscovery.Config{
		HostKeyGlobs:        []string{filepath.Join(etc, "ssh_host_*_key.pub")},
		UserKeyGlobs:        []string{filepath.Join(home, "*.pub")},
		AuthorizedKeysPaths: []string{filepath.Join(home, "authorized_keys")},
		KnownHostsPaths:     []string{filepath.Join(home, "known_hosts")},
		SSHDConfigPaths:     []string{filepath.Join(etc, "sshd_config")},
	})

	found, err := src.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Tally by source.
	bySource := map[string]int{}
	for _, f := range found {
		bySource[f.Source]++
	}
	for _, want := range []string{
		sshinv.SourceHostKey, sshinv.SourceUserKey, sshinv.SourceAuthorizedKeys,
		sshinv.SourceKnownHosts, sshinv.SourceTrustedCA,
	} {
		if bySource[want] == 0 {
			t.Errorf("no SSH material discovered for source %q", want)
		}
	}

	// authorized_keys grants are standing access; the no-comment one is orphaned.
	authStanding, authOrphaned := 0, 0
	for _, f := range found {
		if f.Source == sshinv.SourceAuthorizedKeys {
			if f.StandingAccess {
				authStanding++
			}
			if f.Orphaned {
				authOrphaned++
			}
		}
	}
	if authStanding != 2 {
		t.Errorf("authorized_keys standing-access count = %d, want 2", authStanding)
	}
	if authOrphaned != 1 {
		t.Errorf("orphaned grant count = %d, want 1 (the no-comment key)", authOrphaned)
	}

	// Check the authorized_keys grants precisely: the no-comment ecdsa key is the
	// orphaned one; the alice@laptop ed25519 grant is not.
	for _, f := range found {
		if f.Source != sshinv.SourceAuthorizedKeys {
			continue
		}
		switch f.Fingerprint {
		case ecFP:
			if !f.Orphaned || !f.StandingAccess {
				t.Errorf("no-comment grant %+v should be orphaned standing access", f)
			}
		case edFP:
			if f.Orphaned {
				t.Errorf("owned grant (alice@laptop) must not be orphaned: %+v", f)
			}
		}
	}
	// The rsa key was discovered (as a user key and as the trusted CA).
	if byFingerprint(found)[rsaFP].Fingerprint == "" {
		t.Error("the rsa key was not discovered")
	}
}

// Missing files are skipped, not fatal.
func TestDiscoverBestEffort(t *testing.T) {
	src := sshdiscovery.New(sshdiscovery.Config{
		HostKeyGlobs:        []string{"/nonexistent/ssh_host_*_key.pub"},
		AuthorizedKeysPaths: []string{"/nonexistent/authorized_keys"},
	})
	found, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("missing paths must not error: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("expected nothing discovered, got %d", len(found))
	}
}
