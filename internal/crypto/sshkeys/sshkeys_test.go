package sshkeys_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

const (
	edPub  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt alice@laptop"
	edFP   = "SHA256:eg0upccGdZXXLvQU+nKO1PwItOw1TX8CCe3NwH6DnLE"
	rsaPub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSbBngQfJXUR/uxoZhueA+cT9DxWHyP/Ep3x0F7WNKMuSpWcaDtR7MBkqLJNN77yaSOQQMLXDGuGmo+YSEKQlYYJHkErYNvfr7JY8BesxdVcK7RIxIaNhZu1x/HgzTAT+Xv6nK/xJjIpXJA5HIsaFE80bX+nihU3WHt9p+wpWG0TWzB1xTFwjCa2dz1Fzc+ljpU0u638ox7e4bRImwlI9eSEisy6yp23xGY8Ql+3IUOvBxv7i/9RBWGLTMndEXQDYsQQw9q2++Ht1hD/vBOIoUKQu7s3K9PsF5sEByELh1h3koK6EIm6XBZf+HItJF/Hy8FlizE7Ru+faFunRDFGxz deploy-bot"
	rsaFP  = "SHA256:/3eye22EwjZtPODlHAMNnBpNuhcIE2rc5oJWbyTw5cU"
	ecPub  = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCTRiePj3JSBO27Q7RQcNOhLFvuJVqXzGAJAradHGDPH3fXi2KBp0c2FK8o5YYdngfTuUexh06+qAZXDqkxVmbY="
	ecFP   = "SHA256:Qqg49fPYXEb9soSN6Ebjr/udvM1M5Cm5cmUEC1T81qg"
)

// ParsePublicKey returns the type, standard fingerprint, and comment of a .pub
// file.
func TestParsePublicKey(t *testing.T) {
	info, err := sshkeys.ParsePublicKey([]byte(edPub))
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != "ssh-ed25519" || info.FingerprintSHA256 != edFP || info.Comment != "alice@laptop" {
		t.Errorf("ParsePublicKey = %+v", info)
	}
}

// ParseAuthorizedKeys parses every entry, including its options, and skips
// comment and blank lines.
func TestParseAuthorizedKeys(t *testing.T) {
	file := `# operators
command="/usr/bin/true",no-pty ` + edPub + `

` + rsaPub + `
` + ecPub + `
`
	keys := sshkeys.ParseAuthorizedKeys([]byte(file))
	if len(keys) != 3 {
		t.Fatalf("parsed %d keys, want 3", len(keys))
	}
	if keys[0].FingerprintSHA256 != edFP || len(keys[0].Options) != 2 {
		t.Errorf("entry 0 = %+v, want ed25519 with 2 options", keys[0])
	}
	if keys[1].FingerprintSHA256 != rsaFP || keys[1].Type != "ssh-rsa" {
		t.Errorf("entry 1 = %+v, want rsa", keys[1])
	}
	// The ecdsa key has no comment — an unattributable grant.
	if keys[2].FingerprintSHA256 != ecFP || keys[2].Comment != "" {
		t.Errorf("entry 2 = %+v, want ecdsa with empty comment", keys[2])
	}
}

// ParseKnownHosts parses each host key and the host patterns it is trusted for.
func TestParseKnownHosts(t *testing.T) {
	file := "host1.example.com " + edPub + "\n[host2.example.com]:2222 " + rsaPub + "\n"
	hosts := sshkeys.ParseKnownHosts([]byte(file))
	if len(hosts) != 2 {
		t.Fatalf("parsed %d entries, want 2", len(hosts))
	}
	if hosts[0].FingerprintSHA256 != edFP || len(hosts[0].Hosts) == 0 || hosts[0].Hosts[0] != "host1.example.com" {
		t.Errorf("entry 0 = %+v", hosts[0])
	}
	if hosts[1].FingerprintSHA256 != rsaFP {
		t.Errorf("entry 1 fingerprint = %s, want rsa", hosts[1].FingerprintSHA256)
	}
}
