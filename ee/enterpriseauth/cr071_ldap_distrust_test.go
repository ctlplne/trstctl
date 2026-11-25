// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/trust"
	"trstctl.com/trstctl/internal/crypto/trust/trusttest"
)

// Go's fallback system roots are process-global and one-shot. Run the three
// Enterprise LDAP paths in a child test process so the rest of this package's
// TLS tests retain their normal system trust.
func TestCR071EnterpriseLDAPNeverBindsThroughDistrustedCA(t *testing.T) {
	const childMarker = "TRSTCTL_CR071_LDAP_CHILD"
	if os.Getenv(childMarker) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCR071EnterpriseLDAPNeverBindsThroughDistrustedCA$") // #nosec G204 G702 -- this test reruns its own fixed binary with a fixed test selector, no shell or untrusted argument (CWE-78)
		cmd.Env = append(os.Environ(), childMarker+"=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated Enterprise LDAP distrust regression failed: %v\n%s", err, output)
		}
		return
	}
	listener := trusttest.NewFallbackRootTLSListener(t)
	seen := make(chan []byte, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 4096)
				if n, _ := conn.Read(buf); n > 0 {
					seen <- append([]byte(nil), buf[:n]...)
				}
			}(conn)
		}
	}()
	url := "ldaps://" + listener.Addr().String()
	verifier := LDAPVerifier{
		URL: url, UserDNTemplate: "uid={username},ou=people,dc=example,dc=org", Timeout: 2 * time.Second,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	loginPassword := []byte("cr071-login-canary")
	_, loginErr := verifier.Verify(ctx, "alice", loginPassword)
	currentPassword := []byte("cr071-current-canary")
	changeErr := verifier.ChangePassword(ctx, "alice", currentPassword, []byte("cr071-next-canary"))
	servicePassword := []byte("cr071-service-canary")
	_, _, writebackErr := (&ldapWriteback{}).apply(ctx, ldapWritebackTarget{
		URL: url, BindDN: "cn=svc,dc=example,dc=org", BindPassword: servicePassword, Timeout: 2 * time.Second,
	}, "uid=alice,ou=people,dc=example,dc=org", map[string]bool{})
	for name, err := range map[string]error{"login": loginErr, "password change": changeErr, "writeback": writebackErr} {
		var distrusted *trust.DistrustError
		if !errors.As(err, &distrusted) {
			t.Errorf("%s did not refuse the operator-distrusted CA before bind: %v", name, err)
		}
	}
	for {
		select {
		case frame := <-seen:
			for name, canary := range map[string][]byte{"login": loginPassword, "password change": currentPassword, "writeback": servicePassword} {
				if bytes.Contains(frame, canary) {
					t.Errorf("%s sent its password through the distrusted TLS peer", name)
				}
			}
		default:
			return
		}
	}
}
