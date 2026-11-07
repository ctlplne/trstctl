// SPDX-License-Identifier: BUSL-1.1

package sshgateway

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/crypto/netdevicetest"
)

// TestGatewaySignsInToADeviceWithItsVaultedPasswordA270: a network device
// signs in with a password, so the gateway signs in upstream as the vaulted
// account with it while the client presents nothing; the device runs the
// client's command as that account; a wrong password and an unpinned host
// key both end the session at the gateway.
func TestGatewaySignsInToADeviceWithItsVaultedPasswordA270(t *testing.T) {
	for _, dialect := range []netdevicetest.Dialect{netdevicetest.IOSXE, netdevicetest.Junos, netdevicetest.EOS, netdevicetest.FortiOS, netdevicetest.BIGIP} {
		t.Run(string(dialect), func(t *testing.T) {
			device, err := netdevicetest.Start(dialect, "netadmin", "admin-password-1", "privilege 15")
			if err != nil {
				t.Fatal(err)
			}
			defer device.Close()
			device.AddAccount("ops", "ops-password-1", "privilege 15")
			host, err := NewHostKey()
			if err != nil {
				t.Fatal(err)
			}
			defer host.Destroy()
			serve := func(password string, pins []string) *ssh.Client {
				t.Helper()
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = ln.Close() })
				go func() {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					_ = ServeGuardedPassword(context.Background(), conn, host, []byte(password),
						Upstream{Address: device.Addr(), User: "ops", HostKeyFingerprints: pins}, nil, nil)
					_ = conn.Close()
				}()
				hostPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(host.AuthorizedKey()))
				if err != nil {
					t.Fatal(err)
				}
				client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "anyone", HostKeyCallback: ssh.FixedHostKey(hostPub), Timeout: 10 * time.Second})
				if err != nil {
					t.Fatalf("client through the gateway: %v", err)
				}
				t.Cleanup(func() { _ = client.Close() })
				return client
			}
			version := map[netdevicetest.Dialect]string{netdevicetest.IOSXE: "terminal length 0", netdevicetest.Junos: "set cli screen-length 0",
				netdevicetest.EOS: "show version", netdevicetest.FortiOS: "get system status", netdevicetest.BIGIP: "show sys version"}[dialect]
			session, err := serve("ops-password-1", []string{device.FingerprintSHA256()}).NewSession()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := session.CombinedOutput(version); err != nil {
				t.Fatalf("exec through the gateway: %v", err)
			}
			if ran := device.Ran(); len(ran) != 1 || ran[0] != version {
				t.Fatalf("the device ran %q", ran)
			}
			if _, err := serve("wrong-password", []string{device.FingerprintSHA256()}).NewSession(); err == nil || !strings.Contains(err.Error(), "could not sign in") {
				t.Fatalf("a wrong vaulted password = %v, want refused", err)
			}
			if _, err := serve("ops-password-1", []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}).NewSession(); err == nil {
				t.Fatal("an unpinned device was reached")
			}
			if len(device.Ran()) != 1 {
				t.Fatal("a refused session ran a command on the device")
			}
		})
	}
}
