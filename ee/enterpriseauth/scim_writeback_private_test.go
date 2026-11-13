// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// A directory on a private network used to fail every writeback with
// "transport failure" and burn the row's retries: configuration accepted any
// https endpoint, but delivery's SSRF-guarded client refuses private
// addresses. The operator now lists the directory's network
// (writeback_private_egress_cidrs, the A223 rule) and, for an internal CA,
// names its root (writeback_ca_file). Unlisted, the dial is refused with the
// reason as a definite refusal; listed, the same production client reaches
// the directory. The stand-in listens on this host's own private interface;
// only the throwaway CA's server name is injected, the dial guard stays.
func TestSCIMWritebackReachesAPrivateDirectoryOnlyWhenItsNetworkIsListed(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var address netip.Addr
	for _, candidate := range addresses {
		if p, err := netip.ParsePrefix(candidate.String()); err == nil && p.Addr().Is4() && p.Addr().IsPrivate() {
			address = p.Addr()
			break
		}
	}
	if !address.IsValid() {
		t.Skip("a private directory stand-in needs a private IPv4 interface")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(address.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	const bearerValue = "private-directory-bearer" // #nosec G101 -- fabricated fixture credential (CWE-798)
	directory := &scimDirectoryDouble{bearer: bearerValue, users: map[string]map[string]any{
		"dir-alice": {"id": "dir-alice", "userName": "alice@example.com", "active": true, "roles": []any{}},
	}, byName: map[string]string{"alice@example.com": "dir-alice"}}
	sink := httptest.NewUnstartedServer(http.HandlerFunc(directory.handle))
	_ = sink.Listener.Close()
	sink.Listener = listener
	sink.StartTLS()
	defer sink.Close()
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sink.Certificate().Raw})
	endpoint := sink.URL + "/scim/v2"
	bearer, err := secret.NewFrom([]byte(bearerValue))
	if err != nil {
		t.Fatal(err)
	}
	defer bearer.Destroy()
	member := &store.SCIMIdentity{UserName: "alice@example.com"}
	const tenantID = "11111111-1111-1111-1111-111111111111"

	unlisted, err := withSCIMWritebackClient(scimWritebackTarget{Endpoint: endpoint, bearer: fixedSCIMWritebackBearer(bearer), rootPEM: rootPEM})
	if err != nil {
		t.Fatal(err)
	}
	w := newSCIMWriteback(api.SCIMWritebackDeps{}, map[string]scimWritebackTarget{tenantID: unlisted})
	_, err = w.writeUser(context.Background(), w.targets[tenantID], member, true, []string{"viewer"})
	var refused scimWritebackRefused
	if !errors.As(err, &refused) || !strings.Contains(refused.detail, "non-public address") || !strings.Contains(refused.detail, address.String()) ||
		!strings.Contains(refused.detail, "writeback_private_egress_cidrs") {
		t.Fatalf("an unlisted private directory: %v; want a definite refusal naming the address and the setting", err)
	}
	if n := len(directory.patches); n != 0 {
		t.Fatalf("an unlisted private directory was reached: %d patches", n)
	}

	listed, err := withSCIMWritebackClient(scimWritebackTarget{Endpoint: endpoint, bearer: fixedSCIMWritebackBearer(bearer), rootPEM: rootPEM,
		privateCIDRs: []netip.Prefix{netip.PrefixFrom(address, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	listed.client.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com" // httptest's certificate SAN
	w = newSCIMWriteback(api.SCIMWritebackDeps{}, map[string]scimWritebackTarget{tenantID: listed})
	id, err := w.writeUser(context.Background(), w.targets[tenantID], member, true, []string{"viewer"})
	if err != nil || id != "dir-alice" {
		t.Fatalf("a listed private directory: %q %v; want dir-alice written", id, err)
	}
	directory.mu.Lock()
	patches := len(directory.patches)
	directory.mu.Unlock()
	if patches != 1 {
		t.Fatalf("the listed private directory saw %d patches, want 1", patches)
	}

	// Configuration carries both settings into the delivery target.
	if _, err := withSCIMWritebackClient(scimWritebackTarget{Endpoint: endpoint, bearer: fixedSCIMWritebackBearer(bearer), rootPEM: []byte("not a certificate")}); err == nil {
		t.Fatal("a CA file with no certificate was accepted")
	}
	tok := config.SCIMToken{WritebackEndpoint: endpoint, WritebackPrivateEgressCIDRs: []string{netip.PrefixFrom(address, 32).String()}}
	if prefixes, errs := tok.WritebackPrivatePrefixes(); len(errs) != 0 || len(prefixes) != 1 || !prefixes[0].Contains(address) {
		t.Fatalf("listed prefixes = %v %v", prefixes, errs)
	}
}
