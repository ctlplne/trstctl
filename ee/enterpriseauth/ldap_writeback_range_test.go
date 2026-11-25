// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func ldapTestResult(id int64, tag ber.Tag, code int64) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	res := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	res.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	res.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	res.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	env.AppendChild(res)
	return env.Bytes()
}

// writebackTestDirectory is a stateful in-process directory stand-in. A base search for a
// group answers its values under plain `member` up to MaxValRange (1,500) and,
// above it, the first 1,500 under `member;range=0-1499` (the Active Directory /
// AD LDS automatic range retrieval wire form, MS-ADTS). Modify add/delete
// change the stored membership and answer attributeOrValueExists (20) /
// noSuchAttribute (16) as a real directory does. Unknown bases answer an
// empty success.
type writebackTestDirectory struct {
	mu      sync.Mutex
	members map[string][]string
	ops     []string
}

const writebackTestMaxRange = 1500

func (d *writebackTestDirectory) has(group, dn string) bool {
	for _, v := range d.members[group] {
		if strings.EqualFold(v, dn) {
			return true
		}
	}
	return false
}

func (d *writebackTestDirectory) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			_, _ = c.Write(ldapTestResult(id, ldap.ApplicationBindResponse, 0))
		case ldap.ApplicationSearchRequest:
			base, _ := op.Children[0].Value.(string)
			d.mu.Lock()
			vals, ok := d.members[base]
			vals = append([]string(nil), vals...)
			d.mu.Unlock()
			if !ok {
				_, _ = c.Write(ldapTestResult(id, ldap.ApplicationSearchResultDone, 0))
				continue
			}
			name := "member"
			if len(vals) > writebackTestMaxRange {
				name = fmt.Sprintf("member;range=0-%d", writebackTestMaxRange-1)
				vals = vals[:writebackTestMaxRange]
			}
			env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
			entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
			entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, base, ""))
			attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
			set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			for _, v := range vals {
				set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
			}
			attr.AppendChild(set)
			attrs.AppendChild(attr)
			entry.AppendChild(attrs)
			env.AppendChild(entry)
			_, _ = c.Write(env.Bytes())
			_, _ = c.Write(ldapTestResult(id, ldap.ApplicationSearchResultDone, 0))
		case ldap.ApplicationCompareRequest:
			dn := op.Children[0].Data.String()
			assertion := op.Children[1].Children
			d.mu.Lock()
			result := int64(ldap.LDAPResultCompareFalse)
			if _, ok := d.members[dn]; !ok {
				result = ldap.LDAPResultNoSuchObject
			} else if assertion[0].Data.String() != "member" {
				result = ldap.LDAPResultNoSuchAttribute
			} else if d.has(dn, assertion[1].Data.String()) {
				result = ldap.LDAPResultCompareTrue
			}
			d.mu.Unlock()
			_, _ = c.Write(ldapTestResult(id, ldap.ApplicationCompareResponse, result))
		case ldap.ApplicationModifyRequest:
			dn, _ := op.Children[0].Value.(string)
			code := int64(0)
			d.mu.Lock()
			for _, ch := range op.Children[1].Children {
				kind, _ := ch.Children[0].Value.(int64)
				for _, v := range ch.Children[1].Children[1].Children {
					s, _ := v.Value.(string)
					switch {
					case kind == 0 && d.has(dn, s):
						code = 20
					case kind == 0:
						d.members[dn] = append(d.members[dn], s)
					case kind == 1 && !d.has(dn, s):
						code = 16
					case kind == 1:
						kept := make([]string, 0, len(d.members[dn]))
						for _, m := range d.members[dn] {
							if !strings.EqualFold(m, s) {
								kept = append(kept, m)
							}
						}
						d.members[dn] = kept
					}
					d.ops = append(d.ops, fmt.Sprintf("op=%d %s -> %d", kind, s, code))
				}
			}
			d.mu.Unlock()
			_, _ = c.Write(ldapTestResult(id, ldap.ApplicationModifyResponse, code))
		default:
			return
		}
	}
}

// Exercise both ordinary and ranged groups through the role API and outbox.
func TestLDAPWritebackReconcilesMemberBeyondFirstRange(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "33333333-3333-3333-3333-333333333333"
	dsn := serverTestPostgresDSN(t)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	resetServerTestStore(t, st)

	const viewers = "cn=trstctl-viewers,ou=groups,dc=example,dc=org"
	const alice = "uid=alice,ou=people,dc=example,dc=org"
	const bob = "uid=bob,ou=people,dc=example,dc=org"
	group := func(n int, who string) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			if i == n-1 {
				out = append(out, who)
				continue
			}
			out = append(out, fmt.Sprintf("uid=user%04d,ou=people,dc=example,dc=org", i))
		}
		return out
	}
	dir := &writebackTestDirectory{members: map[string][]string{viewers: group(10, bob)}}
	dln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dln.Close() })
	go func() {
		for {
			c, err := dln.Accept()
			if err != nil {
				return
			}
			go dir.handle(c)
		}
	}()
	bindPasswordFile := filepath.Join(t.TempDir(), "ldap-bind.secret")
	if err := os.WriteFile(bindPasswordFile, []byte("admin-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	ldapCfg := config.LDAP{
		Enabled: true, URL: "ldap://" + dln.Addr().String(), UserDNTemplate: "uid={username},ou=people,dc=example,dc=org",
		BindDN: "cn=admin,dc=example,dc=org", BindPasswordFile: bindPasswordFile,
		GroupSearchBaseDN: "ou=groups,dc=example,dc=org", GroupFilter: "(member={user_dn})", GroupNameAttribute: "cn", EmailAttribute: "mail",
		Writeback:         config.LDAPWriteback{Enabled: true, BaseDN: "dc=example,dc=org", RoleGroups: map[string]string{"viewer": viewers}},
		SessionSecretFile: filepath.Join(t.TempDir(), "ldap-session.secret"), SessionTTL: "1h", LoginRedirect: "/",
		TenantMappings: []config.TenantMapping{{Group: "trstctl-admins", TenantID: tenantID, Roles: []string{"admin"}}},
	}
	srv := buildLDAPServer(t, ctx, dsn, tenantID, ldapCfg)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + ln.Addr().String()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()
	token := seedServedScopedToken(t, st, tenantID, roleAssignerScopes("viewer")...)
	call := func(method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, baseURL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", method+path+body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(out)
	}
	snapshot := func(who string) (bool, []string) {
		dir.mu.Lock()
		defer dir.mu.Unlock()
		ops := append([]string(nil), dir.ops...)
		dir.ops = nil
		return dir.has(viewers, who), ops
	}

	// Control: 10 members, plain `member`.
	if code, body := call(http.MethodPut, "/api/v1/access/members/"+bob, `{"display_name":"Bob","roles":["viewer"],"source":"ldap"}`); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("control upsert = %d %s", code, body)
	}
	cGrantErr := srv.Drain(ctx)
	_, cGrantOps := snapshot(bob)
	if code, body := call(http.MethodPost, "/api/v1/access/members/"+bob+"/offboard", `{"reason":"left the team"}`); code != http.StatusOK {
		t.Fatalf("control offboard = %d %s", code, body)
	}
	cOffErr := srv.Drain(ctx)
	bobStill, cOffOps := snapshot(bob)
	t.Logf("control (10 members, plain member): grant drain=%v ops=%v; offboard drain=%v ops=%v bob still member=%v", cGrantErr, cGrantOps, cOffErr, cOffOps, bobStill)
	if cGrantErr != nil || cOffErr != nil || len(cGrantOps) != 0 || bobStill || len(cOffOps) != 1 {
		t.Fatalf("control failed: the stand-in or the served wiring does not work")
	}

	// The same role group above MaxValRange (1,600 members): AD answers `member;range=0-1499`.
	dir.mu.Lock()
	dir.members[viewers] = group(1600, alice)
	dir.mu.Unlock()
	if code, body := call(http.MethodPut, "/api/v1/access/members/"+alice, `{"display_name":"Alice","roles":["viewer"],"source":"ldap"}`); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("upsert = %d %s", code, body)
	}
	gErr := srv.Drain(ctx)
	_, gOps := snapshot(alice)
	if gErr != nil || len(gOps) != 0 {
		t.Errorf("grant direction: alice already holds the group beyond the first range but the write-back sent %v (drain err=%v): a false not-present Add, refused by the directory with attributeOrValueExists", gOps, gErr)
	}
	if code, body := call(http.MethodPost, "/api/v1/access/members/"+alice+"/offboard", `{"reason":"left the team"}`); code != http.StatusOK {
		t.Fatalf("offboard = %d %s", code, body)
	}
	oErr := srv.Drain(ctx)
	aliceStill, oOps := snapshot(alice)
	if oErr != nil || aliceStill || len(oOps) != 1 {
		t.Errorf("revocation direction: after offboarding and a clean drain (err=%v) alice is STILL in %s; directory modify ops seen=%v (no delete was sent)", oErr, viewers, oOps)
	}
}
