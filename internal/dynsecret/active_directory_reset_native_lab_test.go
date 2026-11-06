// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"github.com/go-ldap/ldap/v3"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/ldapbind"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

var ownedADCrashEnvelope = flag.String("a267-ad-envelope", "", "owned encrypted preparation reference")
var ownedADCrashBoundary = flag.Int("a267-ad-boundary", 0, "owned abrupt exit after native generation")
var ownedADCrashInverse = flag.Bool("a267-ad-inverse", false, "owned native inverse direction")

const ownedADCrashAAD = "trstctl.a267.owned-native-reset-preparation.v2"
const ownedADCrashAdmin = "CN=Administrator,CN=Users,DC=a263,DC=test"

type abruptADResetRuntime struct {
	adPreparedResetRuntime
	baseline uint64
	boundary int
}

func (r abruptADResetRuntime) Reset(ctx context.Context, expected adNativeResetIdentity, password []byte, recovery bool) error {
	if e := r.adPreparedResetRuntime.Reset(ctx, expected, password, recovery); e != nil {
		return e
	}
	if r.boundary > 0 && expected.KeyVersion-r.baseline+1 == uint64(r.boundary) {
		os.Exit(37)
	}
	return nil
}
func ownedADCrashBackend(t *testing.T, dn string) *LDAPBackend {
	t.Helper()
	admin, e := os.ReadFile("/run/ad-admin-password")
	if e != nil {
		t.Fatal("owned AD administrator reference unavailable")
	}
	defer secret.Wipe(admin)
	ca, e := os.ReadFile("/run/ad-ca.pem")
	if e != nil {
		t.Fatal(e)
	}
	backend, e := NewLDAPBackend(LDAPConfig{DirectoryMode: "active_directory", Addr: "ad263:636", TLSServerName: "ad263", TLSCAPEM: ca, BindDN: ownedADCrashAdmin, BindPassword: admin, UsersDN: "OU=TrstctlA263,DC=a263,DC=test", RoleGroups: map[string]string{"directory/durable": dn}})
	if e != nil {
		t.Fatal(e)
	}
	return backend
}
func TestNativeADPreparedResetCrashChildA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_DURABLE_CHILD") != "1" {
		t.Skip("owned native reset worker child only")
	}
	if !filepath.IsAbs(*ownedADCrashEnvelope) || *ownedADCrashBoundary < 0 || *ownedADCrashBoundary > 4 {
		t.Fatal("invalid owned native child reference")
	}
	key, e := secret.New(32)
	if e != nil {
		t.Fatal(e)
	}
	defer key.Destroy()
	if _, e = io.ReadFull(os.Stdin, key.Bytes()); e != nil {
		t.Fatal("owned sealing key pipe unavailable")
	}
	wrapper, e := seal.NewLocalKEK(key.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	defer wrapper.Destroy()
	key.Destroy()
	encrypted, e := secretfile.Load(*ownedADCrashEnvelope)
	if e != nil {
		t.Fatal("owned encrypted preparation unavailable")
	}
	plain, e := seal.Open(wrapper, encrypted, []byte(ownedADCrashAAD))
	if e != nil {
		t.Fatal(e)
	}
	held, e := secret.NewFrom(plain)
	secret.Wipe(plain)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Destroy()
	raw := held.Bytes()
	if len(raw) < 8 || len(raw) > 68<<10 {
		t.Fatal("owned reset envelope exceeds bound")
	}
	preparedLen := int(binary.BigEndian.Uint32(raw[:4]))
	oldLen := int(binary.BigEndian.Uint32(raw[4:8]))
	if preparedLen < 1 || preparedLen > 64<<10 || oldLen < 16 || oldLen > 1024 || 8+preparedLen+oldLen != len(raw) {
		t.Fatal("owned reset envelope framing differs")
	}
	p, e := decodeADStaticPreparation(raw[8 : 8+preparedLen])
	if e != nil {
		t.Fatal(e)
	}
	defer p.destroy()
	old := raw[8+preparedLen:]
	backend := ownedADCrashBackend(t, p.DN)
	defer backend.Close()
	native := abruptADResetRuntime{adPreparedResetRuntime: newADPreparedResetNative(backend, p), baseline: p.KeyVersion, boundary: *ownedADCrashBoundary}
	if e = driveADPreparedReset(t.Context(), p, old, *ownedADCrashInverse, native); e != nil {
		t.Fatal("native durable reset failed", e)
	}
	t.Log("A267_AD_DURABLE_CHILD_OK")
}
func ownedADNativeResetAccount(t *testing.T, ctx context.Context) (string, *secret.Buffer) {
	t.Helper()
	adminRaw, e := os.ReadFile("/run/ad-admin-password")
	if e != nil {
		t.Fatal(e)
	}
	admin, e := secret.NewFrom(adminRaw)
	secret.Wipe(adminRaw)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Destroy)
	ca, e := os.ReadFile("/run/ad-ca.pem")
	if e != nil {
		t.Fatal(e)
	}
	route := ldapbind.PinnedTLS{Address: "ad263:636", ServerName: "ad263", CAPEM: ca}
	open := func(ctx context.Context) (*ldap.Conn, error) {
		raw, e := ldapbind.DialPinned(ctx, route, ownedADCrashAdmin, admin.Bytes())
		if e != nil {
			return nil, e
		}
		conn := ldap.NewConn(raw, true)
		conn.SetTimeout(5 * time.Second)
		conn.Start()
		return conn, nil
	}
	conn, e := open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = conn.Close() }()
	suffix, e := crypto.RandomBytes(4)
	if e != nil {
		t.Fatal(e)
	}
	name := "a267dur_" + hex.EncodeToString(suffix)
	dn := "CN=" + name + ",OU=TrstctlA263,DC=a263,DC=test"
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{name})
	add.Attribute("userAccountControl", []string{"514"})
	if e = conn.Add(add); e != nil {
		t.Fatal("exact owned durable account creation failed")
	}
	result, e := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=user)", []string{"objectGUID"}, nil))
	if e != nil || len(result.Entries) != 1 {
		t.Fatal("owned native account identity unavailable")
	}
	guid := append([]byte(nil), result.Entries[0].GetRawAttributeValue("objectGUID")...)
	if len(guid) != 16 {
		t.Fatal("owned native account GUID unavailable")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		owned, e := open(bounded)
		if e != nil {
			t.Error("owned native account cleanup bind failed")
			return
		}
		defer func() { _ = owned.Close() }()
		found, e := owned.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=user)", []string{"objectGUID"}, nil))
		if e != nil || len(found.Entries) != 1 || !bytes.Equal(found.Entries[0].GetRawAttributeValue("objectGUID"), guid) {
			t.Error("exact owned account cleanup identity differs; preserving it")
			return
		}
		if e = owned.Del(ldap.NewDelRequest(dn, nil)); e != nil {
			t.Error("exact owned native account cleanup failed")
		}
	})
	old, e := newADPreparedPassword()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(old.Destroy)
	if e = ldapbind.ResetADPassword(ctx, route, ownedADCrashAdmin, admin.Bytes(), dn, old.Bytes()); e != nil {
		t.Fatal("owned initial native password unavailable")
	}
	enable := ldap.NewModifyRequest(dn, nil)
	enable.Replace("userAccountControl", []string{"512"})
	if e = conn.Modify(enable); e != nil {
		t.Fatal("owned initial native account could not be enabled")
	}
	return dn, old
}
func runOwnedADCrashWorker(t *testing.T, ctx context.Context, envelope string, key []byte, boundary int, inverse bool) {
	t.Helper()
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	command := exec.CommandContext(ctx, executable, "-test.run=^TestNativeADPreparedResetCrashChildA267$", "-test.v", "-a267-ad-envelope="+envelope, "-a267-ad-boundary="+strconv.Itoa(boundary), "-a267-ad-inverse="+strconv.FormatBool(inverse)) // #nosec G204 -- this exact owned test executable and public fixture references; key material travels only through the anonymous stdin pipe (CWE-78)
	command.Env = []string{"TRSTCTL_AD_DURABLE_CHILD=1"}
	command.Stdin = bytes.NewReader(key)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	e = command.Run()
	defer secret.Wipe(output.Bytes())
	if boundary > 0 {
		var exited *exec.ExitError
		if !errors.As(e, &exited) || exited.ExitCode() != 37 {
			t.Fatal("owned worker did not exit at its completed native write boundary")
		}
		return
	}
	if e != nil || !bytes.Contains(output.Bytes(), []byte("A267_AD_DURABLE_CHILD_OK")) {
		t.Fatal("fresh native worker did not resume its exact encrypted preparation")
	}
}
func ownedADStockBind(t *testing.T, ctx context.Context, dn, name string, password []byte) (bool, bool) {
	t.Helper()
	reader, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = reader.Close() }()
	if _, e = writer.Write(password); e != nil {
		_ = writer.Close()
		t.Fatal(e)
	}
	_ = writer.Close()
	command := exec.CommandContext(ctx, "/usr/bin/ldapsearch", "-LLL", "-x", "-H", "ldaps://ad263:636", "-D", dn, "-y", "/proc/self/fd/3", "-b", dn, "-s", "base", "(objectClass=user)", "sAMAccountName") // #nosec G204 -- fixed stock LDAP binary and exact owned DN; only a private inherited pipe carries the password, no argv/environment/plain file (CWE-78)
	command.Env = []string{"LDAPTLS_CACERT=/run/ad-ca.pem", "LDAPTLS_REQCERT=demand"}
	command.ExtraFiles = []*os.File{reader}
	var public bytes.Buffer
	command.Stdout = &public
	defer func() { secret.Wipe(public.Bytes()) }()
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	e = command.Run()
	defer secret.Wipe(diagnostic.Bytes())
	if e != nil {
		var exited *exec.ExitError
		if !errors.As(e, &exited) {
			t.Logf("stock LDAP launcher failed: %v", e)
		} else {
			t.Logf("stock LDAP exit=%d", exited.ExitCode())
		}
		category := "client-refusal"
		for _, candidate := range []string{"password file", "regular file", "Invalid credentials", "Can't contact LDAP server", "No such file", "Unable to"} {
			if bytes.Contains(diagnostic.Bytes(), []byte(candidate)) {
				category = candidate
				break
			}
		}
		t.Logf("stock LDAP failed category=%s", category)
	}
	return e == nil && bytes.Contains(public.Bytes(), []byte("sAMAccountName: "+name+"\n")), e != nil && bytes.Contains(diagnostic.Bytes(), []byte("Invalid credentials (49)"))
}

func TestNativeADPreparedResetSurvivesEveryWorkerExitA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_DURABLE_LAB") != "1" {
		t.Skip("owned native AD abrupt worker lab not requested")
	}
	for boundary := 1; boundary <= 4; boundary++ {
		t.Run(strconv.Itoa(boundary), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			dn, old := ownedADNativeResetAccount(t, ctx)
			backend := ownedADCrashBackend(t, dn)
			defer backend.Close()
			prepared, e := backend.PrepareStaticCredential(ctx, GenerateRequest{Role: "directory/durable", Static: true, LeaseID: "owned-durable-" + strconv.Itoa(boundary), Predecessor: dn}, strings.Repeat("a", 64))
			if e != nil {
				t.Fatal("durable native preparation unavailable", e)
			}
			defer secret.Wipe(prepared)
			p, e := decodeADStaticPreparation(prepared)
			if e != nil {
				t.Fatal(e)
			}
			defer p.destroy()
			body, e := secret.New(8 + len(prepared) + len(old.Bytes()))
			if e != nil {
				t.Fatal(e)
			}
			defer body.Destroy()
			if len(prepared) > 64<<10 || len(old.Bytes()) > 1024 {
				t.Fatal("owned native preparation exceeds frame bound")
			}
			binary.BigEndian.PutUint32(body.Bytes()[:4], uint32(len(prepared)))     // #nosec G115 -- preparation is checked at <=64KiB before conversion (CWE-190)
			binary.BigEndian.PutUint32(body.Bytes()[4:8], uint32(len(old.Bytes()))) // #nosec G115 -- predecessor is checked at <=1024 bytes before conversion (CWE-190)
			copy(body.Bytes()[8:], prepared)
			copy(body.Bytes()[8+len(prepared):], old.Bytes())
			random, e := crypto.RandomBytes(32)
			if e != nil {
				t.Fatal(e)
			}
			master, e := secret.NewFrom(random)
			secret.Wipe(random)
			if e != nil {
				t.Fatal(e)
			}
			defer master.Destroy()
			wrapper, e := seal.NewLocalKEK(master.Bytes())
			if e != nil {
				t.Fatal(e)
			}
			defer wrapper.Destroy()
			encrypted, e := seal.Seal(wrapper, body.Bytes(), []byte(ownedADCrashAAD))
			if e != nil {
				t.Fatal(e)
			}
			body.Destroy()
			secret.Wipe(prepared)
			reference := filepath.Join(t.TempDir(), "prepared.sealed")
			if e = secretfile.Create(reference, encrypted); e != nil {
				t.Fatal(e)
			}
			if boundary > 2 {
				runOwnedADCrashWorker(t, ctx, reference, master.Bytes(), 0, false)
			}
			runOwnedADCrashWorker(t, ctx, reference, master.Bytes(), boundary, boundary > 2)
			native := newADPreparedResetNative(backend, p)
			current, e := native.Observe(ctx)
			if e != nil || current.KeyVersion != p.KeyVersion+uint64(boundary&0x7) {
				t.Fatal("abrupt worker exit did not preserve exactly its completed native write", e)
			}
			runOwnedADCrashWorker(t, ctx, reference, master.Bytes(), 0, boundary > 2)
			target := uint64(2)
			accepted, rejected := p.Password, old.Bytes()
			if boundary > 2 {
				target = 4
				accepted, rejected = old.Bytes(), p.Password
			}
			current, e = native.Observe(ctx)
			if e != nil || current.KeyVersion != p.KeyVersion+target {
				t.Fatal("fresh worker repeated a native reset after process exit", e)
			}
			if okay, _ := ownedADStockBind(t, ctx, dn, p.Name, accepted); !okay {
				t.Fatal("stock LDAP client refused the current native credential")
			}
			if okay, refused := ownedADStockBind(t, ctx, dn, p.Name, rejected); okay || !refused {
				t.Fatal("stock LDAP client accepted the retired native generation")
			}
			if okay, _ := ownedADStockBind(t, ctx, dn, p.Name, accepted); !okay {
				t.Fatal("stock valid bind did not recover the owned account after the one deliberate retired-password refusal")
			}
			runOwnedADCrashWorker(t, ctx, reference, master.Bytes(), 0, boundary > 2)
			current, e = native.Observe(ctx)
			if e != nil || current.KeyVersion != p.KeyVersion+target {
				t.Fatal("completed native worker replay repeated a reset", e)
			}
		})
	}
	if t.Failed() {
		return
	}
	t.Log("A267_AD_DURABLE_EXIT_OK: four actual worker exits after native writes, encrypted preparation reload, exact native version counts, stock LDAP current acceptance/retired refusal and no-write replay; concurrent external administrative reset is not atomic CAS")
}

func TestNativeADPreparedResetRefusesSerialDriftA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_DURABLE_LAB") != "1" {
		t.Skip("owned native AD serial drift lab not requested")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	dn, old := ownedADNativeResetAccount(t, ctx)
	_ = old
	backend := ownedADCrashBackend(t, dn)
	defer backend.Close()
	req := GenerateRequest{Role: "directory/durable", Static: true, LeaseID: "owned-durable-drift", Predecessor: dn}
	binding := strings.Repeat("a", 64)
	raw, e := backend.PrepareStaticCredential(ctx, req, binding)
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(raw)
	p, e := decodeADStaticPreparation(raw)
	if e != nil {
		t.Fatal(e)
	}
	defer p.destroy()
	native := newADPreparedResetNative(backend, p)
	initial, e := native.Observe(ctx)
	if e != nil {
		t.Fatal(e)
	}
	foreign, e := newADPreparedPassword()
	if e != nil {
		t.Fatal(e)
	}
	defer foreign.Destroy()
	// This deliberate external administrative effect occupies the first native
	// version with a different credential from the frozen operation.
	if e = native.Reset(ctx, initial, foreign.Bytes(), false); e != nil {
		t.Fatal(e)
	}
	readCounts := func() (uint64, uint64) {
		t.Helper()
		var version, bad uint64
		e := backend.bindPassword.Use(func(admin []byte) error {
			transport, e := ldapbind.DialPinned(ctx, native.route, ownedADCrashAdmin, admin)
			if e != nil {
				return e
			}
			conn := ldap.NewConn(transport, true)
			conn.SetTimeout(5 * time.Second)
			conn.Start()
			defer func() { _ = conn.Close() }()
			values, e := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=user)", []string{"msDS-KeyVersionNumber", "badPwdCount"}, nil))
			if e != nil || len(values.Entries) != 1 {
				return errors.New("owned drift counters unavailable")
			}
			version, e = strconv.ParseUint(values.Entries[0].GetAttributeValue("msDS-KeyVersionNumber"), 10, 32)
			if e != nil {
				return e
			}
			bad, e = strconv.ParseUint(values.Entries[0].GetAttributeValue("badPwdCount"), 10, 32)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		return version, bad
	}
	for attempt := 0; attempt < 3; attempt++ {
		_, value, e := backend.GenerateStaticPrepared(ctx, req, raw, binding)
		secret.Wipe(value)
		if e == nil {
			t.Fatal("unrelated native password was overwritten")
		}
		version, bad := readCounts()
		if version != p.KeyVersion+1 || bad != 1 {
			t.Fatal("serial drift caused another reset or password candidate", version, bad)
		}
	}
	if okay, _ := ownedADStockBind(t, ctx, dn, p.Name, foreign.Bytes()); !okay {
		t.Fatal("the unrelated native credential was changed")
	}
	t.Log("A267_AD_DURABLE_DRIFT_OK: serial native password drift refused, one selected-credential attempt only, subsequent lockout-aware retries send none, unrelated credential preserved")
}
