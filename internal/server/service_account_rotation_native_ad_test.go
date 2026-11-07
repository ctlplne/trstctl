// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

// Real directory and PostgreSQL; host native observations remain explicitly
// signed boundary fixtures. Windows receiver execution has its own required lab.
type dependentNativeDirectoryFixture struct {
	provider dynsecret.Provider
	store    *store.Store
	identity servicedependents.AccountBinding
	initial  *secret.Buffer
	drift    *secret.Buffer
}

func newNativeDependentDirectoryFixture(t *testing.T) *dependentNativeDirectoryFixture {
	t.Helper()
	const dn = "CN=a267-discovery-bound,OU=TrstctlA263,DC=a263,DC=test"
	cfg := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "ad-native-dependents", Type: "ldap", DirectoryMode: "active_directory", Addr: "ad263:636", TLSServerName: "ad263", TLSCARef: "file:/run/ad-ca.pem", BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", PasswordRef: "file:/run/ad-admin-password", UsersDN: "OU=TrstctlA263,DC=a263,DC=test", AllowedRoles: []string{"app/dependent"}, RoleBindings: map[string]string{"app/dependent": dn}, AllowStaticRotation: true, MaxTTL: "1h"} // #nosec G101 -- protected lab credential-file reference only, never a credential value (CWE-798)
	providers, err := dynamicSecretProvidersFromConfig(t.Context(), []config.DynamicSecretProviderConfig{cfg}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	provider := providers[servedTestTenant][0]
	if _, ok := provider.(dynsecret.PreparedStaticRotationProvider); !ok {
		t.Fatal("native provider lacks durable preparation")
	}
	discoverer, ok := provider.(pamAccountDiscoverer)
	if !ok {
		t.Fatal("native provider lacks directory discovery")
	}
	accounts, err := discoverer.DynamicSecretDiscoverAccounts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var identity servicedependents.AccountBinding
	for _, account := range accounts {
		if dynsecret.SameADNativeDN(account.Details["dn"], dn) {
			if identity.DN != "" {
				t.Fatal("owned native account is ambiguous")
			}
			identity = servicedependents.AccountBinding{ProviderID: cfg.ID, Name: account.Name, DN: account.Details["dn"], SID: account.Details["native_sid"], GUID: account.Details["native_guid"]}
		}
	}
	if identity.DN == "" || identity.SID == "" || len(identity.GUID) != 32 {
		t.Fatal("owned native account identity unavailable")
	}
	// Assisted fixture setup establishes a valid random predecessor before host
	// admission. The tested change itself uses the normal durable outbox worker.
	credential, err := provider.Generate(t.Context(), dynsecret.GenerateRequest{Role: "app/dependent", Static: true, LeaseID: uuid.NewString(), Predecessor: identity.DN, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(credential.Secret)
	initial, err := secret.NewFrom(credential.Secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(initial.Destroy)
	return &dependentNativeDirectoryFixture{provider: provider, store: nativeDesktopOwnedStore(t), identity: identity, initial: initial}
}

func TestServedNativeADDependentCoordinatorA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_SERVED_LAB") != "1" {
		t.Skip("owned Samba and PostgreSQL native coordinator lab not requested")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("native Samba coordinator requires the retained Linux stock-client lab")
	}
	for _, failure := range []bool{false, true} {
		name := "forward"
		if failure {
			name = "dependent failure"
		}
		t.Run(name, func(t *testing.T) {
			native := newNativeDependentDirectoryFixture(t)
			servedDependentRotationCase(t, native, failure)
		})
	}
	if !t.Failed() {
		t.Log("A267_NATIVE_AD_COORDINATOR_OK: real native directory forward and inverse, stock acceptance/refusal, signed host boundary fixtures, durable source and vault publication barriers")
	}
}

func nativeDependentStockBind(t *testing.T, ctx context.Context, identity servicedependents.AccountBinding, credential []byte) bool {
	t.Helper()
	var value struct {
		Password secret.JSONBytes `json:"password"`
	}
	if json.Unmarshal(credential, &value) != nil || len(value.Password) == 0 {
		t.Fatal("native stock credential unavailable")
	}
	defer secret.Wipe(value.Password)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if _, err = writer.Write(value.Password); err != nil {
		_ = writer.Close()
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "/usr/bin/ldapsearch", "-LLL", "-x", "-H", "ldaps://ad263:636", "-D", identity.DN, "-y", "/proc/self/fd/3", "-b", identity.DN, "-s", "base", "(objectClass=user)", "sAMAccountName") // #nosec G204 -- fixed read-only stock client and independently selected owned account; credential only in an inherited pipe, no shell or credential argv (CWE-78)
	command.ExtraFiles = []*os.File{reader}
	command.Env = []string{"LDAPTLS_CACERT=/run/ad-ca.pem", "LDAPTLS_REQCERT=demand"}
	var public, diagnostic bytes.Buffer
	command.Stdout = &public
	command.Stderr = &diagnostic
	defer func() { secret.Wipe(public.Bytes()); secret.Wipe(diagnostic.Bytes()) }()
	err = command.Run()
	if err == nil {
		if !strings.Contains(public.String(), "sAMAccountName: "+identity.Name) {
			t.Fatal("stock native bind read another account")
		}
		return true
	}
	var exited *exec.ExitError
	if !errors.As(err, &exited) || !bytes.Contains(diagnostic.Bytes(), []byte("Invalid credentials (49)")) {
		t.Fatal("stock native bind failed without an explicit credential refusal")
	}
	return false
}

func assertNativeDependentDirectory(t *testing.T, native *dependentNativeDirectoryFixture, directory *dependentDirectoryBoundary, old []byte, inverse bool) {
	t.Helper()
	directory.mu.Lock()
	current := append([]byte(nil), directory.current.Bytes()...)
	retired := append([]byte(nil), old...)
	if inverse {
		secret.Wipe(retired)
		if directory.lastNative == nil {
			directory.mu.Unlock()
			t.Fatal("native successor custody missing")
		}
		retired = append([]byte(nil), directory.lastNative.Bytes()...)
	}
	directory.mu.Unlock()
	defer secret.Wipe(current)
	defer secret.Wipe(retired)
	if !nativeDependentStockBind(t, t.Context(), native.identity, current) {
		t.Fatal("coordinator final credential rejected by stock LDAP")
	}
	if nativeDependentStockBind(t, t.Context(), native.identity, retired) {
		t.Fatal("coordinator retired generation still accepted by stock LDAP")
	}
	// One intentional retired-password refusal is followed by exactly the known
	// current value; clear its lockout counter without trying other candidates.
	if !nativeDependentStockBind(t, t.Context(), native.identity, current) {
		t.Fatal("known current native generation did not clear the owned refusal")
	}
	if native.drift != nil {
		if nativeDependentStockBind(t, t.Context(), native.identity, native.drift.Bytes()) {
			t.Fatal("reconciliation left independent drift generation accepted")
		}
		if !nativeDependentStockBind(t, t.Context(), native.identity, current) {
			t.Fatal("known reconciled generation did not clear the single owned drift refusal")
		}
	}

}
