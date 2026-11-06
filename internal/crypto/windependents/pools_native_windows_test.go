//go:build windows

// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"unsafe"
)

func setIISPublic(element *automationObject, name, value string) error {
	property, err := iisProperty(element, name)
	if err != nil {
		return err
	}
	defer property.destroy()
	text, err := newAutomationPublicString(value)
	if err != nil {
		return err
	}
	defer func() { _ = text.destroy() }()
	return property.set("Value", text.variant())
}
func setIISNumber(element *automationObject, name string, value uint32) error {
	property, err := iisProperty(element, name)
	if err != nil {
		return err
	}
	defer property.destroy()
	return property.set("Value", automationInteger(value))
}
func createIISFixtureElement(collection *automationObject, kind string) (*automationObject, error) {
	name, err := newAutomationPublicString(kind)
	if err != nil {
		return nil, err
	}
	defer func() { _ = name.destroy() }()
	return collection.object("CreateNewElement", 1, name.variant())
}
func addIISFixtureElement(collection, element *automationObject) error {
	value, err := collection.call("AddElement", 1, automationVariant{VT: 9, Value: element.pointer})
	value.destroy()
	return err
}
func nativeOwnedIISDirectory(t *testing.T, suffix, sid string) string {
	t.Helper()
	decoded, err := hex.DecodeString(suffix)
	if err != nil || len(decoded) != 4 || !validAccountSID(sid) {
		t.Fatal("invalid owned IIS directory identity")
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "trstctl-a267-iis-"+suffix)
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	if err := windows.CreateDirectory(nativeOwnedWide(t, path), &attributes); err != nil {
		t.Fatal("exact owned protected IIS directory creation failed")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error("exact owned IIS directory cleanup failed")
		}
	})
	page := `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<script runat="server">
protected void Page_Load(object sender, System.EventArgs e) {
 string nonce=Request.QueryString["nonce"];
 if(nonce==null || !System.Text.RegularExpressions.Regex.IsMatch(nonce,"^[0-9a-f]{32}$")) {Response.StatusCode=400;return;}
 string result;
 using(var hash=SHA256.Create()) {result=System.BitConverter.ToString(hash.ComputeHash(Encoding.ASCII.GetBytes("pool-work:"+nonce))).Replace("-","").ToLowerInvariant();}
 Response.ContentType="application/json";
 Response.Write("{\"nonce\":\""+nonce+"\",\"sid\":\""+WindowsIdentity.GetCurrent().User.Value+"\",\"pid\":"+Process.GetCurrentProcess().Id+",\"result\":\""+result+"\"}");
}
</script>`
	config := `<configuration><system.web><identity impersonate="false"/></system.web></configuration>`
	if err := os.WriteFile(filepath.Join(path, "default.aspx"), []byte(page), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "web.config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func createOwnedIISPool(t *testing.T, ctx context.Context, name, account string, password []byte) {
	t.Helper()
	err := withIISPools(ctx, func(manager, collection *automationObject) error {
		pool, err := createIISFixtureElement(collection, "add")
		if err != nil {
			return err
		}
		defer pool.destroy()
		if err := setIISPublic(pool, "name", name); err != nil {
			return err
		}
		if err := setIISPublic(pool, "managedRuntimeVersion", "v4.0"); err != nil {
			return err
		}
		process, err := iisChild(pool, "processModel")
		if err != nil {
			return err
		}
		defer process.destroy()
		if err := setIISNumber(process, "identityType", 3); err != nil {
			return err
		}
		if err := setIISPublic(process, "userName", account); err != nil {
			return err
		}
		property, err := iisProperty(process, "password")
		if err != nil {
			return err
		}
		defer property.destroy()
		provider, err := iisPublicMetadata(property, "encryptionProvider")
		if err != nil || provider == "" {
			return errors.New("owned native IIS encryption provider unavailable")
		}
		key, err := newAutomationPublicString("encryptionProvider")
		if err != nil {
			return err
		}
		defer func() { _ = key.destroy() }()
		providerName, err := newAutomationPublicString(provider)
		if err != nil {
			return err
		}
		defer func() { _ = providerName.destroy() }()
		value, err := property.call("SetMetadata", 1, key.variant(), providerName.variant())
		value.destroy()
		if err != nil {
			return err
		}
		credential, err := newAutomationPassword(password)
		if err != nil {
			return err
		}
		defer func() { _ = credential.destroy() }()
		if err := property.set("Value", credential.variant()); err != nil {
			return err
		}
		if err := addIISFixtureElement(collection, pool); err != nil {
			return err
		}
		value, err = manager.call("CommitChanges", 1)
		value.destroy()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteOwnedIISObject(t, nativeIISPools, name) })
}

func createOwnedIISSite(t *testing.T, ctx context.Context, name, poolName, physical, address string, siteID uint32) {
	t.Helper()
	err := withIISCollection(ctx, "system.applicationHost/sites", func(manager, collection *automationObject) error {
		site, err := createIISFixtureElement(collection, "site")
		if err != nil {
			return err
		}
		defer site.destroy()
		if err := setIISPublic(site, "name", name); err != nil {
			return err
		}
		if err := setIISNumber(site, "id", siteID); err != nil {
			return err
		}
		applications, err := site.object("Collection", 2)
		if err != nil {
			return err
		}
		defer applications.destroy()
		application, err := createIISFixtureElement(applications, "application")
		if err != nil {
			return err
		}
		defer application.destroy()
		if err := setIISPublic(application, "path", "/"); err != nil {
			return err
		}
		if err := setIISPublic(application, "applicationPool", poolName); err != nil {
			return err
		}
		directories, err := application.object("Collection", 2)
		if err != nil {
			return err
		}
		defer directories.destroy()
		directory, err := createIISFixtureElement(directories, "virtualDirectory")
		if err != nil {
			return err
		}
		defer directory.destroy()
		if err := setIISPublic(directory, "path", "/"); err != nil {
			return err
		}
		if err := setIISPublic(directory, "physicalPath", physical); err != nil {
			return err
		}
		if err := addIISFixtureElement(directories, directory); err != nil {
			return err
		}
		if err := addIISFixtureElement(applications, application); err != nil {
			return err
		}
		bindings, err := iisChild(site, "bindings")
		if err != nil {
			return err
		}
		defer bindings.destroy()
		bindCollection, err := bindings.object("Collection", 2)
		if err != nil {
			return err
		}
		defer bindCollection.destroy()
		binding, err := createIISFixtureElement(bindCollection, "binding")
		if err != nil {
			return err
		}
		defer binding.destroy()
		if err := setIISPublic(binding, "protocol", "http"); err != nil {
			return err
		}
		if err := setIISPublic(binding, "bindingInformation", address+":"); err != nil {
			return err
		}
		if err := addIISFixtureElement(bindCollection, binding); err != nil {
			return err
		}
		if err := addIISFixtureElement(collection, site); err != nil {
			return err
		}
		value, err := manager.call("CommitChanges", 1)
		value.destroy()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteOwnedIISObject(t, "system.applicationHost/sites", name) })
}
func deleteOwnedIISObject(t *testing.T, section, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := withIISCollection(ctx, section, func(manager, collection *automationObject) error {
		count, err := collection.integer("Count")
		if err != nil || count < 0 || count > 1024 {
			return errors.New("owned native IIS cleanup census invalid")
		}
		for i := uint32(0); i < uint32(count&0xffffffff); i++ {
			object, err := collection.object("Item", 2, automationInteger(i))
			if err != nil {
				return err
			}
			actual, err := iisPublicProperty(object, "name")
			if err != nil {
				object.destroy()
				return err
			}
			if actual != name {
				object.destroy()
				continue
			}
			_ = executePoolMethod(object, "Stop")
			object.destroy()
			value, err := collection.call("DeleteElement", 1, automationInteger(i))
			value.destroy()
			if err != nil {
				return err
			}
			value, err = manager.call("CommitChanges", 1)
			value.destroy()
			return err
		}
		return errors.New("exact owned native IIS object disappeared")
	})
	if err != nil {
		t.Error("exact owned IIS object cleanup failed")
	}
}

type nativePoolWorkReceipt struct {
	Nonce  string
	SID    string
	PID    uint32
	Result string
}

func nativeIISWork(t *testing.T, ctx context.Context, address, sid string) nativePoolWorkReceipt {
	t.Helper()
	random, err := crypto.RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(random)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("owned IIS probe refuses redirects") }}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/default.aspx?nonce="+nonce, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err == nil {
			var receipt nativePoolWorkReceipt
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&receipt)
			_ = response.Body.Close()
			if response.StatusCode == 200 && decodeErr == nil && receipt.Nonce == nonce && receipt.SID == sid && receipt.PID != 0 && receipt.Result == crypto.SHA256Hex([]byte("pool-work:"+nonce)) {
				return receipt
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("owned IIS functional work canceled")
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("fresh native IIS worker did not complete functional HTTP work")
	return nativePoolWorkReceipt{}
}

func verifyOwnedPoolWorkIdentity(t *testing.T, workers []PoolWorker, receipt nativePoolWorkReceipt) {
	t.Helper()
	for _, worker := range workers {
		if worker.ProcessID == receipt.PID && worker.AccountSID == receipt.SID {
			return
		}
	}
	t.Fatal("HTTP work did not come from the independently verified native pool worker")
}
func TestNativeWindowsIISPoolLifecycleA267(t *testing.T) {
	if os.Getenv("TRSTCTL_A267_WINDOWS_IIS") != "1" {
		t.Skip("owned native IIS pool lab not requested")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	random, err := crypto.RandomBytes(4)
	if err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(random)
	name := "trst267_" + suffix
	poolName := "trstctl-a267-pool-" + suffix
	siteName := "trstctl-a267-site-" + suffix
	old, next := nativeOwnedPassword(t), nativeOwnedPassword(t)
	sid := nativeCreateOwnedAccount(t, name, old.Bytes())
	nativeGrantOwnedAccountRight(t, sid, "SeBatchLogonRight")
	path := nativeOwnedIISDirectory(t, suffix, sid.String())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	createOwnedIISPool(t, ctx, poolName, ".\\"+name, old.Bytes())
	createOwnedIISSite(t, ctx, siteName, poolName, path, address, 100000+uint32(random[0])*256+uint32(random[1]))
	first := nativeIISWork(t, ctx, address, sid.String())
	adapter := NewPools()
	found, err := adapter.Discover(ctx, sid.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Name != poolName || !found[0].PasswordProtected || !found[0].WasStarted {
		t.Fatal("native pool discovery/encryption/runtime state differs")
	}
	target := found[0]
	altered := target
	altered.ConfigSHA256 = strings.Repeat("0", 64)
	if err := adapter.UpdatePassword(ctx, altered, next.Bytes()); err == nil {
		t.Fatal("altered native pool configuration admitted")
	}
	nativeSetOwnedPassword(t, name, next.Bytes())
	if err := adapter.UpdatePassword(ctx, target, next.Bytes()); err != nil {
		t.Fatal(err)
	}
	proof, err := adapter.Restart(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	second := nativeIISWork(t, ctx, address, sid.String())
	workers, err := adapter.VerifyWorkers(ctx, target, proof)
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnedPoolWorkIdentity(t, workers, second)
	if first.PID == second.PID {
		t.Fatal("pool reused the predecessor worker")
	}
	if nativeOwnedSignIn(t, name, old.Bytes()) || !nativeOwnedSignIn(t, name, next.Bytes()) {
		t.Fatal("native pool rotation did not refuse/accept exact credentials")
	}
	readback, err := adapter.driver.inspect(ctx, poolName)
	if err != nil || !readback.PasswordProtected || readback.EncryptionProvider != target.EncryptionProvider {
		t.Fatal("native pool did not preserve protected credential storage/provider")
	}
	nativeSetOwnedPassword(t, name, old.Bytes())
	if err := adapter.UpdatePassword(ctx, target, old.Bytes()); err != nil {
		t.Fatal(err)
	}
	recovery, err := adapter.Restart(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	restored := nativeIISWork(t, ctx, address, sid.String())
	workers, err = adapter.VerifyWorkers(ctx, target, recovery)
	if err != nil {
		t.Fatal(err)
	}
	verifyOwnedPoolWorkIdentity(t, workers, restored)
	if restored.PID == second.PID {
		t.Fatal("pool recovery reused the successor worker")
	}
	if !nativeOwnedSignIn(t, name, old.Bytes()) || nativeOwnedSignIn(t, name, next.Bytes()) {
		t.Fatal("native pool recovery did not restore/refuse exact credentials")
	}
	t.Log("A267_WINDOWS_IIS_OK: native pool/site, protected provider readback, fresh HTTP work plus native worker SID, credential rotation and recovery; local SAM is not a forest")
}
