// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
)

type observedImportSigner struct {
	crypto.DigestSigner
}

func (s observedImportSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	fmt.Println("fixture ceremony signature")
	return s.DigestSigner.SignDigest(digest, opts)
}

func TestHierarchyImportProcessHelper(t *testing.T) {
	role := os.Getenv("TRSTCTL_TEST_IMPORT_ROLE")
	if role == "" {
		return
	}
	var socket string
	switch role {
	case "publisher":
		socket = "publisher.sock"
	case "replica":
		socket = "replica.sock"
	default:
		t.Fatal("unknown import fixture process role")
	}
	wrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x53}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	authorizer, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x35}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer authorizer.Destroy()
	store := NewKeyStore("keys", wrapper)
	server, err := NewPersistentServer(store, WithAuthorizer(authorizer))
	if err != nil {
		t.Fatal(err)
	}
	server.beforeImportOpen = func() { fmt.Println("fixture HPKE open") }
	server.checkImportedKey = func(key crypto.DigestSigner) error {
		fmt.Println("fixture ceremony key check")
		return ceremonyCheck(observedImportSigner{DigestSigner: key})
	}
	handle := crypto.CAHierarchySignerHandle(recoveryImportCeremony)
	store.beforeHierarchyFileSync = func(name string) error {
		if name == handle+keyFileExt+custodyStageExt {
			fmt.Println("fixture key file sync")
		}
		return nil
	}
	if role == "publisher" {
		store.beforeHierarchySync = func() error {
			published, err := store.hierarchyEntryExists(handle + keyFileExt)
			if err != nil || !published {
				return err
			}
			fmt.Println("fixture publication barrier")
			var signal [1]byte
			if _, err := io.ReadFull(os.Stdin, signal[:]); err != nil {
				return err
			}
			return errors.New("fixture publisher lost its acknowledgement")
		}
		// Prove that the actual P-256 weak-key check this import needs has
		// completed before the parent times publication. The serving path
		// warms all four EC curves in the background; waiting for all of them
		// here couples this P-256 proof to unrelated curve startup cost.
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer key.Destroy()
			if err := crypto.RefuseWeakKey(key.Public()); err != nil {
				fmt.Println("fixture P-256 weak-key check failed:", err)
				return
			}
			fmt.Println("fixture P-256 weak-key check ready")
		}()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := ServeServerWithOptions(ctx, socket, server,
		ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"}); err != nil {
		t.Fatal(err)
	}
}

type importProofProcess struct {
	client *Client
	input  io.WriteCloser
	output func() string
}

func startImportProofProcess(t *testing.T, dir, role string) importProofProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	logName := role + ".log"
	log, err := root.OpenFile(logName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	socket := filepath.Join(dir, role+".sock")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestHierarchyImportProcessHelper$") // #nosec G204 -- test reexecutes its exact test binary with a fixed selector (CWE-78)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TRSTCTL_TEST_IMPORT_ROLE="+role)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		cancel()
		if err := cmd.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("%s helper process: %v", role, err)
		}
	})
	readEffects := func() string {
		data, err := root.ReadFile(logName)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	client, err := DialReady(t.Context(), socket, 15*time.Second)
	if err != nil {
		t.Fatalf("connect %s signer: %v %s", role, err, readEffects())
	}
	if role == "publisher" {
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		poll := time.NewTicker(10 * time.Millisecond)
		defer poll.Stop()
		for !strings.Contains(readEffects(), "fixture P-256 weak-key check ready") {
			select {
			case <-deadline.C:
				t.Fatalf("%s signer did not finish its P-256 weak-key check: %s", role, readEffects())
			case <-poll.C:
			}
		}
	}
	t.Cleanup(func() { _ = client.Close() })
	return importProofProcess{client: client, input: input, output: readEffects}
}

func TestImportReceiptRecoversAnInterruptedPublicationAcrossSignerProcesses(t *testing.T) {
	dir, err := os.MkdirTemp("", "trstctl-import-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	f := newImportRecoveryFixtureAt(t, keys)
	_, request := f.prepare(t)
	publisher := startImportProofProcess(t, dir, "publisher")
	replica := startImportProofProcess(t, dir, "replica")
	published := make(chan error, 1)
	go func() {
		_, err := publisher.client.svc.ImportWrappedKeyV2(t.Context(), request)
		published <- err
	}()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for !strings.Contains(publisher.output(), "fixture publication barrier") {
		select {
		case err := <-published:
			t.Fatalf("publisher exited before the barrier: %v", err)
		case <-deadline.C:
			t.Fatal("publisher did not reach the barrier")
		case <-poll.C:
		}
	}
	name := f.policy.Handle + keyFileExt
	root, err := os.OpenRoot(f.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	initial, err := root.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replica.client.svc.ImportWrappedKeyV2(t.Context(), request); status.Code(err) != codes.Unavailable {
		t.Fatalf("contending signer = %v, want Unavailable", err)
	}
	if _, err := publisher.input.Write([]byte{'r'}); err != nil {
		t.Fatal(err)
	}
	if err := <-published; status.Code(err) != codes.Internal {
		t.Fatalf("interrupted publisher = %v, want Internal", err)
	}
	result, err := replica.client.svc.ImportWrappedKeyV2(t.Context(), request)
	if err != nil || !bytes.Equal(result.GetPublicKey(), f.policy.ExpectedPublicKey) {
		t.Fatal("second signer did not recover the original result", err)
	}
	after, err := root.Stat(name)
	if err != nil || !os.SameFile(initial, after) {
		t.Fatal("receipt recovery changed the file installed by the first signer", err)
	}
	afterSealed, err := root.ReadFile(name)
	if err != nil || !bytes.Equal(afterSealed, sealed) {
		t.Fatal("receipt recovery changed the installed key bytes", err)
	}
	for _, event := range []string{"fixture HPKE open", "fixture ceremony key check", "fixture key file sync"} {
		if count := strings.Count(publisher.output(), event); count != 1 {
			t.Errorf("publisher reported %d occurrences of %q, want one", count, event)
		}
		if count := strings.Count(replica.output(), event); count != 0 {
			t.Errorf("receipt recovery reported %d occurrences of %q, want zero", count, event)
		}
	}
	// The current ceremony check verifies public key strength. The control
	// plane's later possession signature falls outside this signer replay.
	if strings.Contains(publisher.output(), "fixture ceremony signature") || strings.Contains(replica.output(), "fixture ceremony signature") {
		t.Fatal("the signer import or its receipt recovery signed during its ceremony check")
	}
	assertImportName(t, f.store, keyImportPreparationName(f.policy.Handle), false)
}
