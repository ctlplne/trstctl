// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// fakeTenantKEK stands in for the HSM-backed custody: its "wrapped KEK" names
// the wrapper and binding, so a wrong binding fails as an unwrap would.
type fakeTenantKEK struct {
	wrappers map[string]bool
	closed   bool
}

func (f *fakeTenantKEK) wrappedFor(wrapperID string, binding []byte) []byte {
	return append([]byte("kek|"+wrapperID+"|"), binding...)
}

func (f *fakeTenantKEK) check(wrapperID string, wrapped, binding []byte) error {
	if !f.wrappers[wrapperID] {
		return signing.ErrTenantKEKWrapperUnknown
	}
	if wrapped != nil && !bytes.Equal(wrapped, f.wrappedFor(wrapperID, binding)) {
		return tenantwrap.ErrUnwrap
	}
	return nil
}

func (f *fakeTenantKEK) CreateDomainKEK(_ context.Context, wrapperID string, binding []byte) ([]byte, error) {
	if err := f.check(wrapperID, nil, binding); err != nil {
		return nil, err
	}
	return f.wrappedFor(wrapperID, binding), nil
}

func (f *fakeTenantKEK) OpenDomainKEK(_ context.Context, wrapperID string, wrapped, binding []byte) error {
	return f.check(wrapperID, wrapped, binding)
}

func (f *fakeTenantKEK) WrapDataKey(_ context.Context, wrapperID string, wrapped, binding, dataKey []byte) ([]byte, error) {
	if err := f.check(wrapperID, wrapped, binding); err != nil {
		return nil, err
	}
	out := []byte("dek|")
	for _, b := range dataKey {
		out = append(out, b^0x5a)
	}
	return out, nil
}

func (f *fakeTenantKEK) UnwrapDataKey(_ context.Context, wrapperID string, wrapped, binding, wrappedDataKey []byte) ([]byte, error) {
	if err := f.check(wrapperID, wrapped, binding); err != nil {
		return nil, err
	}
	body, ok := bytes.CutPrefix(wrappedDataKey, []byte("dek|"))
	if !ok {
		return nil, tenantwrap.ErrUnwrap
	}
	out := make([]byte, len(body))
	for i, b := range body {
		out[i] = b ^ 0x5a
	}
	return out, nil
}

func (f *fakeTenantKEK) Close() error {
	f.closed = true
	return nil
}

// A123: over the authenticated socket the control plane creates a tenant
// domain KEK and gets back only its wrapped form, proves it opens, and wraps
// and unwraps data keys through it; a wrong binding is an unwrap failure, an
// unknown wrapper is reported as such, and shutdown closes the custody.
func TestTenantKEKCustodyRoundTripsOverTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "tenant-kek")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	custody := &fakeTenantKEK{wrappers: map[string]bool{"hsm-a": true}}
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, signing.NewServer(signing.WithTenantKEKCustody(custody)), devServeOptions())
	}()
	client := waitReady(t, socket)
	defer func() { _ = client.Close() }()

	binding := []byte("tenant=t1;domain=d1;generation=1")
	wrapped, err := client.CreateTenantDomainKEK(ctx, "hsm-a", binding)
	if err != nil || !bytes.Equal(wrapped, custody.wrappedFor("hsm-a", binding)) {
		t.Fatalf("create = %q, %v", wrapped, err)
	}
	if err := client.OpenTenantDomainKEK(ctx, "hsm-a", wrapped, binding); err != nil {
		t.Fatalf("open the created domain KEK: %v", err)
	}
	if err := client.OpenTenantDomainKEK(ctx, "hsm-a", wrapped, []byte("tenant=t2;domain=d1;generation=1")); !errors.Is(err, tenantwrap.ErrUnwrap) {
		t.Fatalf("open under another binding = %v, want an unwrap failure", err)
	}
	dek, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	wrappedDEK, err := client.WrapTenantDataKey(ctx, "hsm-a", wrapped, binding, dek)
	if err != nil || bytes.Contains(wrappedDEK, dek) {
		t.Fatalf("wrap a data key = %v (or the data key crossed in the clear)", err)
	}
	back, err := client.UnwrapTenantDataKey(ctx, "hsm-a", wrapped, binding, wrappedDEK)
	if err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("unwrap the data key = %v", err)
	}
	if _, err := client.CreateTenantDomainKEK(ctx, "hsm-b", binding); !errors.Is(err, signing.ErrTenantKEKWrapperUnknown) {
		t.Fatalf("create under an unknown wrapper = %v, want ErrTenantKEKWrapperUnknown", err)
	}
	if _, err := client.WrapTenantDataKey(ctx, "hsm-a", wrapped, binding, dek[:31]); err == nil {
		t.Fatal("a 31-byte data key was wrapped")
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("ServeServerWithOptions: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tenant KEK server did not stop")
	}
	if !custody.closed {
		t.Fatal("shutdown did not close the tenant KEK custody")
	}
}

// A signer without tenant KEK custody answers UNIMPLEMENTED, and every request
// outside the bounds is refused before the custody sees it.
func TestTenantKEKRequestsAreBoundedAndNeedCustody(t *testing.T) {
	ctx := context.Background()
	bare := signing.NewServer()
	if _, err := bare.CreateTenantDomainKEK(ctx, &signerpb.CreateTenantDomainKEKRequest{WrapperId: "hsm-a", Binding: []byte("b")}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("create without custody = %v, want Unimplemented", status.Code(err))
	}

	s := signing.NewServer(signing.WithTenantKEKCustody(&fakeTenantKEK{wrappers: map[string]bool{"hsm-a": true}}))
	binding := []byte("tenant=t1;domain=d1;generation=1")
	wrapped := []byte("kek|hsm-a|tenant=t1;domain=d1;generation=1")
	dek := bytes.Repeat([]byte{7}, 32)
	long := strings.Repeat("w", 129)
	for name, call := range map[string]func() error{
		"nil create": func() error { _, err := s.CreateTenantDomainKEK(ctx, nil); return err },
		"empty wrapper": func() error {
			_, err := s.CreateTenantDomainKEK(ctx, &signerpb.CreateTenantDomainKEKRequest{Binding: binding})
			return err
		},
		"padded wrapper": func() error {
			_, err := s.CreateTenantDomainKEK(ctx, &signerpb.CreateTenantDomainKEKRequest{WrapperId: " hsm-a", Binding: binding})
			return err
		},
		"long wrapper": func() error {
			_, err := s.CreateTenantDomainKEK(ctx, &signerpb.CreateTenantDomainKEKRequest{WrapperId: long, Binding: binding})
			return err
		},
		"empty binding": func() error {
			_, err := s.CreateTenantDomainKEK(ctx, &signerpb.CreateTenantDomainKEKRequest{WrapperId: "hsm-a"})
			return err
		},
		"long binding": func() error {
			_, err := s.CreateTenantDomainKEK(ctx, &signerpb.CreateTenantDomainKEKRequest{WrapperId: "hsm-a", Binding: make([]byte, 513)})
			return err
		},
		"open without wrapped": func() error {
			_, err := s.OpenTenantDomainKEK(ctx, &signerpb.OpenTenantDomainKEKRequest{WrapperId: "hsm-a", Binding: binding})
			return err
		},
		"open oversized": func() error {
			_, err := s.OpenTenantDomainKEK(ctx, &signerpb.OpenTenantDomainKEKRequest{WrapperId: "hsm-a", Binding: binding, WrappedDomainKek: make([]byte, 1025)})
			return err
		},
		"wrap short key": func() error {
			_, err := s.WrapTenantDataKey(ctx, &signerpb.WrapTenantDataKeyRequest{WrapperId: "hsm-a", Binding: binding, WrappedDomainKek: wrapped, DataKey: dek[:31]})
			return err
		},
		"wrap long key": func() error {
			_, err := s.WrapTenantDataKey(ctx, &signerpb.WrapTenantDataKeyRequest{WrapperId: "hsm-a", Binding: binding, WrappedDomainKek: wrapped, DataKey: append(dek, 1)})
			return err
		},
		"wrap without wrapped": func() error {
			_, err := s.WrapTenantDataKey(ctx, &signerpb.WrapTenantDataKeyRequest{WrapperId: "hsm-a", Binding: binding, DataKey: dek})
			return err
		},
		"unwrap empty": func() error {
			_, err := s.UnwrapTenantDataKey(ctx, &signerpb.UnwrapTenantDataKeyRequest{WrapperId: "hsm-a", Binding: binding, WrappedDomainKek: wrapped})
			return err
		},
		"unwrap oversized": func() error {
			_, err := s.UnwrapTenantDataKey(ctx, &signerpb.UnwrapTenantDataKeyRequest{WrapperId: "hsm-a", Binding: binding, WrappedDomainKek: wrapped, WrappedDataKey: make([]byte, 257)})
			return err
		},
	} {
		if code := status.Code(call()); code != codes.InvalidArgument {
			t.Errorf("%s = %v, want InvalidArgument", name, code)
		}
	}
}
