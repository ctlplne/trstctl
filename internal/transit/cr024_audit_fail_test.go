// SPDX-License-Identifier: BUSL-1.1

package transit

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestCR024TransitNeverReturnsKeyUseWithoutItsAuditEvent(t *testing.T) {
	ctx := context.Background()
	k := New("tenant-a", nil)
	for name, kind := range map[string]Kind{"sign": KindSign, "mac": KindHMAC, "enc": KindAEAD} {
		if err := k.CreateKey(ctx, name, kind); err != nil {
			t.Fatal(err)
		}
	}
	message := []byte("audit-bound operation")
	sig, pub, err := k.Sign(ctx, "sign", message)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := k.Encrypt(ctx, "enc", message, nil)
	if err != nil {
		t.Fatal(err)
	}
	k.audit = auditsink.AuditorFunc(func(context.Context, string, string, []byte) error {
		return errors.New("event log temporarily unavailable")
	})
	if got, pub, err := k.Sign(ctx, "sign", message); err == nil || len(got) != 0 || len(pub) != 0 {
		t.Errorf("sign returned a signature without its audit event: bytes=%d public=%d err=%v", len(got), len(pub), err)
	}
	if got, err := k.HMAC(ctx, "mac", message); err == nil || len(got) != 0 {
		t.Errorf("HMAC returned a MAC without its audit event: bytes=%d err=%v", len(got), err)
	}
	if got, err := k.Encrypt(ctx, "enc", message, nil); err == nil || got != "" {
		t.Errorf("encrypt returned ciphertext without its audit event: length=%d err=%v", len(got), err)
	}
	if got, err := k.Decrypt(ctx, "enc", ciphertext, nil); err == nil || len(got) != 0 {
		t.Errorf("decrypt returned plaintext without its audit event: bytes=%d err=%v", len(got), err)
	}
	if got, err := k.Rewrap(ctx, "enc", ciphertext, nil); err == nil || got != "" {
		t.Errorf("rewrap returned ciphertext without its audit event: length=%d err=%v", len(got), err)
	}
	if err := k.Verify(ctx, message, sig, pub); err == nil {
		t.Error("verify returned success without its audit event")
	}
	if err := k.VerifyNamed(ctx, "sign", message, sig, pub); err == nil {
		t.Error("named verify returned success without its audit event")
	}
	k.audit = auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, _ []byte) error {
		if eventType == "transit.rewrap" {
			return errors.New("rewrap audit append unavailable")
		}
		return nil
	})
	if got, err := k.Rewrap(ctx, "enc", ciphertext, nil); err == nil || got != "" {
		t.Errorf("rewrap returned ciphertext after its own final audit append failed: length=%d err=%v", len(got), err)
	}
}
