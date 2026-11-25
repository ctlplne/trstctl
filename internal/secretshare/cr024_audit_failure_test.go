// SPDX-License-Identifier: BUSL-1.1

package secretshare

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	secretpkg "trstctl.com/trstctl/internal/crypto/secret"
)

func TestCR024ShareCreationDoesNotPublishUnauditedLink(t *testing.T) {
	appendErr := errors.New("injected share-create audit failure")
	audit := auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, _ []byte) error {
		if eventType == "secret.shared" {
			return appendErr
		}
		return nil
	})
	sharer := New("t1", audit, nil)
	token, err := sharer.Create(t.Context(), []byte("fixture-secret"), time.Hour)
	if !errors.Is(err, appendErr) || len(token) != 0 || len(sharer.links) != 0 {
		t.Fatalf("create published unaudited link: token_present=%t links=%d err=%v", len(token) != 0, len(sharer.links), err)
	}
}

func TestCR024ShareViewRemainsRetryableWhenAuditAppendFails(t *testing.T) {
	appendErr := errors.New("injected share-view audit failure")
	failView := true
	audit := auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, _ []byte) error {
		if eventType == "secret.share.viewed" && failView {
			return appendErr
		}
		return nil
	})
	sharer := New("t1", audit, nil)
	token, err := sharer.Create(t.Context(), []byte("fixture-secret"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer secretpkg.Wipe(token)
	value, err := sharer.View(t.Context(), token)
	if !errors.Is(err, appendErr) || len(value) != 0 {
		t.Fatalf("view exposed unaudited secret: value_present=%t err=%v", len(value) != 0, err)
	}
	if _, ok := sharer.links[crypto.SHA256Hex(token)]; !ok {
		t.Fatal("failed view consumed link; recipient cannot retry")
	}
	failView = false
	value, err = sharer.View(t.Context(), token)
	if err != nil || string(value) != "fixture-secret" {
		t.Fatalf("retry after audit recovery: value_present=%t err=%v", len(value) != 0, err)
	}
	secretpkg.Wipe(value)
	if _, err := sharer.View(t.Context(), token); err == nil {
		t.Fatal("second successful view reused one-time link")
	}
}
