// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"errors"
	"testing"
)

func TestDestructionGrantIsExactControllerBoundAndExpires(t *testing.T) {
	first, foreign := &DestructionAuthority{}, &DestructionAuthority{}
	wire := holdClearanceFixture(t)
	body, err := ParseHoldClearance(wire)
	if err != nil {
		t.Fatal(err)
	}
	request := body.Request
	if err := first.AuthorizeDestruction(t.Context(), request); !errors.Is(err, ErrSource) {
		t.Fatal("missing grant admitted destruction")
	}
	var escaped context.Context
	if err := first.withVerifiedDestructionGrant(t.Context(), request, func(ctx context.Context) error {
		escaped = ctx
		if err := first.AuthorizeDestruction(ctx, request); err != nil {
			return err
		}
		if err := foreign.AuthorizeDestruction(ctx, request); !errors.Is(err, ErrSource) {
			t.Fatal("foreign controller borrowed destruction authority")
		}
		changed := request
		changed.CreationDigest = "different"
		if err := first.AuthorizeDestruction(ctx, changed); !errors.Is(err, ErrSource) {
			t.Fatal("grant changed source coordinates")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := first.AuthorizeDestruction(escaped, request); !errors.Is(err, ErrSource) {
		t.Fatal("escaped grant remained live")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := first.withVerifiedDestructionGrant(ctx, request, func(context.Context) error { t.Fatal("canceled invocation minted a grant"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
