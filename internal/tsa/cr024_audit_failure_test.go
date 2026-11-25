// SPDX-License-Identifier: BUSL-1.1

package tsa

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

func TestCR024TimestampTokenIsWithheldWhenIssuanceAuditFails(t *testing.T) {
	a, _ := newTSA(t, nil)
	appendErr := errors.New("injected audit append failure")
	a.cfg.Audit = auditsink.AuditorFunc(func(context.Context, string, string, []byte) error { return appendErr })
	tok, err := a.Timestamp(t.Context(), crypto.SHA256Sum([]byte("timestamp subject")))
	if !errors.Is(err, appendErr) || len(tok.DER) != 0 || len(tok.Signature) != 0 {
		t.Fatalf("signed timestamp escaped without an audit record: DER=%d signature=%d err=%v", len(tok.DER), len(tok.Signature), err)
	}
}
