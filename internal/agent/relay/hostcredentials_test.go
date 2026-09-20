// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type managementTestChannel struct {
	Channel
	items map[string][]byte
	err   error
	calls int
}

func (c *managementTestChannel) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	c.calls++
	return c.items, c.err
}

func TestHostManagementAdmitsOnlyReviewedReferencesAndWipesWireBytes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		refs      []string
		items     map[string][]byte
		err       error
		wantOK    bool
		wantCalls int
	}{
		{name: "no management needed", wantOK: true},
		{name: "password", refs: []string{"secret://store"}, items: map[string][]byte{"secret://store": []byte("fixture-password")}, wantOK: true, wantCalls: 1},
		{name: "subject key reference", refs: []string{"credential.key_pem"}},
		{name: "empty reference", refs: []string{"secret://"}},
		{name: "duplicate", refs: []string{"secret://store", "secret://store"}},
		{name: "private key response", refs: []string{"secret://store"}, items: map[string][]byte{"credential.key_pem": []byte("unexpected-key")}, wantCalls: 1},
		{name: "extra response", refs: []string{"secret://store"}, items: map[string][]byte{"secret://store": []byte("fixture-password"), "secret://other": []byte("unrelated")}, wantCalls: 1},
		{name: "missing", refs: []string{"secret://store"}, wantCalls: 1},
		{name: "empty value", refs: []string{"secret://store"}, items: map[string][]byte{"secret://store": {}}, wantCalls: 1},
		{name: "partial error", refs: []string{"secret://store"}, items: map[string][]byte{"secret://store": []byte("fixture-password")}, err: errors.New("unavailable"), wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := &managementTestChannel{items: tc.items, err: tc.err}
			material, destroy, err := redeemHostManagement(t.Context(), ch, Job{JobID: 42, Attempt: 3}, tc.refs)
			if (err == nil) != tc.wantOK || ch.calls != tc.wantCalls {
				t.Fatalf("success=%v calls=%d", err == nil, ch.calls)
			}
			for _, value := range ch.items {
				if !bytes.Equal(value, make([]byte, len(value))) {
					t.Fatal("wire bytes survived")
				}
			}
			if destroy != nil {
				if len(tc.refs) > 0 && !bytes.Equal(material[tc.refs[0]], []byte("fixture-password")) {
					t.Fatal("locked material differs")
				}
				destroy()
			}
		})
	}
}
