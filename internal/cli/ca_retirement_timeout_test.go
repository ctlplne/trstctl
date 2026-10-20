// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"strings"
	"testing"
	"time"
)

func TestCAKeyRetirementAllowsSynchronousSignerRecovery(t *testing.T) {
	for _, command := range Commands() {
		if strings.Join(command.Name, " ") != "ca keys retire" {
			continue
		}
		if command.RequestTimeout != 10*time.Minute {
			t.Fatalf("CA key retirement deadline = %s, want 10m for an unambiguous signer result", command.RequestTimeout)
		}
		client, err := httpClientForEnv(Env{}, "", command.RequestTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if client.Timeout != command.RequestTimeout {
			t.Fatalf("client deadline = %s, want %s", client.Timeout, command.RequestTimeout)
		}
		return
	}
	t.Fatal("missing ca keys retire command")
}
