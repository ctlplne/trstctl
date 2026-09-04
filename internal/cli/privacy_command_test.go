// SPDX-License-Identifier: MPL-2.0

package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPrivacyHistoryMutationsUseRecoverableLongRequestDeadline(t *testing.T) {
	want := map[string]bool{
		"privacy erasures erase": false,
		"privacy retention run":  false,
	}
	for _, command := range Commands() {
		name := strings.Join(command.Name, " ")
		if _, ok := want[name]; !ok {
			continue
		}
		want[name] = true
		if command.RequestTimeout != 10*time.Minute {
			t.Errorf("%s timeout = %s, want 10m for synchronous recoverable history work", name, command.RequestTimeout)
		}
		client, err := httpClientForEnv(Env{}, "", command.RequestTimeout)
		if err != nil {
			t.Fatalf("%s client: %v", name, err)
		}
		if client.Timeout != command.RequestTimeout {
			t.Errorf("%s client timeout = %s, want %s", name, client.Timeout, command.RequestTimeout)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing command %s", name)
		}
	}
}

func TestLongRequestDeadlineDoesNotMutateInjectedClient(t *testing.T) {
	injected := &http.Client{Timeout: time.Minute}
	got, err := httpClientForEnv(Env{HTTPClient: injected}, "", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got == injected || got.Timeout != 10*time.Minute || injected.Timeout != time.Minute {
		t.Fatalf("client clone = %p timeout %s; injected = %p timeout %s", got, got.Timeout, injected, injected.Timeout)
	}
}
