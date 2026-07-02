package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// TestServedCryptoAgilityProfilesValidateBoundaryAlgorithms proves F16 on the
// served profile-selection path: operators can select supported classical, hybrid,
// and PQC signature labels through /api/v1/profiles, unsupported labels are
// rejected before they become policy, and the accepted labels round-trip through
// the served read API instead of living only in internal crypto tests.
func TestServedCryptoAgilityProfilesValidateBoundaryAlgorithms(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, string(authz.ProfilesWrite), string(authz.ProfilesRead))

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", tok, "f16-unsupported-profile", map[string]any{
		"name": "unsupported-crypto",
		"spec": map[string]any{
			"allowed_key_algorithms": []string{"Rainbow-I"},
			"allowed_protocols":      []string{"acme"},
			"max_validity":           "720h",
		},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("unsupported crypto-agility profile status = %d body %s, want 400", status, body)
	}

	allowedAlgorithms := []string{
		"RSA",
		"ECDSA",
		string(crypto.Ed25519),
		crypto.HybridMLDSA44ECDSAP256Algorithm,
		string(crypto.MLDSA65),
		string(crypto.SLHDSA128s),
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", tok, "f16-served-profile", map[string]any{
		"name": "crypto-agile-transition",
		"spec": map[string]any{
			"allowed_key_algorithms": allowedAlgorithms,
			"allowed_protocols":      []string{"acme", "est", "scep", "cmp"},
			"max_validity":           "720h",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create crypto-agility profile: status %d body %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/profiles", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list crypto-agility profiles: status %d body %s", status, body)
	}
	var listed struct {
		Items []struct {
			Name string `json:"name"`
			Spec struct {
				AllowedKeyAlgorithms []string `json:"allowed_key_algorithms"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode profile list: %v (%s)", err, body)
	}
	for _, item := range listed.Items {
		if item.Name != "crypto-agile-transition" {
			continue
		}
		if !sameCryptoAgilityStringSet(item.Spec.AllowedKeyAlgorithms, allowedAlgorithms) {
			t.Fatalf("served profile algorithms = %v, want %v", item.Spec.AllowedKeyAlgorithms, allowedAlgorithms)
		}
		if !h.hasEvent(t, "profile.created") {
			t.Fatal("missing profile.created event for served crypto-agility profile selection")
		}
		return
	}
	t.Fatalf("served profile list did not return crypto-agile-transition: %+v", listed.Items)
}

func sameCryptoAgilityStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(got))
	for _, value := range got {
		seen[value]++
	}
	for _, value := range want {
		if seen[value] == 0 {
			return false
		}
		seen[value]--
	}
	return true
}
