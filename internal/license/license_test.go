package license

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func testKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func testClaims(tier Tier, expires time.Time) Claims {
	return Claims{
		V: 1, ID: "lic_test_001", Customer: "Acme Robotics", Tier: tier,
		IssuedAt: expires.Add(-365 * 24 * time.Hour), ExpiresAt: expires,
	}
}

func managerAt(t *testing.T, c Claims, priv, pub []byte, now time.Time) *Manager {
	t.Helper()
	raw, err := Sign(c, priv)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := Verify(raw, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{claims: claims, clock: func() time.Time { return now }}
}

func TestVerifyTable(t *testing.T) {
	priv, pub := testKeypair(t)
	_, otherPub := testKeypair(t)
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	good, err := Sign(testClaims(TierEnterprise, now.Add(24*time.Hour)), priv)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		raw     []byte
		trusted [][]byte
		wantErr string
	}{
		{"valid", good, [][]byte{pub}, ""},
		{"valid with rotation", good, [][]byte{otherPub, pub}, ""},
		{"no trusted keys baked", good, nil, "no trusted license keys"},
		{"untrusted signer", good, [][]byte{otherPub}, "signature verification failed"},
		{"garbage file", []byte("not json"), [][]byte{pub}, "malformed license file"},
		{"tampered payload", tamperJSONField(t, good, "payload"), [][]byte{pub}, "signature verification failed"},
		{"tampered signature", tamperJSONField(t, good, "signature"), [][]byte{pub}, "signature verification failed"},
	}
	for _, tc := range tests {
		_, err := Verify(tc.raw, tc.trusted)
		if tc.wantErr == "" && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: error = %v, want contains %q", tc.name, err, tc.wantErr)
		}
	}

	for name, c := range map[string]Claims{
		"wrong version":             {V: 2, Tier: TierEnterprise, IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"unknown tier":              {V: 1, Tier: "platinum", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"community is not issuable": {V: 1, Tier: TierCommunity, IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"inverted window":           {V: 1, Tier: TierEnterprise, IssuedAt: now, ExpiresAt: now.Add(-time.Hour)},
	} {
		raw, err := Sign(c, priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(raw, [][]byte{pub}); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func tamperJSONField(t *testing.T, raw []byte, field string) []byte {
	t.Helper()
	needle := `"` + field + `": "`
	i := strings.Index(string(raw), needle)
	if i < 0 {
		t.Fatalf("field %q not found in %s", field, raw)
	}
	i += len(needle)
	out := append([]byte(nil), raw...)
	if out[i] == 'A' {
		out[i] = 'B'
	} else {
		out[i] = 'A'
	}
	return out
}

func TestStateLadderAndDegrade(t *testing.T) {
	priv, pub := testKeypair(t)
	expires := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	feature := Feature("future_enterprise_feature")
	c := testClaims(TierEnterprise, expires)
	c.Features = []Feature{feature}

	tests := []struct {
		name      string
		now       time.Time
		wantState State
		wantMode  Mode
	}{
		{"active", expires.Add(-time.Hour), StateActive, ModeEnabled},
		{"grace day 1", expires.Add(24 * time.Hour), StateGrace, ModeEnabled},
		{"grace day 29", expires.Add(29 * 24 * time.Hour), StateGrace, ModeEnabled},
		{"read-only day 31", expires.Add(31 * 24 * time.Hour), StateReadOnly, ModeReadOnly},
	}
	for _, tc := range tests {
		m := managerAt(t, c, priv, pub, tc.now)
		if got := m.State(); got != tc.wantState {
			t.Errorf("%s: state = %s want %s", tc.name, got, tc.wantState)
		}
		if got := m.Mode(feature); got != tc.wantMode {
			t.Errorf("%s: mode = %s want %s", tc.name, got, tc.wantMode)
		}
		if !m.Has(feature) {
			t.Errorf("%s: Has must stay true while licensed, including read_only", tc.name)
		}
		if got := m.Mode(Feature("unlicensed_future_feature")); got != ModeOff {
			t.Errorf("%s: unlicensed feature mode = %s want %s", tc.name, got, ModeOff)
		}
	}
}

func TestCommunityAndLoad(t *testing.T) {
	m := Community()
	if m.Tier() != TierCommunity || m.State() != StateCommunity {
		t.Fatal("community defaults wrong")
	}
	if m.Has(Feature("anything")) || m.Mode(Feature("anything")) != ModeOff {
		t.Fatal("community must have every gated feature off")
	}
	info := m.Info()
	if info.Tier != TierCommunity {
		t.Fatalf("community info wrong: %+v", info)
	}
	assertFeatureRow(t, info, FeatureFIPS, TierEnterprise, false, ModeOff)
	assertFeatureRow(t, info, FeatureRemediation, TierEnterprise, false, ModeOff)
	assertFeatureRow(t, info, FeatureHASupport, TierEnterprise, false, ModeOff)
	if m, err := Load("", nil); err != nil || m.Tier() != TierCommunity {
		t.Fatalf("Load(\"\") = %v, %v", m.Tier(), err)
	}
	if _, err := Load("/does/not/exist.json", nil); err == nil {
		t.Fatal("missing configured license must error")
	}

	priv, pub := testKeypair(t)
	raw, err := Sign(testClaims(TierEnterprise, time.Now().Add(time.Hour)), priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trstctl-license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	lm, err := Load(path, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	if lm.Tier() != TierEnterprise {
		t.Fatal("loaded license tier wrong")
	}
	if _, err := Load(path, nil); err == nil || !strings.Contains(err.Error(), "no trusted license keys") {
		t.Fatalf("keyless build must reject a configured license, got %v", err)
	}
}

func TestInfoRendersLicenseTruth(t *testing.T) {
	priv, pub := testKeypair(t)
	expires := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	feature := Feature("future_provider_feature")
	c := testClaims(TierProvider, expires)
	c.Features = []Feature{feature}
	c.TenantBand = 100
	m := managerAt(t, c, priv, pub, expires.Add(-time.Hour))

	info := m.Info()
	if info.Tier != TierProvider || info.State != StateActive || info.Customer != "Acme Robotics" {
		t.Fatalf("info header wrong: %+v", info)
	}
	if info.ExpiresAt == nil || !info.ExpiresAt.Equal(expires) {
		t.Fatal("expiry missing")
	}
	if info.ReadOnlyAt == nil || !info.ReadOnlyAt.Equal(expires.Add(GracePeriod)) {
		t.Fatal("read-only horizon missing")
	}
	if info.TenantBand != 100 {
		t.Fatalf("tenant band = %d want 100", info.TenantBand)
	}
	assertFeatureRow(t, info, FeatureFIPS, TierEnterprise, false, ModeOff)
	assertFeatureRow(t, info, FeatureHASupport, TierEnterprise, false, ModeOff)
	if !m.Has(feature) || m.Mode(feature) != ModeEnabled {
		t.Fatal("explicit extra feature should be licensed even when it is not part of the table")
	}
}

func TestInfoListsEnterpriseFeatureRows(t *testing.T) {
	community := Community().Info()
	assertFeatureRow(t, community, FeatureFIPS, TierEnterprise, false, ModeOff)
	assertFeatureRow(t, community, FeatureRemediation, TierEnterprise, false, ModeOff)
	assertFeatureRow(t, community, FeatureHASupport, TierEnterprise, false, ModeOff)

	priv, pub := testKeypair(t)
	expires := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	active := managerAt(t, testClaims(TierEnterprise, expires), priv, pub, expires.Add(-time.Hour)).Info()
	assertFeatureRow(t, active, FeatureFIPS, TierEnterprise, true, ModeEnabled)
	assertFeatureRow(t, active, FeatureRemediation, TierEnterprise, true, ModeEnabled)
	assertFeatureRow(t, active, FeatureHASupport, TierEnterprise, true, ModeEnabled)
}

func assertFeatureRow(t *testing.T, info Info, name Feature, tier Tier, licensed bool, mode Mode) {
	t.Helper()
	for _, f := range info.Features {
		if f.Name == name {
			if f.Tier != tier || f.Licensed != licensed || f.Mode != mode {
				t.Fatalf("feature %s row = %+v, want tier=%s licensed=%t mode=%s", name, f, tier, licensed, mode)
			}
			return
		}
	}
	t.Fatalf("feature %s row missing from %+v", name, info.Features)
}

func TestTrustedKeysParsesLdflagsPayload(t *testing.T) {
	old := builtinPubKeysB64
	defer func() { builtinPubKeysB64 = old }()

	builtinPubKeysB64 = ""
	if TrustedKeys() != nil {
		t.Fatal("empty bake must yield no keys")
	}
	_, pub1 := testKeypair(t)
	_, pub2 := testKeypair(t)
	builtinPubKeysB64 = base64.StdEncoding.EncodeToString(pub1) + "," + base64.StdEncoding.EncodeToString(pub2)
	keys := TrustedKeys()
	if len(keys) != 2 || string(keys[0]) != string(pub1) || string(keys[1]) != string(pub2) {
		t.Fatalf("rotation bake parsed wrong: %d keys", len(keys))
	}
}
