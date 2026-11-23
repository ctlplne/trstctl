// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// CR-045: the journal integrity key is separate from the deployment KEK and
// versioned by explicit configuration. Older versions remain loadable until
// their pending producer evidence has settled.
func TestIngressJournalKeyConfigurationCR045(t *testing.T) {
	cfg := config.Default()
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "deployment-kek.bin")
	active, paths, err := cfg.Secrets.IngressJournalKeyFiles()
	if err != nil || active != "v1" || paths["v1"] != filepath.Join(filepath.Dir(cfg.Secrets.KEKFile), "ingress-journal-v1.key") {
		t.Fatalf("derived separate journal key active=%q paths=%v err=%v", active, paths, err)
	}
	cfg.Secrets.IngressJournalActiveKeyID = "plain-v2"
	cfg.Secrets.IngressJournalKeys = []config.IngressJournalKey{
		{ID: "plain-v1", File: filepath.Join(t.TempDir(), "prior.key")},
		{ID: "plain-v2", File: filepath.Join(t.TempDir(), "current.key")},
	}
	active, paths, err = cfg.Secrets.IngressJournalKeyFiles()
	if err != nil || active != "plain-v2" || len(paths) != 2 {
		t.Fatalf("versioned journal key mapping active=%q paths=%v err=%v", active, paths, err)
	}
	cfg.Secrets.IngressJournalKeys = append(cfg.Secrets.IngressJournalKeys, cfg.Secrets.IngressJournalKeys[0])
	if _, _, err := cfg.Secrets.IngressJournalKeyFiles(); err == nil {
		t.Fatal("duplicate journal key version accepted")
	}
	provided := filepath.Join(t.TempDir(), "operator-journal.key")
	env := map[string]string{
		"TRSTCTL_SECRETS_KEK_FILE":                      filepath.Join(t.TempDir(), "operator-kek.key"),
		"TRSTCTL_SECRETS_INGRESS_JOURNAL_ACTIVE_KEY_ID": "operator-v2",
		"TRSTCTL_SECRETS_INGRESS_JOURNAL_KEY_FILE":      provided,
	}
	loaded, err := config.Load(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	active, paths, err = loaded.Secrets.IngressJournalKeyFiles()
	if err != nil || active != "operator-v2" || paths[active] != provided {
		t.Fatalf("environment journal key active=%q paths=%v err=%v", active, paths, err)
	}
}

func TestPostgresRewrapCutoverEnvironment(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_POSTGRES_REWRAP_OLD_LOGIN_ROLE":          "old_fixture_login",
		"TRSTCTL_POSTGRES_REWRAP_NEW_LOGIN_ROLE":          "new_fixture_login",
		"TRSTCTL_POSTGRES_REWRAP_MAINTENANCE_ATTESTATION": "maintenance-confirmed",
	}
	cfg, err := config.Load(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Postgres.RewrapOldLoginRole != "old_fixture_login" ||
		cfg.Postgres.RewrapNewLoginRole != "new_fixture_login" ||
		cfg.Postgres.RewrapMaintenanceAttestation != "maintenance-confirmed" {
		t.Fatalf("rewrap cutover fields were not loaded: %+v", cfg.Postgres)
	}
}
