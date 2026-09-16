// SPDX-License-Identifier: MPL-2.0

package sshtrust

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestAddCATrustRefusesShadowedOrScopedDirectiveBeforeWrites(t *testing.T) {
	const existing = "/etc/ssh/existing_ca_keys"
	const include = "/etc/ssh/sshd_config.d/10-existing.conf"
	for _, tc := range []struct {
		name, config, included, wantError string
	}{
		{"different active file", "TrustedUserCAKeys " + existing + "\n", "", existing},
		{"matching but shadowed directive", "TrustedUserCAKeys " + existing + "\nTrustedUserCAKeys " + trustPath + "\n", "", existing},
		{"included directive wins", "Include " + include + "\nTrustedUserCAKeys " + trustPath + "\n", "TrustedUserCAKeys " + existing + "\n", existing},
		{"match-scoped directive", "Match User deploy\nTrustedUserCAKeys " + trustPath + "\n", "", "Match"},
		{"append would land inside match", "Match User deploy\nPasswordAuthentication no\n", "", "Match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, alreadyPresent := range []bool{false, true} {
				fs := newMemFS()
				fs.files[cfgPath] = []byte(tc.config)
				fs.files[existing] = []byte("ssh-ed25519 AAAAexisting existing-ca\n")
				fs.files[trustPath] = []byte("ssh-ed25519 AAAAother other-ca\n")
				if alreadyPresent {
					fs.files[trustPath] = append(fs.files[trustPath], []byte(caLine+"\n")...)
				}
				if tc.included != "" {
					fs.files[include] = []byte(tc.included)
				}
				before := make(map[string][]byte, len(fs.files))
				for name, content := range fs.files {
					before[name] = append([]byte(nil), content...)
				}
				rl := &fakeReloader{}
				rec := &auditsink.Recorder{}
				changed, err := newApplier(t, fs, rl, rec).AddCATrust(context.Background(), []byte(caLine))
				if changed || err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("present=%v: changed=%v err=%v; want refusal identifying %q", alreadyPresent, changed, err, tc.wantError)
				}
				if len(fs.writes) != 0 || !reflect.DeepEqual(fs.files, before) || rl.reloads != 0 || len(rec.Records()) != 0 {
					t.Fatalf("refused trust change wrote files, reloaded, or emitted a success event: writes=%v reloads=%d events=%v", fs.writes, rl.reloads, rec.Records())
				}
			}
		})
	}
}

func TestAddCATrustUsesFirstGlobalDirective(t *testing.T) {
	fs := newMemFS()
	fs.files[cfgPath] = []byte("TrustedUserCAKeys " + trustPath + "\nTrustedUserCAKeys /etc/ssh/ignored_ca_keys\nMatch User deploy\nPasswordAuthentication no\n")
	before := string(fs.files[cfgPath])
	changed, err := newApplier(t, fs, &fakeReloader{}, nil).AddCATrust(context.Background(), []byte(caLine))
	if err != nil || !changed || string(fs.files[cfgPath]) != before || !strings.Contains(string(fs.files[trustPath]), caLine) {
		t.Fatalf("first global trust file was not updated additively: changed=%v err=%v", changed, err)
	}
}
