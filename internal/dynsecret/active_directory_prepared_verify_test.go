// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestADPreparedPublicationProofNeverResetsOrGuessesA267(t *testing.T) {
	p, old, native := ownedDurableADReset()
	if err := driveADPreparedReset(t.Context(), p, old, false, native); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(struct {
		DN string `json:"bind_dn"`
	}{p.DN})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := appendADCredentialPassword(metadata, p.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(credential)
	native.proved = nil
	if err := verifyADPreparedSuccessor(t.Context(), p, credential, native); err != nil || native.writes != 2 || len(native.proved) != 1 || !bytes.Equal(native.proved[0], p.Password) {
		t.Fatal("read-only publication proof changed native state or failed exact successor", err)
	}
	for name, mutate := range map[string]func(*ownedADResetRuntime){
		"object replaced":  func(n *ownedADResetRuntime) { n.current.GUID = strings.Repeat("d", 32) },
		"SID changed":      func(n *ownedADResetRuntime) { n.current.SID = "010100000000000500000000" },
		"name changed":     func(n *ownedADResetRuntime) { n.current.Name = "other" },
		"DC replaced":      func(n *ownedADResetRuntime) { n.current.DCInvocationID = strings.Repeat("e", 32) },
		"route changed":    func(n *ownedADResetRuntime) { n.current.NativeAddress = "127.0.0.2:636" },
		"later generation": func(n *ownedADResetRuntime) { n.current.KeyVersion++ },
		"unstarted generation": func(n *ownedADResetRuntime) {
			n.current.KeyVersion = p.KeyVersion
			n.current.PasswordSetAt = p.PasswordSetAt
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *native
			candidate.proved = nil
			mutate(&candidate)
			if verifyADPreparedSuccessor(t.Context(), p, credential, &candidate) == nil || candidate.writes != 2 || len(candidate.proved) != 0 {
				t.Fatal("changed native authority received a reset, password guess, or publication proof")
			}
		})
	}
	other, err := appendADCredentialPassword(metadata, []byte("Owned1!unrelated-stored-value"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(other)
	candidate := *native
	candidate.proved = nil
	if verifyADPreparedSuccessor(t.Context(), p, other, &candidate) == nil || candidate.writes != 2 || len(candidate.proved) != 0 {
		t.Fatal("another sealed credential received a native password guess")
	}
	candidate = *native
	candidate.proved = nil
	candidate.password = []byte("Owned1!unrelated-native-value")
	if verifyADPreparedSuccessor(t.Context(), p, credential, &candidate) == nil || candidate.writes != 2 || len(candidate.proved) != 1 || !bytes.Equal(candidate.proved[0], p.Password) {
		t.Fatal("unknown native drift received a reset or alternate password candidates")
	}
}
