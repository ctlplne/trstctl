// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/succession"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

func TestCheckpointResponseRejectsDivergentStoredReadModel(t *testing.T) {
	signed := succession.SignedEpochCheckpoint{
		IdentityID: "spiffe://qa/id", Epoch: 1, LogTreeSize: 4,
		LogRootHash: []byte{1, 2}, Signature: []byte{3, 4}, SignerPublicDER: []byte{5, 6},
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	valid := pcasstore.EpochCheckpoint{
		IdentityID: signed.IdentityID, Epoch: signed.Epoch, LogTreeSize: signed.LogTreeSize,
		LogRoot: signed.LogRootHash, Signature: signed.Signature, CheckpointJSON: raw,
	}
	response, err := checkpointResponse(valid)
	if err != nil || string(response.SignerPublicDER) != string(signed.SignerPublicDER) {
		t.Fatalf("valid checkpoint response=%+v err=%v", response, err)
	}
	for name, mutate := range map[string]func(*pcasstore.EpochCheckpoint){
		"identity":  func(cp *pcasstore.EpochCheckpoint) { cp.IdentityID = "spiffe://qa/other" },
		"epoch":     func(cp *pcasstore.EpochCheckpoint) { cp.Epoch++ },
		"tree size": func(cp *pcasstore.EpochCheckpoint) { cp.LogTreeSize++ },
		"log root":  func(cp *pcasstore.EpochCheckpoint) { cp.LogRoot = []byte{0} },
		"signature": func(cp *pcasstore.EpochCheckpoint) { cp.Signature = []byte{0} },
		"json":      func(cp *pcasstore.EpochCheckpoint) { cp.CheckpointJSON = []byte("{") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			mutate(&changed)
			if _, err := checkpointResponse(changed); err == nil {
				t.Fatal("divergent checkpoint read model was served")
			}
		})
	}
}
