// SPDX-License-Identifier: BUSL-1.1

// Package retirementwire owns the tiny public context that crosses the AN-4
// signer boundary. It deliberately imports no store, event log, outbox, HTTP,
// or retirement orchestration package, so attaching VDEC cannot pull control-
// plane dependencies into cmd/trstctl-signer.
package retirementwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	SchemaV1        = 1
	sha256DigestLen = 32
)

var ErrInvalidContext = errors.New("vdec retirement wire: invalid finalization context")

type FinalizationContextV1 struct {
	Version                    int    `json:"version"`
	KeyClass                   string `json:"key_class"`
	CommandEventID             string `json:"command_event_id"`
	CompletionEventsDigest     []byte `json:"completion_events_digest"`
	RevocationCompletionDigest []byte `json:"revocation_completion_digest"`
	PolicyRef                  string `json:"policy_ref"`
}

func Encode(commandEventID, keyClass string, completionDigest, revocationDigest []byte) ([]byte, error) {
	value := FinalizationContextV1{
		Version: SchemaV1, KeyClass: strings.TrimSpace(keyClass),
		CommandEventID:             strings.TrimSpace(commandEventID),
		CompletionEventsDigest:     append([]byte(nil), completionDigest...),
		RevocationCompletionDigest: append([]byte(nil), revocationDigest...),
		PolicyRef:                  "vdec/registered-minus-accounted-empty/v1",
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func Decode(raw []byte) (FinalizationContextV1, error) {
	var value FinalizationContextV1
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return FinalizationContextV1{}, fmt.Errorf("%w: %v", ErrInvalidContext, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return FinalizationContextV1{}, fmt.Errorf("%w: %v", ErrInvalidContext, err)
	}
	if err := value.Validate(); err != nil {
		return FinalizationContextV1{}, err
	}
	return value, nil
}

func (v *FinalizationContextV1) Validate() error {
	if v == nil {
		return ErrInvalidContext
	}
	v.KeyClass = strings.TrimSpace(v.KeyClass)
	v.CommandEventID = strings.TrimSpace(v.CommandEventID)
	v.PolicyRef = strings.TrimSpace(v.PolicyRef)
	if v.Version != SchemaV1 || v.KeyClass == "" || v.CommandEventID == "" || v.PolicyRef == "" ||
		len(v.CompletionEventsDigest) != sha256DigestLen || len(v.RevocationCompletionDigest) != sha256DigestLen {
		return ErrInvalidContext
	}
	return nil
}
