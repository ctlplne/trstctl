// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/eventauth"
)

// ErrEventAuthentication is returned before an unauthenticated broker record
// can reach a projection, audit reader, identity index, or replay callback.
var ErrEventAuthentication = eventauth.ErrAuthentication

func (l *Log) marshalStored(stored storedEvent) ([]byte, error) {
	if l == nil || l.eventAuth == nil {
		return json.Marshal(stored)
	}
	stored.Authentication = nil
	bare, err := json.Marshal(stored)
	if err != nil {
		return nil, err
	}
	stored.Authentication, err = l.eventAuth.Sign(bare)
	if err != nil {
		return nil, fmt.Errorf("events: sign stored envelope: %w", err)
	}
	return json.Marshal(stored)
}

func (l *Log) authenticateStored(data []byte, seq uint64) error {
	if l == nil || l.eventAuth == nil {
		return nil
	}
	var stored storedEvent
	if err := json.Unmarshal(data, &stored); err != nil {
		return &EnvelopeDecodeError{Sequence: seq, Err: err}
	}
	tag := stored.Authentication
	stored.Authentication = nil
	bare, err := json.Marshal(stored)
	if err != nil {
		return &EnvelopeDecodeError{Sequence: seq, Err: ErrEventAuthentication}
	}
	if err := l.eventAuth.Verify(bare, tag); err != nil {
		return &EnvelopeDecodeError{Sequence: seq, Err: err}
	}
	stored.Authentication = tag
	canonical, err := json.Marshal(stored)
	if err != nil || !bytes.Equal(canonical, data) {
		return &EnvelopeDecodeError{Sequence: seq, Err: ErrEventAuthentication}
	}
	return nil
}

func (l *Log) decodeStored(data []byte, seq uint64) (Event, error) {
	if err := l.authenticateStored(data, seq); err != nil {
		return Event{}, err
	}
	return decodeStored(data, seq)
}

func (l *Log) resignStored(data []byte) ([]byte, error) {
	if l == nil || l.eventAuth == nil {
		return data, nil
	}
	var stored storedEvent
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	return l.marshalStored(stored)
}

func (l *Log) validateBackupLiveRecord(record BackupHistoryRecord) error {
	if err := validateBackupLiveRecord(record); err != nil {
		return err
	}
	return l.authenticateStored(record.Stored, record.Sequence)
}
