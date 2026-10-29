// SPDX-License-Identifier: BUSL-1.1
package adcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// DecodeInventoryObservation preserves the declared historical wire shape.
// Never decode old versions directly into a newly extended active struct.
func DecodeInventoryObservation(version int, raw []byte) (InventoryObserved, error) {
	decode := func(target any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(target); err != nil {
			return err
		}
		if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return errors.New("adcs: observation has trailing JSON")
		}
		return nil
	}
	switch version {
	case 1:
		var old InventoryObservedV1
		if err := decode(&old); err != nil {
			return InventoryObserved{}, err
		}
		return old.Current(), nil
	case 2:
		var old InventoryObservedV2
		if err := decode(&old); err != nil {
			return InventoryObserved{}, err
		}
		return old.Current(), nil
	case InventoryMembershipSchemaVersion:
		var old InventoryObservedV3
		if err := decode(&old); err != nil {
			return InventoryObserved{}, err
		}
		return old.Current(), nil
	default:
		if version != InventoryEventSchemaVersion {
			return InventoryObserved{}, errors.New("adcs: unknown observation schema version")
		}
		var current InventoryObserved
		if err := decode(&current); err != nil {
			return InventoryObserved{}, err
		}
		return current, nil
	}
}
