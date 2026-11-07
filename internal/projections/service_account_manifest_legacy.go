// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Decode historical authority with a frozen type before interpreting it as the
// current structure. A newly optional field set to null is still undeclared in
// an old source version, even though the current Go pointer would be nil.
func decodePublishedDependentSource(raw []byte, out any) error {
	reader := json.NewDecoder(bytes.NewReader(raw))
	reader.DisallowUnknownFields()
	if err := reader.Decode(out); err != nil {
		return err
	}
	if err := reader.Decode(new(any)); err != io.EOF {
		return errors.New("dependent source: exactly one closed JSON value required")
	}
	return nil
}
