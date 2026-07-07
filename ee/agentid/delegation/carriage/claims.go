// SPDX-License-Identifier: LicenseRef-trstctl-EE

package carriage

import (
	"encoding/base64"
	"encoding/json"
)

// claims.go holds the JSON marshaling shared by the two claim-bearing carriage forms
// (workload-identity document and signed token). It carries digest byte-slices as
// base64url strings -- the JSON/JOSE convention for binary claim values -- so both forms
// transport byte-identical bytes and a relying party recovers the exact bound digests.
//
// AN-3: base64/json are structural framing, not crypto. No crypto primitive lives here.

// byteString is a []byte that marshals to / unmarshals from a base64url (no padding)
// JSON string. It is used for every digest and the opaque agent-stack representation in
// the claim-bearing forms so binary bound values survive a JSON round-trip byte-for-byte.
// A nil/empty slice marshals to an empty JSON string; with omitempty on the field, an
// absent bound value therefore round-trips to an absent field (not a present empty one),
// matching BoundValues' omitempty semantics.
type byteString []byte

// MarshalJSON encodes the bytes as a base64url (unpadded) JSON string.
func (b byteString) MarshalJSON() ([]byte, error) {
	if len(b) == 0 {
		return []byte(`""`), nil
	}
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON decodes a base64url (unpadded) JSON string back to bytes. An empty string
// decodes to a nil slice. It fails closed on a non-string token or invalid base64 so a
// malformed claim never yields a partially-decoded value.
func (b *byteString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*b = nil
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*b = raw
	return nil
}
