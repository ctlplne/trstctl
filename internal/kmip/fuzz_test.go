// SPDX-License-Identifier: BUSL-1.1

package kmip

import "testing"

func FuzzParseTTLV(f *testing.F) {
	valid := kmipLocateRequestTTLV()
	f.Add(valid)
	f.Add(valid[:len(valid)-1])
	f.Add([]byte{})
	f.Add([]byte{0x42, 0x00, 0x78, byte(TTLVStructure), 0xff, 0xff, 0xff, 0xff})

	// A124: the observation client decodes responses from a server it does not
	// control with the same parser.
	f.Add(encodeResponse(1, 4, []wireResponseItem{{operation: OperationLocate, payload: encodeStructure(TagResponsePayload,
		encodeText(TagUniqueIdentifier, "k-1"))}}))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTTLV(data)
		_, _ = DecodeRequestMessage(data)
		_, _ = DecodeClientResponse(data)
	})
}
