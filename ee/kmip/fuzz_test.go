package kmip

import "testing"

func FuzzParseTTLV(f *testing.F) {
	valid := kmipLocateRequestTTLV()
	f.Add(valid)
	f.Add(valid[:len(valid)-1])
	f.Add([]byte{})
	f.Add([]byte{0x42, 0x00, 0x78, byte(TTLVStructure), 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTTLV(data)
		_, _ = DecodeRequestMessage(data)
	})
}
