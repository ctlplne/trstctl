package license

import "encoding/base64"

// builtinPubKeysB64 carries comma-separated, base64-encoded PEM public keys
// baked at release build time with:
//
//	go build -ldflags "-X trstctl.com/trstctl/internal/license.builtinPubKeysB64=$(base64 -w0 license-signing.pub)"
//
// Development builds bake no keys. That means no configured license file can
// verify, while an unconfigured deployment remains Community.
var builtinPubKeysB64 string

// TrustedKeys returns the baked trusted license public keys as PEM bytes.
// Malformed entries are ignored; verification then fails closed because no
// valid trusted key matches.
func TrustedKeys() [][]byte {
	if builtinPubKeysB64 == "" {
		return nil
	}
	var out [][]byte
	start := 0
	for i := 0; i <= len(builtinPubKeysB64); i++ {
		if i != len(builtinPubKeysB64) && builtinPubKeysB64[i] != ',' {
			continue
		}
		if pemBytes, err := base64.StdEncoding.DecodeString(builtinPubKeysB64[start:i]); err == nil && len(pemBytes) > 0 {
			out = append(out, pemBytes)
		}
		start = i + 1
	}
	return out
}
