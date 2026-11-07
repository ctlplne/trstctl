// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/sha1" // #nosec G505 -- RFC 6455 4.2.2 fixes SHA-1 for the WebSocket handshake's accept value: an identifier, not integrity (CWE-328)
	"encoding/base64"
)

// webSocketGUID is RFC 6455's fixed handshake GUID.
const webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WebSocketAccept is the Sec-WebSocket-Accept a server must answer a
// handshake's Sec-WebSocket-Key with (RFC 6455 4.2.2), so a client outside
// the boundary can check the upgrade without importing crypto/sha1 (AN-3).
func WebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + webSocketGUID)) // #nosec G401 -- RFC 6455 handshake identifier, not integrity (CWE-328)
	return base64.StdEncoding.EncodeToString(sum[:])
}
