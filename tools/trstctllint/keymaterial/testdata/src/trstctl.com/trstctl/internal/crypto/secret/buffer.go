// Package secret stands in for the real internal/crypto/secret primitive: the
// canonical secret-byte holder. It is key-handling BY CONSTRUCTION, so the AN-8
// rule applies to it whether or not it carries the //trstctl:keymaterial marker
// (ARCH-004, fail-closed). This fixture deliberately OMITS the marker to prove a
// forgotten/deleted marker does NOT disable the gate on the real secret buffers.
package secret

// Buffer holds secret bytes. The bytes must be []byte; a string-typed secret is
// a violation even with no marker present, because this package is default-on.
type Buffer struct {
	bytes  []byte
	Secret string // want "must not use string for key material"
}

// Wrap takes secret material; a string parameter is flagged with no marker.
func Wrap(plaintext string) {} // want "must not use string for key material"
