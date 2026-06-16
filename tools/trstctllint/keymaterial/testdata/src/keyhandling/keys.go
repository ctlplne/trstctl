//trstctl:keymaterial
package keyhandling

// This package handles key material, so string-typed fields, parameters, and
// results are forbidden (AN-8); []byte must be used instead. Detection is
// type-resolved, so it also catches named string types, slices/arrays of
// string, maps WHOSE VALUE is string, and pointers to any of those (ARCH-001) —
// not just the bare literal "string".

// Secret is a named string type. A field of this type still rests on string and
// must be flagged just like a bare string.
type Secret string

type PrivateKey struct {
	Bytes    []byte
	PEM      string            // want "must not use string for key material"
	Material Secret            // want "must not use string for key material"
	Parts    []string          // want "must not use string for key material"
	Labeled  map[string]string // want "must not use string for key material"
	Ptr      *string           // want "must not use string for key material"
	Fixed    [4]string         // want "must not use string for key material"
	NamedPtr *Secret           // want "must not use string for key material"

	// Genuinely safe: bytes, byte slice, and a handle-keyed byte map (the
	// secret lives in the []byte value, the string key is a label).
	Raw    []byte
	Block  [32]byte
	ByHash map[string][]byte
}

func Sign(priv string) {} // want "must not use string for key material"

func Export() (pem string) { // want "must not use string for key material"
	return ""
}

// SealAll takes a slice of named secrets — the parameter is string-backed.
func SealAll(secrets []Secret) {} // want "must not use string for key material"

// Vault returns a map whose VALUE is secret string material — flagged.
func Vault() (m map[string]Secret) { return nil } // want "must not use string for key material"

// ByHandle keys a byte map by a string handle — allowed (value is []byte).
func ByHandle(m map[string][]byte) {}
