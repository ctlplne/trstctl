// SPDX-License-Identifier: MPL-2.0

//go:build linux

package tpm

// Production TPM 2.0 binding using google/go-tpm. It speaks the TPM command
// protocol to /dev/tpmrm0, /dev/tpm0, or a swtpm Unix socket. Signing keys are
// persistent TPM objects; only their public SPKI and numeric handle leave the
// device.

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	gotpm "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

const defaultPersistentHandleBase = 0x81010000

// DeviceConfig selects a TPM device/socket and hierarchy authorization. Auth
// values stay byte-native until go-tpm's string-only command edge.
type DeviceConfig struct {
	Path                 string
	OwnerAuth            []byte
	KeyAuth              []byte
	PersistentHandleBase uint32
}

type goTPMDevice struct {
	mu        sync.Mutex
	rw        io.ReadWriteCloser
	ownerAuth *secret.Buffer
	keyAuth   *secret.Buffer
	base      uint32
	closed    bool
}

var _ Device = (*goTPMDevice)(nil)
var _ LifecycleDevice = (*goTPMDevice)(nil)
var _ OperationDevice = (*goTPMDevice)(nil)

// OpenDevice opens a real TPM 2.0 transport. An empty path uses go-tpm's Linux
// defaults; a Unix socket path reaches swtpm through the same command protocol.
func OpenDevice(cfg DeviceConfig) (Device, error) {
	var (
		rw  io.ReadWriteCloser
		err error
	)
	if strings.TrimSpace(cfg.Path) == "" {
		rw, err = gotpm.OpenTPM()
	} else {
		rw, err = gotpm.OpenTPM(cfg.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("tpm: open TPM 2.0 device: %w", err)
	}
	base := cfg.PersistentHandleBase
	if base == 0 {
		base = defaultPersistentHandleBase
	}
	ownerAuth, err := lockTPMAuth(cfg.OwnerAuth)
	if err != nil {
		_ = rw.Close()
		return nil, fmt.Errorf("tpm: protect owner authorization: %w", err)
	}
	keyAuth, err := lockTPMAuth(cfg.KeyAuth)
	if err != nil {
		if ownerAuth != nil {
			ownerAuth.Destroy()
		}
		_ = rw.Close()
		return nil, fmt.Errorf("tpm: protect key authorization: %w", err)
	}
	return &goTPMDevice{
		rw: rw, ownerAuth: ownerAuth, keyAuth: keyAuth, base: base,
	}, nil
}

func lockTPMAuth(value []byte) (*secret.Buffer, error) {
	if len(value) == 0 {
		return nil, nil
	}
	return secret.NewFrom(value)
}

func tpmAuthBytes(value *secret.Buffer) []byte {
	if value == nil {
		return nil
	}
	return value.Bytes()
}

func (d *goTPMDevice) CreateKey(alg crypto.Algorithm) (string, []byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return "", nil, fmt.Errorf("tpm: device is closed")
	}
	template, err := tpmSigningTemplate(alg)
	if err != nil {
		return "", nil, err
	}
	// A TPM primary is deterministically derived from the hierarchy seed and its
	// public template. Calling CreatePrimary with the signing template for every
	// rotation therefore returns the same key material. Create a transient storage
	// primary, ask the TPM to generate a fresh child signing key beneath it, then
	// persist that child. Neither the child's private blob nor private key leaves
	// the TPM in plaintext.
	parentAuth := secrettext.String(tpmAuthBytes(d.keyAuth))
	parent, _, err := gotpm.CreatePrimary(
		d.rw, gotpm.HandleOwner, gotpm.PCRSelection{},
		secrettext.String(tpmAuthBytes(d.ownerAuth)), parentAuth, tpmStorageParentTemplate(),
	)
	if err != nil {
		return "", nil, fmt.Errorf("tpm: create transient storage parent: %w", err)
	}
	defer func() { _ = gotpm.FlushContext(d.rw, parent) }()
	privateBlob, publicBlob, _, _, _, err := gotpm.CreateKey(
		d.rw, parent, gotpm.PCRSelection{}, parentAuth,
		secrettext.String(tpmAuthBytes(d.keyAuth)), template,
	)
	if err != nil {
		return "", nil, fmt.Errorf("tpm: create child signing object: %w", err)
	}
	defer secret.Wipe(privateBlob)
	defer secret.Wipe(publicBlob)
	transient, _, err := gotpm.Load(d.rw, parent, parentAuth, publicBlob, privateBlob)
	if err != nil {
		return "", nil, fmt.Errorf("tpm: load child signing object: %w", err)
	}
	defer func() { _ = gotpm.FlushContext(d.rw, transient) }()

	var persistent tpmutil.Handle
	for attempt := uint32(0); attempt < 256; attempt++ {
		candidate := tpmutil.Handle(d.base + attempt)
		if _, _, _, readErr := gotpm.ReadPublic(d.rw, candidate); readErr == nil {
			continue
		}
		if err := gotpm.EvictControl(d.rw, secrettext.String(tpmAuthBytes(d.ownerAuth)), gotpm.HandleOwner, transient, candidate); err != nil {
			continue
		}
		persistent = candidate
		break
	}
	if persistent == 0 {
		return "", nil, fmt.Errorf("tpm: no free persistent signing handle in configured range")
	}
	pub, _, _, err := gotpm.ReadPublic(d.rw, persistent)
	if err != nil {
		return "", nil, fmt.Errorf("tpm: read persistent public key: %w", err)
	}
	der, err := tpmPublicDER(pub, alg)
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("0x%08x", uint32(persistent)), der, nil
}

func (d *goTPMDevice) CreateKeyForOperation(operationID string, alg crypto.Algorithm) (string, []byte, error) {
	if operationID == "" || len(operationID) > 256 {
		return "", nil, fmt.Errorf("tpm: durable operation id is required and must be at most 256 bytes")
	}
	operationTag, err := crypto.Digest(crypto.SHA256, []byte("trstctl:tpm2:managed-key:"+operationID))
	if err != nil {
		return "", nil, fmt.Errorf("tpm: derive operation identity: %w", err)
	}
	minHandle := uint64(d.base) + 0x100 // CreateKey owns the first 256 legacy slots.
	const maxHandle = uint64(0x81ffffff)
	if minHandle > maxHandle {
		return "", nil, fmt.Errorf("tpm: configured persistent handle base leaves no operation handle range")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return "", nil, fmt.Errorf("tpm: device is closed")
	}
	// AuthPolicy is immutable TPM public metadata and is returned by ReadPublic.
	// FlagUserWithAuth remains set below, so the ordinary HMAC/password signing
	// authorization is still available; the policy digest is only our full-width
	// operation ownership tag.
	template, err := tpmSigningTemplate(alg)
	if err != nil {
		return "", nil, err
	}
	template.AuthPolicy = append([]byte(nil), operationTag...)
	existingHandle, existingDER, occupied, err := d.findOperationKeyLocked(operationTag, alg, minHandle, maxHandle)
	if err != nil {
		return "", nil, err
	}
	if existingHandle != 0 {
		return formatTPMHandle(existingHandle), existingDER, nil
	}

	parentAuth := secrettext.String(tpmAuthBytes(d.keyAuth))
	parent, _, err := gotpm.CreatePrimary(
		d.rw, gotpm.HandleOwner, gotpm.PCRSelection{},
		secrettext.String(tpmAuthBytes(d.ownerAuth)), parentAuth, tpmStorageParentTemplate(),
	)
	if err != nil {
		return "", nil, fmt.Errorf("tpm: create operation storage parent: %w", err)
	}
	defer func() { _ = gotpm.FlushContext(d.rw, parent) }()
	privateBlob, publicBlob, _, _, _, err := gotpm.CreateKey(
		d.rw, parent, gotpm.PCRSelection{}, parentAuth,
		secrettext.String(tpmAuthBytes(d.keyAuth)), template,
	)
	if err != nil {
		return "", nil, fmt.Errorf("tpm: create operation signing object: %w", err)
	}
	defer secret.Wipe(privateBlob)
	defer secret.Wipe(publicBlob)
	transient, _, err := gotpm.Load(d.rw, parent, parentAuth, publicBlob, privateBlob)
	if err != nil {
		return "", nil, fmt.Errorf("tpm: load operation signing object: %w", err)
	}
	defer func() { _ = gotpm.FlushContext(d.rw, transient) }()
	rangeSize := maxHandle - minHandle + 1
	start := binary.BigEndian.Uint64(operationTag[:8]) % rangeSize
	for probe := uint64(0); probe < rangeSize; probe++ {
		candidate := tpmutil.Handle(minHandle + ((start + probe) % rangeSize))
		if occupied[candidate] {
			continue
		}
		handle := formatTPMHandle(candidate)
		if persistErr := gotpm.EvictControl(d.rw, secrettext.String(tpmAuthBytes(d.ownerAuth)), gotpm.HandleOwner, transient, candidate); persistErr != nil {
			// A concurrent operation can occupy the candidate between capability
			// enumeration and EvictControl. Accept only our exact immutable tag;
			// a same-algorithm foreign object is never an operation result.
			if existing, _, _, readErr := gotpm.ReadPublic(d.rw, candidate); readErr == nil {
				occupied[candidate] = true
				if crypto.ConstantTimeEqual(existing.AuthPolicy, operationTag) {
					der, derErr := tpmPublicDER(existing, alg)
					if derErr != nil {
						return "", nil, fmt.Errorf("tpm: operation handle %q has the right tag but incompatible public key: %w", handle, derErr)
					}
					return handle, der, nil
				}
				continue
			}
			return "", nil, fmt.Errorf("tpm: persist operation signing handle %q: %w", handle, persistErr)
		}
		pub, _, _, readErr := gotpm.ReadPublic(d.rw, candidate)
		if readErr != nil {
			return "", nil, fmt.Errorf("tpm: read back operation signing handle %q: %w", handle, readErr)
		}
		if !crypto.ConstantTimeEqual(pub.AuthPolicy, operationTag) {
			return "", nil, fmt.Errorf("tpm: operation signing handle %q read back with a foreign ownership tag", handle)
		}
		der, derErr := tpmPublicDER(pub, alg)
		if derErr != nil {
			return "", nil, derErr
		}
		return handle, der, nil
	}
	return "", nil, fmt.Errorf("tpm: no free persistent operation handle in configured range")
}

func formatTPMHandle(handle tpmutil.Handle) string {
	return fmt.Sprintf("0x%08x", uint32(handle))
}

// findOperationKeyLocked enumerates the TPM's sparse persistent-handle set,
// rather than reading millions of empty handle values. It searches the entire
// configured operation range for the full immutable tag before choosing a free
// deterministic probe, so a formerly occupied first candidate cannot make a
// restart create a second key at the newly freed slot.
func (d *goTPMDevice) findOperationKeyLocked(operationTag []byte, alg crypto.Algorithm, minHandle, maxHandle uint64) (tpmutil.Handle, []byte, map[tpmutil.Handle]bool, error) {
	occupied := make(map[tpmutil.Handle]bool)
	property := uint32(gotpm.HandleTypePersistent) << 24
	var matched tpmutil.Handle
	var matchedDER []byte
	for {
		values, more, err := gotpm.GetCapability(d.rw, gotpm.CapabilityHandles, 1024, property)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("tpm: enumerate persistent operation handles: %w", err)
		}
		var last uint32
		for _, value := range values {
			handle, ok := value.(tpmutil.Handle)
			if !ok {
				return 0, nil, nil, fmt.Errorf("tpm: capability returned a non-handle persistent object")
			}
			last = uint32(handle)
			if uint64(handle) < minHandle || uint64(handle) > maxHandle {
				continue
			}
			occupied[handle] = true
			pub, _, _, readErr := gotpm.ReadPublic(d.rw, handle)
			if readErr != nil {
				return 0, nil, nil, fmt.Errorf("tpm: read enumerated persistent handle %q: %w", formatTPMHandle(handle), readErr)
			}
			if !crypto.ConstantTimeEqual(pub.AuthPolicy, operationTag) {
				continue
			}
			der, derErr := tpmPublicDER(pub, alg)
			if derErr != nil {
				return 0, nil, nil, fmt.Errorf("tpm: tagged operation handle %q is incompatible: %w", formatTPMHandle(handle), derErr)
			}
			if matched != 0 {
				return 0, nil, nil, fmt.Errorf("tpm: durable operation tag resolves to multiple persistent handles")
			}
			matched, matchedDER = handle, der
		}
		if !more {
			break
		}
		if len(values) == 0 || last == ^uint32(0) {
			return 0, nil, nil, fmt.Errorf("tpm: persistent handle enumeration did not advance")
		}
		property = last + 1
	}
	return matched, matchedDER, occupied, nil
}

func tpmStorageParentTemplate() gotpm.Public {
	return gotpm.Public{
		Type:       gotpm.AlgRSA,
		NameAlg:    gotpm.AlgSHA256,
		Attributes: gotpm.FlagStorageDefault,
		RSAParameters: &gotpm.RSAParams{
			Symmetric: &gotpm.SymScheme{Alg: gotpm.AlgAES, KeyBits: 128, Mode: gotpm.AlgCFB},
			KeyBits:   2048,
		},
	}
}

func tpmSigningTemplate(alg crypto.Algorithm) (gotpm.Public, error) {
	base := gotpm.Public{
		NameAlg:    gotpm.AlgSHA256,
		Attributes: gotpm.FlagSign | gotpm.FlagSensitiveDataOrigin | gotpm.FlagUserWithAuth | gotpm.FlagFixedTPM | gotpm.FlagFixedParent,
	}
	switch alg {
	case crypto.RSA2048:
		base.Type = gotpm.AlgRSA
		base.RSAParameters = &gotpm.RSAParams{
			Sign: &gotpm.SigScheme{Alg: gotpm.AlgRSASSA, Hash: gotpm.AlgSHA256}, KeyBits: 2048,
		}
	case crypto.ECDSAP256:
		base.Type = gotpm.AlgECC
		base.ECCParameters = &gotpm.ECCParams{
			Sign: &gotpm.SigScheme{Alg: gotpm.AlgECDSA, Hash: gotpm.AlgSHA256}, CurveID: gotpm.CurveNISTP256,
		}
	default:
		return gotpm.Public{}, fmt.Errorf("tpm: unsupported algorithm %q (supported: RSA-2048, ECDSA-P256)", alg)
	}
	return base, nil
}

func tpmPublicDER(pub gotpm.Public, alg crypto.Algorithm) ([]byte, error) {
	switch alg {
	case crypto.RSA2048:
		if pub.RSAParameters == nil {
			return nil, fmt.Errorf("tpm: persistent object returned no RSA public parameters")
		}
		exponent := make([]byte, 4)
		binary.BigEndian.PutUint32(exponent, pub.RSAParameters.Exponent())
		for len(exponent) > 1 && exponent[0] == 0 {
			exponent = exponent[1:]
		}
		return crypto.RSAPublicKeyDERFromComponents(pub.RSAParameters.Modulus().Bytes(), exponent)
	case crypto.ECDSAP256:
		if pub.ECCParameters == nil {
			return nil, fmt.Errorf("tpm: persistent object returned no EC public parameters")
		}
		return crypto.ECDSAPublicKeyDERFromComponents("P-256", pub.ECCParameters.Point.X().Bytes(), pub.ECCParameters.Point.Y().Bytes())
	default:
		return nil, fmt.Errorf("tpm: unsupported public algorithm %q", alg)
	}
}

func (d *goTPMDevice) Sign(handle string, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, fmt.Errorf("tpm: device is closed")
	}
	h, err := parseTPMHandle(handle)
	if err != nil {
		return nil, err
	}
	hash, err := tpmHash(opts.Hash)
	if err != nil {
		return nil, err
	}
	pub, _, _, err := gotpm.ReadPublic(d.rw, h)
	if err != nil {
		return nil, fmt.Errorf("tpm: unknown persistent handle %q: %w", handle, err)
	}
	var scheme *gotpm.SigScheme
	switch pub.Type {
	case gotpm.AlgRSA:
		alg := gotpm.AlgRSASSA
		if opts.RSAPadding == crypto.RSAPSS {
			alg = gotpm.AlgRSAPSS
		}
		scheme = &gotpm.SigScheme{Alg: alg, Hash: hash}
	case gotpm.AlgECC:
		scheme = &gotpm.SigScheme{Alg: gotpm.AlgECDSA, Hash: hash}
	default:
		return nil, fmt.Errorf("tpm: persistent handle %q is not a signing key", handle)
	}
	sig, err := gotpm.Sign(d.rw, h, secrettext.String(tpmAuthBytes(d.keyAuth)), digest, nil, scheme)
	if err != nil {
		return nil, fmt.Errorf("tpm: sign digest: %w", err)
	}
	if sig.RSA != nil {
		return append([]byte(nil), sig.RSA.Signature...), nil
	}
	if sig.ECC != nil {
		return asn1.Marshal(struct{ R, S any }{R: sig.ECC.R, S: sig.ECC.S})
	}
	return nil, fmt.Errorf("tpm: device returned an empty signature")
}

func tpmHash(hash crypto.Hash) (gotpm.Algorithm, error) {
	switch hash {
	case "", crypto.SHA256:
		return gotpm.AlgSHA256, nil
	case crypto.SHA384:
		return gotpm.AlgSHA384, nil
	case crypto.SHA512:
		return gotpm.AlgSHA512, nil
	default:
		return 0, fmt.Errorf("tpm: unsupported hash %q", hash)
	}
}

func parseTPMHandle(handle string) (tpmutil.Handle, error) {
	raw := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(handle)), "0x")
	n, err := strconv.ParseUint(raw, 16, 32)
	if err != nil || n < 0x81000000 || n > 0x81ffffff {
		return 0, fmt.Errorf("tpm: invalid persistent handle %q", handle)
	}
	return tpmutil.Handle(n), nil
}

func (d *goTPMDevice) RevokeKey(handle string) error  { return d.removePersistent(handle) }
func (d *goTPMDevice) ZeroizeKey(handle string) error { return d.removePersistent(handle) }

func (d *goTPMDevice) RevokeKeyForOperation(operationID, handle string) error {
	if operationID == "" || len(operationID) > 256 {
		return fmt.Errorf("tpm: durable operation id is required and must be at most 256 bytes")
	}
	return d.removePersistent(handle)
}

func (d *goTPMDevice) ZeroizeKeyForOperation(operationID, handle string) error {
	if operationID == "" || len(operationID) > 256 {
		return fmt.Errorf("tpm: durable operation id is required and must be at most 256 bytes")
	}
	return d.removePersistent(handle)
}

func (d *goTPMDevice) removePersistent(handle string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return fmt.Errorf("tpm: device is closed")
	}
	h, err := parseTPMHandle(handle)
	if err != nil {
		return err
	}
	if _, _, _, err := gotpm.ReadPublic(d.rw, h); err != nil {
		// Already absent is the idempotent zeroize result.
		return nil
	}
	if err := gotpm.EvictControl(d.rw, secrettext.String(tpmAuthBytes(d.ownerAuth)), gotpm.HandleOwner, h, h); err != nil {
		return fmt.Errorf("tpm: remove persistent handle %q: %w", handle, err)
	}
	if _, _, _, err := gotpm.ReadPublic(d.rw, h); err == nil {
		return fmt.Errorf("tpm: persistent handle %q remained present after removal", handle)
	}
	return nil
}

func (d *goTPMDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if d.ownerAuth != nil {
		d.ownerAuth.Destroy()
		d.ownerAuth = nil
	}
	if d.keyAuth != nil {
		d.keyAuth.Destroy()
		d.keyAuth = nil
	}
	return d.rw.Close()
}
