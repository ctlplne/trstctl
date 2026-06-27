package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"trstctl.com/trstctl/internal/crypto/secret"
)

type Argon2idParams struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

func (p Argon2idParams) withDefaults() Argon2idParams {
	if p.MemoryKiB == 0 {
		p.MemoryKiB = 64 * 1024
	}
	if p.Iterations == 0 {
		p.Iterations = 3
	}
	if p.Parallelism == 0 {
		p.Parallelism = 4
	}
	if p.SaltLen == 0 {
		p.SaltLen = 16
	}
	if p.KeyLen == 0 {
		p.KeyLen = 32
	}
	return p
}

func HashArgon2id(password []byte, params Argon2idParams) ([]byte, error) {
	p := params.withDefaults()
	salt, err := RandomBytes(int(p.SaltLen))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(salt)
	digest := argon2.IDKey(password, salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLen)
	defer secret.Wipe(digest)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)
	return []byte(encoded), nil
}

func VerifyArgon2id(encoded, password []byte) (bool, error) {
	p, salt, want, err := parseArgon2id(encoded)
	if err != nil {
		return false, err
	}
	defer secret.Wipe(salt)
	defer secret.Wipe(want)
	got := argon2.IDKey(password, salt, p.Iterations, p.MemoryKiB, p.Parallelism, uint32(len(want)))
	defer secret.Wipe(got)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func parseArgon2id(encoded []byte) (Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2idParams{}, nil, nil, errors.New("argon2id: malformed PHC string")
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || version != argon2.Version {
		return Argon2idParams{}, nil, nil, errors.New("argon2id: unsupported version")
	}
	var p Argon2idParams
	for _, kv := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) != 2 {
			return Argon2idParams{}, nil, nil, errors.New("argon2id: malformed params")
		}
		n, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil {
			return Argon2idParams{}, nil, nil, errors.New("argon2id: malformed params")
		}
		switch pair[0] {
		case "m":
			p.MemoryKiB = uint32(n)
		case "t":
			p.Iterations = uint32(n)
		case "p":
			if n > 255 {
				return Argon2idParams{}, nil, nil, errors.New("argon2id: invalid parallelism")
			}
			p.Parallelism = uint8(n)
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, err
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		secret.Wipe(salt)
		return Argon2idParams{}, nil, nil, err
	}
	return p, salt, digest, nil
}
