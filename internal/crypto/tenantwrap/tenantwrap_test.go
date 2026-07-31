// SPDX-License-Identifier: MPL-2.0

package tenantwrap

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

var (
	testDomainBindingA = []byte("tenant=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa;domain=11111111-1111-4111-8111-111111111111;generation=1")
	testDomainBindingB = []byte("tenant=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb;domain=22222222-2222-4222-8222-222222222222;generation=1")
)

func TestCreateAndOpenDomainKEKRoundTrip(t *testing.T) {
	wrapperKey := bytes.Repeat([]byte{0x11}, localKeySize)
	t.Cleanup(func() { secret.Wipe(wrapperKey) })
	path := writePrivateWrapper(t, wrapperKey)

	created, wrapped, err := CreateDomainKEK(path, testDomainBindingA)
	if err != nil {
		t.Fatalf("CreateDomainKEK: %v", err)
	}
	defer created.Destroy()
	if len(wrapped) != encodedSize {
		t.Fatalf("wrapped length = %d, want %d", len(wrapped), encodedSize)
	}
	if bytes.Contains(wrapped, wrapperKey) {
		t.Fatal("wrapped representation contains the operator wrapper key")
	}

	opened, err := OpenDomainKEK(path, wrapped, testDomainBindingA)
	if err != nil {
		t.Fatalf("OpenDomainKEK: %v", err)
	}
	defer opened.Destroy()
	if err := created.WithKey(func(createdKey []byte) error {
		if bytes.Contains(wrapped, createdKey) {
			return errors.New("wrapped representation contains the plaintext domain KEK")
		}
		return opened.WithKey(func(openedKey []byte) error {
			if !bytes.Equal(createdKey, openedKey) {
				return errors.New("reopened domain KEK differs from the created KEK")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRequiresAnExistingWrapperFileAndNeverCreatesOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tenant-wrapper.key")

	if _, _, err := CreateDomainKEK(path, testDomainBindingA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateDomainKEK missing wrapper error = %v, want ErrUnavailable", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrapper file was created or stat failed unexpectedly: %v", err)
	}

	existingWrapper := bytes.Repeat([]byte{0x12}, localKeySize)
	t.Cleanup(func() { secret.Wipe(existingWrapper) })
	existingPath := writePrivateWrapper(t, existingWrapper)
	domain, wrapped, err := CreateDomainKEK(existingPath, testDomainBindingA)
	if err != nil {
		t.Fatalf("CreateDomainKEK fixture: %v", err)
	}
	domain.Destroy()
	if _, err := OpenDomainKEK(path, wrapped, testDomainBindingA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("OpenDomainKEK missing wrapper error = %v, want ErrUnavailable", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenDomainKEK created wrapper file or stat failed unexpectedly: %v", err)
	}
}

func TestCreateRejectsSymlinkWrapper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink privileges vary by environment")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.key")
	if err := os.WriteFile(target, bytes.Repeat([]byte{0x21}, localKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "tenant-wrapper.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, _, err := CreateDomainKEK(link, testDomainBindingA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateDomainKEK symlink error = %v, want ErrUnavailable", err)
	}
}

func TestCreateRejectsUnsafeWrapperMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows mode bits do not model Unix custody")
	}
	path := filepath.Join(t.TempDir(), "tenant-wrapper.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x31}, localKeySize), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := CreateDomainKEK(path, testDomainBindingA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateDomainKEK unsafe-mode error = %v, want ErrUnavailable", err)
	}
}

func TestCreateRejectsWrongSizeWrapperKey(t *testing.T) {
	path := writePrivateWrapper(t, bytes.Repeat([]byte{0x41}, localKeySize-1))

	if _, _, err := CreateDomainKEK(path, testDomainBindingA); !errors.Is(err, ErrInvalidWrapperKey) {
		t.Fatalf("CreateDomainKEK wrong-size error = %v, want ErrInvalidWrapperKey", err)
	}
}

func TestOpenClassifiesStructuralCorruptionAndAuthenticatedUnwrapFailure(t *testing.T) {
	firstWrapper := bytes.Repeat([]byte{0x51}, localKeySize)
	t.Cleanup(func() { secret.Wipe(firstWrapper) })
	path := writePrivateWrapper(t, firstWrapper)
	domain, wrapped, err := CreateDomainKEK(path, testDomainBindingA)
	if err != nil {
		t.Fatalf("CreateDomainKEK: %v", err)
	}
	domain.Destroy()

	secondWrapper := bytes.Repeat([]byte{0x52}, localKeySize)
	t.Cleanup(func() { secret.Wipe(secondWrapper) })
	if err := os.WriteFile(path, secondWrapper, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDomainKEK(path, wrapped, testDomainBindingA); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("OpenDomainKEK wrong-wrapper error = %v, want ErrUnwrap", err)
	}

	if err := os.WriteFile(path, firstWrapper, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte {
			return b[:len(b)-1]
		},
		"magic": func(b []byte) []byte {
			b[0] ^= 0xff
			return b
		},
		"body": func(b []byte) []byte {
			b[headerSize] ^= 0xff
			return b
		},
	} {
		t.Run(name, func(t *testing.T) {
			corrupt := append([]byte(nil), wrapped...)
			corrupt = mutate(corrupt)
			if _, err := OpenDomainKEK(path, corrupt, testDomainBindingA); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("OpenDomainKEK corrupt error = %v, want ErrCorrupt", err)
			}
		})
	}

	// Recompute the diagnostic checksum after corrupting the domain ciphertext.
	// This reaches the AEAD integrity check instead of only the outer parser.
	corrupt := append([]byte(nil), wrapped...)
	corrupt[headerSize] ^= 0xff
	sum := sha256.Sum256(corrupt[:payloadSize])
	copy(corrupt[payloadSize:], sum[:])
	if _, err := OpenDomainKEK(path, corrupt, testDomainBindingA); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("OpenDomainKEK authenticated-ciphertext error = %v, want ErrUnwrap", err)
	}
}

func TestDomainBindingRejectsCrossTenantAndGenerationSubstitution(t *testing.T) {
	wrapperKey := bytes.Repeat([]byte{0x53}, localKeySize)
	t.Cleanup(func() { secret.Wipe(wrapperKey) })
	path := writePrivateWrapper(t, wrapperKey)

	domainA, wrappedA, err := CreateDomainKEK(path, testDomainBindingA)
	if err != nil {
		t.Fatalf("CreateDomainKEK(A): %v", err)
	}
	defer domainA.Destroy()

	if _, err := OpenDomainKEK(path, wrappedA, testDomainBindingB); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("OpenDomainKEK(A record as B) error = %v, want ErrUnwrap", err)
	}
	nextGeneration := append([]byte(nil), testDomainBindingA...)
	nextGeneration[len(nextGeneration)-1] = '2'
	if _, err := OpenDomainKEK(path, wrappedA, nextGeneration); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("OpenDomainKEK(generation 1 as generation 2) error = %v, want ErrUnwrap", err)
	}

	domainB, wrappedB, err := CreateDomainKEK(path, testDomainBindingB)
	if err != nil {
		t.Fatalf("CreateDomainKEK(B): %v", err)
	}
	defer domainB.Destroy()
	if _, err := OpenDomainKEK(path, wrappedB, testDomainBindingA); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("OpenDomainKEK(B record as A) error = %v, want ErrUnwrap", err)
	}
}

func TestDomainBindingIsRequiredBeforeWrapperCustody(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-wrapper.key")
	if _, _, err := CreateDomainKEK(missing, nil); !errors.Is(err, ErrDomainBinding) {
		t.Fatalf("CreateDomainKEK empty binding error = %v, want ErrDomainBinding", err)
	}
	if _, err := OpenDomainKEK(missing, make([]byte, encodedSize), nil); !errors.Is(err, ErrDomainBinding) {
		t.Fatalf("OpenDomainKEK empty binding error = %v, want ErrDomainBinding", err)
	}
}

func TestRawKeyInputsAreWipedOnSuccessAndFailure(t *testing.T) {
	t.Run("create success", func(t *testing.T) {
		wrapperRaw := bytes.Repeat([]byte{0x61}, localKeySize)
		domainRaw := bytes.Repeat([]byte{0x62}, localKeySize)
		wantDomain := append([]byte(nil), domainRaw...)
		defer secret.Wipe(wantDomain)

		domain, _, err := createDomainKEK(
			"unused",
			testDomainBindingA,
			func(string) ([]byte, error) { return wrapperRaw, nil },
			func() ([]byte, error) { return domainRaw, nil },
			seal.NewLocalKEK,
		)
		if err != nil {
			t.Fatalf("createDomainKEK: %v", err)
		}
		defer domain.Destroy()
		requireZeroed(t, "loaded wrapper key", wrapperRaw)
		requireZeroed(t, "generated domain key", domainRaw)
		if err := domain.WithKey(func(got []byte) error {
			if !bytes.Equal(got, wantDomain) {
				return errors.New("locked domain KEK did not retain its owned copy")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid wrapper size", func(t *testing.T) {
		wrapperRaw := bytes.Repeat([]byte{0x71}, localKeySize-1)
		_, _, err := createDomainKEK(
			"unused",
			testDomainBindingA,
			func(string) ([]byte, error) { return wrapperRaw, nil },
			seal.GenerateKEK,
			seal.NewLocalKEK,
		)
		if !errors.Is(err, ErrInvalidWrapperKey) {
			t.Fatalf("createDomainKEK error = %v, want ErrInvalidWrapperKey", err)
		}
		requireZeroed(t, "wrong-size wrapper key", wrapperRaw)
	})

	t.Run("post-lock create failure destroys owned domain", func(t *testing.T) {
		wrapperRaw := bytes.Repeat([]byte{0x72}, localKeySize)
		domainRaw := bytes.Repeat([]byte{0x73}, localKeySize)
		factoryCalls := 0
		var ownedDomain *seal.LocalKEK
		factory := func(raw []byte) (*seal.LocalKEK, error) {
			factoryCalls++
			k, err := seal.NewLocalKEK(raw)
			if err != nil {
				return nil, err
			}
			if factoryCalls == 1 {
				k.Destroy() // make domain wrapping fail after the domain is locked
			} else {
				ownedDomain = k
			}
			return k, nil
		}
		_, _, err := createDomainKEK(
			"unused",
			testDomainBindingA,
			func(string) ([]byte, error) { return wrapperRaw, nil },
			func() ([]byte, error) { return domainRaw, nil },
			factory,
		)
		if !errors.Is(err, ErrCustody) {
			t.Fatalf("createDomainKEK error = %v, want ErrCustody", err)
		}
		requireZeroed(t, "loaded wrapper key", wrapperRaw)
		requireZeroed(t, "generated domain key", domainRaw)
		if ownedDomain == nil {
			t.Fatal("test did not reach domain KEK allocation")
		}
		if err := ownedDomain.WithKey(func(got []byte) error {
			if got != nil {
				return errors.New("error path left owned domain KEK reachable")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("open wrong wrapper", func(t *testing.T) {
		goodWrapper := bytes.Repeat([]byte{0x81}, localKeySize)
		path := writePrivateWrapper(t, goodWrapper)
		domain, wrapped, err := CreateDomainKEK(path, testDomainBindingA)
		if err != nil {
			t.Fatalf("CreateDomainKEK: %v", err)
		}
		domain.Destroy()

		wrongWrapperRaw := bytes.Repeat([]byte{0x82}, localKeySize)
		_, err = openDomainKEK(
			"unused",
			wrapped,
			testDomainBindingA,
			func(string) ([]byte, error) { return wrongWrapperRaw, nil },
			seal.NewLocalKEK,
		)
		if !errors.Is(err, ErrUnwrap) {
			t.Fatalf("openDomainKEK error = %v, want ErrUnwrap", err)
		}
		requireZeroed(t, "wrong loaded wrapper key", wrongWrapperRaw)
	})
}

func TestPartialSecretBytesAreWipedWhenDependenciesReturnErrors(t *testing.T) {
	injectedErr := errors.New("injected partial read")

	t.Run("create wrapper load", func(t *testing.T) {
		partialWrapper := bytes.Repeat([]byte{0xa1}, localKeySize)
		_, _, err := createDomainKEK(
			"unused",
			testDomainBindingA,
			func(string) ([]byte, error) { return partialWrapper, injectedErr },
			seal.GenerateKEK,
			seal.NewLocalKEK,
		)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("createDomainKEK error = %v, want ErrUnavailable", err)
		}
		requireZeroed(t, "partial wrapper read", partialWrapper)
	})

	t.Run("create domain generation", func(t *testing.T) {
		wrapperRaw := bytes.Repeat([]byte{0xa2}, localKeySize)
		partialDomain := bytes.Repeat([]byte{0xa3}, localKeySize)
		_, _, err := createDomainKEK(
			"unused",
			testDomainBindingA,
			func(string) ([]byte, error) { return wrapperRaw, nil },
			func() ([]byte, error) { return partialDomain, injectedErr },
			seal.NewLocalKEK,
		)
		if !errors.Is(err, ErrCustody) {
			t.Fatalf("createDomainKEK error = %v, want ErrCustody", err)
		}
		requireZeroed(t, "loaded wrapper key", wrapperRaw)
		requireZeroed(t, "partial generated domain key", partialDomain)
	})

	t.Run("open wrapper load", func(t *testing.T) {
		goodWrapper := bytes.Repeat([]byte{0xa4}, localKeySize)
		path := writePrivateWrapper(t, goodWrapper)
		domain, wrapped, err := CreateDomainKEK(path, testDomainBindingA)
		if err != nil {
			t.Fatalf("CreateDomainKEK fixture: %v", err)
		}
		domain.Destroy()

		partialWrapper := bytes.Repeat([]byte{0xa5}, localKeySize)
		_, err = openDomainKEK(
			"unused",
			wrapped,
			testDomainBindingA,
			func(string) ([]byte, error) { return partialWrapper, injectedErr },
			seal.NewLocalKEK,
		)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("openDomainKEK error = %v, want ErrUnavailable", err)
		}
		requireZeroed(t, "partial wrapper read", partialWrapper)
	})
}

func TestReturnedDomainKEKHasCallerOwnedDestroySemantics(t *testing.T) {
	wrapperKey := bytes.Repeat([]byte{0x91}, localKeySize)
	t.Cleanup(func() { secret.Wipe(wrapperKey) })
	domain, _, err := CreateDomainKEK(writePrivateWrapper(t, wrapperKey), testDomainBindingA)
	if err != nil {
		t.Fatalf("CreateDomainKEK: %v", err)
	}

	domain.Destroy()
	domain.Destroy()
	if err := domain.WithKey(func(got []byte) error {
		if got != nil {
			return errors.New("Destroy left domain KEK bytes reachable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func FuzzParseWrappedDomainKEK(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("TDK1"))
	f.Add(make([]byte, encodedSize))
	f.Add(encodeWrappedDomainKEK(make([]byte, domainWrappedSize)))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = parseWrappedDomainKEK(input)
	})
}

func writePrivateWrapper(t *testing.T, key []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tenant-wrapper.key")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireZeroed(t *testing.T, name string, b []byte) {
	t.Helper()
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("%s was not zeroed", name)
	}
}
