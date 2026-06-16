package crypto

// Panic-safe CMS/PKCS#7 parsing, kept inside the AN-3 boundary.
//
// trstctl decodes CMS/PKCS#7 on UNTRUSTED input at three boundaries — the SCEP
// pkiMessage (ParseSCEPRequest), the SCEP CertRep (ParseSCEPResponse), and the
// AWS/Azure cloud instance-identity document (VerifyCMSSignature) — all of which
// route through github.com/smallstep/pkcs7. That library's BER decoder
// (ber.go readObject) indexes out of range on some malformed long-form length
// encodings: a 2-byte input 0x30 0x84 (SEQUENCE, long-form length claiming 4
// length octets, none present) panics with "index out of range [2] with length 2"
// (FUZZ-001). Because the panic is in a dependency we cannot fix in place, we
// guard the trstctl entry points: every untrusted pkcs7.Parse goes through
// safeParsePKCS7, which recovers any panic and converts it into a bounded error.
//
// This is the same fail-closed contract gcmOpen already gives for AEAD.Open's
// wrong-nonce panic (envelope.go): malformed or hostile input returns a clean
// error instead of crashing the process. The parser must not panic on any input.

import (
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/smallstep/pkcs7"
)

// errPKCS7Panic is returned (wrapped) when the underlying CMS decoder panics on
// malformed untrusted input. It is a distinct sentinel so callers/tests can
// assert that the boundary caught a decoder panic rather than a normal parse
// error, and so the failure mode is greppable.
var errPKCS7Panic = errors.New("crypto: CMS/PKCS7 decoder panicked on malformed input")

// safeParsePKCS7 parses CMS/PKCS#7 DER, recovering any panic from the underlying
// BER decoder (smallstep/pkcs7) and returning it as an error. It is the ONLY way
// untrusted bytes should reach pkcs7.Parse inside this boundary: a malformed or
// hostile message must fail closed with an error, never panic the goroutine /
// process (FUZZ-001). It adds no behaviour for well-formed input — on success it
// returns exactly what pkcs7.Parse returns.
func safeParsePKCS7(der []byte) (p7 *pkcs7.PKCS7, err error) {
	defer func() {
		if r := recover(); r != nil {
			// Capture the stack into the structured error so a recovered
			// dependency panic is still diagnosable, without leaking the raw
			// (attacker-controlled) input. The stack is dropped by callers that
			// only inspect err.Error()/errors.Is; %+v surfaces it when needed.
			p7 = nil
			err = fmt.Errorf("%w: %v\n%s", errPKCS7Panic, r, debug.Stack())
		}
	}()
	return pkcs7.Parse(der)
}
