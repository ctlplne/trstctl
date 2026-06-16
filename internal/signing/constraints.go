package signing

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// keyConstraints are the signer-enforceable usage limits attached to a key at
// creation (design §4.5, SIGNER-002/003). They are the one cheap defense the
// signer can apply against an abused-but-authorized control plane: a key minted
// for one purpose cannot be coerced into signing for another, even by a caller
// that holds the handle and reaches the socket.
//
// Empty sets mean "unconstrained" so pre-constraint callers keep working; the
// control plane sets a tight set for CA-class keys (see provisionCA).
type keyConstraints struct {
	// purposes is the allowed KeyPurpose set. Empty = any purpose allowed.
	purposes map[signerpb.KeyPurpose]bool
	// hashes is the allowed Hash set. Empty = any supported hash allowed.
	hashes map[signerpb.Hash]bool
	// requireAuth marks the key DUAL-CONTROL (RED-003): the signer refuses every
	// Sign against it unless the request carries a valid independent authorization
	// token (an HMAC over the exact signing tuple under a secret the signer holds
	// but the on-socket caller does not). It is the cheap signer-side defense that
	// makes "socket access + handle + correct purpose => forge anything" no longer
	// hold for the crown-jewel key classes (CA/code-signing): an attacker on the
	// socket also needs the out-of-band approver secret, and the token commits to
	// the digest so it cannot be replayed onto different bytes. Purpose/hash
	// constraints still apply in addition. Default false = back-compat.
	requireAuth bool
}

// constraintsFromGenerate builds the constraint set declared on a GenerateKey
// request. It rejects an explicitly-unspecified purpose in the allow-set (a
// caller asking to allow "UNSPECIFIED" is almost certainly a bug, and allowing
// it would create a key that the also-unspecified default Sign could always
// use — defeating the constraint).
func constraintsFromGenerate(req *signerpb.GenerateKeyRequest) (keyConstraints, error) {
	kc := keyConstraints{}
	if ap := req.GetAllowedPurposes(); len(ap) > 0 {
		kc.purposes = make(map[signerpb.KeyPurpose]bool, len(ap))
		for _, p := range ap {
			if p == signerpb.KeyPurpose_KEY_PURPOSE_UNSPECIFIED {
				return keyConstraints{}, status.Error(codes.InvalidArgument,
					"allowed_purposes must not contain KEY_PURPOSE_UNSPECIFIED")
			}
			kc.purposes[p] = true
		}
	}
	if ah := req.GetAllowedHashes(); len(ah) > 0 {
		kc.hashes = make(map[signerpb.Hash]bool, len(ah))
		for _, h := range ah {
			if h == signerpb.Hash_HASH_UNSPECIFIED {
				return keyConstraints{}, status.Error(codes.InvalidArgument,
					"allowed_hashes must not contain HASH_UNSPECIFIED")
			}
			kc.hashes[h] = true
		}
	}
	return kc, nil
}

// constrained reports whether any limit is set; an unconstrained key skips the
// purpose check entirely (back-compat).
func (kc keyConstraints) constrained() bool {
	return len(kc.purposes) > 0 || len(kc.hashes) > 0 || kc.requireAuth
}

// check enforces the constraints against a Sign request. A violation returns
// FAILED_PRECONDITION (the code the design reserves for usage constraints, §5.5)
// and never reveals key material. For a constrained-by-purpose key, an
// UNSPECIFIED requested purpose is itself a violation — the caller must declare
// what the signature is for.
func (kc keyConstraints) check(req *signerpb.SignRequest) error {
	if len(kc.purposes) > 0 {
		p := req.GetPurpose()
		if p == signerpb.KeyPurpose_KEY_PURPOSE_UNSPECIFIED {
			return status.Error(codes.FailedPrecondition,
				"key requires an explicit purpose; none was asserted")
		}
		if !kc.purposes[p] {
			return status.Errorf(codes.FailedPrecondition,
				"purpose %s is not permitted for this key", p)
		}
	}
	if len(kc.hashes) > 0 {
		if !kc.hashes[req.GetHash()] {
			return status.Errorf(codes.FailedPrecondition,
				"hash %s is not permitted for this key", req.GetHash())
		}
	}
	return nil
}

// purposeList returns the allowed purposes as a sorted-by-enum slice for
// persistence/round-trip. Order is stable so the sealed metadata is
// deterministic.
func (kc keyConstraints) purposeList() []signerpb.KeyPurpose {
	if len(kc.purposes) == 0 {
		return nil
	}
	out := make([]signerpb.KeyPurpose, 0, len(kc.purposes))
	for p := range kc.purposes {
		out = append(out, p)
	}
	sortPurposes(out)
	return out
}

// hashList returns the allowed hashes as a sorted-by-enum slice for persistence.
func (kc keyConstraints) hashList() []signerpb.Hash {
	if len(kc.hashes) == 0 {
		return nil
	}
	out := make([]signerpb.Hash, 0, len(kc.hashes))
	for h := range kc.hashes {
		out = append(out, h)
	}
	sortHashes(out)
	return out
}

func sortPurposes(s []signerpb.KeyPurpose) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func sortHashes(s []signerpb.Hash) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
