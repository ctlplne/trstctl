// SPDX-License-Identifier: MPL-2.0

package token

// PKCS #11 v2.40 values this token uses, under their specification names so
// the adapter reads like the specification.
const (
	CKR_OK                             = 0x000
	CKR_HOST_MEMORY                    = 0x002
	CKR_SLOT_ID_INVALID                = 0x003
	CKR_GENERAL_ERROR                  = 0x005
	CKR_FUNCTION_FAILED                = 0x006
	CKR_ARGUMENTS_BAD                  = 0x007
	CKR_ATTRIBUTE_SENSITIVE            = 0x011
	CKR_ATTRIBUTE_TYPE_INVALID         = 0x012
	CKR_DATA_LEN_RANGE                 = 0x021
	CKR_DEVICE_ERROR                   = 0x030
	CKR_FUNCTION_NOT_SUPPORTED         = 0x054
	CKR_KEY_HANDLE_INVALID             = 0x060
	CKR_KEY_TYPE_INCONSISTENT          = 0x063
	CKR_MECHANISM_INVALID              = 0x070
	CKR_OBJECT_HANDLE_INVALID          = 0x082
	CKR_OPERATION_ACTIVE               = 0x090
	CKR_OPERATION_NOT_INITIALIZED      = 0x091
	CKR_PIN_INCORRECT                  = 0x0A0
	CKR_SESSION_HANDLE_INVALID         = 0x0B3
	CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x0B4
	CKR_SESSION_READ_ONLY_EXISTS       = 0x0B7
	CKR_TOKEN_WRITE_PROTECTED          = 0x0E2
	CKR_USER_ALREADY_LOGGED_IN         = 0x100
	CKR_USER_NOT_LOGGED_IN             = 0x101
	CKR_USER_TYPE_INVALID              = 0x103
	CKR_BUFFER_TOO_SMALL               = 0x150
	CKR_CRYPTOKI_NOT_INITIALIZED       = 0x190
	CKR_CRYPTOKI_ALREADY_INITIALIZED   = 0x191

	CKO_CERTIFICATE = 1
	CKO_PUBLIC_KEY  = 2
	CKO_PRIVATE_KEY = 3

	CKK_RSA = 0
	CKK_EC  = 3

	CKC_X_509 = 0

	CKU_SO   = 0
	CKU_USER = 1

	CKM_RSA_PKCS        = 0x0001
	CKM_SHA256_RSA_PKCS = 0x0040
	CKM_ECDSA           = 0x1041
	CKM_ECDSA_SHA256    = 0x1044

	CKA_CLASS               = 0x000
	CKA_TOKEN               = 0x001
	CKA_PRIVATE             = 0x002
	CKA_LABEL               = 0x003
	CKA_VALUE               = 0x011
	CKA_CERTIFICATE_TYPE    = 0x080
	CKA_ISSUER              = 0x081
	CKA_SERIAL_NUMBER       = 0x082
	CKA_TRUSTED             = 0x086
	CKA_KEY_TYPE            = 0x100
	CKA_SUBJECT             = 0x101
	CKA_ID                  = 0x102
	CKA_SENSITIVE           = 0x103
	CKA_ENCRYPT             = 0x104
	CKA_DECRYPT             = 0x105
	CKA_WRAP                = 0x106
	CKA_UNWRAP              = 0x107
	CKA_SIGN                = 0x108
	CKA_SIGN_RECOVER        = 0x109
	CKA_VERIFY              = 0x10A
	CKA_VERIFY_RECOVER      = 0x10B
	CKA_DERIVE              = 0x10C
	CKA_MODULUS             = 0x120
	CKA_MODULUS_BITS        = 0x121
	CKA_PUBLIC_EXPONENT     = 0x122
	CKA_PRIVATE_EXPONENT    = 0x123
	CKA_EXTRACTABLE         = 0x162
	CKA_LOCAL               = 0x163
	CKA_NEVER_EXTRACTABLE   = 0x164
	CKA_ALWAYS_SENSITIVE    = 0x165
	CKA_MODIFIABLE          = 0x170
	CKA_EC_PARAMS           = 0x180
	CKA_EC_POINT            = 0x181
	CKA_ALWAYS_AUTHENTICATE = 0x202

	CKF_RNG                  = 0x0001
	CKF_WRITE_PROTECTED      = 0x0002
	CKF_LOGIN_REQUIRED       = 0x0004
	CKF_USER_PIN_INITIALIZED = 0x0008
	CKF_TOKEN_INITIALIZED    = 0x0400
	CKF_TOKEN_PRESENT        = 0x0001
	CKF_RW_SESSION           = 0x0002
	CKF_SERIAL_SESSION       = 0x0004
	CKF_SIGN                 = 0x0800
	CKF_VERIFY               = 0x2000
	CKF_EC_F_P               = 0x100000
	CKF_EC_NAMEDCURVE        = 0x800000
	CKF_EC_UNCOMPRESS        = 0x1000000

	CKS_RO_PUBLIC_SESSION = 0
	CKS_RO_USER_FUNCTIONS = 1
	CKS_RW_PUBLIC_SESSION = 2
	CKS_RW_USER_FUNCTIONS = 3
)

// MechanismName is the name trstctl records as the signing request's artifact
// type, so the mechanism is part of what is approved and audited.
func MechanismName(mechanism uint64) string {
	switch mechanism {
	case CKM_RSA_PKCS:
		return "CKM_RSA_PKCS"
	case CKM_SHA256_RSA_PKCS:
		return "CKM_SHA256_RSA_PKCS"
	case CKM_ECDSA:
		return "CKM_ECDSA"
	case CKM_ECDSA_SHA256:
		return "CKM_ECDSA_SHA256"
	}
	return ""
}
