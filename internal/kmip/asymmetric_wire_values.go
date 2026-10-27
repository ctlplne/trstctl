// SPDX-License-Identifier: BUSL-1.1

package kmip

// Wire values for the asymmetric profile (A197), from the OASIS KMIP 1.4
// specification's tag table (9.1.3.1) and enumerations (9.1.3.2).

const (
	OperationCreateKeyPair    Operation = 0x00000002
	OperationGetAttributes    Operation = 0x0000000b
	OperationGetAttributeList Operation = 0x0000000c
	OperationAddAttribute     Operation = 0x0000000d
	OperationModifyAttribute  Operation = 0x0000000e
	OperationDeleteAttribute  Operation = 0x0000000f
	OperationActivate         Operation = 0x00000012
	OperationSign             Operation = 0x00000021
	OperationSignatureVerify  Operation = 0x00000022
)

const (
	TagActivationDate              uint32 = 0x420001
	TagAttributeIndex              uint32 = 0x420009
	TagCommonTemplateAttribute     uint32 = 0x42001f
	TagHashingAlgorithm            uint32 = 0x420038
	TagLinkType                    uint32 = 0x42004b
	TagLinkedObjectIdentifier      uint32 = 0x42004c
	TagName                        uint32 = 0x420053
	TagNameType                    uint32 = 0x420054
	TagNameValue                   uint32 = 0x420055
	TagPaddingMethod               uint32 = 0x42005f
	TagPrivateKey                  uint32 = 0x420064
	TagPrivateKeyTemplateAttribute uint32 = 0x420065
	TagPrivateKeyUniqueIdentifier  uint32 = 0x420066
	TagPublicKey                   uint32 = 0x42006d
	TagPublicKeyTemplateAttribute  uint32 = 0x42006e
	TagPublicKeyUniqueIdentifier   uint32 = 0x42006f
	TagRevocationReason            uint32 = 0x420081
	TagRevocationReasonCode        uint32 = 0x420082
	TagValidityIndicator           uint32 = 0x42009b
	TagDigitalSignatureAlgorithm   uint32 = 0x4200ae
	TagCorrelationValue            uint32 = 0x4200d6
	TagData                        uint32 = 0x4200c2
	TagSignatureData               uint32 = 0x4200c3
	TagInitIndicator               uint32 = 0x4200d7
	TagFinalIndicator              uint32 = 0x4200d8
	TagDigestedData                uint32 = 0x420107
)

const (
	objectTypePublicKey  int32 = 0x00000003
	objectTypePrivateKey int32 = 0x00000004

	cryptographicAlgorithmRSA   int32 = 0x00000004
	cryptographicAlgorithmECDSA int32 = 0x00000006

	keyFormatTypePKCS8 int32 = 0x00000004
	keyFormatTypeX509  int32 = 0x00000005

	stateEnumPreActive   int32 = 0x00000001
	stateEnumActive      int32 = 0x00000002
	stateEnumDeactivated int32 = 0x00000003
	stateEnumCompromised int32 = 0x00000004
	stateEnumDestroyed   int32 = 0x00000005

	linkTypePublicKey  int32 = 0x00000102
	linkTypePrivateKey int32 = 0x00000103

	usageMaskSign   int32 = 0x00000001
	usageMaskVerify int32 = 0x00000002

	paddingMethodPKCS1v15 int32 = 0x00000008
	paddingMethodPSS      int32 = 0x0000000a

	hashingAlgorithmSHA256 int32 = 0x00000006
	hashingAlgorithmSHA384 int32 = 0x00000007
	hashingAlgorithmSHA512 int32 = 0x00000008

	signatureSHA256WithRSA   int32 = 0x00000005
	signatureSHA384WithRSA   int32 = 0x00000006
	signatureSHA512WithRSA   int32 = 0x00000007
	signatureRSASSAPSS       int32 = 0x00000008
	signatureECDSAWithSHA256 int32 = 0x0000000e
	signatureECDSAWithSHA384 int32 = 0x0000000f
	signatureECDSAWithSHA512 int32 = 0x00000010

	validityIndicatorValid   int32 = 0x00000001
	validityIndicatorInvalid int32 = 0x00000002

	nameTypeUninterpretedText int32 = 0x00000001

	revocationReasonKeyCompromise int32 = 0x00000002
	revocationReasonCACompromise  int32 = 0x00000003

	resultReasonFeatureNotSupported  int32 = 0x00000008
	resultReasonCryptographicFailure int32 = 0x0000000a
	resultReasonIllegalOperation     int32 = 0x0000000b
	resultReasonPermissionDenied     int32 = 0x0000000c
	resultReasonIndexOutOfBounds     int32 = 0x0000000e
	resultReasonNotExtractable       int32 = 0x00000017
)
