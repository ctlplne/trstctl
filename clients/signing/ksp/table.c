/* SPDX-License-Identifier: MPL-2.0 */

//go:build cgo

#include "ksp.h"
#include "_cgo_export.h"

/* The function table CNG reads after GetKeyStorageInterface. Every entry is
 * one of the Go functions exported in module.go. */
static KSP_FUNCTION_TABLE trstctl_ksp_table = {
	{1, 0},
	kspOpenProvider,
	kspOpenKey,
	kspCreatePersistedKey,
	kspGetProviderProperty,
	kspGetKeyProperty,
	kspSetProviderProperty,
	kspSetKeyProperty,
	kspFinalizeKey,
	kspDeleteKey,
	kspFreeProvider,
	kspFreeKey,
	kspFreeBuffer,
	kspEncrypt,
	kspDecrypt,
	kspIsAlgSupported,
	kspEnumAlgorithms,
	kspEnumKeys,
	kspImportKey,
	kspExportKey,
	kspSignHash,
	kspVerifySignature,
	kspPromptUser,
	kspNotifyChangeKey,
	kspSecretAgreement,
	kspDeriveKey,
	kspFreeSecret,
};

KSP_EXPORT KSP_STATUS GetKeyStorageInterface(KSP_LPCWSTR pszProviderName, KSP_FUNCTION_TABLE **ppFunctionTable, KSP_DWORD dwFlags) {
	(void)pszProviderName;
	(void)dwFlags;
	if (ppFunctionTable == NULL) {
		return (KSP_STATUS)0x80090027; /* NTE_INVALID_PARAMETER */
	}
	*ppFunctionTable = &trstctl_ksp_table;
	return 0;
}
