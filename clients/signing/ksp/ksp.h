/* SPDX-License-Identifier: MPL-2.0 */

/*
 * The subset of the Windows CNG key storage provider interface that
 * trstctl-ksp implements, declared here so the provider builds and is tested
 * on any platform: the provider DLL exports GetKeyStorageInterface, which
 * returns a version 1 function table (the layout of
 * NCRYPT_KEY_STORAGE_FUNCTION_TABLE). Types mirror their Windows sizes:
 * SECURITY_STATUS is a 32-bit LONG, DWORD 32 bits, WCHAR UTF-16 code units,
 * and NCRYPT_*_HANDLE pointer-sized. Built for 64-bit Windows (x64, arm64),
 * where there is one calling convention.
 */
#ifndef TRSTCTL_KSP_H
#define TRSTCTL_KSP_H

#include <stddef.h>
#include <stdint.h>

typedef int32_t KSP_STATUS;
typedef uint32_t KSP_DWORD;
typedef uint16_t KSP_WCHAR;
typedef const KSP_WCHAR *KSP_LPCWSTR;
typedef uint8_t KSP_BYTE;
typedef uintptr_t KSP_HANDLE;

typedef struct {
	uint16_t MajorVersion;
	uint16_t MinorVersion;
} KSP_INTERFACE_VERSION;

/* BCRYPT_PKCS1_PADDING_INFO */
typedef struct {
	KSP_LPCWSTR pszAlgId;
} KSP_PKCS1_PADDING_INFO;

/* NCryptAlgorithmName */
typedef struct {
	KSP_WCHAR *pszName;
	KSP_DWORD dwClass;
	KSP_DWORD dwAlgOperations;
	KSP_DWORD dwFlags;
} KSP_ALGORITHM_NAME;

/* NCryptKeyName */
typedef struct {
	KSP_WCHAR *pszName;
	KSP_WCHAR *pszAlgid;
	KSP_DWORD dwLegacyKeySpec;
	KSP_DWORD dwFlags;
} KSP_KEY_NAME;

typedef KSP_STATUS (*KSP_OpenProviderFn)(KSP_HANDLE *phProvider, KSP_LPCWSTR pszProviderName, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_OpenKeyFn)(KSP_HANDLE hProvider, KSP_HANDLE *phKey, KSP_LPCWSTR pszKeyName, KSP_DWORD dwLegacyKeySpec, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_CreatePersistedKeyFn)(KSP_HANDLE hProvider, KSP_HANDLE *phKey, KSP_LPCWSTR pszAlgId, KSP_LPCWSTR pszKeyName, KSP_DWORD dwLegacyKeySpec, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_GetProviderPropertyFn)(KSP_HANDLE hProvider, KSP_LPCWSTR pszProperty, KSP_BYTE *pbOutput, KSP_DWORD cbOutput, KSP_DWORD *pcbResult, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_GetKeyPropertyFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, KSP_LPCWSTR pszProperty, KSP_BYTE *pbOutput, KSP_DWORD cbOutput, KSP_DWORD *pcbResult, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_SetProviderPropertyFn)(KSP_HANDLE hProvider, KSP_LPCWSTR pszProperty, KSP_BYTE *pbInput, KSP_DWORD cbInput, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_SetKeyPropertyFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, KSP_LPCWSTR pszProperty, KSP_BYTE *pbInput, KSP_DWORD cbInput, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_FinalizeKeyFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_DeleteKeyFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_FreeProviderFn)(KSP_HANDLE hProvider);
typedef KSP_STATUS (*KSP_FreeKeyFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey);
typedef KSP_STATUS (*KSP_FreeBufferFn)(void *pvInput);
typedef KSP_STATUS (*KSP_EncryptFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, KSP_BYTE *pbInput, KSP_DWORD cbInput, void *pPaddingInfo, KSP_BYTE *pbOutput, KSP_DWORD cbOutput, KSP_DWORD *pcbResult, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_DecryptFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, KSP_BYTE *pbInput, KSP_DWORD cbInput, void *pPaddingInfo, KSP_BYTE *pbOutput, KSP_DWORD cbOutput, KSP_DWORD *pcbResult, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_IsAlgSupportedFn)(KSP_HANDLE hProvider, KSP_LPCWSTR pszAlgId, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_EnumAlgorithmsFn)(KSP_HANDLE hProvider, KSP_DWORD dwAlgOperations, KSP_DWORD *pdwAlgCount, KSP_ALGORITHM_NAME **ppAlgList, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_EnumKeysFn)(KSP_HANDLE hProvider, KSP_LPCWSTR pszScope, KSP_KEY_NAME **ppKeyName, void **ppEnumState, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_ImportKeyFn)(KSP_HANDLE hProvider, KSP_HANDLE hImportKey, KSP_LPCWSTR pszBlobType, void *pParameterList, KSP_HANDLE *phKey, KSP_BYTE *pbData, KSP_DWORD cbData, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_ExportKeyFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, KSP_HANDLE hExportKey, KSP_LPCWSTR pszBlobType, void *pParameterList, KSP_BYTE *pbOutput, KSP_DWORD cbOutput, KSP_DWORD *pcbResult, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_SignHashFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, void *pPaddingInfo, KSP_BYTE *pbHashValue, KSP_DWORD cbHashValue, KSP_BYTE *pbSignature, KSP_DWORD cbSignature, KSP_DWORD *pcbResult, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_VerifySignatureFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, void *pPaddingInfo, KSP_BYTE *pbHashValue, KSP_DWORD cbHashValue, KSP_BYTE *pbSignature, KSP_DWORD cbSignature, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_PromptUserFn)(KSP_HANDLE hProvider, KSP_HANDLE hKey, KSP_LPCWSTR pszOperation, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_NotifyChangeKeyFn)(KSP_HANDLE hProvider, void **phEvent, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_SecretAgreementFn)(KSP_HANDLE hProvider, KSP_HANDLE hPrivKey, KSP_HANDLE hPubKey, KSP_HANDLE *phAgreedSecret, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_DeriveKeyFn)(KSP_HANDLE hProvider, KSP_HANDLE hSharedSecret, KSP_LPCWSTR pwszKDF, void *pParameterList, KSP_BYTE *pbDerivedKey, KSP_DWORD cbDerivedKey, KSP_DWORD *pcbResult, KSP_DWORD dwFlags);
typedef KSP_STATUS (*KSP_FreeSecretFn)(KSP_HANDLE hProvider, KSP_HANDLE hSharedSecret);

/* NCRYPT_KEY_STORAGE_FUNCTION_TABLE, interface version 1. */
typedef struct {
	KSP_INTERFACE_VERSION Version;
	KSP_OpenProviderFn OpenProvider;
	KSP_OpenKeyFn OpenKey;
	KSP_CreatePersistedKeyFn CreatePersistedKey;
	KSP_GetProviderPropertyFn GetProviderProperty;
	KSP_GetKeyPropertyFn GetKeyProperty;
	KSP_SetProviderPropertyFn SetProviderProperty;
	KSP_SetKeyPropertyFn SetKeyProperty;
	KSP_FinalizeKeyFn FinalizeKey;
	KSP_DeleteKeyFn DeleteKey;
	KSP_FreeProviderFn FreeProvider;
	KSP_FreeKeyFn FreeKey;
	KSP_FreeBufferFn FreeBuffer;
	KSP_EncryptFn Encrypt;
	KSP_DecryptFn Decrypt;
	KSP_IsAlgSupportedFn IsAlgSupported;
	KSP_EnumAlgorithmsFn EnumAlgorithms;
	KSP_EnumKeysFn EnumKeys;
	KSP_ImportKeyFn ImportKey;
	KSP_ExportKeyFn ExportKey;
	KSP_SignHashFn SignHash;
	KSP_VerifySignatureFn VerifySignature;
	KSP_PromptUserFn PromptUser;
	KSP_NotifyChangeKeyFn NotifyChangeKey;
	KSP_SecretAgreementFn SecretAgreement;
	KSP_DeriveKeyFn DeriveKey;
	KSP_FreeSecretFn FreeSecret;
} KSP_FUNCTION_TABLE;

#if defined(_WIN32)
#define KSP_EXPORT __declspec(dllexport)
#else
#define KSP_EXPORT __attribute__((visibility("default")))
#endif

KSP_EXPORT KSP_STATUS GetKeyStorageInterface(KSP_LPCWSTR pszProviderName, KSP_FUNCTION_TABLE **ppFunctionTable, KSP_DWORD dwFlags);

#endif
