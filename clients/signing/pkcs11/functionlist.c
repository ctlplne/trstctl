// SPDX-License-Identifier: MPL-2.0

//go:build cgo

// The module's function list. The entry points the token implements are Go
// functions exported from module.go; the rest answer
// CKR_FUNCTION_NOT_SUPPORTED: the token signs, and nothing else — it cannot
// create, import, export, derive, wrap or decrypt with any key.

#include <stddef.h>
#include "ck.h"
#include "_cgo_export.h"

#define NOT_SUPPORTED 0x54UL

CK_RV C_InitToken(CK_SLOT_ID a, CK_UTF8CHAR_PTR b, CK_ULONG c, CK_UTF8CHAR_PTR d) { return NOT_SUPPORTED; }
CK_RV C_InitPIN(CK_SESSION_HANDLE a, CK_UTF8CHAR_PTR b, CK_ULONG c) { return NOT_SUPPORTED; }
CK_RV C_SetPIN(CK_SESSION_HANDLE a, CK_UTF8CHAR_PTR b, CK_ULONG c, CK_UTF8CHAR_PTR d, CK_ULONG e) { return NOT_SUPPORTED; }
CK_RV C_GetOperationState(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c) { return NOT_SUPPORTED; }
CK_RV C_SetOperationState(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_OBJECT_HANDLE d, CK_OBJECT_HANDLE e) { return NOT_SUPPORTED; }
CK_RV C_CreateObject(CK_SESSION_HANDLE a, CK_ATTRIBUTE *b, CK_ULONG c, CK_OBJECT_HANDLE *d) { return NOT_SUPPORTED; }
CK_RV C_CopyObject(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ATTRIBUTE *c, CK_ULONG d, CK_OBJECT_HANDLE *e) { return NOT_SUPPORTED; }
CK_RV C_DestroyObject(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b) { return NOT_SUPPORTED; }
CK_RV C_GetObjectSize(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ULONG_PTR c) { return NOT_SUPPORTED; }
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ATTRIBUTE *c, CK_ULONG d) { return NOT_SUPPORTED; }
CK_RV C_EncryptInit(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_OBJECT_HANDLE c) { return NOT_SUPPORTED; }
CK_RV C_Encrypt(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_EncryptFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c) { return NOT_SUPPORTED; }
CK_RV C_DecryptInit(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_OBJECT_HANDLE c) { return NOT_SUPPORTED; }
CK_RV C_Decrypt(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_DecryptFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c) { return NOT_SUPPORTED; }
CK_RV C_DigestInit(CK_SESSION_HANDLE a, CK_MECHANISM *b) { return NOT_SUPPORTED; }
CK_RV C_Digest(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_DigestUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c) { return NOT_SUPPORTED; }
CK_RV C_DigestKey(CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b) { return NOT_SUPPORTED; }
CK_RV C_DigestFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c) { return NOT_SUPPORTED; }
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_OBJECT_HANDLE c) { return NOT_SUPPORTED; }
CK_RV C_SignRecover(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_VerifyInit(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_OBJECT_HANDLE c) { return NOT_SUPPORTED; }
CK_RV C_Verify(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG e) { return NOT_SUPPORTED; }
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c) { return NOT_SUPPORTED; }
CK_RV C_VerifyFinal(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c) { return NOT_SUPPORTED; }
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_OBJECT_HANDLE c) { return NOT_SUPPORTED; }
CK_RV C_VerifyRecover(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e) { return NOT_SUPPORTED; }
CK_RV C_GenerateKey(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_ATTRIBUTE *c, CK_ULONG d, CK_OBJECT_HANDLE *e) { return NOT_SUPPORTED; }
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_ATTRIBUTE *c, CK_ULONG d, CK_ATTRIBUTE *e, CK_ULONG f, CK_OBJECT_HANDLE *g, CK_OBJECT_HANDLE *h) { return NOT_SUPPORTED; }
CK_RV C_WrapKey(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_OBJECT_HANDLE c, CK_OBJECT_HANDLE d, CK_BYTE_PTR e, CK_ULONG_PTR f) { return NOT_SUPPORTED; }
CK_RV C_UnwrapKey(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_OBJECT_HANDLE c, CK_BYTE_PTR d, CK_ULONG e, CK_ATTRIBUTE *f, CK_ULONG g, CK_OBJECT_HANDLE *h) { return NOT_SUPPORTED; }
CK_RV C_DeriveKey(CK_SESSION_HANDLE a, CK_MECHANISM *b, CK_OBJECT_HANDLE c, CK_ATTRIBUTE *d, CK_ULONG e, CK_OBJECT_HANDLE *f) { return NOT_SUPPORTED; }
CK_RV C_SeedRandom(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c) { return NOT_SUPPORTED; }
CK_RV C_GenerateRandom(CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c) { return NOT_SUPPORTED; }
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE a) { return 0x51UL; }  // CKR_FUNCTION_NOT_PARALLEL
CK_RV C_CancelFunction(CK_SESSION_HANDLE a) { return 0x51UL; }     // CKR_FUNCTION_NOT_PARALLEL
CK_RV C_WaitForSlotEvent(CK_FLAGS a, CK_SLOT_ID *b, CK_VOID_PTR c) { return NOT_SUPPORTED; }

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

static CK_FUNCTION_LIST functionList = {
	{2, 40},
	C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo,
	C_GetMechanismList, C_GetMechanismInfo, C_InitToken, C_InitPIN, C_SetPIN, C_OpenSession, C_CloseSession,
	C_CloseAllSessions, C_GetSessionInfo, C_GetOperationState, C_SetOperationState, C_Login, C_Logout,
	C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue,
	C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal, C_EncryptInit, C_Encrypt, C_EncryptUpdate,
	C_EncryptFinal, C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal, C_DigestInit, C_Digest,
	C_DigestUpdate, C_DigestKey, C_DigestFinal, C_SignInit, C_Sign, C_SignUpdate, C_SignFinal,
	C_SignRecoverInit, C_SignRecover, C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal,
	C_VerifyRecoverInit, C_VerifyRecover, C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate,
	C_DecryptVerifyUpdate, C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey,
	C_SeedRandom, C_GenerateRandom, C_GetFunctionStatus, C_CancelFunction, C_WaitForSlotEvent,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	if (ppFunctionList == NULL) {
		return 0x07UL; // CKR_ARGUMENTS_BAD
	}
	*ppFunctionList = &functionList;
	return 0;
}
