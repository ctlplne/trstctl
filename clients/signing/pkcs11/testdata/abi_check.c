// SPDX-License-Identifier: MPL-2.0
//
// Drives libtrstctl-pkcs11 through its function list the way PKCS #11 tools
// do: two-call attribute reads, a search, and a signature with a length query.
// Usage: abi_check <module> <pin>; prints key=value lines for the Go test.
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include "../ck.h"

#define CHECK(call) do { CK_RV rv_ = (call); if (rv_ != 0) { printf("fail=%s rv=%#lx\n", #call, rv_); return 1; } } while (0)

int main(int argc, char **argv) {
	if (argc != 3) { return 2; }
	void *lib = dlopen(argv[1], RTLD_NOW);
	if (lib == NULL) { printf("fail=dlopen %s\n", dlerror()); return 1; }
	CK_RV (*getList)(CK_FUNCTION_LIST_PTR_PTR) = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(lib, "C_GetFunctionList");
	CK_FUNCTION_LIST_PTR f;
	CHECK(getList(&f));
	CHECK(f->C_Initialize(NULL));
	CK_SESSION_HANDLE s;
	CHECK(f->C_OpenSession(1, 4, NULL, NULL, &s));
	CHECK(f->C_Login(s, 1, (CK_UTF8CHAR_PTR)argv[2], strlen(argv[2])));

	CK_ULONG cls = 3; // CKO_PRIVATE_KEY
	CK_ATTRIBUTE find[] = {{0x0, &cls, sizeof(cls)}};
	CHECK(f->C_FindObjectsInit(s, find, 1));
	CK_OBJECT_HANDLE keys[4];
	CK_ULONG n = 0;
	CHECK(f->C_FindObjects(s, keys, 4, &n));
	CHECK(f->C_FindObjectsFinal(s));
	printf("private_keys=%lu\n", n);
	if (n < 1) { return 1; }

	// Two-call read: lengths first, then values, as Java's SunPKCS11 does.
	CK_ATTRIBUTE attrs[] = {{0x3, NULL, 0}, {0x102, NULL, 0}, {0x180, NULL, 0}, {0x162, NULL, 0}};
	CHECK(f->C_GetAttributeValue(s, keys[0], attrs, 4));
	unsigned char label[256], id[64], params[64], extractable[8];
	printf("label_len=%lu id_len=%lu params_len=%lu\n", attrs[0].ulValueLen, attrs[1].ulValueLen, attrs[2].ulValueLen);
	attrs[0].pValue = label; attrs[1].pValue = id; attrs[2].pValue = params; attrs[3].pValue = extractable;
	CHECK(f->C_GetAttributeValue(s, keys[0], attrs, 4));
	printf("label=%.*s extractable=%d\n", (int)attrs[0].ulValueLen, label, extractable[0]);
	CK_ATTRIBUTE secret[] = {{0x11, NULL, 0}};
	CK_RV rv = f->C_GetAttributeValue(s, keys[0], secret, 1);
	printf("value_rv=%#lx value_len_unavailable=%d\n", rv, secret[0].ulValueLen == (CK_ULONG)-1);

	CK_MECHANISM mech = {0x1044, NULL, 0}; // CKM_ECDSA_SHA256
	CHECK(f->C_SignInit(s, &mech, keys[0]));
	const char *msg = "abi check message";
	CK_ULONG sigLen = 0;
	CHECK(f->C_Sign(s, (CK_BYTE_PTR)msg, strlen(msg), NULL, &sigLen));
	unsigned char sig[512];
	CK_ULONG small = sigLen - 1;
	rv = f->C_Sign(s, (CK_BYTE_PTR)msg, strlen(msg), sig, &small);
	printf("short_rv=%#lx\n", rv);
	CHECK(f->C_Sign(s, (CK_BYTE_PTR)msg, strlen(msg), sig, &sigLen));
	printf("signature=");
	for (CK_ULONG i = 0; i < sigLen; i++) { printf("%02x", sig[i]); }
	printf("\n");
	CHECK(f->C_Logout(s));
	CHECK(f->C_CloseSession(s));
	CHECK(f->C_Finalize(NULL));
	printf("ok=1\n");
	return 0;
}
