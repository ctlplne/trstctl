/* SPDX-License-Identifier: MPL-2.0 */

/*
 * Drives trstctl-ksp through its exported interface, as CNG does: load the
 * library, ask GetKeyStorageInterface for the function table, open the
 * provider and each named key, read properties with the two-call convention,
 * export the public key, size and make a signature over the hash given on the
 * command line, and probe the refusals. Prints key=value lines.
 *
 * usage: ksp_check <library> <sha256-hash-hex> <key>...
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../ksp.h"

static KSP_WCHAR *W(const char *s) {
	size_t n = strlen(s);
	KSP_WCHAR *w = calloc(n + 1, sizeof(KSP_WCHAR));
	for (size_t i = 0; i < n; i++) {
		w[i] = (KSP_WCHAR)(unsigned char)s[i];
	}
	return w;
}

static void narrow(const KSP_WCHAR *w, char *out, size_t size) {
	size_t i = 0;
	for (; w[i] != 0 && i + 1 < size; i++) {
		out[i] = (char)w[i];
	}
	out[i] = 0;
}

static void hexprint(const char *key, const KSP_BYTE *b, KSP_DWORD n) {
	printf("%s=", key);
	for (KSP_DWORD i = 0; i < n; i++) {
		printf("%02x", b[i]);
	}
	printf("\n");
}

static int unhex(const char *s, KSP_BYTE *out, size_t max) {
	size_t n = strlen(s) / 2;
	if (n > max) {
		return -1;
	}
	for (size_t i = 0; i < n; i++) {
		unsigned v;
		if (sscanf(s + 2 * i, "%2x", &v) != 1) {
			return -1;
		}
		out[i] = (KSP_BYTE)v;
	}
	return (int)n;
}

int main(int argc, char **argv) {
	if (argc < 4) {
		fprintf(stderr, "usage: ksp_check <library> <hash-hex> <key>...\n");
		return 2;
	}
	void *lib = dlopen(argv[1], RTLD_NOW);
	if (lib == NULL) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}
	KSP_STATUS (*getInterface)(KSP_LPCWSTR, KSP_FUNCTION_TABLE **, KSP_DWORD) =
		(KSP_STATUS (*)(KSP_LPCWSTR, KSP_FUNCTION_TABLE **, KSP_DWORD))dlsym(lib, "GetKeyStorageInterface");
	if (getInterface == NULL) {
		fprintf(stderr, "no GetKeyStorageInterface\n");
		return 1;
	}
	KSP_FUNCTION_TABLE *t = NULL;
	KSP_STATUS rv = getInterface(W("trstctl Key Storage Provider"), &t, 0);
	printf("interface_rv=0x%x version=%u.%u\n", (unsigned)rv, t->Version.MajorVersion, t->Version.MinorVersion);

	KSP_HANDLE prov = 0;
	printf("open_provider_rv=0x%x\n", (unsigned)t->OpenProvider(&prov, W("trstctl Key Storage Provider"), 0));
	KSP_DWORD need = 0;
	t->GetProviderProperty(prov, W("Name"), NULL, 0, &need, 0);
	KSP_BYTE *nameBuf = malloc(need);
	t->GetProviderProperty(prov, W("Name"), nameBuf, need, &need, 0);
	char narrowName[256];
	narrow((KSP_WCHAR *)nameBuf, narrowName, sizeof narrowName);
	printf("provider_name=%s\n", narrowName);

	KSP_DWORD algCount = 0;
	KSP_ALGORITHM_NAME *algs = NULL;
	t->EnumAlgorithms(prov, 0x10, &algCount, &algs, 0);
	printf("algorithms=%u\n", (unsigned)algCount);
	t->FreeBuffer(algs);

	void *state = NULL;
	KSP_KEY_NAME *kn = NULL;
	int listed = 0;
	while (t->EnumKeys(prov, NULL, &kn, &state, 0) == 0) {
		char n[128];
		narrow(kn->pszName, n, sizeof n);
		printf("listed_%d=%s\n", listed++, n);
		t->FreeBuffer(kn);
	}
	t->FreeBuffer(state);
	printf("listed=%d\n", listed);

	KSP_BYTE hash[32];
	if (unhex(argv[2], hash, sizeof hash) != 32) {
		fprintf(stderr, "hash must be 32 bytes of hex\n");
		return 2;
	}
	for (int i = 3; i < argc; i++) {
		const char *id = argv[i];
		char key[160];
		KSP_HANDLE k = 0;
		snprintf(key, sizeof key, "%s_open_rv", id);
		KSP_STATUS open = t->OpenKey(prov, &k, W(id), 0, 0);
		printf("%s=0x%x\n", key, (unsigned)open);
		if (open != 0) {
			continue;
		}
		KSP_BYTE group[64];
		KSP_DWORD got = 0;
		t->GetKeyProperty(prov, k, W("Algorithm Group"), group, sizeof group, &got, 0);
		char g[32];
		narrow((KSP_WCHAR *)group, g, sizeof g);
		printf("%s_group=%s\n", id, g);
		KSP_DWORD length = 0, policy = 99;
		t->GetKeyProperty(prov, k, W("Length"), (KSP_BYTE *)&length, sizeof length, &got, 0);
		t->GetKeyProperty(prov, k, W("Export Policy"), (KSP_BYTE *)&policy, sizeof policy, &got, 0);
		printf("%s_length=%u %s_export_policy=%u\n", id, (unsigned)length, id, (unsigned)policy);

		KSP_DWORD blobLen = 0;
		t->ExportKey(prov, k, 0, W("PUBLICBLOB"), NULL, NULL, 0, &blobLen, 0);
		KSP_BYTE *blob = malloc(blobLen);
		t->ExportKey(prov, k, 0, W("PUBLICBLOB"), NULL, blob, blobLen, &blobLen, 0);
		snprintf(key, sizeof key, "%s_public_blob", id);
		hexprint(key, blob, blobLen);
		printf("%s_private_export_rv=0x%x\n", id, (unsigned)t->ExportKey(prov, k, 0, W("RSAFULLPRIVATEBLOB"), NULL, NULL, 0, &blobLen, 0));

		int rsa = strcmp(g, "RSA") == 0;
		KSP_PKCS1_PADDING_INFO pkcs1 = {W("SHA256")};
		void *padding = rsa ? &pkcs1 : NULL;
		KSP_DWORD flags = rsa ? 0x2 : 0;
		KSP_DWORD sigLen = 0;
		t->SignHash(prov, k, padding, hash, 32, NULL, 0, &sigLen, flags);
		printf("%s_signature_length=%u\n", id, (unsigned)sigLen);
		KSP_BYTE small[8];
		KSP_DWORD smallLen = 0;
		printf("%s_short_rv=0x%x\n", id, (unsigned)t->SignHash(prov, k, padding, hash, 32, small, sizeof small, &smallLen, flags));
		if (rsa) {
			printf("%s_pss_rv=0x%x\n", id, (unsigned)t->SignHash(prov, k, padding, hash, 32, NULL, 0, &smallLen, 0x8));
		}
		KSP_BYTE *sig = malloc(sigLen);
		KSP_STATUS signRV = t->SignHash(prov, k, padding, hash, 32, sig, sigLen, &sigLen, flags);
		printf("%s_sign_rv=0x%x\n", id, (unsigned)signRV);
		if (signRV == 0) {
			snprintf(key, sizeof key, "%s_signature", id);
			hexprint(key, sig, sigLen);
			printf("%s_verify_rv=0x%x\n", id, (unsigned)t->VerifySignature(prov, k, padding, hash, 32, sig, sigLen, flags));
		}
		t->FreeKey(prov, k);
	}
	KSP_HANDLE made = 0;
	printf("create_rv=0x%x\n", (unsigned)t->CreatePersistedKey(prov, &made, W("RSA"), W("new"), 0, 0));
	printf("free_provider_rv=0x%x\n", (unsigned)t->FreeProvider(prov));
	printf("ok=1\n");
	return 0;
}
