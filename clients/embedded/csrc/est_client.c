/*
 * trstctl-est-client (S8.6): a lightweight POSIX EST (RFC 7030) /simpleenroll client for
 * constrained devices. It has no library dependencies beyond libc and the openssl CLI: it
 * generates the device key + PKCS#10 and parses the issued certs-only PKCS#7 via `openssl`,
 * and speaks HTTP over a POSIX socket. TLS is expected to be terminated by an on-device
 * proxy or added with mbedTLS in a real deployment; this reference keeps the transport
 * minimal so it builds anywhere (cc -O2 -o est_client est_client.c).
 *
 * Usage: est_client <base-url> <workdir>
 *   e.g. est_client http://127.0.0.1:8080 /tmp/enroll
 * On success it writes <workdir>/cert.pem and exits 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

static int sh(const char *cmd) { return system(cmd); }

/*
 * safe_path_arg validates an operator-supplied string (the workdir, the parsed
 * host) before it is interpolated into a shell command run via system() (FUZZ-005).
 * The commands below build openssl invocations by string interpolation; a workdir
 * or host containing shell metacharacters ($ ` ; | & < > ( ) newline, quotes, glob,
 * whitespace, ...) would let those characters break out of the intended argument
 * and inject commands. Rather than attempt to quote/escape (error-prone), we reject
 * any argument that is not drawn from a conservative allow-list of path/host-safe
 * characters: ASCII letters, digits, and the set [-._/:@]. This is strict enough to
 * cover real workdirs (e.g. /tmp/enroll, ./out) and hostnames (host, 1.2.3.4, with
 * an optional :port handled separately) while making shell injection impossible.
 * Returns 1 if s is safe, 0 otherwise. An empty string is rejected.
 */
static int safe_path_arg(const char *s) {
	if (s == NULL || s[0] == '\0') return 0;
	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		unsigned char c = *p;
		int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		         (c >= '0' && c <= '9') ||
		         c == '-' || c == '.' || c == '_' || c == '/' || c == ':' || c == '@';
		if (!ok) return 0;
	}
	return 1;
}

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: %s <base-url> <workdir>\n", argv[0]);
		return 2;
	}
	const char *base = argv[1];
	const char *wd = argv[2];
	char cmd[4096], path[2048];

	/*
	 * Reject a workdir containing anything but path-safe characters before it is
	 * interpolated into a system() command line (FUZZ-005). Without this, a workdir
	 * like "/tmp/x; rm -rf ~" would inject a second command into every openssl call.
	 */
	if (!safe_path_arg(wd)) {
		fprintf(stderr, "est: refusing unsafe workdir %s (allowed: letters, digits, -._/:@)\n", wd);
		return 2;
	}

	/* 1. Generate the device key and a PKCS#10 (DER) with openssl. */
	snprintf(cmd, sizeof cmd,
		"openssl req -new -newkey rsa:2048 -nodes -keyout %s/key.pem -outform DER -out %s/csr.der -subj /CN=device-c 2>/dev/null",
		wd, wd);
	if (sh(cmd) != 0) { fprintf(stderr, "est: key/CSR generation failed\n"); return 1; }

	/* 2. base64-encode the CSR (single line) for the EST body. */
	snprintf(cmd, sizeof cmd, "openssl base64 -A -in %s/csr.der -out %s/csr.b64", wd, wd);
	if (sh(cmd) != 0) { fprintf(stderr, "est: base64 of CSR failed\n"); return 1; }

	snprintf(path, sizeof path, "%s/csr.b64", wd);
	FILE *f = fopen(path, "r");
	if (!f) { fprintf(stderr, "est: cannot read CSR\n"); return 1; }
	char body[16384];
	size_t n = fread(body, 1, sizeof body - 1, f);
	fclose(f);
	body[n] = 0;
	while (n && (body[n - 1] == '\n' || body[n - 1] == '\r')) body[--n] = 0;

	/* 3. Parse the base URL (http://host[:port]). */
	char host[256];
	int port = 80;
	if (sscanf(base, "http://%255[^:/]:%d", host, &port) < 1 &&
	    sscanf(base, "http://%255[^:/]", host) < 1) {
		fprintf(stderr, "est: unsupported URL %s\n", base);
		return 1;
	}
	/*
	 * Validate the parsed host (defense in depth): it is interpolated into the HTTP
	 * request line/Host header below, and a host containing CR/LF or other control
	 * characters could split the request. The same path-safe allow-list rejects all
	 * of those (FUZZ-005). The numeric port is parsed by sscanf as an int and bounds-
	 * checked next, so it cannot carry injection.
	 */
	if (!safe_path_arg(host)) {
		fprintf(stderr, "est: refusing unsafe host %s\n", host);
		return 1;
	}
	if (port < 1 || port > 65535) {
		fprintf(stderr, "est: port %d out of range\n", port);
		return 1;
	}

	/* 4. Connect. */
	char portstr[16];
	snprintf(portstr, sizeof portstr, "%d", port);
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, portstr, &hints, &res) != 0) { fprintf(stderr, "est: resolve failed\n"); return 1; }
	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
		fprintf(stderr, "est: connect failed\n");
		return 1;
	}
	freeaddrinfo(res);

	/* 5. POST the base64 PKCS#10 to /.well-known/est/simpleenroll (HTTP/1.0, no chunking). */
	char req[20000];
	int reqlen = snprintf(req, sizeof req,
		"POST /.well-known/est/simpleenroll HTTP/1.0\r\n"
		"Host: %s\r\n"
		"Content-Type: application/pkcs10\r\n"
		"Content-Transfer-Encoding: base64\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n\r\n%s",
		host, n, body);
	if (write(fd, req, (size_t)reqlen) != reqlen) { fprintf(stderr, "est: write failed\n"); close(fd); return 1; }

	/*
	 * 6. Read the whole response into a fixed buffer.
	 *
	 * The buffer caps the certs-only PKCS#7 chain this reference client accepts at
	 * ~64 KiB (RESP_CAP below) — ample for a leaf + a normal CA chain. The bug this
	 * guards against (CODE-003): if the response is LARGER than the buffer, a naive
	 * loop fills the buffer, stops, and then base64-decodes a TRUNCATED PKCS#7 — which
	 * `openssl pkcs7` may parse into a corrupt/partial cert.pem, or silently accept a
	 * truncated chain. So we treat "buffer full with more bytes still pending" as a
	 * hard ERROR ("response too large") and exit non-zero WITHOUT writing cert.pem,
	 * rather than decode a truncated chain. We detect the overflow by leaving one byte
	 * of headroom: if the read fills the buffer up to that last byte, one more byte is
	 * still available on the socket, so the response exceeded the cap.
	 */
	char resp[65536];
	const size_t RESP_CAP = sizeof resp - 1; /* reserve 1 byte for the NUL terminator */
	size_t total = 0;
	ssize_t r;
	int truncated = 0;
	while (total < RESP_CAP && (r = read(fd, resp + total, RESP_CAP - total)) > 0) {
		total += (size_t)r;
	}
	if (total >= RESP_CAP) {
		/* The buffer is full. If even one more byte is readable, the response was
		 * larger than the cap and what we hold is truncated — fail closed. */
		char extra;
		if (read(fd, &extra, 1) > 0) truncated = 1;
	}
	close(fd);
	resp[total] = 0;

	if (truncated) {
		fprintf(stderr, "est: response too large (> %zu bytes); refusing to decode a truncated certificate chain\n", RESP_CAP);
		return 1;
	}

	if (strncmp(resp, "HTTP/1.0 200", 12) != 0 && strncmp(resp, "HTTP/1.1 200", 12) != 0) {
		fprintf(stderr, "est: enrollment rejected: %.48s\n", resp);
		return 1;
	}
	char *p = strstr(resp, "\r\n\r\n");
	if (!p) { fprintf(stderr, "est: malformed response\n"); return 1; }
	p += 4;

	/* 7. Decode the certs-only PKCS#7 to cert.pem. */
	snprintf(path, sizeof path, "%s/p7.b64", wd);
	FILE *o = fopen(path, "w");
	if (!o) { fprintf(stderr, "est: cannot write response\n"); return 1; }
	fputs(p, o);
	fclose(o);
	snprintf(cmd, sizeof cmd,
		"openssl base64 -d -in %s/p7.b64 -out %s/p7.der && "
		"openssl pkcs7 -inform DER -in %s/p7.der -print_certs -out %s/cert.pem 2>/dev/null",
		wd, wd, wd, wd);
	if (sh(cmd) != 0) { fprintf(stderr, "est: decoding issued certificate failed\n"); return 1; }

	fprintf(stdout, "est: enrolled, certificate at %s/cert.pem\n", wd);
	return 0;
}
