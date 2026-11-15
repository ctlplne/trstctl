// SPDX-License-Identifier: BUSL-1.1
//
// tpmrm-bridge: the lab's stand-in for a host kernel's /dev/tpmrm0 for a
// second client (TPM-O1-L1). swtpm takes one connection, which tpm2-abrmd
// holds once nginx's tpm2 provider uses the TPM; this bridge gives the agent
// its own tpm2-abrmd connection on a unix socket, so the agent and nginx use
// the TPM at the same time through the resource manager, as both would
// through the kernel's. go-tpm's socket transport connects once per command,
// and tpm2-abrmd flushes a connection's loaded objects when it closes, so the
// bridge holds one TCTI context for its whole life and serves every client
// connection on it, one at a time; raw TPM command and response bytes pass
// through unchanged.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <tss2/tss2_tctildr.h>

#define MAX_BUFFER 4096

static int read_full(int fd, uint8_t *buf, size_t n) {
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, buf + got, n - got);
		if (r <= 0) {
			if (r < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		got += (size_t)r;
	}
	return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t n) {
	size_t sent = 0;
	while (sent < n) {
		ssize_t w = write(fd, buf + sent, n - sent);
		if (w <= 0) {
			if (w < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		sent += (size_t)w;
	}
	return 0;
}

// serve passes one client's commands to the TPM; it reports whether the TCTI
// is still usable.
static int serve(int client, TSS2_TCTI_CONTEXT *tcti) {
	uint8_t command[MAX_BUFFER], response[MAX_BUFFER];
	for (;;) {
		if (read_full(client, command, 10) != 0) {
			break;
		}
		uint32_t size = ((uint32_t)command[2] << 24) | ((uint32_t)command[3] << 16) | ((uint32_t)command[4] << 8) | command[5];
		if (size < 10 || size > MAX_BUFFER || read_full(client, command + 10, size - 10) != 0) {
			break;
		}
		if (Tss2_Tcti_Transmit(tcti, size, command) != TSS2_RC_SUCCESS) {
			return 0;
		}
		size_t rsize = sizeof(response);
		if (Tss2_Tcti_Receive(tcti, &rsize, response, TSS2_TCTI_TIMEOUT_BLOCK) != TSS2_RC_SUCCESS) {
			return 0;
		}
		if (write_full(client, response, rsize) != 0) {
			break;
		}
	}
	return 1;
}

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "usage: tpmrm-bridge SOCKET TCTI\n");
		return 2;
	}
	int server = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(argv[1]) >= sizeof(addr.sun_path)) {
		return 2;
	}
	strcpy(addr.sun_path, argv[1]);
	unlink(argv[1]);
	if (server < 0 || bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(server, 4) != 0) {
		perror("tpmrm-bridge");
		return 1;
	}
	TSS2_TCTI_CONTEXT *tcti = NULL;
	for (;;) {
		int client = accept(server, NULL, NULL);
		if (client < 0) {
			if (errno == EINTR) {
				continue;
			}
			return 1;
		}
		if (tcti == NULL && Tss2_TctiLdr_Initialize(argv[2], &tcti) != TSS2_RC_SUCCESS) {
			fprintf(stderr, "tpmrm-bridge: cannot open TCTI %s\n", argv[2]);
			tcti = NULL;
			close(client);
			continue;
		}
		if (!serve(client, tcti)) {
			Tss2_TctiLdr_Finalize(&tcti);
			tcti = NULL;
		}
		close(client);
	}
}
