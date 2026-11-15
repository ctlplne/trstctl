# TPM-O1 host key journey image: the swtpm test image (testdata/swtpm: Go,
# swtpm, tpm2-tools) plus OpenSSL 3's tpm2 provider, the swtpm TCTI it reaches
# the software TPM with, nginx, and tpm2-abrmd, the user-space TPM resource
# manager (with the D-Bus daemon it runs on), all from Debian's own packages.
# swtpm, unlike a host's kernel /dev/tpmrm0, swaps no object contexts, and a
# TLS handshake through the tpm2 provider needs more than its three slots;
# tpm2-abrmd swaps them as the kernel does. Built from the local swtpm image,
# so no base image is pulled.
ARG BASE=trstctl-swtpm-go:aud-26-edge-custody
FROM ${BASE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tpm2-openssl \
        libtss2-tcti-swtpm0 \
        libtss2-tcti-tabrmd0 \
        tpm2-abrmd \
        dbus \
        nginx \
        openssl \
        gcc \
        libc6-dev \
        libtss2-dev \
    && rm -rf /var/lib/apt/lists/*
# TPM-O1-L1: tpmrm-bridge gives a second client (the agent) its own
# tpm2-abrmd connection while nginx holds another, as two clients of a
# host's /dev/tpmrm0 have.
COPY tpmrm-bridge.c /usr/local/src/tpmrm-bridge.c
RUN gcc -O2 -Wall -Werror -o /usr/local/bin/tpmrm-bridge /usr/local/src/tpmrm-bridge.c -ltss2-tctildr
# TPM-O1-L2: the other OpenSSL-based host services, from Debian's packages:
# haproxy, postfix and dovecot, which serve a TPM-held key through the tpm2
# provider, and apache2, postgresql and mariadb-server, whose lab test shows
# why they cannot (their threads or forked processes share one provider
# context).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        haproxy \
        postfix \
        dovecot-imapd \
        apache2 \
        postgresql \
        mariadb-server \
    && rm -rf /var/lib/apt/lists/*
