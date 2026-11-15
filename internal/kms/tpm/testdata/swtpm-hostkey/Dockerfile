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
    && rm -rf /var/lib/apt/lists/*
