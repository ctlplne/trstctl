FROM golang:1.26-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        swtpm \
        tpm2-tools \
    && rm -rf /var/lib/apt/lists/*
