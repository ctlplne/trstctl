FROM golang:1.26-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        findutils \
        gcc \
        libc6-dev \
        opensc \
        softhsm2 \
    && rm -rf /var/lib/apt/lists/*
