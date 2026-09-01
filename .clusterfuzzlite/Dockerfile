# ClusterFuzzLite build image for trstctl's Go native fuzz targets (FUZZ-003).
# The OSS-Fuzz base supplies compile_native_go_fuzzer_v2 and libFuzzer, while
# the digest-pinned toolchain stage supplies the exact Go release required by
# go.mod. OSS-Fuzz can lag the language release; using its ambient Go would make
# every fuzzer disappear at compile time when the module advances.
FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS trstctl-go-toolchain

FROM gcr.io/oss-fuzz-base/base-builder-go

COPY --from=trstctl-go-toolchain /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOTOOLCHAIN=local
RUN test "$(go version)" = "go version go1.26.6 linux/amd64"

# compile_native_go_fuzzer_v2 is a shell wrapper around this source-processing
# tool. Replacing only `go` is insufficient: a helper compiled by Go 1.25 cannot
# load a Go 1.26 package graph. Rebuild the exact helper revision already selected
# by the OSS-Fuzz base, through the Go checksum database, with our pinned compiler.
ARG TRSTCTL_GO_FUZZ_BUILD_VERSION=v0.0.0-20250911191804-fc5dc53b9db8
RUN GOBIN=/root/go/bin go install "github.com/AdamKorcz/go-118-fuzz-build@${TRSTCTL_GO_FUZZ_BUILD_VERSION}" \
    && cp /root/go/bin/go-118-fuzz-build /root/go/bin/go-118-fuzz-build_v2 \
    && go version -m /root/go/bin/go-118-fuzz-build_v2 | grep -F 'go1.26.6'

COPY . $SRC/trstctl
WORKDIR $SRC/trstctl
COPY .clusterfuzzlite/build.sh $SRC/build.sh
