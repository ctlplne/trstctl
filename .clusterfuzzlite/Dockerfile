# ClusterFuzzLite build image for trstctl's Go native fuzz targets (FUZZ-003).
# Based on the OSS-Fuzz Go base image, which provides compile_go_fuzzer and the
# libFuzzer toolchain. The repo is copied to $SRC/trstctl and built by build.sh.
FROM gcr.io/oss-fuzz-base/base-builder-go

COPY . $SRC/trstctl
WORKDIR $SRC/trstctl
COPY .clusterfuzzlite/build.sh $SRC/build.sh
