// Package docker holds trstctl's container distribution artifacts — the
// reproducible image Dockerfile, the one-command Compose evaluation stack, and
// the release pipeline — together with tests that hold those artifacts to the
// S7.4 acceptance criteria (distroless/scratch under an 80 MB budget, cosign signing, a
// CycloneDX SBOM, a reproducible build, a GHCR primary with a Docker Hub mirror,
// and a tested external-datastore configuration).
//
// It contains no runtime code; the package exists so the artifacts have a home
// and a test target in the module.
package docker
