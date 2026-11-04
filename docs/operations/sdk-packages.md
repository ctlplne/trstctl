# SDK packages from a local registry

The four client SDKs build as installable packages of one version, and one
command serves them as local registries. Teams that keep their own package
mirrors, and evaluators who want the exact bytes CI tested, install from there.
**None of these packages is published to a public registry**; publishing is a
release decision.

## Build the packages

```bash
scripts/release/sdk-packages.sh 0.1.0 dist/sdk-registry    # or: make sdk-packages
```

| Ecosystem | What is built | Where |
|---|---|---|
| Go | module `trstctl.com/sdk/go` `v0.1.0`: the module zip, `.mod`, `.info` and `list` | `go/trstctl.com/sdk/go/@v/` |
| npm | `@trstctl/sdk` `0.1.0`: compiled JavaScript and declarations (`dist/`), the TypeScript sources and the README, with the registry document carrying its `sha512` integrity | `npm/tarballs/`, `npm/meta/` |
| PyPI | `trstctl-sdk` `0.1.0`: a pure-Python wheel (no build backend needed) and its PEP 503 index with `#sha256=` links | `pypi/packages/`, `pypi/simple/` |
| Maven | `com.trstctl:trstctl-sdk:0.1.0`: the JDK-only jar (Java 11 bytecode) and its pom, with `.sha256`/`.sha512` files and `maven-metadata.xml` | `maven/com/trstctl/trstctl-sdk/` |

Only tracked files are packaged, so a stray local file never ships. Every
package carries the commit's time, so a rebuild of one commit produces the
same bytes. `manifest.json` lists each package's file, version, SHA-256 and
size, and `SHA256SUMS` lets you check them:

```bash
(cd dist/sdk-registry && shasum -a 256 -c SHA256SUMS)
```

The Maven package needs a JDK (`javac` and `jar`); without one the script
builds the other three and says so.

## Serve them

```bash
go run ./tools/sdkpack serve --dir dist/sdk-registry --addr 127.0.0.1:8790
```

One read-only server answers as four registries: `/go/` speaks the Go module
proxy protocol, `/npm/` is an npm registry, `/pypi/simple/` is a PEP 503
index, and `/maven/` is the Maven 2 layout.

## Install by exact version

Go — the local proxy is the only source, and the SDK's module path never
reaches a public proxy or checksum database:

```bash
GOPROXY=http://127.0.0.1:8790/go \
GOPRIVATE='trstctl.com/*,github.com/ctlplne/*' \
GONOPROXY=none \
  go get trstctl.com/sdk/go@v0.1.0
```

`GOPRIVATE` keeps both module paths out of the checksum database;
`GONOPROXY=none` sends them through `GOPROXY` anyway, and with no `,direct`
fallback nothing else is asked.

npm — `package-lock.json` records the registry's tarball and its integrity:

```bash
npm install --registry http://127.0.0.1:8790/npm/ @trstctl/sdk@0.1.0
```

PyPI:

```bash
python3 -m pip install --index-url http://127.0.0.1:8790/pypi/simple/ trstctl-sdk==0.1.0
```

Maven — the jar by its coordinates, checked against the repository's digest:

```bash
base=http://127.0.0.1:8790/maven/com/trstctl/trstctl-sdk/0.1.0
curl -fsSO "$base/trstctl-sdk-0.1.0.jar"
test "$(shasum -a 256 trstctl-sdk-0.1.0.jar | cut -d' ' -f1)" = "$(curl -fsS "$base/trstctl-sdk-0.1.0.jar.sha256")"
```

## Several versions in one registry

Build each version into the same directory and the registry holds them side by
side: the Go module's `list`, the npm document (its `latest` tag is the highest
version), the PyPI project page and `maven-metadata.xml` each list every version,
and `manifest.json` lists every package of every version.

```bash
scripts/release/sdk-packages.sh 0.1.0 dist/sdk-registry
scripts/release/sdk-packages.sh 0.1.1 dist/sdk-registry
```

Upgrade the same way you installed, with the same registry settings, naming the new
version:
`go get trstctl.com/sdk/go@v0.1.1`, `npm install @trstctl/sdk@0.1.1`,
`pip install --upgrade trstctl-sdk==0.1.1`.

## In a release

A tagged release builds the four packages at the tag's version and attaches them
to the GitHub Release as one archive, `trstctl-sdk-registry_<version>.tar.gz`, with
SLSA build provenance (`trstctl-sdk-packages.intoto.jsonl`), as the CLI archives
and the Python SDK have. Unpack it and serve the `sdk-registry` directory.

## What the install check proves

`make sdk-install-check` builds two versions of the packages into one registry,
serves it, and for each SDK, in a clean environment (its own home, empty package
caches, only the local registry): installs the first version exactly, checks the
registry served the file `manifest.json` names (the Go module zip in the module
cache and the Maven jar are compared with their digests), runs one round trip
against a served control plane, then upgrades to the second version and runs it
again. The round trip: an unauthenticated read is refused with `401`; a secret is
created, read, rotated and read again; a PKI certificate is issued and revoked;
the secret is deleted. In front of the control plane, the first create from each
SDK is answered `503` with `Retry-After: 1`: each SDK retries it at least a second
later with the same `Idempotency-Key`. CI runs the check with a JDK, so the Java
SDK is installed and run there too.

## The CLI and agent archives on clean machines

The CLI and host-agent archives get the same treatment on clean Linux and macOS CI
runners (`release archives / OS package checks`): `scripts/release/cli-assets.sh`
and `agent-assets.sh` build that runner's archives, and
`scripts/ci/os-package-check.sh` verifies every archive against its `SHA256SUMS`,
unpacks the runner's own into an empty directory, and runs it; `--version` must
report the commit it was built from.
