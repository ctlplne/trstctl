#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# A250: build the four client SDKs as installable packages of one version into a
# local registry directory — a Go module proxy tree, an npm tarball and its
# registry document, a wheel and its PEP 503 index, a Maven jar and pom — with
# manifest.json and SHA256SUMS binding each file to its digest. `go run
# ./tools/sdkpack serve --dir <out-dir>` serves the directory; nothing here
# publishes to a public registry.
#
# Only tracked files are packaged (git ls-files), so a stray local file never
# ships. Without a JDK the Maven package is skipped with a note, unless
# TRSTCTL_REQUIRE_JAVA_SDK=1 (CI), which makes a missing JDK an error.
set -euo pipefail

VERSION_INPUT="${1:?usage: sdk-packages.sh <X.Y.Z> <out-dir>}"
OUT="${2:?usage: sdk-packages.sh <X.Y.Z> <out-dir>}"
VERSION="${VERSION_INPUT#v}"
case "$VERSION" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "sdk-packages: version $VERSION_INPUT is not X.Y.Z" >&2; exit 2 ;;
esac

REPO="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$REPO"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# The packages carry the commit's time, so a rebuild of one commit is the same.
WHEN="$(git log -1 --format=%cI)"

go build -o "$WORK/sdkpack" ./tools/sdkpack
git ls-files clients/sdk > "$WORK/files"

# Go: the module proxy tree for trstctl.com/sdk/go.
"$WORK/sdkpack" gomodule --files "$WORK/files" --src clients/sdk/go --module trstctl.com/sdk/go \
  --version "v$VERSION" --time "$WHEN" --out "$OUT"

# Python: a pure-Python wheel and its simple index (no build backend needed).
"$WORK/sdkpack" wheel --files "$WORK/files" --src clients/sdk/python --version "$VERSION" --out "$OUT"

# npm: compiled JavaScript and declarations, so plain Node can load the package
# from node_modules (it will not strip types there), packed at this version.
STAGE="$WORK/npm"
mkdir -p "$STAGE"
cp clients/sdk/typescript/package.json clients/sdk/typescript/README.md "$STAGE/"
cp -R clients/sdk/typescript/src "$STAGE/src"
node clients/sdk/typescript/node_modules/typescript/bin/tsc -p clients/sdk/typescript/tsconfig.build.json --outDir "$STAGE/dist"
node -e 'const fs = require("fs"); const [file, version] = process.argv.slice(1);
  const pkg = JSON.parse(fs.readFileSync(file, "utf8")); pkg.version = version;
  fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");' "$STAGE/package.json" "$VERSION"
(cd "$STAGE" && npm pack --ignore-scripts --silent --pack-destination "$WORK" >/dev/null)
"$WORK/sdkpack" npm --tarball "$WORK/trstctl-sdk-$VERSION.tgz" --out "$OUT"

# Maven: the JDK-only jar (Java 11 bytecode, as the pom builds) and its pom.
if command -v javac >/dev/null 2>&1 && javac -version >/dev/null 2>&1 && command -v jar >/dev/null 2>&1; then
  CLASSES="$WORK/classes"
  mkdir -p "$CLASSES"
  git ls-files 'clients/sdk/java/src/main/java/*.java' > "$WORK/java-sources"
  javac --release 11 -d "$CLASSES" @"$WORK/java-sources"
  jar --create --file "$WORK/trstctl-sdk-$VERSION.jar" -C "$CLASSES" .
  python3 -c 'import re, sys; src, dst, version = sys.argv[1:]
text = open(src, encoding="utf-8").read()
open(dst, "w", encoding="utf-8").write(re.sub(r"<version>[^<]*</version>", "<version>%s</version>" % version, text, count=1))' \
    clients/sdk/java/pom.xml "$WORK/trstctl-sdk-$VERSION.pom" "$VERSION"
  "$WORK/sdkpack" maven --jar "$WORK/trstctl-sdk-$VERSION.jar" --pom "$WORK/trstctl-sdk-$VERSION.pom" \
    --group com.trstctl --artifact trstctl-sdk --version "$VERSION" --time "$WHEN" --out "$OUT"
elif [ "${TRSTCTL_REQUIRE_JAVA_SDK:-0}" = "1" ]; then
  echo "sdk-packages: a JDK (javac and jar) is required for the Maven package" >&2
  exit 1
else
  echo "sdk-packages: no JDK here, so the Maven package was not built" >&2
fi

echo "sdk-packages: $OUT holds trstctl SDK $VERSION; serve it with: go run ./tools/sdkpack serve --dir $OUT"
