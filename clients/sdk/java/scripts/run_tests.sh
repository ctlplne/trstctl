#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
JAVA_ROOT="${ROOT}/clients/sdk/java"

required_sources=(
  "${JAVA_ROOT}/src/main/java/com/trstctl/sdk/TrstctlClient.java"
  "${JAVA_ROOT}/src/test/java/com/trstctl/sdk/TrstctlClientTest.java"
)
for source in "${required_sources[@]}"; do
  if [[ ! -f "${source}" ]]; then
    echo "error: missing required Java SDK source: ${source#${ROOT}/}" >&2
    exit 1
  fi
done

if ! command -v javac >/dev/null 2>&1 || ! command -v java >/dev/null 2>&1 || ! javac -version >/dev/null 2>&1 || ! java -version >/dev/null 2>&1; then
  if [[ "${TRSTCTL_REQUIRE_JAVA_SDK:-0}" == "1" ]]; then
    echo "error: Java SDK tests require javac and java" >&2
    exit 1
  fi
  echo "warn: javac/java not found; skipping Java SDK tests on this machine" >&2
  exit 0
fi

classes="$(mktemp -d)"
trap 'rm -rf "${classes}"' EXIT

sources=()
while IFS= read -r source; do
  sources+=("${source}")
done < <(find "${JAVA_ROOT}/src/main/java" "${JAVA_ROOT}/src/test/java" -name '*.java' | sort)
if [[ "${#sources[@]}" -eq 0 ]]; then
  echo "error: Java SDK source tree contains no .java files" >&2
  exit 1
fi
javac --add-modules jdk.httpserver -d "${classes}" "${sources[@]}"
java --add-modules jdk.httpserver -cp "${classes}" com.trstctl.sdk.TrstctlClientTest
