#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# retry-registry-errors.sh CMD [ARGS...] — run CMD (an image build, pull or
# manifest read) and, when it fails because a container registry answered HTTP
# 429 or 5xx or the connection to it timed out, run it again. A registry error
# is retried until CMD has run TRSTCTL_REGISTRY_ATTEMPTS times in all (default
# 4), waiting TRSTCTL_REGISTRY_RETRY_DELAY seconds (default 20) times the
# attempt number between runs. Any other failure ends at once with CMD's exit
# status, so a broken build is never run twice.
#
# CMD's standard output passes through untouched (a caller may capture it, as
# the image scan does with a digest); its standard error is shown as it is
# written and kept to find the registry error.
#
# Why: on 2026-11-12 Docker Hub answered 500 to the Security scans' image build
# (run 43163959685), so the Trivy job failed without scanning anything.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: retry-registry-errors.sh CMD [ARGS...]" >&2
  exit 2
fi

attempts="${TRSTCTL_REGISTRY_ATTEMPTS:-4}"
delay="${TRSTCTL_REGISTRY_RETRY_DELAY:-20}"
case "${attempts}${delay}" in
  *[!0-9]*)
    echo "retry-registry-errors: TRSTCTL_REGISTRY_ATTEMPTS and TRSTCTL_REGISTRY_RETRY_DELAY must be whole numbers" >&2
    exit 2
    ;;
esac
if [ "$attempts" -lt 1 ]; then
  attempts=1
fi

# A registry error as BuildKit, the Docker CLI and registry clients print it:
# an HTTP 429 or 5xx answer, a rate limit, or a network timeout or reset.
registry_error='unexpected status.*[: ](429|5[0-9][0-9])( [A-Za-z]|$)|toomanyrequests|TLS handshake timeout|i/o timeout|connection reset by peer'

errlog="$(mktemp)"
trap 'rm -f "$errlog"' EXIT

attempt=1
while :; do
  status=0
  # fd 3 carries CMD's standard output past the pipe, which tees only its
  # standard error (pipefail makes the status CMD's).
  { "$@" 2>&1 1>&3 3>&- | tee "$errlog" 1>&2 3>&-; } 3>&1 || status=$?
  if [ "$status" -eq 0 ]; then
    exit 0
  fi
  if ! grep -qiE "$registry_error" "$errlog"; then
    exit "$status"
  fi
  if [ "$attempt" -ge "$attempts" ]; then
    echo "retry-registry-errors: a container registry still failed after ${attempt} attempts" >&2
    exit "$status"
  fi
  wait_s=$((delay * attempt))
  echo "::warning::a container registry failed on attempt ${attempt} of ${attempts}; retrying in ${wait_s}s" >&2
  sleep "$wait_s"
  attempt=$((attempt + 1))
done
