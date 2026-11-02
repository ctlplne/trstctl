#!/usr/bin/env bash
# Download the whole module graph for a CI job, retrying a transient module-proxy failure: on CI 41451560632 an
# HTTP/2 stream reset from the proxy failed a server lane before any test ran. Three attempts, 10 s and then 30 s
# apart; the third failure fails the step. A module that does not exist or fails its go.sum check fails every
# attempt the same way, so nothing is masked.
set -uo pipefail
attempt=1
for delay in 10 30; do
  go mod download && exit 0
  echo "go mod download failed (attempt $attempt of 3); retrying in ${delay}s" >&2
  sleep "$delay"
  attempt=$((attempt + 1))
done
go mod download && exit 0
echo "::error::go mod download failed three times" >&2
exit 1
