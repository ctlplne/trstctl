#!/bin/sh
# Build a Firefox profile that trusts only the evaluation control-plane certificate,
# without touching any workstation trust store. TLS validation stays on.
# Usage: scripts/dev/isolated-firefox-profile.sh <control-plane.crt> [profile-dir] [https-url]
set -eu
CERT=${1:?usage: isolated-firefox-profile.sh <control-plane.crt> [profile-dir] [https-url]}
PROFILE=${2:-./trstctl-eval-profile}
URL=${3:-https://localhost:8443}
mkdir -p "$PROFILE"
cp "$CERT" "$PROFILE/control-plane.crt"
docker run --rm -v "$(cd "$PROFILE" && pwd):/profile" alpine:3.20 sh -c \
  'apk add --no-cache nss-tools >/dev/null && certutil -N -d sql:/profile --empty-password && \
   certutil -A -n "trstctl evaluation" -t "C,," -i /profile/control-plane.crt -d sql:/profile && \
   certutil -L -d sql:/profile'
echo "profile ready: firefox --profile \"$(cd "$PROFILE" && pwd)\" $URL"
