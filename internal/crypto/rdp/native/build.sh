#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
set -eu
# Debian bookworm: freerdp2-dev=2.11.7+dfsg1-6~deb12u1 (Apache-2.0).
# Fail closed on a different ABI; security package revisions may change.
case "$(pkg-config --modversion freerdp2)" in 2.11.*) ;; *) echo 'FreeRDP 2.11.x required' >&2; exit 1;; esac
: "${CC:=cc}"
"$CC" -std=c11 -O2 -g -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
 -fPIE -pie -Wl,-z,relro,-z,now -o "$1" "$(dirname "$0")/desktop.c" \
 $(pkg-config --cflags --libs freerdp2 freerdp-client2 winpr2 openssl)
