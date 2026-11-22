#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Offer a committed-pin-verified CI archive to legacy embedded-PG tests.

The served runtime reads the verified cache directly. Older integration tests
use embedded-postgres.NewDatabase and its home-directory archive cache instead.
Only bytes matching deploy/supply-chain/embedded-postgres.json may cross over.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def seed(manifest_path: Path, verified_root: Path, library_cache: Path) -> int:
    if not verified_root.is_dir() or verified_root.is_symlink():
        return 0
    manifest = json.loads(manifest_path.read_text())
    version = manifest["postgresVersion"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("invalid committed PostgreSQL version")
    count = 0
    for archive in manifest["archives"]:
        arch, digest = archive["arch"], archive["txz_sha256"]
        if not re.fullmatch(r"[a-z0-9-]+", arch) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid committed PostgreSQL archive identity")
        name = f"embedded-postgres-binaries-{arch}-{version}.txz"
        parent = verified_root / f"{arch}-{version}-{digest}"
        source = parent / name
        if not parent.is_dir() or parent.is_symlink() or source.is_symlink():
            continue
        try:
            fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE_BYTES:
                raise ValueError(f"invalid verified-cache archive: {name}")
            payload = bytearray()
            with os.fdopen(fd, "rb", closefd=False) as handle:
                while chunk := handle.read(1024 * 1024):
                    payload.extend(chunk)
                    if len(payload) > MAX_ARCHIVE_BYTES:
                        raise ValueError(f"oversize verified-cache archive: {name}")
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError(f"verified-cache archive differs from committed pin: {name}")
        finally:
            os.close(fd)
        if library_cache.is_symlink():
            raise ValueError("legacy archive cache is a symlink")
        library_cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = library_cache / name
        if target.is_symlink():
            raise ValueError(f"legacy archive is a symlink: {name}")
        with tempfile.NamedTemporaryFile(dir=library_cache, prefix=".pg-archive-", delete=False) as temp:
            temp_name = temp.name
            try:
                os.fchmod(temp.fileno(), 0o600)
                temp.write(payload)
                temp.flush()
                os.fsync(temp.fileno())
            except BaseException:
                os.unlink(temp_name)
                raise
        os.replace(temp_name, target)
        count += 1
    return count


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: seed-pg-legacy-cache.py MANIFEST VERIFIED_ROOT LIBRARY_CACHE")
    try:
        count = seed(*(Path(arg) for arg in sys.argv[1:]))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        raise SystemExit(f"PostgreSQL archive cache seed refused: {error}") from error
    print(f">> PostgreSQL legacy archive cache: {count} committed-pin-verified archive(s) seeded")
