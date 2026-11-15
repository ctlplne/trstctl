#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Keep a SHA-256-verified mirror of the Alpine packages trstctl's images pin (TOOL-O1).

Every image build fetches its Alpine packages as
ADD --checksum=sha256:<digest> ${ALPINE_MIRROR}/<path>, each listed in
deploy/supply-chain/alpine-packages.json. Alpine removes a package from its CDN
when it rebuilds it, so a pinned fetch 404s and an older commit stops building.
This keeps a copy of each pinned package, checked against its digest, that a
build can use instead:

  fetch DIR   keep every pinned package in DIR at its Alpine path, from --mirror
              (or TRSTCTL_ALPINE_MIRROR) when given, falling back to the
              manifest's upstream, the Alpine CDN. A download must match its
              pinned SHA-256 or it is refused and nothing is written; a file
              already present and matching is kept without a download.
  verify DIR  check every pinned package in DIR against its digest.
  serve DIR   serve DIR on 127.0.0.1 for a build:
              docker build --build-arg ALPINE_MIRROR=http://host.docker.internal:PORT ...

A mirror or upstream is an https URL, or an http URL on a loopback host.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MAX_PACKAGE = 64 << 20
PATH_RE = re.compile(r"^v\d+\.\d+/(main|community)/(x86_64|aarch64)/[A-Za-z0-9._+-]+\.apk$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "deploy" / "supply-chain" / "alpine-packages.json"


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "trstctl.alpine-packages.v1":
        raise SystemExit(f"{path}: not a trstctl.alpine-packages.v1 manifest")
    check_base(manifest.get("upstream", ""), "upstream")
    seen = set()
    for package in manifest.get("packages", []):
        if not PATH_RE.match(package.get("path", "")) or not DIGEST_RE.match(package.get("sha256", "")):
            raise SystemExit(f"{path}: malformed package entry {package!r}")
        if package["path"] in seen:
            raise SystemExit(f"{path}: {package['path']} is listed twice")
        seen.add(package["path"])
    if not seen:
        raise SystemExit(f"{path}: no packages")
    return manifest


def check_base(base: str, name: str) -> str:
    url = urllib.parse.urlparse(base)
    if url.scheme == "https" and url.hostname:
        return base.rstrip("/")
    if url.scheme == "http" and url.hostname:
        host = url.hostname
        loopback = host in ("localhost", "host.docker.internal")
        try:
            loopback = loopback or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if loopback:
            return base.rstrip("/")
    raise SystemExit(f"{name} {base!r} must be an https URL, or an http URL on a loopback host")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "trstctl-alpine-mirror"})
    with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310 -- scheme checked by check_base
        body = response.read(MAX_PACKAGE + 1)
    if len(body) > MAX_PACKAGE:
        raise ValueError("larger than 64 MiB")
    return body


def fetch(manifest: dict, root: Path, mirror: str | None) -> int:
    sources = ([check_base(mirror, "mirror")] if mirror else []) + [check_base(manifest["upstream"], "upstream")]
    failed = 0
    for package in manifest["packages"]:
        target = root / package["path"]
        if target.is_file() and sha256_file(target) == package["sha256"]:
            print(f"kept     {package['path']}")
            continue
        for source in sources:
            url = f"{source}/{package['path']}"
            try:
                body = download(url)
            except (urllib.error.URLError, OSError, ValueError) as err:
                print(f"missing  {package['path']} at {source}: {err}", file=sys.stderr)
                continue
            if hashlib.sha256(body).hexdigest() != package["sha256"]:
                print(f"refused  {package['path']} from {source}: not the pinned SHA-256", file=sys.stderr)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
                tmp.write(body)
            os.replace(tmp.name, target)
            print(f"fetched  {package['path']} from {source}")
            break
        else:
            failed += 1
    if failed:
        print(f"{failed} pinned package(s) could not be fetched", file=sys.stderr)
        return 1
    return 0


def verify(manifest: dict, root: Path) -> int:
    bad = 0
    for package in manifest["packages"]:
        target = root / package["path"]
        if not target.is_file():
            print(f"absent   {package['path']}", file=sys.stderr)
            bad += 1
        elif sha256_file(target) != package["sha256"]:
            print(f"differs  {package['path']}", file=sys.stderr)
            bad += 1
    print(f"{len(manifest['packages']) - bad} of {len(manifest['packages'])} pinned packages match")
    return 1 if bad else 0


def serve(root: Path, port: int) -> int:
    handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(*args, directory=str(root), **kwargs)  # noqa: E731
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"serving {root} on http://127.0.0.1:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    sub = parser.add_subparsers(dest="command", required=True)
    p_fetch = sub.add_parser("fetch")
    p_fetch.add_argument("dir", type=Path)
    p_fetch.add_argument("--mirror", default=os.environ.get("TRSTCTL_ALPINE_MIRROR"))
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("dir", type=Path)
    p_serve = sub.add_parser("serve")
    p_serve.add_argument("dir", type=Path)
    p_serve.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if args.command == "serve":
        return serve(args.dir.resolve(), args.port)
    manifest = load_manifest(args.manifest)
    if args.command == "fetch":
        return fetch(manifest, args.dir.resolve(), args.mirror)
    return verify(manifest, args.dir.resolve())


if __name__ == "__main__":
    sys.exit(main())
