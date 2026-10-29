# SPDX-License-Identifier: BUSL-1.1
"""Build a deterministic .spl archive containing only the reviewed app assets."""

import argparse
import gzip
import io
from pathlib import Path
import tarfile

from contract import App, ASSETS


def archive(root, output):
    root = Path(root)
    App(root).validate()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        with tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
        ) as package:
            directories = {"trstctl"}
            for relative in ASSETS:
                parent = Path("trstctl") / Path(relative).parent
                while parent.as_posix() != ".":
                    directories.add(parent.as_posix())
                    parent = parent.parent
            for name in sorted(directories, key=lambda item: (item.count("/"), item)):
                entry = tarfile.TarInfo(name)
                entry.type, entry.mode, entry.mtime = tarfile.DIRTYPE, 0o755, 0
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                package.addfile(entry)
            for relative in sorted(ASSETS):
                content = (root / relative).read_bytes()
                entry = tarfile.TarInfo("trstctl/" + relative)
                entry.size, entry.mode, entry.mtime = len(content), 0o644, 0
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                package.addfile(entry, io.BytesIO(content))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("wb") as handle:
        archive(Path(__file__).resolve().parents[1] / "trstctl", handle)
