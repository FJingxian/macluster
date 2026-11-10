#!/usr/bin/env python3

import argparse
import hashlib
import os
import pathlib
import re
import stat
import tarfile
import tempfile


VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class PackageError(ValueError):
    pass


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_release(binary, version, output_dir):
    if not VERSION_RE.fullmatch(version):
        raise PackageError("version must use MAJOR.MINOR.PATCH")
    binary = pathlib.Path(binary)
    try:
        metadata = binary.lstat()
    except FileNotFoundError as error:
        raise PackageError(f"binary does not exist: {binary}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise PackageError(f"binary is not a regular file: {binary}")

    output_dir = pathlib.Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    asset = output_dir / f"macluster-v{version}-macos-arm64.tar.gz"
    temporary = output_dir / f".{asset.name}.tmp"
    try:
        with tarfile.open(temporary, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo("macluster")
            member.size = metadata.st_size
            member.mode = 0o755
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "wheel"
            member.mtime = 0
            with binary.open("rb") as source:
                archive.addfile(member, source)
        os.replace(temporary, asset)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

    digest = _sha256(asset)
    checksum = output_dir / "SHA256SUMS"
    checksum.write_text(f"{digest}  {asset.name}\n", encoding="utf-8")
    return asset, digest


def main():
    parser = argparse.ArgumentParser(
        description="Package a signed macluster executable for a GitHub release"
    )
    parser.add_argument("--binary", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    try:
        asset, digest = package_release(
            args.binary, args.version, args.output_dir
        )
    except PackageError as error:
        parser.error(str(error))
    print(asset)
    print(digest)


if __name__ == "__main__":
    main()
