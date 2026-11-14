#!/usr/bin/env python3

import argparse
import pathlib
import re
import stat
import subprocess
import sys


STABLE_IDENTIFIER = "org.macluster.macluster"
IDENTITY_RE = re.compile(r'"([^"]+)"')


class SigningError(ValueError):
    pass


def is_distribution_identity(identity):
    return identity.startswith("Developer ID Application:")


def is_development_identity(identity):
    return identity.startswith("Apple Development:")


def select_signing_identity(
    identities, requested=None, distribution_only=False
):
    identities = tuple(dict.fromkeys(identity.strip() for identity in identities if identity.strip()))
    if requested:
        if requested not in identities:
            raise SigningError(f"requested signing identity is not available: {requested}")
        if distribution_only and not is_distribution_identity(requested):
            raise SigningError("Developer ID Application signing is required")
        return requested

    for identity in identities:
        if is_distribution_identity(identity):
            return identity
    if distribution_only:
        raise SigningError(
            "Developer ID Application signing is required for public distribution"
        )
    for identity in identities:
        if is_development_identity(identity):
            return identity
    raise SigningError(
        "no Apple Development or Developer ID Application signing identity is available"
    )


def codesign_command(binary, identity, timestamp=True, keychain=None):
    command = [
        "codesign",
        "--force",
        "--sign",
        identity,
        "--identifier",
        STABLE_IDENTIFIER,
        "--options",
        "runtime",
    ]
    if timestamp and identity != "-":
        command.append("--timestamp")
    if keychain:
        command.extend(["--keychain", str(keychain)])
    command.append(str(binary))
    return command


def require_stable_requirement(requirement):
    normalized = requirement.lower()
    if "cdhash h" in normalized:
        raise SigningError(
            "designated requirement is bound to a CDHash and will not survive rebuilds"
        )
    if f'identifier "{STABLE_IDENTIFIER}"'.lower() not in normalized:
        raise SigningError(
            f"designated requirement does not contain {STABLE_IDENTIFIER}"
        )
    if "anchor apple generic" not in normalized:
        raise SigningError("designated requirement is not anchored to an Apple identity")


def _run(command, capture=False):
    try:
        return subprocess.run(
            command,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except FileNotFoundError as error:
        raise SigningError(f"required command is unavailable: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise SigningError(f"command failed: {' '.join(command)}{suffix}") from error


def discover_identities(keychain=None):
    command = ["security", "find-identity", "-v", "-p", "codesigning"]
    if keychain:
        command.append(str(keychain))
    output = _run(command, capture=True).stdout
    return IDENTITY_RE.findall(output)


def extract_designated_requirement(stdout, stderr):
    for output in (stdout, stderr):
        for line in output.splitlines():
            if line.strip().startswith("designated =>"):
                return line.strip()
    raise SigningError("codesign did not report a designated requirement")


def designated_requirement(binary):
    result = subprocess.run(
        ["codesign", "-d", "-r-", str(binary)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise SigningError(f"cannot inspect designated requirement: {detail}")
    return extract_designated_requirement(result.stdout, result.stderr)


def sign_binary(binary, identity, timestamp=True, keychain=None):
    binary = pathlib.Path(binary)
    try:
        metadata = binary.lstat()
    except FileNotFoundError as error:
        raise SigningError(f"binary does not exist: {binary}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise SigningError(f"binary is not a regular file: {binary}")

    _run(codesign_command(binary, identity, timestamp=timestamp, keychain=keychain))
    _run(["codesign", "--verify", "--strict", "--verbose=4", str(binary)])
    if identity == "-":
        return ""
    requirement = designated_requirement(binary)
    require_stable_requirement(requirement)
    return requirement


def main():
    parser = argparse.ArgumentParser(
        description="Apply a stable Apple code signature to a macluster binary"
    )
    parser.add_argument("--binary", required=True)
    parser.add_argument("--identity")
    parser.add_argument("--keychain")
    parser.add_argument(
        "--distribution-only",
        action="store_true",
        help="require a Developer ID Application identity",
    )
    parser.add_argument(
        "--allow-adhoc",
        action="store_true",
        help="explicitly allow an unstable ad-hoc signature",
    )
    parser.add_argument("--no-timestamp", action="store_true")
    args = parser.parse_args()

    try:
        if args.allow_adhoc:
            identity = "-"
        else:
            identity = select_signing_identity(
                discover_identities(args.keychain),
                requested=args.identity,
                distribution_only=args.distribution_only,
            )
        requirement = sign_binary(
            args.binary,
            identity,
            timestamp=not args.no_timestamp,
            keychain=args.keychain,
        )
    except SigningError as error:
        parser.error(str(error))
    print(f"Signed {args.binary} with {identity}")
    if requirement:
        print(requirement)


if __name__ == "__main__":
    main()
