#!/usr/bin/env python3

import argparse
import pathlib
import re


VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class FormulaError(ValueError):
    pass


def _validate_version(version):
    if not VERSION_RE.fullmatch(version):
        raise FormulaError("version must use MAJOR.MINOR.PATCH")


def _validate_sha256(digest):
    if not SHA256_RE.fullmatch(digest):
        raise FormulaError("sha256 must be 64 lowercase hexadecimal characters")


def render_formula(version, digest):
    _validate_version(version)
    _validate_sha256(digest)
    asset = f"macluster-v{version}-macos-arm64.tar.gz"
    url = (
        "https://github.com/FJingxian/macluster/releases/download/"
        f"v{version}/{asset}"
    )
    return f"""# typed: strict
# frozen_string_literal: true

# Homebrew formula for macluster.
class Macluster < Formula
  desc "Lightweight macOS cluster manager"
  homepage "https://github.com/FJingxian/macluster"
  url "{url}"
  sha256 "{digest}"

  license "GPL-3.0-or-later"

  livecheck do
    url :stable
    strategy :github_latest
  end

  depends_on arch: :arm64
  depends_on macos: :monterey

  def install
    bin.install "macluster"
    aliases = %w[msub mjob mqueue mkill mtop mnode mfans]
    aliases.each do |name|
      bin.install_symlink bin/"macluster" => name
    end
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/macluster --version")
    aliases = %w[msub mjob mqueue mkill mtop mnode mfans]
    aliases.each do |name|
      assert_predicate bin/name, :symlink?
    end
  end
end
"""


def main():
    parser = argparse.ArgumentParser(
        description="Generate the macluster Homebrew formula"
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        formula = render_formula(args.version, args.sha256)
    except FormulaError as error:
        parser.error(str(error))

    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(formula, encoding="utf-8")


if __name__ == "__main__":
    main()
