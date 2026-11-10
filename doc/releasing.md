# Releasing macluster

The release workflow builds the Apple silicon binary, applies an ad-hoc code
signature, publishes the GitHub Release, and updates the Homebrew tap. No paid
Apple Developer Program certificate is required for this early-access channel.

## Requirements

- A public `FJingxian/homebrew-macluster` repository.
- A write-enabled SSH deploy key for that tap repository.

## GitHub secrets

Configure these repository secrets in `FJingxian/macluster`:

| Secret | Value |
| --- | --- |
| `HOMEBREW_TAP_SSH_KEY` | Private half of the write-enabled tap deploy key |

Optionally set the repository variable `HOMEBREW_TAP_REPOSITORY`. The default is
`FJingxian/homebrew-macluster`.

Never commit the tap deploy key.

The current ad-hoc signature allows normal Homebrew installation, but manually
downloaded binaries may still trigger stronger Gatekeeper warnings. Developer ID
signing and notarization can be added later without changing the Release or
Homebrew version format.

## Release process

1. Update `[workspace.package].version` in `Cargo.toml`.
2. Run the release tooling tests and the normal workspace tests.
3. Commit and push the version change to `main`.
4. Create and push the matching tag:

```sh
git tag v0.1.7
git push origin main
git push origin v0.1.7
```

The tag workflow rejects a tag whose version differs from `Cargo.toml`. It also
stops before publishing if signing, notarization, checksum verification, or
Homebrew formula generation fails.

## Homebrew installation

```sh
brew install FJingxian/macluster/macluster
brew upgrade macluster
```

The workflow always pins a release version and SHA256 in
`Formula/macluster.rb`. Homebrew does not silently replace a running binary;
users receive the new version after `brew update` and `brew upgrade`.

## Local release-tool checks

```sh
python3 -m unittest discover -s scripts/release/tests -v
actionlint .github/workflows/release.yml
```

The package script writes only `macluster` into the tar archive, sets mode
`0755`, removes AppleDouble metadata, and writes `SHA256SUMS`.
