# Releasing macluster

The release workflow supports two channels:

- **Stable local development:** an installed Apple Development identity signs
  the binary with a stable identifier and designated requirement. A free Apple
  account/personal team can be enough for a locally built development binary;
  no provisioning profile is needed for this command-line target.
- **Public distribution:** a Developer ID Application identity, hardened
  runtime, secure timestamp, and Apple notarization remove normal Gatekeeper
  warnings. Developer ID distribution requires Apple Developer Program
  membership, currently 99 USD per year except approved fee waivers.

Build a stable locally signed binary with:

```sh
scripts/release/build_signed_macos.sh
```

Use `--distribution-only` to fail unless a Developer ID Application identity is
available. Use `--allow-adhoc` only for an explicitly unsigned/early-access
fallback.

## Requirements

- A public `FJingxian/homebrew-macluster` repository.
- A write-enabled SSH deploy key for that tap repository.

## GitHub secrets

Configure these repository secrets in `FJingxian/macluster`:

| Secret | Value |
| --- | --- |
| `HOMEBREW_TAP_SSH_KEY` | Private half of the write-enabled tap deploy key |
| `MACLUSTER_CODESIGN_P12_BASE64` | Base64-encoded Developer ID Application certificate and private key |
| `MACLUSTER_CODESIGN_P12_PASSWORD` | Password protecting the `.p12` |
| `MACLUSTER_CODESIGN_IDENTITY` | Full identity shown by `security find-identity`, for example `Developer ID Application: ... (TEAMID)` |
| `MACLUSTER_NOTARY_APPLE_ID` | Apple Account used by `notarytool` |
| `MACLUSTER_NOTARY_PASSWORD` | App-specific password for the notary service |
| `MACLUSTER_NOTARY_TEAM_ID` | Apple Developer team identifier |

Optionally set the repository variable `HOMEBREW_TAP_REPOSITORY`. The default is
`FJingxian/homebrew-macluster`.

Never commit the tap deploy key.

If the five Developer ID/notary secrets are absent, the workflow deliberately
falls back to an explicit ad-hoc signature. If any signing secret is supplied,
all signing and notarization values must be complete or the workflow fails.
Notarization is applied to a ZIP containing the signed command-line binary.
Apple does not support stapling a notarization ticket directly to a standalone
command-line executable, so Gatekeeper performs the online notarization lookup.

## Release process

1. Update `[workspace.package].version` in `Cargo.toml`.
2. Run the release tooling tests and the normal workspace tests.
3. Commit and push the version change to `main`.
4. Create and push the matching tag:

```sh
git tag v0.2.0
git push origin main
git push origin v0.2.0
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
