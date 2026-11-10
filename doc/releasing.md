# Releasing macluster

The release workflow builds the Apple silicon binary, signs it with a Developer
ID Application certificate, notarizes it with Apple, publishes the GitHub
Release, and updates the Homebrew tap.

## Requirements

- An active Apple Developer Program membership.
- A `Developer ID Application` certificate and private key installed in the
  Keychain. An `Apple Development` certificate is not sufficient for public
  distribution or notarization.
- An Apple app-specific password for notarization.
- A public `FJingxian/homebrew-macluster` repository.
- A write-enabled SSH deploy key for that tap repository.

## GitHub secrets

Configure these repository secrets in `FJingxian/macluster`:

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE_P12_BASE64` | Base64 of the exported Developer ID Application `.p12` |
| `APPLE_CERTIFICATE_PASSWORD` | Password used when exporting the `.p12` |
| `APPLE_ID` | Apple Developer account email |
| `APPLE_TEAM_ID` | Apple Developer team identifier |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password used by `notarytool` |
| `HOMEBREW_TAP_SSH_KEY` | Private half of the write-enabled tap deploy key |

Optionally set the repository variable `HOMEBREW_TAP_REPOSITORY`. The default is
`FJingxian/homebrew-macluster`.

Export only the Developer ID Application identity from Keychain Access as a
password-protected `.p12`, then create the base64 secret:

```sh
base64 < developer-id.p12 | tr -d '\n' > developer-id.p12.base64
gh secret set APPLE_CERTIFICATE_P12_BASE64 \
  --repo FJingxian/macluster < developer-id.p12.base64
```

Never commit the `.p12`, its password, the app-specific password, or the tap
deploy key.

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
