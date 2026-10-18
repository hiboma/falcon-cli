# Release provenance

Tag pushes matching `vMAJOR.MINOR.PATCH` invoke `release.yml`, which calls
`release-build.yml` at the same commit. The reusable workflow builds the four
supported targets with Cargo's `--locked` option and signs each `.tar.gz` archive
with `actions/attest` before uploading it. GitHub Actions OIDC and Sigstore supply
the signing identity; no long-lived signing key is configured.

The publishing job verifies all four archives against the repository, tag,
source commit, and reusable workflow commit. It copies only those verified
archives into the release directory, generates `sha256sums.txt`, uploads all
assets to a draft release, then publishes it. A failed verification prevents
publication. The checksum file is a convenience; the archive attestations are
the cryptographic provenance evidence.

## Verify a download

Install and authenticate GitHub CLI (`gh auth login`). Download the archive from
the intended release. Set these values to the release tag, its full source
commit SHA, and the downloaded archive path:

```sh
tag=vMAJOR.MINOR.PATCH
commit=FULL_RELEASE_COMMIT_SHA
artifact=./falcon-cli-aarch64-apple-darwin.tar.gz

gh attestation verify "$artifact" \
  --repo hiboma/falcon-cli \
  --source-ref "refs/tags/$tag" \
  --source-digest "$commit" \
  --signer-digest "$commit" \
  --signer-workflow hiboma/falcon-cli/.github/workflows/release-build.yml \
  --deny-self-hosted-runners
```

Obtain the expected commit from the release's tag and compare it with the source
revision you intend to trust. Verification must succeed before extracting or
running the binary. Older releases created before this workflow was introduced
do not have these attestations; a missing attestation is not a successful check.

## Immutable releases and recovery

Release immutability was enabled for `hiboma/falcon-cli` on 2026-10-18. Confirm
the setting with `gh api repos/hiboma/falcon-cli/immutable-releases`; `enabled`
must be `true`. For forks, enable **Settings > General > Releases > Release
immutability** before publishing. The setting affects future published releases,
not existing ones.
All assets must be attached while the release is still a draft. After publishing,
its assets and tag cannot be replaced or deleted while the release exists.
Corrections require a new version. Do not move a published tag or try to
overwrite a published asset.

If upload or publication fails, inspect the draft and the workflow logs. The
workflow intentionally refuses to create a second release for an existing tag.
Before retrying, remove only the incomplete draft after confirming that it has
not been published. Published releases must never be removed as retry cleanup.

## Scope and validation

Action commits and repository identities are recorded in `actions.lock`. Run
the checks in [workflow dependency maintenance](github-actions.md) after editing
either release workflow. Signing permissions are limited to the build job;
release publication uses a separate job with no OIDC signing permission.

The current Rust `stable` toolchain, runner images, cross container image, and
archive timestamps are not fixed. `--locked` prevents Cargo dependency resolution
from changing the committed lockfile, but does not make builds byte-for-byte
reproducible. Attestations establish provenance; they do not prove absence of
vulnerabilities or independently certify a SLSA level.

The first release using this workflow must be checked end to end: all four
archive attestations must verify with the command above, the release must contain
the four archives and `sha256sums.txt`, and the GitHub release API must report
`immutable: true`. Local lint and lockfile verification cannot exercise GitHub's
OIDC signing or the publication API.

References:

- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
- [Reusable build and attestation example](https://songmu.jp/riji/entry/2026-10-11-github-actions-artifact-attestations.html)
