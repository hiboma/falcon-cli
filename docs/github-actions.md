# GitHub Actions dependency maintenance

All workflows in `.github/workflows/` are registered in `actions.lock`, generated
by GitHub's `gh-actions-lock` extension. Existing commit SHA references remain in
place. The lockfile also records repository identities and transitive action
dependencies. CI runs an online verification with read-only repository access.

## Updating workflows

Install the same extension version used in CI and authenticate GitHub CLI:

```sh
gh auth login
gh extension install github/gh-actions-lock --pin v0.2.0
```

If the extension is already installed at another version, use the install
command with `--force` to align it with CI.

After adding, removing, or changing an action or workflow, run from the repository
root:

```sh
gh actions-lock --no-narrow
gh actions-lock --verify
actionlint
```

Commit the workflow changes and generated lockfile together. Never edit the
lockfile by hand. Review changed commits as dependency updates and investigate
any changed `owner_id` or `repo_id` before merging.
Use `--no-narrow` to preserve the workflow's commit SHA references instead of
rewriting them to tags during onboarding.

`gh actions-lock --verify-local` checks coverage offline; it does not validate
upstream commits or repository identities and does not replace `--verify`.
For an intentional update to a moving branch or partial version reference,
review upstream changes before running `gh actions-lock --relock`.

Dependabot is configured for GitHub Actions and updates lockfile entries for
onboarded workflows. New workflows still need `gh actions-lock --no-narrow` to onboard them.
The CI verification scans the whole directory to detect missing onboarding.

Workflow lockfiles are in public preview. Update the pinned extension version in
CI and this guide together, regenerate the lockfile, and verify the result.
Repository-wide **Require lockfile** enforcement is a separate GitHub setting;
this change registers the existing workflows without changing that setting.

References:

- [GitHub's lockfile guide](https://docs.github.com/en/actions/how-tos/secure-your-work/lock-workflow-dependencies)
- [gh-actions-lock](https://github.com/github/gh-actions-lock)
