# moat

Supply-chain security auditor for GitHub organizations.

`moat` audits a GitHub user or organization against a set of supply-chain hardening checks — the kind of controls you want in place before a malicious dependency, a compromised maintainer account, or a leaked token turns into an incident.

## Install

### Homebrew (macOS / Linux)

```sh
brew install nunomaduro/tap/moat
```

### Cargo

```sh
cargo install moat
```

### Prebuilt binaries

Download the archive for your platform from the [releases page](https://github.com/nunomaduro/moat/releases) and place `moat` on your `PATH`.

## Usage

```sh
moat audit <account>
```

Examples:

```sh
moat audit <your-org>
moat audit <your-org> --only org
moat audit <your-org> --only repos
```

`<account>` can be a GitHub organization or a user. `--only org` runs only org-level checks; `--only repos` runs only repository-level checks.

## Authentication

`moat` resolves a GitHub token in this order:

1. `GITHUB_TOKEN` environment variable
2. `GH_TOKEN` environment variable
3. `gh auth token` (if the [GitHub CLI](https://cli.github.com) is installed and logged in)

For organization audits the token needs:

- `read:org` — list members, admins, outside collaborators, 2FA enforcement
- `repo` — read branch protection, required reviews, secret scanning, Dependabot alerts, workflow files, repository contents (CODEOWNERS, SECURITY.md), and repository webhooks (the webhook check requires admin access on the repo; it is skipped where the token lacks it)

A classic PAT or a fine-grained token with the equivalent permissions both work. For user accounts (no org scope), only repo read access is required.

## Checks

### Organization
- Two-factor authentication required for all members
- Members without 2FA enabled
- Number of organization admins (owners)
- Outside collaborators with access to private repos
- Default repository permission for org members (`read`/`none` pass, `write`/`admin` fail)

### Repository
- Branch protection enabled on the default branch
- Pull request reviews required before merge
- Signed commits required
- Secret scanning enabled
- Push protection enabled
- Dependabot alerts enabled
- Default `GITHUB_TOKEN` workflow permissions (read vs. write)
- Branch protection is enforced on admins (no bypass on the default branch)
- Default branch requires linear history and disallows force pushes and deletions
- `CODEOWNERS` file is present and code-owner review is required on the default branch
- Every `uses:` in `.github/workflows/*.yml` is pinned to a 40-char commit SHA
- No workflow combines `pull_request_target` with a checkout of an untrusted PR head ref
- Every workflow declares a top-level `permissions:` block that is not `write-all`
- Repository webhooks use HTTPS and have a secret configured
- `SECURITY.md` is present (at the repo root, in `.github/`, or in `docs/`)

## Exit codes

- `0` — all checks passed
- non-zero — at least one check failed or an error occurred

## License

MIT — see [LICENSE](LICENSE).
