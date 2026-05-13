<p align="center">
    <img src="./art/logo.png" alt="moat" width="800">
    <p align="center">
        <a href="https://github.com/nunomaduro/moat/actions"><img alt="GitHub Workflow Status (main)" src="https://github.com/nunomaduro/moat/actions/workflows/ci.yml/badge.svg"></a>
        <a href="https://github.com/nunomaduro/moat/releases"><img alt="Latest Version" src="https://img.shields.io/github/v/release/nunomaduro/moat"></a>
        <a href="https://github.com/nunomaduro/moat/blob/0.x/LICENSE"><img alt="License" src="https://img.shields.io/github/license/nunomaduro/moat"></a>
    </p>
</p>

## Introduction

**moat** is a supply-chain security auditor for GitHub organizations. It works with any GitHub **user**, **organization**, or **repository** — auditing the controls you want in place before a malicious dependency, a compromised maintainer account, or a leaked token turns into an incident.

It checks **two-factor authentication**, **branch protection**, **signed commits**, **secret scanning**, **Dependabot alerts**, **workflow permissions**, **pinned actions**, **repository webhooks**, and more. Zero config — just install and run.

## Installation

> **Works with any GitHub organization, user, or repository.** A `GITHUB_TOKEN`, `GH_TOKEN`, or [GitHub CLI](https://cli.github.com) login is required.

### Homebrew (macOS / Linux)

```bash
brew install nunomaduro/tap/moat
```

### Prebuilt binaries

Download the archive for your platform from the [releases page](https://github.com/nunomaduro/moat/releases) and place `moat` on your `PATH`.

## Usage

```bash
moat <account>
```

`<account>` can be a GitHub organization, a user, or an `<owner>/<repo>` slug.

```bash
moat <your-org>
moat <owner>/<repo>
```

## Authentication

`moat` resolves a GitHub token in this order:

1. `GITHUB_TOKEN` environment variable
2. `GH_TOKEN` environment variable
3. `gh auth token` (if the [GitHub CLI](https://cli.github.com) is installed and logged in)

For organization audits the token needs:

- `read:org` — list members, admins, outside collaborators, 2FA enforcement
- `repo` — read branch protection, required reviews, secret scanning, Dependabot alerts, workflow files, repository contents (`SECURITY.md`), and repository webhooks

A classic PAT or a fine-grained token with the equivalent permissions both work. For user accounts (no org scope), only repo read access is required.

## Checks

### `organization_requires_two_factor`

Stolen passwords are the entry point of most maintainer-account compromises; enforcing 2FA org-wide raises the cost of a takeover from a phishing email to a physical device.

### `organization_members_all_have_two_factor`

The org-wide 2FA policy only covers members enrolled after it was turned on; anyone predating it remains the weakest unlocked door into the org.

### `organization_new_members_default_to_no_permissions`

This setting decides the blast radius of a single compromised account; with write or admin as the default, one stolen session can push to every repo at once instead of just the ones that member legitimately touches.

### `repositories_actions_workflow_token_is_read_only`

Every workflow inherits this token by default; granting write at the org or repo level means a typo'd action reference or a hijacked third-party action can rewrite history, tags, and releases without ever needing a maintainer's credentials.

### `repositories_secret_scanning_is_enabled`

Secrets accidentally committed stay valid until someone notices; scanning gives you minutes-to-hours warning instead of waiting for a leaked-credential abuse alert from a downstream provider.

### `repositories_secret_push_protection_is_enabled`

Scanning finds secrets after they reach GitHub; push protection rejects them at the git layer so the credential never enters history, forks, mirrors, or backups in the first place.

### `repositories_dependabot_alerts_are_enabled`

Most package compromises are disclosed publicly before they are widely exploited; alerts tell you which of your repos consume the bad version so you can pin or patch within the window before mass scanning catches up.

### `repositories_releases_are_immutable`

Without immutability, an existing tag can be moved or its assets replaced after the fact; downstream consumers pinned to a version they audited will silently fetch different bytes the next time they install.

### `repositories_fork_pull_requests_require_approval`

A fork PR can ship malicious workflow changes that run with your runners' filesystem and network access on the first push; approval gating lets a human read the diff before code from a stranger executes.

### `repositories_release_branches_are_protected`

Every other branch-level safeguard (signed commits, required reviews, linear history) hangs off a ruleset — with no ruleset attached to your release branches, none of those protections apply.

### `repositories_commits_are_signed`

A stolen developer token can push commits authored as anyone; requiring a verified signature ties each commit to a key the attacker doesn't have, turning a leaked token from a code-push into a noisy failure.

### `repositories_pull_requests_require_reviews`

Without required reviews, a single compromised contributor account can push directly to a release branch — peer review is the cheapest mechanism that catches malicious patches before they ship.

### `repositories_branch_protection_applies_to_admins`

If admins can bypass the ruleset, a single compromised admin token is enough to push unsigned or unreviewed code straight to a release branch — the rule becomes advisory.

### `repositories_default_branch_is_locked`

Force pushes and branch deletions rewrite history — an attacker (or a tired maintainer) can erase the audit trail of a malicious commit or quietly replace a tagged release with a different tree.

### `repositories_default_branch_has_linear_history`

Merge commits can hide unreviewed parents — a `git merge` of an unprotected side branch can introduce code that no reviewer ever saw, while still appearing as a normal merge in the PR.

### `repositories_webhooks_are_secure`

Plain-HTTP hooks leak payloads (and any secrets inside them) to any network on the path, and a hook without a shared secret has no way to prove the request actually came from GitHub.

### `repositories_have_no_direct_collaborators`

Direct collaborators bypass org-level team membership audits and outlive role changes; access reviews miss them, so a long-departed contributor can keep push rights indefinitely.

### `repositories_private_vulnerability_reporting_is_enabled`

Without a private intake, researchers either drop a public issue (advertising the bug before it's fixed) or give up; the private channel lets you triage and ship a patched release before exploitation.

### `repositories_workflow_actions_are_pinned`

Tags and branches are mutable — when `tj-actions/changed-files` was compromised in 2025 the attacker repointed the existing tags, so every workflow `@v1` instantly ran malicious code; SHA pins make that impossible.

### `repositories_pull_request_target_is_safe`

`pull_request_target` runs with the base repo's secrets and write token; if the workflow then checks out the PR's code, any fork PR executes attacker-controlled code with full repo privileges.

### `repositories_workflow_permissions_are_restricted`

Without a declared `permissions:` block (or with `write-all`), every step in the workflow — including third-party actions — runs with full repo write access, turning any compromised action into a code-push primitive.

### `repositories_have_security_policy`

Without a disclosure channel, well-meaning researchers file public issues with full PoCs — `SECURITY.md` is what funnels them to a private channel before the world sees the bug.

### `repositories_have_dependabot_config`

Pinning actions to SHAs is only safe if something keeps them up to date; without dependabot the pins rot and either get bumped to a tag (defeating the pin) or stay stuck on a known-vulnerable revision.

## Configuration

`moat` looks for a `moat.toml` file at the root of each audited repository. Use it to disable checks that don't apply to that repo. Disabled checks are still shown in the output (as `off`) but don't count toward the failure total.

```toml
[checks]
repositories_commits_are_signed = "off"
repositories_workflow_actions_are_pinned = "off"
```

Values are `"on"` (default) or `"off"`. Use any check ID from the [Checks](#checks) section above.

## Exit Codes

- `0` — all checks passed
- non-zero — at least one check failed or an error occurred

## Contributing

Thank you for considering contributing to moat! The contribution guide can be found in the [Laravel documentation](https://laravel.com/docs/contributions).

## Code of Conduct

In order to ensure that the Laravel community is welcoming to all, please review and abide by the [Code of Conduct](https://laravel.com/docs/contributions#code-of-conduct).

## Security Vulnerabilities

Please review [our security policy](https://github.com/nunomaduro/moat/security/policy) on how to report security vulnerabilities.

## License

moat is open-sourced software licensed under the [MIT license](LICENSE).
