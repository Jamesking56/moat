# Releasing moat

## One-time setup

1. Create the GitHub repo `nunomaduro/moat` and push this code.
2. Create a second public repo named `nunomaduro/homebrew-tap` with a `Formula/` directory. Copy `packaging/homebrew/moat.rb` into `Formula/moat.rb` there.
3. For `cargo install moat`: grab an API token at https://crates.io/me/tokens and add it as the `CARGO_REGISTRY_TOKEN` repo secret in `nunomaduro/moat`. The release workflow will run `cargo publish` automatically on each tag.

## Cutting a release

1. Bump `version` in `Cargo.toml`, commit.
2. Tag and push:
   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. The `Release` workflow builds binaries for macOS (arm64 + x86_64), Linux (arm64 + x86_64), and Windows (x86_64), then attaches them plus `SHA256SUMS` to a GitHub release.
4. Update the Homebrew tap:
   - In `homebrew-tap/Formula/moat.rb`, set `version` to the new value and paste the four SHA256s from the release's `SHA256SUMS` file into the corresponding `sha256` lines.
   - Commit and push. Users now get the new version on `brew upgrade`.
5. crates.io publish happens automatically in the same workflow run.

## Install methods users will have

- `brew install nunomaduro/tap/moat` — Mac/Linux, no Rust required.
- `cargo install moat` — anywhere with a Rust toolchain (after `cargo publish`).
- Download a prebuilt tarball from the GitHub Releases page.
