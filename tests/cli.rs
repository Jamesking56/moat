use assert_cmd::Command;
use predicates::prelude::*;

fn moat() -> Command {
    let mut c = Command::cargo_bin("moat").unwrap();
    // Block the binary from inheriting the developer's real token or shelling out to `gh`.
    c.env_remove("GITHUB_TOKEN")
        .env_remove("GH_TOKEN")
        .env("PATH", "/nonexistent");
    c
}

#[test]
fn help_lists_audit_subcommand() {
    moat()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ACCOUNT"))
        .stdout(predicate::str::contains("moat"));
}

#[test]
fn version_prints_package_version() {
    moat()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn no_subcommand_errors() {
    moat().assert().failure();
}

#[test]
fn audit_without_token_fails_with_helpful_message() {
    moat()
        .args(["octocat"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("gh").or(predicate::str::contains("GITHUB_TOKEN")));
}

#[test]
fn unknown_flag_errors() {
    moat().args(["octocat", "--not-a-flag"]).assert().failure();
}

#[test]
fn help_mentions_format_flag() {
    moat()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--format"))
        .stdout(predicate::str::contains("pretty"))
        .stdout(predicate::str::contains("json"))
        .stdout(predicate::str::contains("markdown"));
}

#[test]
fn format_accepts_known_values() {
    for v in ["pretty", "json", "markdown"] {
        // No token, so it should fail at auth — but argument parsing must succeed
        // (i.e. clap doesn't reject the value). Exit code is non-zero from missing
        // token, and stderr should mention the token, not a clap parse error.
        moat()
            .args(["octocat", "--format", v])
            .assert()
            .failure()
            .stdout(predicate::str::contains("gh").or(predicate::str::contains("GITHUB_TOKEN")));
    }
}

#[test]
fn format_rejects_unknown_value() {
    moat()
        .args(["octocat", "--format", "yaml"])
        .assert()
        .failure()
        .stdout(
            predicate::str::contains("invalid value")
                .or(predicate::str::contains("possible values")),
        );
}
