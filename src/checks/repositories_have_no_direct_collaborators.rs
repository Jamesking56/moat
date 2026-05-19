use crate::checks::StateCtx;
use crate::checks::common::{noun, repos_word};
use crate::checks::org_context::OrgContext;
use crate::checks::repo_context::RepoContext;
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories have no direct collaborators";
pub const HOW_TO_FIX: &str = "In all the links below > Manage access > *Remove* -> Every direct/outside user > Grant access via teams instead";
pub const WHY_ENABLE: &str = "Direct collaborators bypass org-level team membership audits and outlive role changes; access reviews miss them, so a long-departed contributor can keep push rights indefinitely.";

pub fn how_to_fix(_ctx: StateCtx<'_>) -> &'static str {
    HOW_TO_FIX
}

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    if ctx.outside_collaborators.is_empty() {
        CheckOutcome::pass("No outside collaborators")
    } else {
        CheckOutcome::fail(format!(
            "{} outside collaborator(s) with access to private/elevated repositories",
            ctx.outside_collaborators.len()
        ))
        .with_items(ctx.outside_collaborators.clone())
    }
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    if ctx.direct_collaborators.is_empty() {
        CheckOutcome::pass("✓")
    } else {
        CheckOutcome::fail(ctx.direct_collaborators.len().to_string())
    }
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    let mut bad_repos = 0usize;
    let mut total_direct = 0usize;
    for r in ctx.repos {
        if !r.direct_collaborators.is_empty() {
            bad_repos += 1;
            total_direct += r.direct_collaborators.len();
        }
    }

    let org_outside = ctx.org.map(|o| o.outside_collaborators.len());

    let org_phrase: Option<String> = org_outside.map(|n| {
        if n == 0 {
            "the organization has no outside collaborators".into()
        } else {
            format!(
                "{n} outside {} have access to private or elevated repositories",
                noun(n, "collaborator", "collaborators")
            )
        }
    });

    let repo_phrase: Option<String> = if total == 0 {
        None
    } else if bad_repos == 0 {
        Some(format!(
            "all {total} {} are free of direct collaborators",
            repos_word(total)
        ))
    } else {
        Some(format!(
            "{total_direct} direct {} retain access across {bad_repos}/{total} {}",
            noun(total_direct, "collaborator", "collaborators"),
            repos_word(total)
        ))
    };

    match (org_phrase, repo_phrase) {
        (Some(o), Some(r)) => Some(format!("{o}, and {r}")),
        (Some(o), None) => Some(o),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    }
}
