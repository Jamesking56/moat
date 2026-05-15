use crate::checks::StateCtx;
use crate::checks::common::{noun, repos_word};
use crate::checks::org_context::{MemberList, OrgContext};
use crate::checks::repo_context::{DirectCollaboratorsState, RepoContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Repositories have no direct collaborators";
pub const HOW_TO_FIX: &str = "https://github.com/{org}/{repo}/settings/access > Manage access > __Remove__ -> Every direct/outside user > Grant access via teams instead";
pub const WHY_ENABLE: &str = "Direct collaborators bypass org-level team membership audits and outlive role changes; access reviews miss them, so a long-departed contributor can keep push rights indefinitely.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.outside_collaborators
        .outcome(CheckOutcome::pass("No outside collaborators"), |v| {
            CheckOutcome::fail(format!(
                "{} outside collaborator(s) with access to private/elevated repositories",
                v.len()
            ))
        })
}

pub fn repo_check(ctx: &RepoContext) -> CheckOutcome {
    match &ctx.direct_collaborators {
        DirectCollaboratorsState::NoPermission => CheckOutcome::skipped("?"),
        DirectCollaboratorsState::Ok(v) if v.is_empty() => CheckOutcome::pass("✓"),
        DirectCollaboratorsState::Ok(v) => CheckOutcome::fail(v.len().to_string()),
    }
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let total = ctx.repos.len();
    let mut bad_repos = 0usize;
    let mut total_direct = 0usize;
    for r in ctx.repos {
        if let DirectCollaboratorsState::Ok(v) = &r.direct_collaborators
            && !v.is_empty()
        {
            bad_repos += 1;
            total_direct += v.len();
        }
    }

    let org_outside = ctx.org.and_then(|o| match &o.outside_collaborators {
        MemberList::NoPermission => None,
        MemberList::Ok(v) => Some(v.len()),
    });

    let org_phrase: Option<String> = org_outside.map(|n| {
        if n == 0 {
            "no outside collaborators on the organization".into()
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
            "no direct collaborators across {total} {}",
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
        (Some(o), Some(r)) => Some(format!("{o}; {r}")),
        (Some(o), None) => Some(o),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    }
}
