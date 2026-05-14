use crate::checks::StateCtx;
use crate::checks::common::noun;
use crate::checks::org_context::{MemberList, OrgContext};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Organization members all have two factor";
pub const HOW_TO_FIX: &str = "GitHub → your organization → people → filter by \"two-factor:disabled\" → ask each listed member to enable two-factor authentication on their GitHub account (user settings → password and authentication).";
pub const WHY_ENABLE: &str = "The org-wide 2FA policy only covers members enrolled after it was turned on; anyone here predates it and remains the weakest unlocked door into the org.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    ctx.members_without_2fa
        .outcome(CheckOutcome::pass("Every member has 2FA enabled"), |v| {
            CheckOutcome::fail(format!("{} member(s) without 2FA enabled", v.len()))
        })
}

pub fn state_note(ctx: StateCtx<'_>) -> Option<String> {
    let org = ctx.org?;
    match &org.members_without_2fa {
        MemberList::NoPermission => None,
        MemberList::Ok(v) if v.is_empty() => {
            Some("every member has two-factor authentication enabled".into())
        }
        MemberList::Ok(v) => Some(format!(
            "{} {} can sign in without two-factor authentication",
            v.len(),
            noun(v.len(), "member", "members")
        )),
    }
}
