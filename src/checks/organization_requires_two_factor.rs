use crate::checks::StateCtx;
use crate::checks::org_context::{OrgContext, TwoFactorState};
use crate::support::outcome::CheckOutcome;

pub const LABEL: &str = "Organization requires two factor";
pub const HOW_TO_FIX: &str = "https://github.com/organizations/{org}/settings/security > Two-factor authentication > *Check* -> Require two-factor authentication for everyone in the {org} organization > *Check* -> Only allow secure two-factor methods > *Click* -> Save";
pub const WHY_ENABLE: &str = "Stolen passwords are the entry point of most maintainer-account compromises; enforcing 2FA org-wide raises the cost of a takeover from a phishing email to a physical device.";

pub fn org_check(ctx: &OrgContext) -> CheckOutcome {
    match ctx.two_factor_required {
        TwoFactorState::Required => CheckOutcome::pass("Required for every member"),
        TwoFactorState::NotRequired => CheckOutcome::fail("Not required"),
    }
}

pub fn description(ctx: StateCtx<'_>) -> Option<String> {
    let org = ctx.org?;
    Some(match org.two_factor_required {
        TwoFactorState::Required => {
            "every member must sign in with two-factor authentication".into()
        }
        TwoFactorState::NotRequired => {
            "members can sign in without two-factor authentication".into()
        }
    })
}
