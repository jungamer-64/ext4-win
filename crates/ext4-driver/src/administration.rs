//! Control ownership and narrow mount-time configuration selection.
use crate::identity::{
    IdentityCatalog, IdentityCommand, IdentityDirectory, PreparedIdentityAction,
};
use crate::kernel::status::DriverResult;
use crate::policy::{PolicyCatalog, PolicyCommand, PolicyDirectory, PreparedPolicyAction};

/// Administrative command captured before leaving requestor context.
#[derive(Debug)]
pub(crate) enum AdministrationCommand {
    /// Principal correspondence configuration.
    Identity(IdentityCommand),
    /// Future mounted-session policy.
    Policy(PolicyCommand),
}
/// Control-device lifetime owner of the two independent configuration domains.
#[derive(Debug)]
pub(crate) struct ControlCatalog {
    /// Identity persistence and publication authority.
    pub(crate) identities: IdentityCatalog,
    /// Future-mount policy persistence authority.
    pub(crate) policies: PolicyCatalog,
}
/// Mount registration can select policy and bind identity without saving either domain.
#[derive(Debug)]
pub(crate) struct MountDirectory<'a> {
    /// UUID-scoped identity registration authority.
    pub(crate) identities: &'a mut IdentityDirectory,
    /// Known durable policies, copied once before any recovery effect.
    pub(crate) policies: &'a PolicyDirectory,
}
/// Fully captured command preparation before any persistent effect.
#[derive(Debug)]
pub(crate) enum PreparedAdministration {
    /// Identity-domain preparation.
    Identity(PreparedIdentityAction),
    /// Mount-policy-domain preparation.
    Policy(PreparedPolicyAction),
}
impl ControlCatalog {
    /// Constructs unpublished defaults without persistence authority.
    pub(crate) const fn empty() -> Self {
        Self {
            identities: IdentityCatalog::empty(),
            policies: PolicyCatalog::empty(),
        }
    }
    /// Loads each independent configuration domain before publishing the control endpoint.
    /// # Safety
    /// The counted loader service path remains valid throughout initialization.
    /// # Errors
    /// Rejects invalid saved records and preserves resource and native registry failures.
    #[expect(
        unsafe_code,
        reason = "both synchronous loaders borrow the same loader-owned service path"
    )]
    pub(crate) unsafe fn load(path: wdk_sys::PCUNICODE_STRING) -> DriverResult<Self> {
        let mut catalog = Self::empty();
        catalog.identities = unsafe {
            // SAFETY: Caller retains this counted service path through synchronous initialization.
            IdentityCatalog::load(path)
        }?;
        catalog.policies = unsafe {
            // SAFETY: The same caller-owned path remains valid for this synchronous constructor.
            PolicyCatalog::load(path)
        }?;
        Ok(catalog)
    }
    /// Narrows authority to mount registration for one non-suspending actor callback.
    pub(crate) fn mount_directory(&mut self) -> MountDirectory<'_> {
        MountDirectory {
            identities: self.identities.directory_mut(),
            policies: self.policies.directory(),
        }
    }
    /// Performs domain validation and pre-effect output/resource admission.
    /// # Errors
    /// Preserves each domain's admission failures without starting persistence.
    pub(crate) fn prepare(
        &mut self,
        command: AdministrationCommand,
        capacity: usize,
    ) -> DriverResult<PreparedAdministration> {
        match command {
            AdministrationCommand::Identity(command) => self
                .identities
                .prepare(command, capacity)
                .map(PreparedAdministration::Identity),
            AdministrationCommand::Policy(command) => self
                .policies
                .prepare(command, capacity)
                .map(PreparedAdministration::Policy),
        }
    }
}
