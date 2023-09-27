pub mod igvm_loader;
mod loader;
use igvm_defs::IGVM_VHS_SNP_ID_BLOCK;
use igvm_parser::snp_defs::SevVmsa;
use std::mem::MaybeUninit;

#[derive(Debug, Clone)]
pub struct IgvmLoadedInfo {
    pub gpas: Vec<u64>,
    pub vmsa_gpa: u64,
    pub first_gpa: u64,
    pub snp_id_block: IGVM_VHS_SNP_ID_BLOCK,
    pub start_gpa: u64,
    pub length: u64,
    pub vmsa: SevVmsa,
}

impl Default for IgvmLoadedInfo {
    fn default() -> Self {
        let ret = MaybeUninit::<IgvmLoadedInfo>::zeroed();
        unsafe { ret.assume_init() }
    }
}
impl IgvmLoadedInfo {
    pub fn new() -> Self {
        IgvmLoadedInfo {
            gpas: Vec::new(),
            ..Default::default()
        }
    }
    pub fn gpas_as_array(&self) -> &[u64] {
        &self.gpas[..]
    }
}

pub const HV_PAGE_SIZE: u64 = 4096;
pub const IGVM_VHF_PAGE_DATA_FLAGS_UNMEASURED: u32 = 0x2;

/// The page acceptance used for importing pages into the initial launch context of the guest.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BootPageAcceptance {
    /// The page is accepted exclusive (no host visibility) and the page data is measured.
    Exclusive,
    /// The page is accepted exclusive (no host visibility) and the page data is unmeasured.
    ExclusiveUnmeasured,
    /// The page contains hardware-specific VP context information.
    VpContext,
    /// This page communicates error information to the host.
    ErrorPage,
    /// This page communicates hardware-specific secret information and the page data is unmeasured.
    SecretsPage,
    /// This page includes guest-specified CPUID information.
    CpuidPage,
    /// This page should include the enumeration of extended state CPUID leaves.
    CpuidExtendedStatePage,
}

/// The startup memory type used to notify a well behaved host that memory should be present before attempting to
/// start the guest.
#[derive(Debug, PartialEq, Eq)]
pub enum StartupMemoryType {
    /// The range is normal memory.
    Ram,
    /// The range is normal memory that additionally can have VTL2 protections
    /// applied by the guest.
    Vtl2ProtectableRam,
}
