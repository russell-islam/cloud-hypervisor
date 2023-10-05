pub mod igvm_loader;
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
        // SAFETY: set is initialized above
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
}
