use crate::cpu::CpuManager;
use crate::igvm::IgvmLoadedInfo;
use crate::memory_manager::{ArchMemRegion, MemoryManager};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid igvm file")]
    InvalidIgvmFile(#[source] igvm_parser::Error),
}
///
/// Load the given IGVM file to guest memory.
/// Right now it only supports SNP based isolation
///
pub fn load_igvm(
    mut _file: &std::fs::File,
    _memory_manager: Arc<Mutex<MemoryManager>>,
    _cpu_manager: Arc<Mutex<CpuManager>>,
    _mem_regions: Vec<ArchMemRegion>,
    _proc_count: u32,
    _cmdline: &str,
    #[cfg(feature = "snp")] host_data: &str,
) -> Result<Box<IgvmLoadedInfo>, Error> {
    unimplemented!()
}
