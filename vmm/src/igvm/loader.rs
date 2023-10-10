use crate::igvm::BootPageAcceptance;
use igvm_parser::hv_defs::Vtl;
use range_map_vec::RangeMap;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

#[allow(dead_code)]
pub struct Loader {
    memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
    accepted_ranges: RangeMap<u64, BootPageAcceptance>,
    max_vtl: Vtl,
    bytes_written: u64,
}
