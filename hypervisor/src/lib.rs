pub mod cpuidpatch;
pub mod wrapper;
pub use self::wrapper::{
    get_hypervisor, HyperVisorType, HypervisorRegs, HypervisorStates, VcpuOps, VmFdOps,
};
