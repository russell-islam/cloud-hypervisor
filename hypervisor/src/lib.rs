pub mod cpuidpatch;
pub mod wrapper;
pub use self::wrapper::{
    get_hypervisor, Hypervisor, HypervisorRegs, HypervisorStates, VcpuOps, VmFdOps,
};
