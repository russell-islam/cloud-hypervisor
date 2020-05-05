pub mod cpuidpatch;
pub mod wrapper;
pub use self::wrapper::{get_default_vmfd, HypervisorRegs, HypervisorStates, VcpuOps, VmFdOps};
