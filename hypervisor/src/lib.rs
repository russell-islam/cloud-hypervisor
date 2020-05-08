pub mod cpuidpatch;
pub mod regs;
pub mod wrapper;
pub use self::wrapper::{get_hypervisor, HyperVisorType, Hypervisor, VcpuOps, VmFdOps};
