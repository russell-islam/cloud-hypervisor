pub mod cpuidpatch;
pub mod kvm;
pub mod params;
pub mod wrapper;

pub use self::wrapper::get_hypervisor;

pub use self::wrapper::{HyperVisorType, Hypervisor, VcpuOps, VmFdOps};
