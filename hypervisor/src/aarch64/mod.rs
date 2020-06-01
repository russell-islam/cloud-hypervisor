use crate::kvm::{KvmError, KvmResult};
pub use {kvm_ioctls::Cap, kvm_ioctls::Kvm};

pub fn check_required_kvm_extensions(kvm: &Kvm) -> KvmResult<()> {
    if !kvm.check_extension(Cap::SignalMsi) {
        return Err(KvmError::CapabilityMissing(Cap::SignalMsi));
    }
    Ok(())
}
