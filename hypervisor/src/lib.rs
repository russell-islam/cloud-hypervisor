// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsft  Corporation
//
pub mod bindings;
#[cfg(target_arch = "x86_64")]
pub mod cpuidpatch;
pub mod kvm;

use crate::bindings::*;
#[cfg(feature = "kvm")]
use crate::kvm::KvmHyperVisor;
use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;
extern crate libc;

use std::fmt;

/// Errors associated with VM management

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HyperVisorType {
    KVM,
    HyperV,
    None,
}
impl fmt::Display for HyperVisorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub trait GenVmFd: Send + Sync {
    #[cfg(target_arch = "x86_64")]
    fn set_tss_address(&self, offset: usize) -> ResultOps<()>;
    fn create_irq_chip(&self) -> ResultOps<()>;
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()>;
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()>;
    fn create_vcpu(&self, id: u8) -> ResultOps<Arc<dyn GenVcpuFd>>;
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<u64>,
    ) -> ResultOps<()>;
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> ResultOps<()>;
    fn set_gsi_routing(&self, irq_routing: &IrqRouting) -> ResultOps<()>;
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> ResultOps<()>;
    fn create_device(&self, device: &mut CreateDevice) -> ResultOps<DeviceFd>;
    #[cfg(target_arch = "x86_64")]
    fn patch_cpuid(&self, vcpu: Arc<dyn GenVcpuFd>, id: u8);
    #[cfg(target_arch = "x86_64")]
    fn get_cpu_id(&self) -> ResultOps<CpuId>;
}
pub trait Hypervisor: Send + Sync {
    fn create_vm(&self) -> Result<Arc<dyn GenVmFd>>;
    fn get_api_version(&self) -> i32;
    fn get_vcpu_mmap_size(&self) -> ResultOps<usize>;
    fn get_max_vcpus(&self) -> ResultOps<usize>;
    fn get_nr_vcpus(&self) -> ResultOps<usize>;
    #[cfg(target_arch = "x86_64")]
    fn check_extension(&self, c: Cap) -> bool;
}
#[cfg(feature = "kvm")]
pub fn get_hypervisor() -> Result<Arc<dyn Hypervisor>> {
    Ok(Arc::new(KvmHyperVisor::new().unwrap()))
}
#[cfg(feature = "hyperv")]
pub fn get_hypervisor() -> Result<Arc<dyn Hypervisor>> {
    Err(Error::HyperVisorTypeMismatch)
}

pub trait GenVcpuFd: Send + Sync {
    #[cfg(target_arch = "x86_64")]
    fn get_regs(&self) -> ResultOps<StandardRegisters>;
    #[cfg(target_arch = "x86_64")]
    fn set_regs(&self, regs: &StandardRegisters) -> ResultOps<()>;
    #[cfg(target_arch = "x86_64")]
    fn get_sregs(&self) -> ResultOps<SpecialRegisters>;
    #[cfg(target_arch = "x86_64")]
    fn set_sregs(&self, sregs: &SpecialRegisters) -> ResultOps<()>;
    #[cfg(target_arch = "x86_64")]
    fn get_fpu(&self) -> ResultOps<FpuState>;
    #[cfg(target_arch = "x86_64")]
    fn set_fpu(&self, fpu: &FpuState) -> ResultOps<()>;
    #[cfg(target_arch = "x86_64")]
    fn set_cpuid2(&self, cpuid: &CpuId) -> ResultOps<()>;
    #[cfg(target_arch = "x86_64")]
    fn get_cpuid2(&self, num_entries: usize) -> ResultOps<CpuId>;
    #[cfg(target_arch = "x86_64")]
    fn get_lapic(&self) -> ResultOps<LapicState>;
    #[cfg(target_arch = "x86_64")]
    fn set_lapic(&self, lapic: &LapicState) -> ResultOps<()>;
    #[cfg(target_arch = "x86_64")]
    fn get_msrs(&self, msrs: &mut MsrEntries) -> ResultOps<usize>;
    #[cfg(target_arch = "x86_64")]
    fn set_msrs(&self, msrs: &MsrEntries) -> ResultOps<usize>;
    fn get_mp_state(&self) -> ResultOps<MpState>;
    fn set_mp_state(&self, mp_state: MpState) -> ResultOps<()>;
    #[cfg(target_arch = "x86_64")]
    fn get_xsave(&self) -> ResultOps<Xsave>;
    #[cfg(target_arch = "x86_64")]
    fn set_xsave(&self, xsave: &Xsave) -> ResultOps<()>;
    #[cfg(target_arch = "x86_64")]
    fn get_xcrs(&self) -> ResultOps<ExtendedControlRegisters>;
    #[cfg(target_arch = "x86_64")]
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> ResultOps<()>;
    fn run(&self) -> ResultOps<VcpuExit>;
    fn get_vcpu_events(&self) -> ResultOps<VcpuEvents>;
}
