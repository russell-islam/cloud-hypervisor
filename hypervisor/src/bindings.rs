// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsft  Corporation
//
use vmm_sys_util::errno;
extern crate libc;
use std::result;

#[cfg(target_arch = "x86_64")]
pub use {
    kvm_bindings::kvm_cpuid_entry2 as CpuIdEntry2, kvm_bindings::kvm_dtable as DescriptorTable,
    kvm_bindings::kvm_lapic_state as LapicState, kvm_bindings::kvm_segment as SegmentRegister,
    kvm_bindings::kvm_xcrs as ExtendedControlRegisters, kvm_bindings::kvm_xsave as Xsave,
    kvm_bindings::CpuId, kvm_bindings::Msrs as MsrEntries, kvm_ioctls::Cap,
};
pub use {
    kvm_bindings::kvm_create_device as CreateDevice, kvm_bindings::kvm_fpu as FpuState,
    kvm_bindings::kvm_irq_routing as IrqRouting, kvm_bindings::kvm_mp_state as MpState,
    kvm_bindings::kvm_regs as StandardRegisters, kvm_bindings::kvm_sregs as SpecialRegisters,
    kvm_bindings::kvm_userspace_memory_region as MemoryRegion,
    kvm_bindings::kvm_vcpu_events as VcpuEvents, kvm_ioctls::DeviceFd, kvm_ioctls::IoEventAddress,
    kvm_ioctls::VcpuExit,
};
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HypervisorError(i32);
#[derive(Debug)]
pub enum Error {
    HyperVisorTypeMismatch,
    VmCreate,
    VmSetup,
}
// HyperV regs
pub type Result<T> = result::Result<T, Error>;
pub type ResultOps<T> = std::result::Result<T, errno::Error>;
