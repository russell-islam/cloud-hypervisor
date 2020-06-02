// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//
use crate::kvm::{Cap, Kvm, KvmError, KvmResult};
///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
pub use {
    kvm_bindings::kvm_create_device as CreateDevice, kvm_bindings::kvm_dtable as DescriptorTable,
    kvm_bindings::kvm_fpu as FpuState, kvm_bindings::kvm_lapic_state as LapicState,
    kvm_bindings::kvm_mp_state as MpState, kvm_bindings::kvm_regs as StandardRegisters,
    kvm_bindings::kvm_segment as SegmentRegister, kvm_bindings::kvm_sregs as SpecialRegisters,
    kvm_bindings::kvm_vcpu_events as VcpuEvents,
    kvm_bindings::kvm_xcrs as ExtendedControlRegisters, kvm_bindings::kvm_xsave as Xsave,
    kvm_bindings::CpuId, kvm_bindings::Msrs as MsrEntries,
};

use kvm_bindings::{kvm_msr_entry, Msrs};

use arch_gen::x86::msr_index;
use serde_derive::{Deserialize, Serialize};

// MTRR constants
const MTRR_ENABLE: u64 = 0x800; // IA32_MTRR_DEF_TYPE MSR: E (MTRRs enabled) flag, bit 11
const MTRR_MEM_TYPE_WB: u64 = 0x6;

macro_rules! kvm_msr {
    ($msr:expr) => {
        kvm_msr_entry {
            index: $msr,
            data: 0x0,
            ..Default::default()
        }
    };
}
macro_rules! kvm_msr_data {
    ($msr:expr, $data:expr) => {
        kvm_msr_entry {
            index: $msr,
            data: $data,
            ..Default::default()
        }
    };
}

pub fn boot_msr_entries() -> Msrs {
    Msrs::from_entries(&[
        kvm_msr!(msr_index::MSR_IA32_SYSENTER_CS),
        kvm_msr!(msr_index::MSR_IA32_SYSENTER_ESP),
        kvm_msr!(msr_index::MSR_IA32_SYSENTER_EIP),
        kvm_msr!(msr_index::MSR_STAR),
        kvm_msr!(msr_index::MSR_CSTAR),
        kvm_msr!(msr_index::MSR_LSTAR),
        kvm_msr!(msr_index::MSR_KERNEL_GS_BASE),
        kvm_msr!(msr_index::MSR_SYSCALL_MASK),
        kvm_msr!(msr_index::MSR_IA32_TSC),
        kvm_msr_data!(
            msr_index::MSR_IA32_MISC_ENABLE,
            msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64
        ),
        kvm_msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
    ])
}

///
/// Check KVM extension for Linux
///
pub fn check_required_kvm_extensions(kvm: &Kvm) -> KvmResult<()> {
    if !kvm.check_extension(Cap::SignalMsi) {
        return Err(KvmError::CapabilityMissing(Cap::SignalMsi));
    }
    if !kvm.check_extension(Cap::TscDeadlineTimer) {
        return Err(KvmError::CapabilityMissing(Cap::TscDeadlineTimer));
    }
    if !kvm.check_extension(Cap::SplitIrqchip) {
        return Err(KvmError::CapabilityMissing(Cap::SplitIrqchip));
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuKvmState {
    pub msrs: MsrEntries,
    pub vcpu_events: VcpuEvents,
    pub regs: StandardRegisters,
    pub sregs: SpecialRegisters,
    pub fpu: FpuState,
    pub lapic_state: LapicState,
    pub xsave: Xsave,
    pub xcrs: ExtendedControlRegisters,
    pub mp_state: MpState,
}
