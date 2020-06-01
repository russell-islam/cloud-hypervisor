// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
//

///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
///
pub use {
    kvm_bindings::kvm_cpuid_entry2 as CpuIdEntry2, kvm_bindings::kvm_create_device as CreateDevice,
    kvm_bindings::kvm_dtable as DescriptorTable, kvm_bindings::kvm_lapic_state as LapicState,
    kvm_bindings::kvm_segment as SegmentRegister,
    kvm_bindings::kvm_xcrs as ExtendedControlRegisters, kvm_bindings::kvm_xsave as Xsave,
    kvm_bindings::CpuId, kvm_bindings::Msrs as MsrEntries, kvm_ioctls::Cap,
};
