pub use {
    kvm_bindings::kvm_cpuid_entry2 as CpuIdEntry2, kvm_bindings::kvm_create_device as CreateDevice,
    kvm_bindings::kvm_dtable as DescriptorTable, kvm_bindings::kvm_fpu as FpuState,
    kvm_bindings::kvm_irq_routing as IrqRouting, kvm_bindings::kvm_lapic_state as LapicState,
    kvm_bindings::kvm_mp_state as MpState, kvm_bindings::kvm_regs as StandardRegisters,
    kvm_bindings::kvm_segment as SegmentRegister, kvm_bindings::kvm_sregs as SpecialRegisters,
    kvm_bindings::kvm_userspace_memory_region as MemoryRegion,
    kvm_bindings::kvm_vcpu_events as VcpuEvents,
    kvm_bindings::kvm_xcrs as ExtendedControlRegisters, kvm_bindings::kvm_xsave as Xsave,
    kvm_bindings::CpuId, kvm_bindings::Msrs as MsrEntries,
};

// HyperV regs
