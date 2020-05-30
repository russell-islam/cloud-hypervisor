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
    kvm_bindings::kvm_create_device as CreateDevice, kvm_bindings::kvm_irq_routing as IrqRouting,
    kvm_bindings::kvm_userspace_memory_region as MemoryRegion, kvm_ioctls::DeviceFd,
    kvm_ioctls::IoEventAddress,
};
