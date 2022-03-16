// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// This file implements the GicV3 device.

pub mod kvm {
    use crate::aarch64::gic::kvm::KvmGicDevice;
    use crate::aarch64::gic::{Error, GicDevice};
    use std::any::Any;
    use std::{boxed::Box, result};
    type Result<T> = result::Result<T, Error>;
    use crate::layout;
    use hypervisor::kvm::kvm_bindings;
    use hypervisor::CpuState;
    use std::sync::Arc;

    /// Represent a GIC v2 device
    pub struct KvmGicV2 {
        /// The hypervisor agnostic device
        device: Arc<dyn hypervisor::Device>,

        /// GIC device properties, to be used for setting up the fdt entry
        properties: [u64; 4],

        /// Number of CPUs handled by the device
        vcpu_count: u64,
    }

    impl KvmGicV2 {
        // Device trees specific constants
        const ARCH_GIC_V2_MAINT_IRQ: u32 = 8;

        /// Get the address of the GICv2 distributor.
        const fn get_dist_addr() -> u64 {
            layout::GIC_V2_DIST_START
        }

        /// Get the size of the GIC_v2 distributor.
        const fn get_dist_size() -> u64 {
            layout::GIC_V2_DIST_SIZE
        }

        /// Get the address of the GIC_v2 CPU.
        const fn get_cpu_addr() -> u64 {
            KvmGicV2::get_dist_addr() - KvmGicV2::get_cpu_size()
        }

        /// Get the size of the GIC_v2 CPU.
        const fn get_cpu_size() -> u64 {
            layout::GIC_V2_CPU_SIZE
        }
    }

    impl GicDevice for KvmGicV2 {
        fn device(&self) -> &Arc<dyn hypervisor::Device> {
            &self.device
        }

        fn device_properties(&self) -> &[u64] {
            &self.properties
        }

        fn fdt_compatibility(&self) -> &str {
            "arm,gic-400"
        }

        fn fdt_maint_irq(&self) -> u32 {
            KvmGicV2::ARCH_GIC_V2_MAINT_IRQ
        }

        fn vcpu_count(&self) -> u64 {
            self.vcpu_count
        }

        fn set_its_device(&mut self, _its_device: Option<Arc<dyn hypervisor::Device>>) {}

        fn set_gicr_typers(&mut self, _vcpu_states: &[CpuState]) {}

        fn as_any_concrete_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    impl KvmGicDevice for KvmGicV2 {
        fn version() -> u32 {
            kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2
        }

        fn create_device(
            device: Arc<dyn hypervisor::Device>,
            vcpu_count: u64,
        ) -> Box<dyn GicDevice> {
            Box::new(KvmGicV2 {
                device,
                properties: [
                    KvmGicV2::get_dist_addr(),
                    KvmGicV2::get_dist_size(),
                    KvmGicV2::get_cpu_addr(),
                    KvmGicV2::get_cpu_size(),
                ],
                vcpu_count,
            })
        }

        fn init_device_attributes(
            _vm: &Arc<dyn hypervisor::Vm>,
            gic_device: &mut dyn GicDevice,
        ) -> Result<()> {
            /* Setting up the distributor attribute.
            We are placing the GIC below 1GB so we need to substract the size of the distributor. */
            Self::set_device_attribute(
                gic_device.device(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_DIST),
                &KvmGicV2::get_dist_addr() as *const u64 as u64,
                0,
            )?;

            /* Setting up the CPU attribute. */
            Self::set_device_attribute(
                gic_device.device(),
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_CPU),
                &KvmGicV2::get_cpu_addr() as *const u64 as u64,
                0,
            )?;

            Ok(())
        }
    }
}
