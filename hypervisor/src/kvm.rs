// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::cpu;
use crate::hv;
use crate::vm;

use crate::common::{CreateDevice, DeviceFd, IoEventAddress, IrqRouting, MemoryRegion};
use crate::common::{FpuState, MpState, SpecialRegisters, StandardRegisters, VcpuEvents, VcpuExit};
#[cfg(target_arch = "x86_64")]
use crate::x86_64::check_required_kvm_extensions;
use crate::x86_64::{CpuId, ExtendedControlRegisters, LapicState, MsrEntries, Xsave};
#[cfg(target_arch = "x86_64")]
use devices::ioapic;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{kvm_enable_cap, KVM_CAP_SPLIT_IRQCHIP};
use kvm_ioctls::{Cap, Kvm, NoDatamatch, VcpuFd, VmFd};
use std::result;
use std::sync::Arc;
use vm_memory::{Address, GuestAddress};

use vmm_sys_util::eventfd::EventFd;
pub const KVM_TSS_ADDRESS: GuestAddress = GuestAddress(0xfffb_d000);
extern crate linux_loader;

/// Wrapper over KVM VM ioctls.
pub struct KvmVm {
    fd: Arc<VmFd>,
}
///
/// Implementation of Vm trait for KVM
/// Example:
/// hv = KvmHyperVisor::new().unwrap()
/// vm = hv.create_vm().unwrap()
/// vm.create_irq_chip().map_err()
///
impl vm::Vm for KvmVm {
    #[cfg(target_arch = "x86_64")]
    /// Sets the address of the three-page region in the VM's address space.
    ///
    /// See the documentation for `KVM_SET_TSS_ADDR`.
    ///
    /// # Arguments
    ///
    /// * `offset` - Physical address of a three-page region in the guest's physical address space.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// vm.set_tss_address(0xfffb_d000).unwrap();
    /// ```
    ///
    fn set_tss_address(&self, offset: usize) -> vm::Result<()> {
        self.fd
            .set_tss_address(offset)
            .map_err(|e| vm::HypervisorVmError::SetTssAddress(e.into()))
    }
    /// Creates an in-kernel interrupt controller.
    ///
    /// See the documentation for `KVM_CREATE_IRQCHIP`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    ///
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// vm.create_irq_chip().unwrap();
    /// #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] {
    ///     use kvm_bindings::{kvm_create_device,
    ///         kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2, KVM_CREATE_DEVICE_TEST};
    ///     let mut gic_device = kvm_bindings::kvm_create_device {
    ///         type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
    ///         fd: 0,
    ///         flags: KVM_CREATE_DEVICE_TEST,
    ///     };
    ///     if vm.create_device(&mut gic_device).is_ok() {
    ///         vm.create_irq_chip().unwrap();
    ///     }
    /// }
    /// ```
    ///
    fn create_irq_chip(&self) -> vm::Result<()> {
        self.fd
            .create_irq_chip()
            .map_err(|e| vm::HypervisorVmError::CreateIrq(e.into()))
    }
    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    /// # Arguments
    ///
    /// * `fd` - `EventFd` to be signaled.
    /// * `gsi` - IRQ to be triggered.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// # extern crate libc;
    /// # extern crate vmm_sys_util;
    /// # use libc::EFD_NONBLOCK;
    /// # use vmm_sys_util::eventfd::EventFd;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
    ///     vm.create_irq_chip().unwrap();
    ///     vm.register_irqfd(&evtfd, 0).unwrap();
    /// }
    /// ```
    ///
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        self.fd
            .register_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))
    }
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    /// # Arguments
    ///
    /// * `fd` - `EventFd` to be signaled.
    /// * `gsi` - IRQ to be triggered.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// # extern crate libc;
    /// # extern crate vmm_sys_util;
    /// # use libc::EFD_NONBLOCK;
    /// # use vmm_sys_util::eventfd::EventFd;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
    ///     vm.create_irq_chip().unwrap();
    ///     vm.register_irqfd(&evtfd, 0).unwrap();
    ///     vm.unregister_irqfd(&evtfd, 0).unwrap();
    /// }
    /// ```
    ///
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        self.fd
            .unregister_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::UnregisterIrqFd(e.into()))
    }
    /// Creates a VcpuFd object from a vcpu RawFd.
    ///
    /// This function is unsafe as the primitives currently returned have the contract that
    /// they are the sole owner of the file descriptor they are wrapping. Usage of this function
    /// could accidentally allow violating this contract which can cause memory unsafety in code
    /// that relies on it being true.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    /// // Create one vCPU with the ID=0.
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let rawfd = unsafe { libc::dup(vcpu.as_raw_fd()) };
    /// assert!(rawfd >= 0);
    /// let vcpu = unsafe { vm.create_vcpu_from_rawfd(rawfd).unwrap() };
    /// ```
    ///
    fn create_vcpu(&self, id: u8) -> vm::Result<Arc<dyn cpu::Vcpu>> {
        let vc = self.fd.create_vcpu(id).expect("new VcpuFd failed");
        let vcpu = KvmVcpu { fd: vc };
        Ok(Arc::new(vcpu))
    }
    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// See the documentation for `KVM_IOEVENTFD`.
    ///
    /// # Arguments
    ///
    /// * `fd` - `EventFd` which will be signaled. When signaling, the usual `vmexit` to userspace
    ///           is prevented.
    /// * `addr` - Address being written to.
    /// * `datamatch` - Limits signaling `fd` to only the cases where the value being written is
    ///                 equal to this parameter. The size of `datamatch` is important and it must
    ///                 match the expected size of the guest's write.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// vm_fd
    ///    .register_ioevent(&evtfd, &IoEventAddress::Pio(0xf4), NoDatamatch)
    ///    .unwrap();
    /// vm_fd
    ///    .register_ioevent(&evtfd, &IoEventAddress::Mmio(0x1000), NoDatamatch)
    ///    .unwrap();
    /// ```
    ///
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<u64>,
    ) -> vm::Result<()> {
        if let Some(kvm_datamatch) = datamatch {
            self.fd
                .register_ioevent(fd, addr, kvm_datamatch)
                .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))
        } else {
            self.fd
                .register_ioevent(fd, addr, NoDatamatch)
                .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))
        }
    }
    /// Unregisters an event from a certain address it has been previously registered to.
    ///
    /// See the documentation for `KVM_IOEVENTFD`.
    ///
    /// # Arguments
    ///
    /// * `fd` - FD which will be unregistered.
    /// * `addr` - Address being written to.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it relies on RawFd.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// extern crate libc;
    /// extern crate vmm_sys_util;
    /// # use kvm_ioctls::{IoEventAddress, Kvm, NoDatamatch};
    /// use libc::EFD_NONBLOCK;
    /// use vmm_sys_util::eventfd::EventFd;
    ///
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    /// let evtfd = EventFd::new(EFD_NONBLOCK).unwrap();
    /// let pio_addr = IoEventAddress::Pio(0xf4);
    /// let mmio_addr = IoEventAddress::Mmio(0x1000);
    /// vm_fd
    ///    .register_ioevent(&evtfd, &pio_addr, NoDatamatch)
    ///    .unwrap();
    /// vm_fd
    ///    .register_ioevent(&evtfd, &mmio_addr, NoDatamatch)
    ///    .unwrap();
    /// vm_fd
    ///    .unregister_ioevent(&evtfd, &pio_addr)
    ///    .unwrap();
    /// vm_fd
    ///    .unregister_ioevent(&evtfd, &mmio_addr)
    ///    .unwrap();
    /// ```
    ///
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> vm::Result<()> {
        self.fd
            .unregister_ioevent(fd, addr)
            .map_err(|e| vm::HypervisorVmError::UnregisterIoEvent(e.into()))
    }
    /// Sets the GSI routing table entries, overwriting any previously set
    /// entries, as per the `KVM_SET_GSI_ROUTING` ioctl.
    ///
    /// See the documentation for `KVM_SET_GSI_ROUTING`.
    ///
    /// Returns an io::Error when the table could not be updated.
    ///
    /// # Arguments
    ///
    /// * kvm_irq_routing - IRQ routing configuration. Describe all routes
    ///                     associated with GSI entries. For details check
    ///                     the `kvm_irq_routing` and `kvm_irq_routing_entry`
    ///                     structures in the
    ///                     [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// use kvm_bindings::kvm_irq_routing;
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// vm.create_irq_chip().unwrap();
    ///
    /// let irq_routing = kvm_irq_routing::default();
    /// vm.set_gsi_routing(&irq_routing).unwrap();
    /// ```
    ///
    fn set_gsi_routing(&self, irq_routing: &IrqRouting) -> vm::Result<()> {
        self.fd
            .set_gsi_routing(irq_routing)
            .map_err(|e| vm::HypervisorVmError::SetGsiRouting(e.into()))
    }
    /// Creates/modifies a guest physical memory slot.
    ///
    /// See the documentation for `KVM_SET_USER_MEMORY_REGION`.
    ///
    /// # Arguments
    ///
    /// * `user_memory_region` - Guest physical memory slot. For details check the
    ///             `kvm_userspace_memory_region` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Safety
    ///
    /// This function is unsafe because there is no guarantee `userspace_addr` points to a valid
    /// memory region, nor the memory region lives as long as the kernel needs it to.
    ///
    /// The caller of this method must make sure that:
    /// - the raw pointer (`userspace_addr`) points to valid memory
    /// - the regions provided to KVM are not overlapping other memory regions.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    ///
    /// let mem_region = kvm_userspace_memory_region {
    ///                     slot: 0,
    ///                     guest_phys_addr: 0x10000 as u64,
    ///                     memory_size: 0x10000 as u64,
    ///                     userspace_addr: 0x0 as u64,
    ///                     flags: 0,
    ///                 };
    ///
    /// vm.set_user_memory_region(mem_region).unwrap();
    ///
    /// ```
    ///
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> vm::Result<()> {
        unsafe {
            self.fd
                .set_user_memory_region(user_memory_region)
                .map_err(|e| vm::HypervisorVmError::SetUserMemory(e.into()))
        }
    }
    /// Creates an emulated device in the kernel.
    ///
    /// See the documentation for `KVM_CREATE_DEVICE`.
    ///
    /// # Arguments
    ///
    /// * `device`: device configuration. For details check the `kvm_create_device` structure in the
    ///                [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate kvm_bindings;
    /// # use kvm_ioctls::Kvm;
    /// use kvm_bindings::{
    ///     kvm_device_type_KVM_DEV_TYPE_VFIO,
    ///     kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
    ///     kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
    ///     KVM_CREATE_DEVICE_TEST,
    /// };
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    ///
    ///
    /// // Creating a device with the KVM_CREATE_DEVICE_TEST flag to check
    /// // whether the device type is supported. This will not create the device.
    /// // To create the device the flag needs to be removed.
    /// let mut device = kvm_bindings::kvm_create_device {
    ///     #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ///     type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
    ///     #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    ///     type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
    ///     fd: 0,
    ///     flags: KVM_CREATE_DEVICE_TEST,
    /// };
    /// // On ARM, creating VGICv3 may fail due to hardware dependency.
    /// // Retry to create VGICv2 in that case.
    /// let device_fd = vm.create_device(&mut device).unwrap_or_else(|_| {
    ///     #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ///     panic!("Cannot create VFIO device.");
    ///     #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    ///     {
    ///         device.type_ = kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2;
    ///         vm.create_device(&mut device).expect("Cannot create vGIC device")
    ///     }
    /// });
    /// ```
    ///
    fn create_device(&self, device: &mut CreateDevice) -> vm::Result<DeviceFd> {
        self.fd
            .create_device(device)
            .map_err(|e| vm::HypervisorVmError::CreateDevice(e.into()))
    }
}
/// Wrapper over KVM system ioctls.
pub struct KvmHyperVisor {
    kvm: Kvm,
}
/// Enum for KVM related error
#[derive(Debug)]
pub enum KvmError {
    CapabilityMissing(Cap),
}
pub type KvmResult<T> = result::Result<T, KvmError>;
impl KvmHyperVisor {
    /// Create a hypervisor based on Kvm
    pub fn new() -> hv::Result<KvmHyperVisor> {
        let kvm_obj = Kvm::new().map_err(|e| hv::HypervisorError::KvmNew(e.into()))?;
        Ok(KvmHyperVisor { kvm: kvm_obj })
    }
}

impl hv::Hypervisor for KvmHyperVisor {
    /// Create a KVM vm object and return the object as Vm trait object
    /// Example
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap()
    ///
    fn create_vm(&self) -> hv::Result<Arc<dyn vm::Vm>> {
        let kvm = Kvm::new().map_err(|e| hv::HypervisorError::KvmNew(e.into()))?;

        check_required_kvm_extensions(&kvm).expect("Missing KVM capabilities");

        let fd: VmFd;
        loop {
            match kvm.create_vm() {
                Ok(res) => fd = res,
                Err(e) => {
                    if e.errno() == libc::EINTR {
                        // If the error returned is EINTR, which means the
                        // ioctl has been interrupted, we have to retry as
                        // this can't be considered as a regular error.
                        continue;
                    } else {
                        return Err(hv::HypervisorError::VmCreate(e.into()));
                    }
                }
            }
            break;
        }
        let vm_fd = Arc::new(fd);

        // Set TSS
        #[cfg(target_arch = "x86_64")]
        vm_fd
            .set_tss_address(KVM_TSS_ADDRESS.raw_value() as usize)
            .map_err(|e| hv::HypervisorError::VmSetup(e.into()))?;

        #[cfg(target_arch = "x86_64")]
        {
            // Create split irqchip
            // Only the local APIC is emulated in kernel, both PICs and IOAPIC
            // are not.
            let mut cap: kvm_enable_cap = Default::default();
            cap.cap = KVM_CAP_SPLIT_IRQCHIP;
            cap.args[0] = ioapic::NUM_IOAPIC_PINS as u64;
            vm_fd
                .enable_cap(&cap)
                .map_err(|e| hv::HypervisorError::VmSetup(e.into()))?;
        }
        let kvm_fd = KvmVm { fd: vm_fd };
        Ok(Arc::new(kvm_fd))
    }
    // Returns the KVM API version.
    ///
    /// See the documentation for `KVM_GET_API_VERSION`.
    ///
    /// # Example
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHyperVisor;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// assert_eq!(hv.get_api_version(), 12);
    /// ```
    ///
    fn get_api_version(&self) -> i32 {
        self.kvm.get_api_version()
    }
    ///  Returns the size of the memory mapping required to use the vcpu's `kvm_run` structure.
    ///
    /// See the documentation for `KVM_GET_VCPU_MMAP_SIZE`.
    ///
    /// # Example
    ///
    /// ```
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// assert!(hv.get_vcpu_mmap_size().unwrap() > 0);
    /// ```
    ///
    fn get_vcpu_mmap_size(&self) -> hv::Result<usize> {
        self.kvm
            .get_vcpu_mmap_size()
            .map_err(|e| hv::HypervisorError::GetMaxVcpu(e.into()))
    }
    /// Gets the recommended maximum number of VCPUs per VM.
    ///
    /// See the documentation for `KVM_CAP_MAX_VCPUS`.
    /// Returns [get_nr_vcpus()](struct.Kvm.html#method.get_nr_vcpus) when
    /// `KVM_CAP_MAX_VCPUS` is not implemented.
    ///
    /// # Example
    ///
    /// ```
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// assert!(hv.get_max_vcpus() > 0);
    /// ```
    ///
    fn get_max_vcpus(&self) -> hv::Result<usize> {
        Ok(self.kvm.get_max_vcpus())
    }
    /// Gets the recommended number of VCPUs per VM.
    ///
    /// See the documentation for `KVM_CAP_NR_VCPUS`.
    /// Default to 4 when `KVM_CAP_NR_VCPUS` is not implemented.
    ///
    /// # Example
    ///
    /// ```

    /// yse hypervisor::Cap
    /// let hv = KvmHyperVisor::new().unwrap();
    /// // We expect the number of vCPUs to be > 0 as per KVM API documentation.
    /// assert!(hv.get_nr_vcpus() > 0);
    /// ```
    ///
    fn get_nr_vcpus(&self) -> hv::Result<usize> {
        Ok(self.kvm.get_nr_vcpus())
    }
    #[cfg(target_arch = "x86_64")]
    /// Checks if a particular `Cap` is available.
    ///
    /// Returns true if the capability is supported and false otherwise.
    /// See the documentation for `KVM_CHECK_EXTENSION`.
    ///
    /// # Arguments
    ///
    /// * `c` - KVM capability to check.
    ///
    /// # Example
    ///
    /// ```
    /// use hypervisor::KvmVm;
    /// use hypervisor::KvmVm;
    /// let hv = KvmHyperVisor::new().unwrap();
    /// // Check if `KVM_CAP_USER_MEMORY` is supported.
    /// assert!(hv.check_extension(Cap::UserMemory));
    /// ```
    ///

    fn check_extension(&self, c: Cap) -> bool {
        self.kvm.check_extension(c)
    }
    #[cfg(target_arch = "x86_64")]
    /// X86 specific call to get the system supported CPUID values.
    ///
    /// See the documentation for `KVM_GET_SUPPORTED_CPUID`.
    ///
    /// # Arguments
    ///
    /// * `max_entries_count` - Maximum number of CPUID entries. This function can return less than
    ///                         this when the hardware does not support so many CPUID entries.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate kvm_bindings;
    /// use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    /// use kvm_ioctls::Kvm;
    ///
    /// let kvm = Kvm::new().unwrap();
    /// let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    /// let cpuid_entries = cpuid.as_mut_slice();
    /// assert!(cpuid_entries.len() <= KVM_MAX_CPUID_ENTRIES);
    /// ```
    ///
    fn get_cpuid(&self) -> hv::Result<CpuId> {
        self.kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| hv::HypervisorError::GetCpuId(e.into()))
    }
}

pub struct KvmVcpu {
    fd: VcpuFd,
}
impl cpu::Vcpu for KvmVcpu {
    #[cfg(target_arch = "x86_64")]

    /// Returns the vCPU general purpose registers.
    ///
    /// The registers are returned in a `kvm_regs` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_GET_REGS`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    /// let regs = vcpu.get_regs().unwrap();
    /// ```
    ///
    fn get_regs(&self) -> cpu::Result<StandardRegisters> {
        self.fd
            .get_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetStandardRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// Sets the vCPU general purpose registers using the `KVM_SET_REGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `regs` - general purpose registers. For details check the `kvm_regs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))] {
    ///     // Get the current vCPU registers.
    ///     let mut regs = vcpu.get_regs().unwrap();
    ///     // Set a new value for the Instruction Pointer.
    ///     regs.rip = 0x100;
    ///     vcpu.set_regs(&regs).unwrap();
    /// }
    /// ```
    ///
    fn set_regs(&self, regs: &StandardRegisters) -> cpu::Result<()> {
        self.fd
            .set_regs(regs)
            .map_err(|e| cpu::HypervisorCpuError::SetStandardRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// Returns the vCPU special registers.
    ///
    /// The registers are returned in a `kvm_sregs` structure as defined in the
    /// [KVM API documentation](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See documentation for `KVM_GET_SREGS`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let sregs = vcpu.get_sregs().unwrap();
    /// ```
    ///
    fn get_sregs(&self) -> cpu::Result<SpecialRegisters> {
        self.fd
            .get_sregs()
            .map_err(|e| cpu::HypervisorCpuError::GetSpecialRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// Sets the vCPU special registers using the `KVM_SET_SREGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `sregs` - Special registers. For details check the `kvm_sregs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))] {
    ///     let mut sregs = vcpu.get_sregs().unwrap();
    ///     // Update the code segment (cs).
    ///     sregs.cs.base = 0;
    ///     sregs.cs.selector = 0;
    ///     vcpu.set_sregs(&sregs).unwrap();
    /// }
    /// ```
    ///
    fn set_sregs(&self, sregs: &SpecialRegisters) -> cpu::Result<()> {
        self.fd
            .set_sregs(sregs)
            .map_err(|e| cpu::HypervisorCpuError::SetSpecialRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// Returns the floating point state (FPU) from the vCPU.
    ///
    /// The state is returned in a `kvm_fpu` structure as defined in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See the documentation for `KVM_GET_FPU`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    /// let fpu = vcpu.get_fpu().unwrap();
    /// ```
    ///
    fn get_fpu(&self) -> cpu::Result<FpuState> {
        self.fd
            .get_fpu()
            .map_err(|e| cpu::HypervisorCpuError::GetFloatingPointRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// Set the floating point state (FPU) of a vCPU using the `KVM_SET_FPU` ioct.
    ///
    /// # Arguments
    ///
    /// * `fpu` - FPU configuration. For details check the `kvm_fpu` structure in the
    ///           [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
    ///     let KVM_FPU_CWD: u16 = 0x37f;
    ///     let fpu = kvm_fpu {
    ///         fcw: KVM_FPU_CWD,
    ///         ..Default::default()
    ///     };
    ///     vcpu.set_fpu(&fpu).unwrap();
    /// }
    /// ```
    ///
    fn set_fpu(&self, fpu: &FpuState) -> cpu::Result<()> {
        self.fd
            .set_fpu(fpu)
            .map_err(|e| cpu::HypervisorCpuError::SetFloatingPointRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// X86 specific call to setup the CPUID registers.
    ///
    /// See the documentation for `KVM_SET_CPUID2`.
    ///
    /// # Arguments
    ///
    /// * `cpuid` - CPUID registers.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # use hypervisor::KvmHypervisor;
    /// # use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    ///
    /// // Update the CPUID entries to disable the EPB feature.
    /// const ECX_EPB_SHIFT: u32 = 3;
    /// {
    ///     let entries = kvm_cpuid.as_mut_slice();
    ///     for entry in entries.iter_mut() {
    ///         match entry.function {
    ///             6 => entry.ecx &= !(1 << ECX_EPB_SHIFT),
    ///             _ => (),
    ///         }
    ///     }
    /// }
    ///
    /// vcpu.set_cpuid2(&kvm_cpuid).unwrap();
    /// ```
    ///
    fn set_cpuid2(&self, cpuid: &CpuId) -> cpu::Result<()> {
        self.fd
            .set_cpuid2(cpuid)
            .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()))
    }
    /// X86 specific call to retrieve the CPUID registers.
    ///
    /// It requires knowledge of how many `kvm_cpuid_entry2` entries there are to get.
    /// See the documentation for `KVM_GET_CPUID2` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `num_entries` - Number of CPUID entries to be read.
    ///
    /// # Example
    ///
    ///  ```rust
    /// # use hypervisor::KvmHypervisor;
    /// # use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let cpuid = vcpu.get_cpuid2(KVM_MAX_CPUID_ENTRIES).unwrap();
    /// ```
    ///
    #[cfg(target_arch = "x86_64")]
    fn get_cpuid2(&self, num_entries: usize) -> cpu::Result<CpuId> {
        self.fd
            .get_cpuid2(num_entries)
            .map_err(|e| cpu::HypervisorCpuError::GetCpuid(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    /// The state is returned in a `kvm_lapic_state` structure as defined in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// See the documentation for `KVM_GET_LAPIC`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let lapic = vcpu.get_lapic().unwrap();
    /// ```
    ///
    fn get_lapic(&self) -> cpu::Result<LapicState> {
        self.fd
            .get_lapic()
            .map_err(|e| cpu::HypervisorCpuError::GetlapicState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    /// See the documentation for `KVM_SET_LAPIC`.
    ///
    /// # Arguments
    ///
    /// * `klapic` - LAPIC state. For details check the `kvm_lapic_state` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// # extern crate kvm_ioctls;
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// use std::io::Write;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// // For `get_lapic` to work, you first need to create a IRQ chip before creating the vCPU.
    /// vm.create_irq_chip().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mut lapic = vcpu.get_lapic().unwrap();
    ///
    /// // Write to APIC_ICR offset the value 2.
    /// let apic_icr_offset = 0x300;
    /// let write_value: &[u8] = &[2, 0, 0, 0];
    /// let mut apic_icr_slice =
    ///     unsafe { &mut *(&mut lapic.regs[apic_icr_offset..] as *mut [i8] as *mut [u8]) };
    /// apic_icr_slice.write(write_value).unwrap();
    ///
    /// // Update the value of LAPIC.
    ///vcpu.set_lapic(&lapic).unwrap();
    /// ```
    ///
    fn set_lapic(&self, klapic: &LapicState) -> cpu::Result<()> {
        self.fd
            .set_lapic(klapic)
            .map_err(|e| cpu::HypervisorCpuError::SetLapicState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    /// It emulates `KVM_GET_MSRS` ioctl's behavior by returning the number of MSRs
    /// successfully read upon success or the last error number in case of failure.
    /// The MSRs are returned in the `msr` method argument.
    ///
    /// # Arguments
    ///
    /// * `msrs`  - MSRs (input/output). For details check the `kvm_msrs` structure in the
    ///             [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// // Configure the struct to say which entries we want to get.
    /// let mut msrs = Msrs::from_entries(&[
    ///     kvm_msr_entry {
    ///         index: 0x0000_0174,
    ///         ..Default::default()
    ///     },
    ///     kvm_msr_entry {
    ///         index: 0x0000_0175,
    ///         ..Default::default()
    ///     },
    /// ]);
    /// let read = vcpu.get_msrs(&mut msrs).unwrap();
    /// assert_eq!(read, 2);
    /// ```
    ///
    fn get_msrs(&self, msrs: &mut MsrEntries) -> cpu::Result<usize> {
        self.fd
            .get_msrs(msrs)
            .map_err(|e| cpu::HypervisorCpuError::GetMsrEntries(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    /// See the documentation for `KVM_SET_MSRS`.
    ///
    /// # Arguments
    ///
    /// * `msrs` - MSRs. For details check the `kvm_msrs` structure in the
    ///            [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// // Configure the entries we want to set.
    /// let mut msrs = Msrs::from_entries(&[
    ///     kvm_msr_entry {
    ///         index: 0x0000_0174,
    ///         ..Default::default()
    ///     },
    /// ]);
    /// let written = vcpu.set_msrs(&msrs).unwrap();
    /// assert_eq!(written, 1);
    /// ```
    ///
    fn set_msrs(&self, msrs: &MsrEntries) -> cpu::Result<usize> {
        self.fd
            .set_msrs(msrs)
            .map_err(|e| cpu::HypervisorCpuError::SetMsrEntries(e.into()))
    }
    /// Returns the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for `KVM_GET_MP_STATE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_mp_state` - multiprocessing state to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mp_state = vcpu.get_mp_state().unwrap();
    /// ```
    ///
    fn get_mp_state(&self) -> cpu::Result<MpState> {
        self.fd
            .get_mp_state()
            .map_err(|e| cpu::HypervisorCpuError::GetMpState(e.into()))
    }
    /// Sets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for `KVM_SET_MP_STATE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_mp_state` - multiprocessing state to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let mp_state = Default::default();
    /// // Your `mp_state` manipulation here.
    /// vcpu.set_mp_state(mp_state).unwrap();
    /// ```
    ///
    fn set_mp_state(&self, mp_state: MpState) -> cpu::Result<()> {
        self.fd
            .set_mp_state(mp_state)
            .map_err(|e| cpu::HypervisorCpuError::SetMpState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// X86 specific call that returns the vcpu's current "xsave struct".
    ///
    /// See the documentation for `KVM_GET_XSAVE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xsave` - xsave struct to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xsave = vcpu.get_xsave().unwrap();
    /// ```
    ///
    fn get_xsave(&self) -> cpu::Result<Xsave> {
        self.fd
            .get_xsave()
            .map_err(|e| cpu::HypervisorCpuError::GetXsaveState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// X86 specific call that sets the vcpu's current "xsave struct".
    ///
    /// See the documentation for `KVM_SET_XSAVE` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xsave` - xsave struct to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xsave = Default::default();
    /// // Your `xsave` manipulation here.
    /// vcpu.set_xsave(&xsave).unwrap();
    /// ```
    ///
    fn set_xsave(&self, xsave: &Xsave) -> cpu::Result<()> {
        self.fd
            .set_xsave(xsave)
            .map_err(|e| cpu::HypervisorCpuError::SetXsaveState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// X86 specific call that returns the vcpu's current "xcrs".
    ///
    /// See the documentation for `KVM_GET_XCRS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xcrs` - xcrs to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let xcrs = vcpu.get_xcrs().unwrap();
    /// ```
    ///
    fn get_xcrs(&self) -> cpu::Result<ExtendedControlRegisters> {
        self.fd
            .get_xcrs()
            .map_err(|e| cpu::HypervisorCpuError::GetXcsr(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    /// X86 specific call that sets the vcpu's current "xcrs".
    ///
    /// See the documentation for `KVM_SET_XCRS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_xcrs` - xcrs to be written.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// let vcpu = vm.create_vcpu(0).unwrap()
    /// let xcrs = Default::default();
    /// // Your `xcrs` manipulation here.
    /// vcpu.set_xcrs(&xcrs).unwrap();
    /// ```
    ///
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> cpu::Result<()> {
        self.fd
            .set_xcrs(&xcrs)
            .map_err(|e| cpu::HypervisorCpuError::SetXcsr(e.into()))
    }
    /// Triggers the running of the current virtual CPU returning an exit reason.
    ///
    /// See documentation for `KVM_RUN`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::{KvmHypervisor, VcpuExit};
    /// # use std::io::Write;
    /// # use std::ptr::null_mut;
    /// # use std::slice;
    /// # use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_LOG_DIRTY_PAGES};
    /// let hv = KvmHypervisor::new().unwrap();
    /// let vm = hv.create_vm().unwrap();
    /// // This is a dummy example for running on x86 based on https://lwn.net/Articles/658511/.
    /// #[cfg(target_arch = "x86_64")] {
    ///     let mem_size = 0x4000;
    ///     let guest_addr: u64 = 0x1000;
    ///     let load_addr: *mut u8 = unsafe {
    ///         libc::mmap(
    ///             null_mut(),
    ///             mem_size,
    ///             libc::PROT_READ | libc::PROT_WRITE,
    ///             libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
    ///             -1,
    ///             0,
    ///         ) as *mut u8
    ///     };
    ///
    ///     let mem_region = kvm_userspace_memory_region {
    ///         slot: 0,
    ///         guest_phys_addr: guest_addr,
    ///         memory_size: mem_size as u64,
    ///         userspace_addr: load_addr as u64,
    ///         flags: 0,
    ///     };
    ///     unsafe { vm.set_user_memory_region(mem_region).unwrap() };
    ///
    ///     // Dummy x86 code that just calls halt.
    ///     let x86_code = [
    ///             0xf4,             /* hlt */
    ///     ];
    ///
    ///     // Write the code in the guest memory. This will generate a dirty page.
    ///     unsafe {
    ///         let mut slice = slice::from_raw_parts_mut(load_addr, mem_size);
    ///         slice.write(&x86_code).unwrap();
    ///     }
    ///
    ///     let vcpu_fd = vm.create_vcpu(0).unwrap();
    ///
    ///     let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    ///     vcpu_sregs.cs.base = 0;
    ///     vcpu_sregs.cs.selector = 0;
    ///     vcpu_fd.set_sregs(&vcpu_sregs).unwrap();
    ///
    ///     let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    ///     // Set the Instruction Pointer to the guest address where we loaded the code.
    ///     vcpu_regs.rip = guest_addr;
    ///     vcpu_regs.rax = 2;
    ///     vcpu_regs.rbx = 3;
    ///     vcpu_regs.rflags = 2;
    ///     vcpu_fd.set_regs(&vcpu_regs).unwrap();
    ///
    ///     loop {
    ///         match vcpu_fd.run().expect("run failed") {
    ///             VcpuExit::Hlt => {
    ///                 break;
    ///             }
    ///             exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
    ///         }
    ///     }
    /// }
    /// ```
    ///
    fn run(&self) -> cpu::Result<VcpuExit> {
        self.fd
            .run()
            .map_err(|e| cpu::HypervisorCpuError::RunVcpu(e.into()))
    }
    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    ///
    /// See the documentation for `KVM_GET_VCPU_EVENTS` in the
    /// [KVM API doc](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt).
    ///
    /// # Arguments
    ///
    /// * `kvm_vcpu_events` - vcpu events to be read.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::{KvmHypervisor, Cap};
    /// let hv = KvmHypervisor::new().unwrap();
    /// if kvm.check_extension(Cap::VcpuEvents) {
    ///     let vm = hv.create_vm().unwrap();
    ///     let vcpu = vm.create_vcpu(0).unwrap();
    ///     let vcpu_events = vcpu.get_vcpu_events().unwrap();
    /// }
    /// ```
    ///
    fn get_vcpu_events(&self) -> cpu::Result<VcpuEvents> {
        self.fd
            .get_vcpu_events()
            .map_err(|e| cpu::HypervisorCpuError::GetVcpuEvents(e.into()))
    }
}
