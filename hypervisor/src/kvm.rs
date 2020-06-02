// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

use crate::cpu;
use crate::hv;
use crate::vm;

#[cfg(target_arch = "aarch64")]
use crate::aarch64::check_required_kvm_extensions;
use crate::common::{CpuState, CreateDevice, DeviceFd, IoEventAddress, IrqRouting, MemoryRegion};
use crate::common::{MpState};
#[cfg(target_arch = "x86_64")]

#[cfg(target_arch = "x86_64")]
use crate::x86_64::{boot_msr_entries, check_required_kvm_extensions, SpecialRegisters, FpuState, StandardRegisters, VcpuEvents};
#[cfg(target_arch = "x86_64")]
use crate::x86_64::{CpuId, ExtendedControlRegisters, LapicState, MsrEntries, Xsave};
#[cfg(target_arch = "x86_64")]
use devices::ioapic;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{kvm_enable_cap, KVM_CAP_SPLIT_IRQCHIP};

pub use kvm_bindings::{kvm_userspace_memory_region,
    kvm_irq_routing, kvm_irq_routing_entry, KVM_IRQ_ROUTING_MSI,
    KVM_MEM_READONLY, kvm_create_device, kvm_device_type_KVM_DEV_TYPE_VFIO,
};
use kvm_ioctls::{NoDatamatch, VcpuFd, VmFd};
pub use kvm_ioctls::{Kvm, Cap};
pub use kvm_ioctls;
pub use kvm_ioctls::VcpuExit;
use std::result;
use std::sync::Arc;
#[cfg(target_arch = "x86_64")]
use vm_memory::{Address, GuestAddress};

use vmm_sys_util::eventfd::EventFd;
#[cfg(target_arch = "x86_64")]
pub const KVM_TSS_ADDRESS: GuestAddress = GuestAddress(0xfffb_d000);

/// Wrapper over KVM VM ioctls.
pub struct KvmVm {
    fd: Arc<VmFd>,
}
///
/// Implementation of Vm trait for KVM
/// Example:
/// #[cfg(feature = "kvm")]
/// extern crate hypervisor
/// let kvm = hypervisor::kvm::KvmHyperVisor::new().unwrap();
/// let hv: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
/// let vm = hv.create_vm().expect("new VM fd creation failed");
/// vm.set/get().unwrap()
///
impl vm::Vm for KvmVm {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the address of the three-page region in the VM's address space.
    ///
    fn set_tss_address(&self, offset: usize) -> vm::Result<()> {
        self.fd
            .set_tss_address(offset)
            .map_err(|e| vm::HypervisorVmError::SetTssAddress(e.into()))
    }
    ///
    /// Creates an in-kernel interrupt controller.
    ///
    fn create_irq_chip(&self) -> vm::Result<()> {
        self.fd
            .create_irq_chip()
            .map_err(|e| vm::HypervisorVmError::CreateIrq(e.into()))
    }
    ///
    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        self.fd
            .register_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::RegisterIrqFd(e.into()))
    }
    ///
    /// Unregisters an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> vm::Result<()> {
        self.fd
            .unregister_irqfd(fd, gsi)
            .map_err(|e| vm::HypervisorVmError::UnregisterIrqFd(e.into()))
    }
    ///
    /// Creates a VcpuFd object from a vcpu RawFd.
    ///
    fn create_vcpu(&self, id: u8) -> vm::Result<Arc<dyn cpu::Vcpu>> {
        let vc = self
            .fd
            .create_vcpu(id)
            .map_err(|e| vm::HypervisorVmError::CreateVcpu(e.into()))?;
        let vcpu = KvmVcpu { fd: vc };
        Ok(Arc::new(vcpu))
    }
    ///
    /// Registers an event to be signaled whenever a certain address is written to.
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
                .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into()))
        } else {
            self.fd
                .register_ioevent(fd, addr, NoDatamatch)
                .map_err(|e| vm::HypervisorVmError::RegisterIoEvent(e.into()))
        }
    }
    ///
    /// Unregisters an event from a certain address it has been previously registered to.
    /// 
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> vm::Result<()> {
        self.fd
            .unregister_ioevent(fd, addr)
            .map_err(|e| vm::HypervisorVmError::UnregisterIoEvent(e.into()))
    }
    ///
    /// Sets the GSI routing table entries, overwriting any previously set
    /// entries, as per the `KVM_SET_GSI_ROUTING` ioctl.
    ///
    fn set_gsi_routing(&self, irq_routing: &IrqRouting) -> vm::Result<()> {
        self.fd
            .set_gsi_routing(irq_routing)
            .map_err(|e| vm::HypervisorVmError::SetGsiRouting(e.into()))
    }
    ///
    /// Creates/modifies a guest physical memory slot.
    ///
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> vm::Result<()> {
        unsafe {
            self.fd
                .set_user_memory_region(user_memory_region)
                .map_err(|e| vm::HypervisorVmError::SetUserMemory(e.into()))
        }
    }
    ///
    /// Creates an emulated device in the kernel.
    ///
    /// See the documentation for `KVM_CREATE_DEVICE`.
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
        let kvm_obj = Kvm::new().map_err(|e| hv::HypervisorError::VmCreate(e.into()))?;
        Ok(KvmHyperVisor { kvm: kvm_obj })
    }
}
/// Implementation of Hypervisor trait for KVM
/// Example:
/// #[cfg(feature = "kvm")]
/// extern crate hypervisor
/// let kvm = hypervisor::kvm::KvmHyperVisor::new().unwrap();
/// let hv: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
/// let vm = hv.create_vm().expect("new VM fd creation failed");
///
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
        let kvm = Kvm::new().map_err(|e| hv::HypervisorError::VmCreate(e.into()))?;

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
    ///
    // Returns the KVM API version.
    ///
    fn get_api_version(&self) -> i32 {
        self.kvm.get_api_version()
    }
    ///
    ///  Returns the size of the memory mapping required to use the vcpu's `kvm_run` structure.
    ///
    fn get_vcpu_mmap_size(&self) -> hv::Result<usize> {
        self.kvm
            .get_vcpu_mmap_size()
            .map_err(|e| hv::HypervisorError::GetVcpuMmap(e.into()))
    }
    ///
    /// Gets the recommended maximum number of VCPUs per VM.
    ///
    fn get_max_vcpus(&self) -> hv::Result<usize> {
        Ok(self.kvm.get_max_vcpus())
    }
    ///
    /// Gets the recommended number of VCPUs per VM.
    ///
    fn get_nr_vcpus(&self) -> hv::Result<usize> {
        Ok(self.kvm.get_nr_vcpus())
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Checks if a particular `Cap` is available.
    ///
    fn check_capability(&self, c: Cap) -> bool {
        self.kvm.check_extension(c)
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to get the system supported CPUID values.
    ///
    fn get_cpuid(&self) -> hv::Result<CpuId> {
        self.kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| hv::HypervisorError::GetCpuId(e.into()))
    }
}
/// Vcpu struct for KVM
pub struct KvmVcpu {
    fd: VcpuFd,
}
/// Implementation of Vcpu trait for KVM
/// Example:
/// #[cfg(feature = "kvm")]
/// extern crate hypervisor
/// let kvm = hypervisor::kvm::KvmHyperVisor::new().unwrap();
/// let hv: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
/// let vm = hv.create_vm().expect("new VM fd creation failed");
/// let vcpu = vm.create_vcpu(0).unwrap();
/// vcpu.get/set().unwrap()
///
impl cpu::Vcpu for KvmVcpu {
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU general purpose registers.
    ///
    fn get_regs(&self) -> cpu::Result<StandardRegisters> {
        self.fd
            .get_regs()
            .map_err(|e| cpu::HypervisorCpuError::GetStandardRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU general purpose registers using the `KVM_SET_REGS` ioctl.
    ///
    fn set_regs(&self, regs: &StandardRegisters) -> cpu::Result<()> {
        self.fd
            .set_regs(regs)
            .map_err(|e| cpu::HypervisorCpuError::SetStandardRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the vCPU special registers.
    ///
    fn get_sregs(&self) -> cpu::Result<SpecialRegisters> {
        self.fd
            .get_sregs()
            .map_err(|e| cpu::HypervisorCpuError::GetSpecialRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the vCPU special registers using the `KVM_SET_SREGS` ioctl.
    ///
    fn set_sregs(&self, sregs: &SpecialRegisters) -> cpu::Result<()> {
        self.fd
            .set_sregs(sregs)
            .map_err(|e| cpu::HypervisorCpuError::SetSpecialRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the floating point state (FPU) from the vCPU.
    ///
    fn get_fpu(&self) -> cpu::Result<FpuState> {
        self.fd
            .get_fpu()
            .map_err(|e| cpu::HypervisorCpuError::GetFloatingPointRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Set the floating point state (FPU) of a vCPU using the `KVM_SET_FPU` ioct.
    ///
    fn set_fpu(&self, fpu: &FpuState) -> cpu::Result<()> {
        self.fd
            .set_fpu(fpu)
            .map_err(|e| cpu::HypervisorCpuError::SetFloatingPointRegs(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call to setup the CPUID registers.
    ///
    fn set_cpuid2(&self, cpuid: &CpuId) -> cpu::Result<()> {
        self.fd
            .set_cpuid2(cpuid)
            .map_err(|e| cpu::HypervisorCpuError::SetCpuid(e.into()))
    }
    ///
    /// X86 specific call to retrieve the CPUID registers.
    ///
    #[cfg(target_arch = "x86_64")]
    fn get_cpuid2(&self, num_entries: usize) -> cpu::Result<CpuId> {
        self.fd
            .get_cpuid2(num_entries)
            .map_err(|e| cpu::HypervisorCpuError::GetCpuid(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn get_lapic(&self) -> cpu::Result<LapicState> {
        self.fd
            .get_lapic()
            .map_err(|e| cpu::HypervisorCpuError::GetlapicState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Sets the state of the LAPIC (Local Advanced Programmable Interrupt Controller).
    ///
    fn set_lapic(&self, klapic: &LapicState) -> cpu::Result<()> {
        self.fd
            .set_lapic(klapic)
            .map_err(|e| cpu::HypervisorCpuError::SetLapicState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns the model-specific registers (MSR) for this vCPU.
    ///
    fn get_msrs(&self, msrs: &mut MsrEntries) -> cpu::Result<usize> {
        self.fd
            .get_msrs(msrs)
            .map_err(|e| cpu::HypervisorCpuError::GetMsrEntries(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Setup the model-specific registers (MSR) for this vCPU.
    /// Returns the number of MSR entries actually written.
    ///
    fn set_msrs(&self, msrs: &MsrEntries) -> cpu::Result<usize> {
        self.fd
            .set_msrs(msrs)
            .map_err(|e| cpu::HypervisorCpuError::SetMsrEntries(e.into()))
    }
    ///
    /// Returns the vcpu's current "multiprocessing state".
    ///
    fn get_mp_state(&self) -> cpu::Result<MpState> {
        self.fd
            .get_mp_state()
            .map_err(|e| cpu::HypervisorCpuError::GetMpState(e.into()))
    }
    ///
    /// Sets the vcpu's current "multiprocessing state".
    ///
    fn set_mp_state(&self, mp_state: MpState) -> cpu::Result<()> {
        self.fd
            .set_mp_state(mp_state)
            .map_err(|e| cpu::HypervisorCpuError::SetMpState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xsave struct".
    ///
    fn get_xsave(&self) -> cpu::Result<Xsave> {
        self.fd
            .get_xsave()
            .map_err(|e| cpu::HypervisorCpuError::GetXsaveState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xsave struct".
    ///
    fn set_xsave(&self, xsave: &Xsave) -> cpu::Result<()> {
        self.fd
            .set_xsave(xsave)
            .map_err(|e| cpu::HypervisorCpuError::SetXsaveState(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that returns the vcpu's current "xcrs".
    ///
    fn get_xcrs(&self) -> cpu::Result<ExtendedControlRegisters> {
        self.fd
            .get_xcrs()
            .map_err(|e| cpu::HypervisorCpuError::GetXcsr(e.into()))
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// X86 specific call that sets the vcpu's current "xcrs".
    ///
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> cpu::Result<()> {
        self.fd
            .set_xcrs(&xcrs)
            .map_err(|e| cpu::HypervisorCpuError::SetXcsr(e.into()))
    }
    ///
    /// Triggers the running of the current virtual CPU returning an exit reason.
    ///
    fn run(&self) -> std::result::Result<VcpuExit, vmm_sys_util::errno::Error> {
        self.fd.run()
    }
    #[cfg(target_arch = "x86_64")]
    ///
    /// Returns currently pending exceptions, interrupts, and NMIs as well as related
    /// states of the vcpu.
    ///
    fn get_vcpu_events(&self) -> cpu::Result<VcpuEvents> {
        self.fd
            .get_vcpu_events()
            .map_err(|e| cpu::HypervisorCpuError::GetVcpuEvents(e.into()))
    }

    #[cfg(target_arch = "x86_64")]
    /// Get the current CPU state
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let kvm = hypervisor::kvm::KvmHyperVisor::new().unwrap();
    /// let hv: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
    /// let vm = hv.create_vm().expect("new VM fd creation failed");
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let state = vcpu.cpu_state().unwrap();
    ///
    fn cpu_state(&self) -> cpu::Result<CpuState> {
        let mut msrs = boot_msr_entries();
        self.get_msrs(&mut msrs)?;

        let vcpu_events = self.get_vcpu_events()?;
        let regs = self.get_regs()?;
        let sregs = self.get_sregs()?;
        let lapic_state = self.get_lapic()?;
        let fpu = self.get_fpu()?;
        let xsave = self.get_xsave()?;
        let xcrs = self.get_xcrs()?;
        let mp_state = self.get_mp_state()?;

        Ok(CpuState {
            msrs,
            vcpu_events,
            regs,
            sregs,
            fpu,
            lapic_state,
            xsave,
            xcrs,
            mp_state,
        })
    }
    #[cfg(target_arch = "aarch64")]
    fn cpu_state(&self) -> cpu::Result<CpuState> {
        unimplemented!();
    }
    #[cfg(target_arch = "x86_64")]
    /// Restore the previously saved CPU state
    ///
    /// Arguments: CpuState
    /// # Example
    ///
    /// ```rust
    /// # extern crate hypervisor;
    /// # use hypervisor::KvmHypervisor;
    /// let kvm = hypervisor::kvm::KvmHyperVisor::new().unwrap();
    /// let hv: Arc<dyn hypervisor::Hypervisor> = Arc::new(kvm);
    /// let vm = hv.create_vm().expect("new VM fd creation failed");
    /// let vcpu = vm.create_vcpu(0).unwrap();
    /// let state = vcpu.set_cpu_state(&state).unwrap();
    ///
    fn set_cpu_state(&self, state: &CpuState) -> cpu::Result<()> {
        self.set_regs(&state.regs)?;

        self.set_fpu(&state.fpu)?;

        self.set_xsave(&state.xsave)?;

        self.set_sregs(&state.sregs)?;

        self.set_xcrs(&state.xcrs)?;

        self.set_msrs(&state.msrs)?;

        self.set_lapic(&state.lapic_state)?;

        self.set_mp_state(state.mp_state)?;

        Ok(())
    }
    #[cfg(target_arch = "aarch64")]
    fn set_cpu_state(&self, state: &CpuState) -> cpu::Result<()> {
        Ok(())
    }
}
