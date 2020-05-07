extern crate kvm_ioctls;
use kvm_bindings::*;
use kvm_ioctls::*;
use std::sync::Arc;
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;
extern crate libc;
use devices::ioapic;
use std::fmt;
use std::result;

use kvm_bindings::{kvm_enable_cap, kvm_userspace_memory_region, KVM_CAP_SPLIT_IRQCHIP};
use vm_memory::{Address, GuestAddress};
extern crate linux_loader;

use crate::cpuidpatch::*;

pub const WRAPPER_DEFAULT_MODULE: &str = "kvm";
pub const KVM_TSS_ADDRESS: GuestAddress = GuestAddress(0xfffb_d000);
/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot create the KVM instance
    VmCreate(kvm_ioctls::Error),

    /// Cannot set the VM up
    VmSetup(kvm_ioctls::Error),

    /// Failed to create a new KVM instance
    KvmNew(kvm_ioctls::Error),

    HyperVisorTypeMismatch,

    /// Capability missing
    CapabilityMissing(Cap),
}
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
pub type Result<T> = result::Result<T, Error>;
pub type ResultOps<T> = std::result::Result<T, errno::Error>;
pub trait VmFdOps: Send + Sync {
    fn set_tss_address(&self, offset: usize) -> ResultOps<()>;
    fn create_irq_chip(&self) -> ResultOps<()>;
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()>;
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()>;
    fn create_vcpu(&self, id: u8) -> ResultOps<Arc<dyn VcpuOps>>;
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<u64>,
    ) -> ResultOps<()>;
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> ResultOps<()>;
    fn set_gsi_routing(&self, irq_routing: &kvm_irq_routing) -> ResultOps<()>;
    fn set_user_memory_region(
        &self,
        user_memory_region: kvm_userspace_memory_region,
    ) -> ResultOps<()>;
    fn create_device(&self, device: &mut kvm_create_device) -> ResultOps<DeviceFd>;
    fn patch_cpuid(&self, vcpu: Arc<dyn VcpuOps>, id: u8);
}

pub struct KvmVmFd {
    fd: Arc<VmFd>,
    cpuid: CpuId,
}
impl VmFdOps for KvmVmFd {
    fn set_tss_address(&self, offset: usize) -> ResultOps<()> {
        self.fd.set_tss_address(offset)
    }
    fn create_irq_chip(&self) -> ResultOps<()> {
        self.fd.create_irq_chip()
    }
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()> {
        self.fd.register_irqfd(fd, gsi)
    }
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()> {
        self.fd.unregister_irqfd(fd, gsi)
    }
    fn create_vcpu(&self, id: u8) -> ResultOps<Arc<dyn VcpuOps>> {
        let vc = self.fd.create_vcpu(id).expect("new VcpuFd failed");
        let vcpu = KvmVcpuId { fd: vc };
        Ok(Arc::new(vcpu))
    }
    fn register_ioevent(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: Option<u64>,
    ) -> ResultOps<()> {
        if let Some(kvm_datamatch) = datamatch {
            self.fd.register_ioevent(fd, addr, kvm_datamatch)
        } else {
            self.fd.register_ioevent(fd, addr, NoDatamatch)
        }
    }
    fn unregister_ioevent(&self, fd: &EventFd, addr: &IoEventAddress) -> ResultOps<()> {
        self.fd.unregister_ioevent(fd, addr)
    }
    fn set_gsi_routing(&self, irq_routing: &kvm_irq_routing) -> ResultOps<()> {
        self.fd.set_gsi_routing(irq_routing)
    }
    fn set_user_memory_region(
        &self,
        user_memory_region: kvm_userspace_memory_region,
    ) -> ResultOps<()> {
        unsafe { self.fd.set_user_memory_region(user_memory_region) }
    }
    fn create_device(&self, device: &mut kvm_create_device) -> ResultOps<DeviceFd> {
        self.fd.create_device(device)
    }
    fn patch_cpuid(&self, vcpu: Arc<dyn VcpuOps>, id: u8) {
        let mut cpuid = self.cpuid.clone();
        CpuidPatch::set_cpuid_reg(&mut cpuid, 0xb, None, CpuidReg::EDX, u32::from(id));
        vcpu.set_cpuid2(&cpuid).unwrap()
    }
}
pub trait Hypervisor: Send + Sync {
    fn create_vm(&self) -> Result<Arc<dyn VmFdOps>>;
    fn get_api_version(&self) -> i32;
    fn get_vcpu_mmap_size(&self) -> ResultOps<usize>;
    fn get_max_vcpus(&self) -> ResultOps<usize>;
    fn get_nr_vcpus(&self) -> ResultOps<usize>;
}

struct KvmHyperVisor {
    kvm: Kvm,
}
impl KvmHyperVisor {
    fn new() -> Result<KvmHyperVisor> {
        let kvm = Kvm::new().map_err(Error::KvmNew)?;
        Ok(KvmHyperVisor { kvm: kvm })
    }
}
/*
pub struct HyperVHyperVisor {
    name: String,
}
impl HyperVHyperVisor {
    fn new() -> Result<HyperVHyperVisor> {
        Ok(HyperVHyperVisor {
            name: "HyperV".to_string(),
        })
    }
}
*/
impl Hypervisor for KvmHyperVisor {
    fn create_vm(&self) -> Result<Arc<dyn VmFdOps>> {
        // Check required capabilities:
        if !self.kvm.check_extension(Cap::SignalMsi) {
            return Err(Error::CapabilityMissing(Cap::SignalMsi));
        }

        if !self.kvm.check_extension(Cap::TscDeadlineTimer) {
            return Err(Error::CapabilityMissing(Cap::SignalMsi));
        }

        if !self.kvm.check_extension(Cap::SplitIrqchip) {
            return Err(Error::CapabilityMissing(Cap::SplitIrqchip));
        }

        let fd: VmFd;
        loop {
            match self.kvm.create_vm() {
                Ok(res) => fd = res,
                Err(e) => {
                    if e.errno() == libc::EINTR {
                        // If the error returned is EINTR, which means the
                        // ioctl has been interrupted, we have to retry as
                        // this can't be considered as a regular error.
                        continue;
                    } else {
                        return Err(Error::VmCreate(e));
                    }
                }
            }
            break;
        }
        let fd = Arc::new(fd);

        // Set TSS
        fd.set_tss_address(KVM_TSS_ADDRESS.raw_value() as usize)
            .map_err(Error::VmSetup)?;

        // Create split irqchip
        // Only the local APIC is emulated in kernel, both PICs and IOAPIC
        // are not.
        let mut cap: kvm_enable_cap = Default::default();
        cap.cap = KVM_CAP_SPLIT_IRQCHIP;
        cap.args[0] = ioapic::NUM_IOAPIC_PINS as u64;
        fd.enable_cap(&cap).map_err(Error::VmSetup)?;
        let cpuid: CpuId = patch_cpuid(&self.kvm).unwrap();

        Ok(Arc::new(KvmVmFd {
            fd: fd,
            cpuid: cpuid,
        }))
    }
    fn get_api_version(&self) -> i32 {
        let v: i32 = 1;
        v
    }
    fn get_vcpu_mmap_size(&self) -> ResultOps<usize> {
        self.kvm.get_vcpu_mmap_size()
    }
    fn get_max_vcpus(&self) -> ResultOps<usize> {
        Ok(self.kvm.get_max_vcpus())
    }
    fn get_nr_vcpus(&self) -> ResultOps<usize> {
        Ok(self.kvm.get_nr_vcpus())
    }
}
pub fn get_hypervisor(t: HyperVisorType) -> Result<Arc<dyn Hypervisor>> {
    if t == HyperVisorType::KVM {
        Ok(Arc::new(KvmHyperVisor::new().unwrap()))
    }
    /*else if (t == HyperVisorType::HyperV) {
        Ok(Arc::new(HyperVHyperVisor::new().unwrap()))
    } */
    else {
        Err(Error::HyperVisorTypeMismatch)
    }
}
#[derive(Copy, Clone)]
pub struct HypervisorRegs {
    pub kvm_regs: Option<kvm_regs>,
    pub kvm_sregs: Option<kvm_sregs>,
    pub kvm_xcrs: Option<kvm_xcrs>,
    pub kvm_fpu: Option<kvm_fpu>,
    // HyperV registers
}
impl Default for HypervisorRegs {
    fn default() -> HypervisorRegs {
        HypervisorRegs {
            kvm_regs: None,
            kvm_sregs: None,
            kvm_xcrs: None,
            kvm_fpu: None,
        }
    }
}
#[derive(Copy, Clone)]
pub struct HypervisorStates {
    pub kvm_xsave: Option<kvm_xsave>,
    pub kvm_mp_state: Option<kvm_mp_state>,
    pub kvm_vcpu_events: Option<kvm_vcpu_events>,
    // Hyper States
}
impl Default for HypervisorStates {
    fn default() -> HypervisorStates {
        HypervisorStates {
            kvm_xsave: None,
            kvm_mp_state: None,
            kvm_vcpu_events: None,
        }
    }
}
pub trait VcpuOps: Send + Sync {
    fn get_regs(&self) -> ResultOps<HypervisorRegs>;
    fn set_regs(&self, hregs: HypervisorRegs) -> ResultOps<()>;
    fn get_sregs(&self) -> ResultOps<HypervisorRegs>;
    fn set_sregs(&self, hregs: HypervisorRegs) -> ResultOps<()>;
    fn get_fpu(&self) -> ResultOps<HypervisorRegs>;
    fn set_fpu(&self, hregs: HypervisorRegs) -> ResultOps<()>;
    fn set_cpuid2(&self, cpuid: &CpuId) -> ResultOps<()>;
    fn get_cpuid2(&self, num_entries: usize) -> ResultOps<CpuId>;
    fn get_lapic(&self) -> ResultOps<kvm_lapic_state>;
    fn set_lapic(&self, klapic: &kvm_lapic_state) -> ResultOps<()>;
    fn get_msrs(&self, msrs: &mut Msrs) -> ResultOps<usize>;
    fn set_msrs(&self, msrs: &Msrs) -> ResultOps<usize>;
    fn get_mp_state(&self) -> ResultOps<HypervisorStates>;
    fn set_mp_state(&self, mp_state: HypervisorStates) -> ResultOps<()>;
    fn get_xsave(&self) -> ResultOps<HypervisorStates>;
    fn set_xsave(&self, hv_state: HypervisorStates) -> ResultOps<()>;
    fn get_xcrs(&self) -> ResultOps<HypervisorRegs>;
    fn set_xcrs(&self, hregs: HypervisorRegs) -> ResultOps<()>;
    fn run(&self) -> ResultOps<VcpuExit>;
    fn get_vcpu_events(&self) -> ResultOps<HypervisorStates>;
}

pub struct KvmVcpuId {
    fd: VcpuFd,
}
impl VcpuOps for KvmVcpuId {
    fn get_regs(&self) -> ResultOps<HypervisorRegs> {
        let kregs = self.fd.get_regs().unwrap();
        let mut regs: HypervisorRegs = HypervisorRegs::default();
        regs.kvm_regs = Some(kregs);
        Ok(regs)
    }
    fn set_regs(&self, hregs: HypervisorRegs) -> ResultOps<()> {
        let regs: kvm_regs = hregs.kvm_regs.unwrap();
        self.fd.set_regs(&regs)
    }
    fn get_sregs(&self) -> ResultOps<HypervisorRegs> {
        let ksregs = self.fd.get_sregs().unwrap();
        let mut sregs: HypervisorRegs = HypervisorRegs::default();
        sregs.kvm_sregs = Some(ksregs);
        Ok(sregs)
    }
    fn set_sregs(&self, hsregs: HypervisorRegs) -> ResultOps<()> {
        let sregs: kvm_sregs = hsregs.kvm_sregs.unwrap();
        self.fd.set_sregs(&sregs)
    }
    fn get_fpu(&self) -> ResultOps<HypervisorRegs> {
        let kfpu = self.fd.get_fpu().unwrap();
        let mut regs: HypervisorRegs = HypervisorRegs::default();
        regs.kvm_fpu = Some(kfpu);
        Ok(regs)
    }
    fn set_fpu(&self, hregs: HypervisorRegs) -> ResultOps<()> {
        let fpu = hregs.kvm_fpu.unwrap();
        self.fd.set_fpu(&fpu)
    }
    fn set_cpuid2(&self, cpuid: &CpuId) -> ResultOps<()> {
        self.fd.set_cpuid2(cpuid)
    }
    fn get_cpuid2(&self, num_entries: usize) -> ResultOps<CpuId> {
        self.fd.get_cpuid2(num_entries)
    }
    fn get_lapic(&self) -> ResultOps<kvm_lapic_state> {
        self.fd.get_lapic()
    }
    fn set_lapic(&self, klapic: &kvm_lapic_state) -> ResultOps<()> {
        self.fd.set_lapic(klapic)
    }
    fn get_msrs(&self, msrs: &mut Msrs) -> ResultOps<usize> {
        self.fd.get_msrs(msrs)
    }
    fn set_msrs(&self, msrs: &Msrs) -> ResultOps<usize> {
        self.fd.set_msrs(msrs)
    }
    fn get_mp_state(&self) -> ResultOps<HypervisorStates> {
        let kmp_state = self.fd.get_mp_state().unwrap();
        let mut hstate = HypervisorStates::default();
        hstate.kvm_mp_state = Some(kmp_state);
        Ok(hstate)
    }
    fn set_mp_state(&self, hv_state: HypervisorStates) -> ResultOps<()> {
        let mp_state = hv_state.kvm_mp_state.unwrap();
        self.fd.set_mp_state(mp_state)
    }
    fn get_xsave(&self) -> ResultOps<HypervisorStates> {
        let k_xsave = self.fd.get_xsave().unwrap();
        let mut hstate = HypervisorStates::default();
        hstate.kvm_xsave = Some(k_xsave);
        Ok(hstate)
    }
    fn set_xsave(&self, hv_state: HypervisorStates) -> ResultOps<()> {
        let xsave = hv_state.kvm_xsave.unwrap();
        self.fd.set_xsave(&xsave)
    }
    fn get_xcrs(&self) -> ResultOps<HypervisorRegs> {
        let kxcr = self.fd.get_xcrs().unwrap();
        let mut hregs: HypervisorRegs = HypervisorRegs::default();
        hregs.kvm_xcrs = Some(kxcr);
        Ok(hregs)
    }
    fn set_xcrs(&self, hregs: HypervisorRegs) -> ResultOps<()> {
        let xcrs: kvm_xcrs = hregs.kvm_xcrs.unwrap();
        self.fd.set_xcrs(&xcrs)
    }
    fn run(&self) -> ResultOps<VcpuExit> {
        self.fd.run()
    }
    fn get_vcpu_events(&self) -> ResultOps<HypervisorStates> {
        let k_events = self.fd.get_vcpu_events().unwrap();
        let mut hstate = HypervisorStates::default();
        hstate.kvm_vcpu_events = Some(k_events);
        Ok(hstate)
    }
}
