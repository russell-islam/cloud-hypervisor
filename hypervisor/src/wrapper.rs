extern crate kvm_ioctls;

use kvm_ioctls::*;
use std::sync::Arc;
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;
extern crate libc;
use devices::ioapic;
use std::fmt;
use std::result;

use kvm_bindings::{kvm_enable_cap, KVM_CAP_SPLIT_IRQCHIP};
use vm_memory::{Address, GuestAddress};
extern crate linux_loader;

use crate::cpuidpatch::*;
use crate::regs::*;

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
    fn set_gsi_routing(&self, irq_routing: &IrqRouting) -> ResultOps<()>;
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> ResultOps<()>;
    fn create_device(&self, device: &mut CreateDevice) -> ResultOps<DeviceFd>;
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
    fn set_gsi_routing(&self, irq_routing: &IrqRouting) -> ResultOps<()> {
        self.fd.set_gsi_routing(irq_routing)
    }
    fn set_user_memory_region(&self, user_memory_region: MemoryRegion) -> ResultOps<()> {
        unsafe { self.fd.set_user_memory_region(user_memory_region) }
    }
    fn create_device(&self, device: &mut CreateDevice) -> ResultOps<DeviceFd> {
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

pub trait VcpuOps: Send + Sync {
    fn get_regs(&self) -> ResultOps<StandardRegisters>;
    fn set_regs(&self, regs: &StandardRegisters) -> ResultOps<()>;
    fn get_sregs(&self) -> ResultOps<SpecialRegisters>;
    fn set_sregs(&self, sregs: &SpecialRegisters) -> ResultOps<()>;
    fn get_fpu(&self) -> ResultOps<FpuState>;
    fn set_fpu(&self, fpu: &FpuState) -> ResultOps<()>;
    fn set_cpuid2(&self, cpuid: &CpuId) -> ResultOps<()>;
    fn get_cpuid2(&self, num_entries: usize) -> ResultOps<CpuId>;
    fn get_lapic(&self) -> ResultOps<LapicState>;
    fn set_lapic(&self, lapic: &LapicState) -> ResultOps<()>;
    fn get_msrs(&self, msrs: &mut MsrEntries) -> ResultOps<usize>;
    fn set_msrs(&self, msrs: &MsrEntries) -> ResultOps<usize>;
    fn get_mp_state(&self) -> ResultOps<MpState>;
    fn set_mp_state(&self, mp_state: MpState) -> ResultOps<()>;
    fn get_xsave(&self) -> ResultOps<Xsave>;
    fn set_xsave(&self, xsave: &Xsave) -> ResultOps<()>;
    fn get_xcrs(&self) -> ResultOps<ExtendedControlRegisters>;
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> ResultOps<()>;
    fn run(&self) -> ResultOps<VcpuExit>;
    fn get_vcpu_events(&self) -> ResultOps<VcpuEvents>;
}

pub struct KvmVcpuId {
    fd: VcpuFd,
}
impl VcpuOps for KvmVcpuId {
    fn get_regs(&self) -> ResultOps<StandardRegisters> {
        //let kregs = self.fd.get_regs().unwrap();
        //let mut regs: HypervisorRegs = HypervisorRegs::default();
        //regs.kvm_regs = Some(kregs);
        //Ok(regs)
        self.fd.get_regs()
    }
    fn set_regs(&self, regs: &StandardRegisters) -> ResultOps<()> {
        self.fd.set_regs(regs)
    }
    fn get_sregs(&self) -> ResultOps<SpecialRegisters> {
        self.fd.get_sregs()
    }
    fn set_sregs(&self, sregs: &SpecialRegisters) -> ResultOps<()> {
        self.fd.set_sregs(sregs)
    }
    fn get_fpu(&self) -> ResultOps<FpuState> {
        self.fd.get_fpu()
    }
    fn set_fpu(&self, fpu: &FpuState) -> ResultOps<()> {
        self.fd.set_fpu(fpu)
    }
    fn set_cpuid2(&self, cpuid: &CpuId) -> ResultOps<()> {
        self.fd.set_cpuid2(cpuid)
    }
    fn get_cpuid2(&self, num_entries: usize) -> ResultOps<CpuId> {
        self.fd.get_cpuid2(num_entries)
    }
    fn get_lapic(&self) -> ResultOps<LapicState> {
        self.fd.get_lapic()
    }
    fn set_lapic(&self, klapic: &LapicState) -> ResultOps<()> {
        self.fd.set_lapic(klapic)
    }
    fn get_msrs(&self, msrs: &mut MsrEntries) -> ResultOps<usize> {
        self.fd.get_msrs(msrs)
    }
    fn set_msrs(&self, msrs: &MsrEntries) -> ResultOps<usize> {
        self.fd.set_msrs(msrs)
    }
    fn get_mp_state(&self) -> ResultOps<MpState> {
        self.fd.get_mp_state()
    }
    fn set_mp_state(&self, mp_state: MpState) -> ResultOps<()> {
        self.fd.set_mp_state(mp_state)
    }
    fn get_xsave(&self) -> ResultOps<Xsave> {
        self.fd.get_xsave()
    }
    fn set_xsave(&self, xsave: &Xsave) -> ResultOps<()> {
        self.fd.set_xsave(xsave)
    }
    fn get_xcrs(&self) -> ResultOps<ExtendedControlRegisters> {
        self.fd.get_xcrs()
    }
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> ResultOps<()> {
        self.fd.set_xcrs(&xcrs)
    }
    fn run(&self) -> ResultOps<VcpuExit> {
        self.fd.run()
    }
    fn get_vcpu_events(&self) -> ResultOps<VcpuEvents> {
        self.fd.get_vcpu_events()
    }
}
