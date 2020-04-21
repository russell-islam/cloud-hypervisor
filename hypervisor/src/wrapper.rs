extern crate kvm_ioctls;
use kvm_bindings::*;
use kvm_ioctls::*;
use std::sync::Arc;
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;
extern crate libc;
use devices::ioapic;
use std::io::{self};
use std::{result, str};


use kvm_bindings::{kvm_enable_cap, kvm_userspace_memory_region, KVM_CAP_SPLIT_IRQCHIP};
use vm_memory::{Address, GuestAddress};
extern crate linux_loader;
use crate::cpuidpatch::*;

pub const WRAPPER_DEFAULT_MODULE: &str = "kvm";
pub const KVM_TSS_ADDRESS: GuestAddress = GuestAddress(0xfffb_d000);
/// Errors associated with VM management
#[derive(Debug)]
pub enum Error {
    /// Cannot open the VM file descriptor.
    VmFd(io::Error),
    VcpuFd(kvm_ioctls::Error),
    /// Cannot create the KVM instance
    VmCreate(kvm_ioctls::Error),

    /// Cannot set the VM up
    VmSetup(kvm_ioctls::Error),

    /// Cannot open the kernel image
    KernelFile(io::Error),

    /// Cannot open the initramfs image
    InitramfsFile(io::Error),

    /// Cannot load the kernel in memory
    KernelLoad(linux_loader::loader::Error),

    /// Cannot load the initramfs in memory
    InitramfsLoad,

    /// Cannot load the command line in memory
    LoadCmdLine(linux_loader::loader::Error),

    /// Cannot modify the command line
    CmdLineInsertStr(linux_loader::cmdline::Error),

    /// Cannot convert command line into CString
    CmdLineCString(std::ffi::NulError),

    PoisonedState,

    /// Write to the console failed.
    Console(vmm_sys_util::errno::Error),

    /// Cannot setup terminal in raw mode.
    SetTerminalRaw(vmm_sys_util::errno::Error),

    /// Cannot setup terminal in canonical mode.
    SetTerminalCanon(vmm_sys_util::errno::Error),

    /// Failed parsing network parameters
    ParseNetworkParameters,

    /// Memory is overflow
    MemOverflow,

    /// Failed to allocate the IOAPIC memory range.
    IoapicRangeAllocation,

    /// Cannot spawn a signal handler thread
    SignalHandlerSpawn(io::Error),

    /// Failed to join on vCPU threads
    ThreadCleanup(std::boxed::Box<dyn std::any::Any + std::marker::Send>),

    /// Failed to create a new KVM instance
    KvmNew(kvm_ioctls::Error),

    /// VM is not created
    VmNotCreated,

    /// VM is already created
    VmAlreadyCreated,

    /// VM is not running
    VmNotRunning,

    /// Cannot clone EventFd.
    EventFdClone(io::Error),

    /// Capability missing
    CapabilityMissing(Cap),


    /// No PCI support
    NoPciSupport,

    /// Eventfd write error
    EventfdError(std::io::Error),

    /// Cannot convert source URL from Path into &str
    RestoreSourceUrlPathToStr,
}
pub type Result<T> = result::Result<T, Error>;
pub type ResultOps<T> = std::result::Result<T, errno::Error>;
pub trait VmFdOps: Send + Sync {
    fn set_tss_address(&self, offset: usize) -> ResultOps<()>;
    fn create_irq_chip(&self) -> ResultOps<()>;
    fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()>;
    fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> ResultOps<()>;
    fn create_vcpu(&self, id: u8) -> ResultOps<Arc< dyn VcpuOps>>;
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
        let vcpu = KvmVcpuId{ fd : vc };
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

pub fn get_default_vmfd() -> Result<Arc<dyn VmFdOps>> {
    KvmVmFd::new()
}
impl KvmVmFd {
    fn new()-> Result<Arc<dyn VmFdOps>> {
        let kvm = Kvm::new().map_err(Error::KvmNew)?;

        // Check required capabilities:
        if !kvm.check_extension(Cap::SignalMsi) {
            return Err(Error::CapabilityMissing(Cap::SignalMsi));
        }

        if !kvm.check_extension(Cap::TscDeadlineTimer) {
            return Err(Error::CapabilityMissing(Cap::SignalMsi));
        }

        if !kvm.check_extension(Cap::SplitIrqchip) {
            return Err(Error::CapabilityMissing(Cap::SplitIrqchip));
        }

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
        let cpuid: CpuId = patch_cpuid(&kvm).unwrap();

        Ok(Arc::new(KvmVmFd {
            fd: fd,
            cpuid: cpuid,
        }))
    }
}

pub trait VcpuOps: Send + Sync {
    fn get_regs(&self) -> ResultOps<kvm_regs>;
    fn set_regs(&self, regs: &kvm_regs) -> ResultOps<()>;
    fn get_sregs(&self) -> ResultOps<kvm_sregs>;
    fn set_sregs(&self, sregs: &kvm_sregs) -> ResultOps<()>;
    fn get_fpu(&self) -> ResultOps<kvm_fpu>;
    fn set_fpu(&self, fpu: &kvm_fpu) -> ResultOps<()>;
    fn set_cpuid2(&self, cpuid: &CpuId) -> ResultOps<()>;
    fn get_cpuid2(&self, num_entries: usize) -> ResultOps<CpuId>;
    fn get_lapic(&self) -> ResultOps<kvm_lapic_state>;
    fn set_lapic(&self, klapic: &kvm_lapic_state) -> ResultOps<()>;
    fn get_msrs(&self, msrs: &mut Msrs) -> ResultOps<usize>;
    fn set_msrs(&self, msrs: &Msrs) -> ResultOps<usize>;
    fn get_mp_state(&self) -> ResultOps<kvm_mp_state>;
    fn set_mp_state(&self, mp_state: kvm_mp_state) -> ResultOps<()>;
    fn get_xsave(&self) -> ResultOps<kvm_xsave>;
    fn set_xsave(&self, xsave: &kvm_xsave) -> ResultOps<()>;
    fn get_xcrs(&self) -> ResultOps<kvm_xcrs>;
    fn set_xcrs(&self, xcrs: &kvm_xcrs) -> ResultOps<()>;
    fn run(&self) -> ResultOps<VcpuExit>;
    fn get_vcpu_events(&self) -> ResultOps<kvm_vcpu_events>;
}
pub struct KvmVcpuId {
    fd: VcpuFd,
}
impl VcpuOps for KvmVcpuId {
    fn get_regs(&self) -> ResultOps<kvm_regs> {
        self.fd.get_regs()
    }
    fn set_regs(&self, regs: &kvm_regs) -> ResultOps<()> {
        self.fd.set_regs(regs)
    }
    fn get_sregs(&self) -> ResultOps<kvm_sregs> {
        self.fd.get_sregs()
    }
    fn set_sregs(&self, sregs: &kvm_sregs) -> ResultOps<()> {
        self.fd.set_sregs(sregs)
    }
    fn get_fpu(&self) -> ResultOps<kvm_fpu> {
        self.fd.get_fpu()
    }
    fn set_fpu(&self, fpu: &kvm_fpu) -> ResultOps<()> {
        self.fd.set_fpu(fpu)
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
    fn get_mp_state(&self) -> ResultOps<kvm_mp_state> {
        self.fd.get_mp_state()
    }
    fn set_mp_state(&self, mp_state: kvm_mp_state) -> ResultOps<()> {
        self.fd.set_mp_state(mp_state)
    }
    fn get_xsave(&self) -> ResultOps<kvm_xsave> {
        self.fd.get_xsave()
    }
    fn set_xsave(&self, xsave: &kvm_xsave) -> ResultOps<()>{
        self.fd.set_xsave(xsave)
    }
    fn get_xcrs(&self) -> ResultOps<kvm_xcrs> {
        self.fd.get_xcrs()
    }
    fn set_xcrs(&self, xcrs: &kvm_xcrs) -> ResultOps<()>{
        self.fd.set_xcrs(xcrs)
    }
    fn run(&self) -> ResultOps<VcpuExit> {
        self.fd.run()
    }
    fn get_vcpu_events(&self) -> ResultOps<kvm_vcpu_events> {
        self.fd.get_vcpu_events()
    }
}
