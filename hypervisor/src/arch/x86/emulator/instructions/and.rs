//
// Copyright © 2025 Microsoft
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(non_camel_case_types)]

//
// AND - Logical AND
//

use crate::arch::x86::emulator::instructions::*;

macro_rules! and_rm_r {
    ($bound:ty) => {
        fn emulate(
            &self,
            insn: &Instruction,
            state: &mut T,
            platform: &mut dyn PlatformEmulator<CpuState = T>,
        ) -> Result<(), EmulationError<Exception>> {
            let src_reg_value = get_op(&insn, 1, std::mem::size_of::<$bound>(), state, platform)
                .map_err(EmulationError::PlatformEmulationError)?;

            let dst_value = get_op(&insn, 0, std::mem::size_of::<$bound>(), state, platform)
                .map_err(EmulationError::PlatformEmulationError)?;

            let result = src_reg_value & dst_value;

            set_op(
                &insn,
                0,
                std::mem::size_of::<$bound>(),
                state,
                platform,
                result,
            )
            .map_err(EmulationError::PlatformEmulationError)?;

            Ok(())
        }
    };
}

macro_rules! and_rm_imm {
    ($imm:ty, $bound:ty) => {
        fn emulate(
            &self,
            insn: &Instruction,
            state: &mut T,
            platform: &mut dyn PlatformEmulator<CpuState = T>,
        ) -> Result<(), EmulationError<Exception>> {
            let imm_value = get_op(&insn, 1, std::mem::size_of::<$imm>(), state, platform)
                .map_err(EmulationError::PlatformEmulationError)?;

            let dst_value = get_op(&insn, 0, std::mem::size_of::<$bound>(), state, platform)
                .map_err(EmulationError::PlatformEmulationError)?;

            let result = imm_value & dst_value;

            set_op(
                &insn,
                0,
                std::mem::size_of::<$bound>(),
                state,
                platform,
                result,
            )
            .map_err(EmulationError::PlatformEmulationError)?;

            Ok(())
        }
    };
}

pub struct And_rm8_r8;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm8_r8 {
    and_rm_r!(u8);
}

pub struct And_rm16_r16;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm16_r16 {
    and_rm_r!(u16);
}

pub struct And_rm32_r32;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm32_r32 {
    and_rm_r!(u32);
}

pub struct And_rm64_r64;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm64_r64 {
    and_rm_r!(u64);
}

pub struct And_rm8_imm8;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm8_imm8 {
    and_rm_imm!(u8, u8);
}

pub struct And_rm16_imm16;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm16_imm16 {
    and_rm_imm!(u16, u16);
}

pub struct And_rm32_imm32;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm32_imm32 {
    and_rm_imm!(u32, u32);
}

pub struct And_rm64_imm32;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm64_imm32 {
    and_rm_imm!(u32, u64);
}

pub struct And_rm16_imm8;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm16_imm8 {
    and_rm_imm!(u8, u16);
}

pub struct And_rm32_imm8;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm32_imm8 {
    and_rm_imm!(u8, u32);
}

pub struct And_rm64_imm8;
impl<T: CpuStateManager> InstructionHandler<T> for And_rm64_imm8 {
    and_rm_imm!(u8, u64);
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::arch::x86::emulator::mock_vmm::*;

    #[test]
    // and byte ptr [rax+1h], sil
    fn test_and_rm8_r8() {
        let rax = 0;
        let insn = [0x40, 0x20, 0x70, 0x01];
        let cpu_id = 0;
        let ip: u64 = 0x1000;
        let sil = 0xaa;
        let memory = [0x0, 0xff];

        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::SIL, sil), (Register::RAX, rax)],
            Some((0, &memory)),
        );

        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let mut out: [u8; 1] = [0; 1];
        vmm.read_memory(rax + 1, &mut out).unwrap();
        assert_eq!(u8::from_le_bytes(out), 0xaa);
    }

    #[test]
    // and byte ptr [rax+1h], 0x0f
    fn test_and_rm8_imm8() {
        let rax = 0;
        let insn = [0x80, 0x60, 0x01, 0x0f];
        let cpu_id = 0;
        let ip: u64 = 0x1000;
        let memory = [0x0, 0xff];

        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::RAX, rax)],
            Some((0, &memory)),
        );

        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let mut out: [u8; 1] = [0; 1];
        vmm.read_memory(rax + 1, &mut out).unwrap();
        assert_eq!(u8::from_le_bytes(out), 0x0f);
    }

    #[test]
    // and dword ptr [rax], ecx
    fn test_and_rm32_r32() {
        let rax = 0;
        let insn = [0x21, 0x08];
        let cpu_id = 0;
        let ip: u64 = 0x1000;
        let ecx: u64 = 0x0f0f0f0f;
        let memory = [0xff, 0xff, 0xff, 0xff];

        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::ECX, ecx), (Register::RAX, rax)],
            Some((0, &memory)),
        );

        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let mut out: [u8; 4] = [0; 4];
        vmm.read_memory(rax, &mut out).unwrap();
        assert_eq!(u32::from_le_bytes(out), 0x0f0f0f0f);
    }

    #[test]
    // and qword ptr [rax], rcx
    fn test_and_rm64_r64() {
        let rax = 0;
        let insn = [0x48, 0x21, 0x08];
        let cpu_id = 0;
        let ip: u64 = 0x1000;
        let rcx: u64 = 0x00ff00ff00ff00ff;
        let memory = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        let mut vmm = MockVmm::new(
            ip,
            vec![(Register::RCX, rcx), (Register::RAX, rax)],
            Some((0, &memory)),
        );

        vmm.emulate_first_insn(cpu_id, &insn).unwrap();

        let mut out: [u8; 8] = [0; 8];
        vmm.read_memory(rax, &mut out).unwrap();
        assert_eq!(u64::from_le_bytes(out), 0x00ff00ff00ff00ff);
    }
}
