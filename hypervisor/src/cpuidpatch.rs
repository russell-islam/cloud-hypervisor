// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Copyright © 2020, Microsft  Corporation
//
use kvm_bindings::CpuId;
use kvm_ioctls::*;
use std::result;
pub type Result<T> = result::Result<T, Error>;

// CPUID feature bits
#[cfg(target_arch = "x86_64")]
const TSC_DEADLINE_TIMER_ECX_BIT: u8 = 24; // tsc deadline timer ecx bit.
#[cfg(target_arch = "x86_64")]
const HYPERVISOR_ECX_BIT: u8 = 31; // Hypervisor ecx bit.

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum CpuidReg {
    EAX,
    EBX,
    ECX,
    EDX,
}
#[derive(Debug)]
pub enum Error {
    /// Cannot patch the CPU ID
    PatchCpuId(kvm_ioctls::Error),
}
pub struct CpuidPatch {
    pub function: u32,
    pub index: u32,
    pub flags_bit: Option<u8>,
    pub eax_bit: Option<u8>,
    pub ebx_bit: Option<u8>,
    pub ecx_bit: Option<u8>,
    pub edx_bit: Option<u8>,
}
pub fn patch_cpuid(kvm: &Kvm) -> Result<CpuId> {
    let mut cpuid_patches = Vec::new();

    // Patch tsc deadline timer bit
    cpuid_patches.push(CpuidPatch {
        function: 1,
        index: 0,
        flags_bit: None,
        eax_bit: None,
        ebx_bit: None,
        ecx_bit: Some(TSC_DEADLINE_TIMER_ECX_BIT),
        edx_bit: None,
    });

    // Patch hypervisor bit
    cpuid_patches.push(CpuidPatch {
        function: 1,
        index: 0,
        flags_bit: None,
        eax_bit: None,
        ebx_bit: None,
        ecx_bit: Some(HYPERVISOR_ECX_BIT),
        edx_bit: None,
    });

    // Supported CPUID
    let mut cpuid = kvm
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .map_err(Error::PatchCpuId)?;

    CpuidPatch::patch_cpuid(&mut cpuid, cpuid_patches);

    Ok(cpuid)
}
impl CpuidPatch {
    pub fn set_cpuid_reg(
        cpuid: &mut CpuId,
        function: u32,
        index: Option<u32>,
        reg: CpuidReg,
        value: u32,
    ) {
        let entries = cpuid.as_mut_slice();

        for entry in entries.iter_mut() {
            if entry.function == function && (index == None || index.unwrap() == entry.index) {
                match reg {
                    CpuidReg::EAX => {
                        entry.eax = value;
                    }
                    CpuidReg::EBX => {
                        entry.ebx = value;
                    }
                    CpuidReg::ECX => {
                        entry.ecx = value;
                    }
                    CpuidReg::EDX => {
                        entry.edx = value;
                    }
                }
            }
        }
    }

    pub fn patch_cpuid(cpuid: &mut CpuId, patches: Vec<CpuidPatch>) {
        let entries = cpuid.as_mut_slice();

        for entry in entries.iter_mut() {
            for patch in patches.iter() {
                if entry.function == patch.function && entry.index == patch.index {
                    if let Some(flags_bit) = patch.flags_bit {
                        entry.flags |= 1 << flags_bit;
                    }
                    if let Some(eax_bit) = patch.eax_bit {
                        entry.eax |= 1 << eax_bit;
                    }
                    if let Some(ebx_bit) = patch.ebx_bit {
                        entry.ebx |= 1 << ebx_bit;
                    }
                    if let Some(ecx_bit) = patch.ecx_bit {
                        entry.ecx |= 1 << ecx_bit;
                    }
                    if let Some(edx_bit) = patch.edx_bit {
                        entry.edx |= 1 << edx_bit;
                    }
                }
            }
        }
    }
}
