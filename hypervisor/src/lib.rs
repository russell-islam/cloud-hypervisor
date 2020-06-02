// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
//

//! A generic abstraction around hypervisor functionality
//!
//! This crate offers a trait abstraction for underlying hypervisors
//!
//! # Platform support
//!
//! - x86_64
//! - arm64
//!

/// Module defining for hypervisor trait
pub mod hv;

#[cfg(target_arch = "x86_64")]
/// X86_64 related module
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
/// arm64 related module
pub mod aarch64;


/// Common for both x86 and aarch64
pub mod common;
/// CPU related module
mod cpu;
/// Vm related module
pub mod vm;

/// KVM implementation module
pub mod kvm;

pub use cpu::{HypervisorCpuError, Vcpu};
pub use hv::{Hypervisor, HypervisorError};

//KVM related exports
pub use common::DeviceFd;
pub use vm::{HypervisorVmError, Vm};
pub use kvm::*;
#[cfg(target_arch = "x86_64")]
pub use x86_64::CpuId;
extern crate arch_gen;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate thiserror;
