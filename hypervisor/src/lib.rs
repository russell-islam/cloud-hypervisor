// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
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

/// X86_64 related module
pub mod x86_64;

/// arm64 related module
pub mod aarch64;
/// Vm related module
pub mod vm;

/// Common for both x86 and aarch64
pub mod common;

/// CPU related module
mod cpu;

/// KVM implementation module
pub mod kvm;

pub use cpu::{HypervisorCpuError, Vcpu};
pub use hv::{Hypervisor, HypervisorError};
pub use vm::{HypervisorVmError, Vm};
extern crate thiserror;
