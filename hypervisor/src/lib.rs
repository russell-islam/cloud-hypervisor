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
pub mod hypervisor;

/// Vm related module
pub mod vm;

/// CPU related module
mod cpu;

/// KVM implementation module
pub mod kvm;

/// x86 definitions
#[cfg(target_arch = "x86_64")]
pub mod x86;

pub use cpu::{HypervisorCpuError, Vcpu};
pub use hypervisor::{Hypervisor, HypervisorError};

pub use kvm::*;
pub use vm::{HypervisorVmError, Vm};

extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate thiserror;
