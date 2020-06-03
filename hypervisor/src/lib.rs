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
#[cfg(target_arch = "x86_64")]
/// X86_64 related module
pub mod x86_64;

/// Common for both x86 and aarch64
pub mod common;
/// CPU related module
mod cpu;
