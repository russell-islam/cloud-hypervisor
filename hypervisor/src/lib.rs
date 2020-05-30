// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
//
#![allow(unused)]
#![deny(missing_docs)]
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
