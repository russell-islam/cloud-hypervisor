// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsoft  Corporation
//
// Copyright 2018-2019 CrowdStrike, Inc.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::vm::Vm;
#[cfg(target_arch = "x86_64")]
use crate::x86_64::{Cap, CpuId};
use std::sync::Arc;

use thiserror::Error;

#[derive(Error, Debug)]
///
///
pub enum HypervisorError {
    ///
    /// Vm creation failure
    ///
    #[error("Failed to create kvm: {0}")]
    KvmNew(#[source] anyhow::Error),
    ///
    /// Vm creation failure
    ///
    #[error("Failed to create Vm: {0}")]
    VmCreate(#[source] anyhow::Error),
    ///
    /// Vm setup failure
    ///
    #[error("Failed to setup Vm: {0}")]
    VmSetup(#[source] anyhow::Error),
    ///
    /// API version error
    ///
    #[error("Failed to get API Version: {0}")]
    GetApiVersion(#[source] anyhow::Error),
    ///
    /// Vcpu mmap error
    ///
    #[error("Failed to get Vcpu Mmap: {0}")]
    GetVcpuMmap(#[source] anyhow::Error),
    ///
    /// Max Vcpu error
    ///
    #[error("Failed to get number of max vcpus: {0}")]
    GetMaxVcpu(#[source] anyhow::Error),
    ///
    /// Recommended Vcpu error
    ///
    #[error("Failed to get number of max vcpus: {0}")]
    GetNrVcpus(#[source] anyhow::Error),
    ///
    /// CpuId error
    ///
    #[error("Failed to get number of max vcpus: {0}")]
    GetCpuId(#[source] anyhow::Error),
}

///
/// Result type for returning from a function
///
pub type Result<T> = std::result::Result<T, HypervisorError>;

///
/// Trait to represent a Hypervisor
///
/// This crate provides a hypervisor-agnostic interfaces
///
pub trait Hypervisor: Send + Sync {
    ///
    /// Create a Vm using the underlying hypervisor
    /// Return a hypervisor-agnostic Vm trait object
    ///
    fn create_vm(&self) -> Result<Arc<dyn Vm>>;
    ///
    /// Get the API version of the hypervisor
    ///
    fn get_api_version(&self) -> i32;
    ///
    /// Returns the size of the memory mapping required to use the vcpu's structures
    ///
    fn get_vcpu_mmap_size(&self) -> Result<usize>;
    ///
    /// Gets the recommended maximum number of VCPUs per VM.
    ///
    fn get_max_vcpus(&self) -> Result<usize>;
    ///
    /// Gets the recommended number of VCPUs per VM.
    ///
    fn get_nr_vcpus(&self) -> Result<usize>;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Checks if a particular `Cap` is available.
    ///
    fn check_extension(&self, c: Cap) -> bool;
    #[cfg(target_arch = "x86_64")]
    ///
    /// Get the supported CpuID
    ///
    fn get_cpuid(&self) -> Result<CpuId>;
}
