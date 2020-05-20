// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020, Microsft  Corporation
//
pub mod cpuidpatch;
pub mod kvm;
pub mod params;
pub mod wrapper;

pub use self::wrapper::get_hypervisor;

pub use self::wrapper::{HyperVisorType, Hypervisor, VcpuOps, VmFdOps};
