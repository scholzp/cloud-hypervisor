// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Launch support for confidential VMs (CVMs).

use igvm::IgvmFile;

use crate::igvm::igvm_loader;
use crate::vm_config::CvmType;

pub(crate) mod sev_snp;

impl CvmType {
    pub(crate) fn into_cvm_config(self, igvm: Option<&IgvmFile>) -> hypervisor::CvmConfig {
        match self {
            CvmType::SevSnp => hypervisor::CvmConfig::SevSnp {
                vmsa_features: igvm.map_or(0, igvm_loader::extract_sev_features),
            },
        }
    }
}
