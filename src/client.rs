/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

#![allow(dead_code)]

use crate::types::ArtifactDetail;
use crate::types::ArtifactListItem;
use crate::types::PaginatedResponse;
use crate::types::ProofDetail;
use crate::types::ProofListItem;

pub(crate) trait BtClient {
    fn list_proofs(
        &self,
        namespace: &str,
        limit: Option<u32>,
        after: Option<&str>,
        before_epoch: Option<u64>,
    ) -> anyhow::Result<PaginatedResponse<ProofListItem>>;

    fn get_proof(&self, proof_id: &str) -> anyhow::Result<ProofDetail>;

    fn get_proof_by_namespace_epoch(
        &self,
        namespace: &str,
        epoch: u64,
    ) -> anyhow::Result<ProofDetail>;

    fn list_artifacts(
        &self,
        proof_id: &str,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> anyhow::Result<PaginatedResponse<ArtifactListItem>>;

    fn get_artifact(&self, artifact_id: &str) -> anyhow::Result<ArtifactDetail>;

    fn download_artifact(&self, cdn_url: &str) -> anyhow::Result<Vec<u8>>;
}
