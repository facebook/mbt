/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use anyhow::bail;
use sha2::Digest;
use sha2::Sha256;

use crate::client::BtClient;
use crate::types::ArtifactDetail;
use crate::types::ArtifactListItem;
use crate::types::CursorInfo;
use crate::types::PaginatedResponse;
use crate::types::PagingInfo;
use crate::types::ProofDetail;
use crate::types::ProofListItem;

pub(crate) struct MockClient;

/// Number of synthetic epochs for `eb-verify-namespace` mock data.
///
/// The mock generates `EB_EPOCH_COUNT` proofs at epochs 1..=EB_EPOCH_COUNT,
/// each pointing at a distinct fleet-key JSON artifact. The set of keys
/// varies per epoch to exercise all four `ChangeKind` variants
/// (Baseline, Added, Removed, RoleChanged) in the Phase 2 delta table.
const EB_EPOCH_COUNT: u64 = 5;

/// Encrypted-backup namespace for fleet keys (mocked).
const EB_NAMESPACE: &str = "meta.encrypted_backups.fleet_keys.v1";

/// Distinct base64-shaped key strings used in the synthetic mock fixtures.
/// They are intentionally long (>30 chars) so integration tests can verify
/// the `--key` flag renders the full key (vs. truncated form).
const KEY_A: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1aaaaaaaaaaaaaaa";
const KEY_B: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2bbbbbbbbbbbbbbb";
const KEY_C: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3ccccccccccccccc";
const KEY_D: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4dddddddddddddddd";

/// Returns the synthetic fleet key set for a given mock epoch.
///
/// The progression is hand-tuned to surface every `ChangeKind` variant
/// when the deltas are computed across consecutive epochs:
/// - Epoch 1: KEY_A [Login], KEY_B [Login, Register]              → baseline
/// - Epoch 2: KEY_A [Login, Register], KEY_B [Login, Register]    → RoleChanged on KEY_A
/// - Epoch 3: + KEY_C [Register]                                  → Added
/// - Epoch 4: drop KEY_B                                          → Removed
/// - Epoch 5: + KEY_D [Login]                                     → Added (again)
fn fleet_keys_for_epoch(epoch: u64) -> Vec<(&'static str, Vec<u32>)> {
    match epoch {
        1 => vec![(KEY_A, vec![1]), (KEY_B, vec![1, 2])],
        2 => vec![(KEY_A, vec![1, 2]), (KEY_B, vec![1, 2])],
        3 => vec![(KEY_A, vec![1, 2]), (KEY_B, vec![1, 2]), (KEY_C, vec![2])],
        4 => vec![(KEY_A, vec![1, 2]), (KEY_C, vec![2])],
        _ => vec![(KEY_A, vec![1, 2]), (KEY_C, vec![2]), (KEY_D, vec![1])],
    }
}

/// Renders fleet key data as the on-the-wire JSON consumed by
/// `eb-verify-namespace` Phase 2.
fn fleet_key_json(epoch: u64) -> String {
    let keys: Vec<_> = fleet_keys_for_epoch(epoch)
        .into_iter()
        .map(|(k, roles)| serde_json::json!({"key": k, "roles": roles}))
        .collect();
    serde_json::json!({"version": 1, "keys": keys}).to_string()
}

/// Computes the SHA256 of the given bytes as lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Stable proof ID for a synthetic eb-verify-namespace epoch.
fn eb_proof_id(epoch: u64) -> String {
    format!("proof-eb-{epoch}")
}

/// Stable artifact ID for a synthetic eb-verify-namespace epoch.
fn eb_artifact_id(epoch: u64) -> String {
    format!("artifact-eb-{epoch}")
}

/// Stable CDN URL for a synthetic eb-verify-namespace epoch. The mock uses
/// the URL as a routing key for `download_artifact`.
fn eb_cdn_url(epoch: u64) -> String {
    format!("mock://eb/epoch/{epoch}")
}

/// Builds a synthetic [`ProofDetail`] for a given mock epoch. Digest matches
/// the SHA256 of the corresponding fleet-key JSON, so digest verification
/// passes against `MockClient::download_artifact`.
fn eb_proof_detail(epoch: u64) -> ProofDetail {
    let json = fleet_key_json(epoch);
    let digest = sha256_hex(json.as_bytes());
    ProofDetail {
        id: eb_proof_id(epoch),
        namespace_name: EB_NAMESPACE.to_string(),
        epoch,
        signer: "CLOUDFLARE".to_string(),
        version: "ProtobufEd25519".to_string(),
        timestamp: epoch as i64,
        key_id: Some(212),
        signature: "c2lnbmF0dXJlLWJ5dGVzLWhlcmU=".to_string(),
        serialized_message: Some("c2VyaWFsaXplZC1tZXNzYWdlLWJ5dGVz".to_string()),
        meta_signature: Some("bWV0YS1zaWduYXR1cmUtYnl0ZXM=".to_string()),
        artifact_id: eb_artifact_id(epoch),
        digest: Some(digest),
    }
}

/// Synthetic proof list item for a given mock epoch — the projection of
/// [`eb_proof_detail`] used by `list_proofs`.
fn eb_proof_list_item(epoch: u64) -> ProofListItem {
    ProofListItem {
        id: eb_proof_id(epoch),
        epoch,
        signer: "CLOUDFLARE".to_string(),
        timestamp: epoch as i64,
        key_id: Some(212),
        version: "ProtobufEd25519".to_string(),
    }
}

impl BtClient for MockClient {
    fn list_proofs(
        &self,
        namespace: &str,
        limit: Option<u32>,
        _after: Option<&str>,
        before_epoch: Option<u64>,
    ) -> anyhow::Result<PaginatedResponse<ProofListItem>> {
        if namespace != EB_NAMESPACE {
            return Ok(PaginatedResponse {
                data: Vec::new(),
                paging: None,
            });
        }

        // Generate synthetic items at epochs EB_EPOCH_COUNT..=1 (newest first).
        let upper = before_epoch
            .map(|b| b.saturating_sub(1).min(EB_EPOCH_COUNT))
            .unwrap_or(EB_EPOCH_COUNT);

        let mut items: Vec<ProofListItem> = (1..=upper).rev().map(eb_proof_list_item).collect();

        if let Some(l) = limit {
            items.truncate(l as usize);
        }

        Ok(PaginatedResponse {
            data: items,
            paging: Some(PagingInfo {
                cursors: CursorInfo {
                    after: None,
                    before: None,
                },
            }),
        })
    }

    fn get_proof(&self, proof_id: &str) -> anyhow::Result<ProofDetail> {
        // Legacy fixture path: the integration tests for `proof`/`artifact`
        // commands assert against `proof-001-abc` / `artifact-001-xyz`.
        if proof_id == "proof-001-abc" {
            return Ok(serde_json::from_str(include_str!(
                "testdata/proof_detail.json"
            ))?);
        }

        if let Some(epoch_str) = proof_id.strip_prefix("proof-eb-") {
            if let Ok(epoch) = epoch_str.parse::<u64>() {
                if (1..=EB_EPOCH_COUNT).contains(&epoch) {
                    return Ok(eb_proof_detail(epoch));
                }
            }
        }

        bail!("proof not found: {}", proof_id);
    }

    fn get_proof_by_namespace_epoch(
        &self,
        namespace: &str,
        epoch: u64,
    ) -> anyhow::Result<ProofDetail> {
        let detail: ProofDetail = serde_json::from_str(include_str!("testdata/proof_detail.json"))?;
        if detail.namespace_name == namespace && detail.epoch == epoch {
            return Ok(detail);
        }
        if namespace == EB_NAMESPACE && (1..=EB_EPOCH_COUNT).contains(&epoch) {
            return Ok(eb_proof_detail(epoch));
        }
        bail!("proof not found for namespace={namespace} epoch={epoch}");
    }

    fn list_artifacts(
        &self,
        _proof_id: &str,
        _limit: Option<u32>,
        _after: Option<&str>,
    ) -> anyhow::Result<PaginatedResponse<ArtifactListItem>> {
        let response: PaginatedResponse<ArtifactListItem> =
            serde_json::from_str(include_str!("testdata/artifacts_list.json"))?;
        Ok(response)
    }

    fn get_artifact(&self, artifact_id: &str) -> anyhow::Result<ArtifactDetail> {
        if artifact_id == "artifact-001-xyz" {
            return Ok(serde_json::from_str(include_str!(
                "testdata/artifact_detail.json"
            ))?);
        }

        if let Some(epoch_str) = artifact_id.strip_prefix("artifact-eb-") {
            if let Ok(epoch) = epoch_str.parse::<u64>() {
                if (1..=EB_EPOCH_COUNT).contains(&epoch) {
                    let json = fleet_key_json(epoch);
                    let digest = sha256_hex(json.as_bytes());
                    return Ok(ArtifactDetail {
                        id: eb_artifact_id(epoch),
                        namespace_name: EB_NAMESPACE.to_string(),
                        digest,
                        digest_algorithm: "SHA256".to_string(),
                        additional_digests: Default::default(),
                        cdn_url: eb_cdn_url(epoch),
                    });
                }
            }
        }

        bail!("artifact not found: {}", artifact_id);
    }

    fn download_artifact(&self, cdn_url: &str) -> anyhow::Result<Vec<u8>> {
        if let Some(epoch_str) = cdn_url.strip_prefix("mock://eb/epoch/") {
            if let Ok(epoch) = epoch_str.parse::<u64>() {
                if (1..=EB_EPOCH_COUNT).contains(&epoch) {
                    return Ok(fleet_key_json(epoch).into_bytes());
                }
            }
        }
        Ok(include_bytes!("testdata/artifact_bytes.bin").to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_proofs_returns_valid_data() {
        let client = MockClient;
        let result = client
            .list_proofs("meta.encrypted_backups.fleet_keys.v1", None, None, None)
            .expect("list_proofs should succeed");

        // Expect EB_EPOCH_COUNT items, newest epoch first.
        assert_eq!(result.data.len(), EB_EPOCH_COUNT as usize);
        assert_eq!(result.data[0].epoch, EB_EPOCH_COUNT);
        assert_eq!(result.data[0].signer, "CLOUDFLARE");
        assert_eq!(result.data[0].version, "ProtobufEd25519");
    }

    #[test]
    fn test_list_proofs_respects_limit() {
        let client = MockClient;
        let result = client
            .list_proofs("meta.encrypted_backups.fleet_keys.v1", Some(2), None, None)
            .expect("list_proofs should succeed");
        assert_eq!(result.data.len(), 2);
    }

    #[test]
    fn test_list_proofs_respects_before_epoch() {
        let client = MockClient;
        let result = client
            .list_proofs("meta.encrypted_backups.fleet_keys.v1", None, None, Some(3))
            .expect("list_proofs should succeed");
        // before_epoch = 3 → epochs 2, 1
        assert_eq!(result.data.len(), 2);
        assert_eq!(result.data[0].epoch, 2);
        assert_eq!(result.data[1].epoch, 1);
    }

    #[test]
    fn test_get_proof_returns_detail() {
        let client = MockClient;
        let detail = client
            .get_proof("proof-001-abc")
            .expect("get_proof should succeed");

        assert_eq!(detail.id, "proof-001-abc");
        assert_eq!(
            detail.namespace_name,
            "meta.encrypted_backups.fleet_keys.v1"
        );
        assert_eq!(detail.epoch, 1709251200);
        assert_eq!(detail.signer, "CLOUDFLARE");
        assert_eq!(detail.version, "ProtobufEd25519");
        assert!(!detail.signature.is_empty(), "signature should be present");
        assert!(
            detail.serialized_message.is_some(),
            "serialized_message should be present"
        );
        assert!(
            detail.meta_signature.is_some(),
            "meta_signature should be present"
        );
        assert_eq!(detail.artifact_id, "artifact-001-xyz");
        assert!(detail.digest.is_some(), "digest should be present");
    }

    #[test]
    fn test_get_proof_eb_synthetic_digest_matches_artifact() {
        let client = MockClient;
        let detail = client.get_proof("proof-eb-1").expect("get_proof");
        let bytes = client
            .download_artifact("mock://eb/epoch/1")
            .expect("download_artifact");
        assert_eq!(detail.digest.unwrap(), sha256_hex(&bytes));
    }

    #[test]
    fn test_list_artifacts_returns_valid_data() {
        let client = MockClient;
        let result = client
            .list_artifacts("proof-001-abc", None, None)
            .expect("list_artifacts should succeed");

        assert_eq!(result.data.len(), 2, "should return 2 artifact items");
        assert_eq!(result.data[0].digest_algorithm, "SHA256");
        assert!(
            !result.data[0].digest.is_empty(),
            "digest should be present"
        );
    }

    #[test]
    fn test_get_artifact_returns_detail_with_cdn_url() {
        let client = MockClient;
        let detail = client
            .get_artifact("artifact-001-xyz")
            .expect("get_artifact should succeed");

        assert_eq!(detail.id, "artifact-001-xyz");
        assert_eq!(detail.cdn_url, "https://cdn.example.com/artifacts/12345");
        assert_eq!(detail.digest_algorithm, "SHA256");
    }

    #[test]
    fn test_download_artifact_returns_bytes() {
        let client = MockClient;
        let bytes = client
            .download_artifact("https://cdn.example.com/artifacts/12345")
            .expect("download_artifact should succeed");

        assert!(!bytes.is_empty(), "downloaded bytes should be non-empty");
    }

    #[test]
    fn test_fleet_keys_cover_all_change_kinds() {
        // Sanity-check: walking the synthetic epochs in order surfaces every
        // ChangeKind variant the Phase 2 table renders.
        use std::collections::BTreeMap;
        use std::collections::BTreeSet;

        let epochs: Vec<u64> = (1..=EB_EPOCH_COUNT).collect();
        let mut prev: Option<BTreeMap<&str, BTreeSet<u32>>> = None;
        let mut saw_added = false;
        let mut saw_removed = false;
        let mut saw_role_changed = false;

        for e in epochs {
            let curr: BTreeMap<&str, BTreeSet<u32>> = fleet_keys_for_epoch(e)
                .into_iter()
                .map(|(k, r)| (k, r.into_iter().collect()))
                .collect();
            if let Some(prev_map) = &prev {
                for (k, roles) in &curr {
                    match prev_map.get(k) {
                        None => saw_added = true,
                        Some(old) if old != roles => saw_role_changed = true,
                        _ => {}
                    }
                }
                for k in prev_map.keys() {
                    if !curr.contains_key(k) {
                        saw_removed = true;
                    }
                }
            }
            prev = Some(curr);
        }

        assert!(saw_added, "synthetic data must surface Added");
        assert!(saw_removed, "synthetic data must surface Removed");
        assert!(saw_role_changed, "synthetic data must surface RoleChanged");
    }
}
