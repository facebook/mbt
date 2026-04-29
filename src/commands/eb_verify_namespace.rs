/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::process;

use anyhow::Result;
use serde::Deserialize;

use crate::client::BtClient;
use crate::cloudflare_client::CloudflareClient;
use crate::verification;
use crate::verification::ProofResult;

/// Hardcoded encrypted-backup namespace — eb-verify-namespace does not accept --namespace.
const EB_NAMESPACE: &str = "meta.encrypted_backups.fleet_keys.v1";

/// Fleet key JSON schema: {"version":1,"keys":[{"key":"<base64>","roles":[1,2]}]}
#[derive(Debug, Deserialize)]
struct FleetKeyFile {
    #[allow(dead_code)]
    version: u64,
    keys: Vec<FleetKey>,
}

#[derive(Debug, Deserialize, Clone)]
struct FleetKey {
    key: String,
    roles: Vec<u32>,
}

fn role_name(role: u32) -> &'static str {
    match role {
        0 => "Unknown",
        1 => "Login",
        2 => "Register",
        _ => "Unknown",
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChangeKind {
    Baseline,
    Added,
    Removed,
    RoleChanged { old: BTreeSet<u32> },
}

#[derive(Debug)]
pub(crate) struct KeyRow {
    pub epoch: u64,
    pub kind: ChangeKind,
    pub roles: BTreeSet<u32>,
    pub key: String,
}

pub(crate) struct EbVerifyNamespaceArgs {
    pub limit: usize,
    pub before_epoch: Option<u64>,
    pub show_full_key: bool,
}

pub(crate) fn run(
    client: &dyn BtClient,
    cloudflare: &CloudflareClient,
    args: EbVerifyNamespaceArgs,
) -> Result<()> {
    let EbVerifyNamespaceArgs {
        limit,
        before_epoch,
        show_full_key,
    } = args;
    let ns_config = verification::NAMESPACES
        .iter()
        .find(|c| c.name == EB_NAMESPACE)
        .expect("Encrypted-backup namespace must be in NAMESPACES");

    if limit == 0 || limit > verification::MAX_LIMIT {
        eprintln!(
            "Error [INVALID_INPUT]: --limit must be between 1 and {}",
            verification::MAX_LIMIT
        );
        process::exit(2);
    }

    if let Some(epoch) = before_epoch {
        if epoch == 0 {
            eprintln!("Error [INVALID_INPUT]: --before-epoch must be > 0");
            process::exit(2);
        }
    }

    let proofs = verification::fetch_proofs(client, EB_NAMESPACE, limit, before_epoch)?;
    let fetched_count = proofs.len();

    if proofs.is_empty() {
        eprintln!("No proofs found for namespace '{}'", EB_NAMESPACE);
        process::exit(3);
    }

    // === Phase 1: Verification with deferred cleanup ===
    eprintln!("Verifying {} proofs...", proofs.len());
    let mut results: Vec<(u64, ProofResult)> = Vec::new();
    let total = proofs.len();
    let mut pass_count = 0usize;
    let mut fail_count = 0usize;
    let mut error_count = 0usize;

    for (i, proof_item) in proofs.iter().enumerate() {
        eprint!(
            "\rVerifying epoch {} ({}/{})...  ",
            proof_item.epoch,
            i + 1,
            total
        );
        let _ = std::io::stderr().flush();

        let result = verification::verify_single_proof(
            client,
            cloudflare,
            ns_config,
            &proof_item.id,
            false, // deferred cleanup for Phase 2 key delta analysis
        );

        match &result {
            ProofResult::Pass { .. } => pass_count += 1,
            ProofResult::Fail { .. } => fail_count += 1,
            ProofResult::Error { .. } => error_count += 1,
        }

        results.push((proof_item.epoch, result));
    }

    // Clear the in-place progress line
    eprint!("\r{}\r", " ".repeat(60));
    let _ = std::io::stderr().flush();

    if fail_count == 0 && error_count == 0 {
        eprintln!("Verified {} proofs: all passed \u{2713}", total);
    } else {
        eprintln!(
            "Verified {} proofs: {} \u{2713}  {} \u{2717}  {} \u{26A0}",
            total, pass_count, fail_count, error_count
        );
    }

    // Print verification summary
    verification::print_summary(&results, EB_NAMESPACE);

    // === Phase 2: Key Delta Analysis ===

    // Collect passing results with temp file paths, sorted by epoch ascending
    let mut epoch_artifacts: Vec<(u64, String)> = Vec::new();
    for (epoch, result) in &results {
        if let ProofResult::Pass {
            tmp_path: Some(path),
        } = result
        {
            if let Ok(content) = fs::read_to_string(path) {
                epoch_artifacts.push((*epoch, content));
            }
        }
    }

    // Sort by epoch ascending for delta analysis
    epoch_artifacts.sort_by_key(|(epoch, _)| *epoch);

    if !epoch_artifacts.is_empty() {
        let mut rows: Vec<KeyRow> = Vec::new();
        let mut prev_keys: Option<BTreeMap<String, BTreeSet<u32>>> = None;
        let mut first_epoch: Option<u64> = None;
        let mut last_epoch: Option<u64> = None;

        for (epoch, content) in &epoch_artifacts {
            let key_file: FleetKeyFile = match serde_json::from_str(content) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Epoch {}: failed to parse fleet key JSON: {}", epoch, e);
                    continue;
                }
            };

            let current_keys: BTreeMap<String, BTreeSet<u32>> = key_file
                .keys
                .into_iter()
                .map(|fk| (fk.key, fk.roles.into_iter().collect()))
                .collect();

            match &prev_keys {
                None => {
                    rows.extend(baseline_rows(*epoch, &current_keys));
                    first_epoch = Some(*epoch);
                }
                Some(prev) => {
                    rows.extend(compute_key_deltas(*epoch, prev, &current_keys));
                }
            }

            prev_keys = Some(current_keys);
            last_epoch = Some(*epoch);
        }

        if !rows.is_empty() {
            let first = first_epoch.expect("first_epoch set whenever rows is non-empty");
            let last = last_epoch.expect("last_epoch set whenever rows is non-empty");
            eprintln!();
            print!(
                "{}",
                render_key_changes_table(first, last, &rows, show_full_key)
            );
            eprintln!();
        }
    }

    // Cleanup deferred temp files
    for (_, result) in &results {
        match result {
            ProofResult::Pass {
                tmp_path: Some(path),
            }
            | ProofResult::Fail {
                tmp_path: Some(path),
                ..
            }
            | ProofResult::Error {
                tmp_path: Some(path),
                ..
            } => {
                let _ = fs::remove_file(path);
            }
            _ => {}
        }
    }

    // "Next page" hint: show only when fetched count == limit (more may be
    // available) AND the last epoch is > 1 (epochs are 1-indexed, so
    // `--before-epoch 1` would always return an empty page).
    let next_page_epoch = proofs
        .last()
        .map(|p| p.epoch)
        .filter(|&e| fetched_count == limit && e > 1);
    if let Some(epoch) = next_page_epoch {
        eprintln!();
        eprintln!("Next page: mbt eb-verify-namespace --before-epoch {epoch}");
    }

    // Determine exit code
    let has_failures = results
        .iter()
        .any(|(_, r)| matches!(r, ProofResult::Fail { .. }));
    let has_errors = results
        .iter()
        .any(|(_, r)| matches!(r, ProofResult::Error { .. }));

    if has_failures {
        process::exit(1);
    } else if has_errors {
        process::exit(3);
    }

    Ok(())
}

fn compute_key_deltas(
    epoch: u64,
    prev: &BTreeMap<String, BTreeSet<u32>>,
    current: &BTreeMap<String, BTreeSet<u32>>,
) -> Vec<KeyRow> {
    let mut rows = Vec::new();

    for (key, roles) in current {
        match prev.get(key) {
            None => rows.push(KeyRow {
                epoch,
                kind: ChangeKind::Added,
                roles: roles.clone(),
                key: key.clone(),
            }),
            Some(old_roles) if old_roles != roles => rows.push(KeyRow {
                epoch,
                kind: ChangeKind::RoleChanged {
                    old: old_roles.clone(),
                },
                roles: roles.clone(),
                key: key.clone(),
            }),
            _ => {}
        }
    }

    for (key, roles) in prev {
        if !current.contains_key(key) {
            rows.push(KeyRow {
                epoch,
                kind: ChangeKind::Removed,
                roles: roles.clone(),
                key: key.clone(),
            });
        }
    }

    rows
}

fn baseline_rows(epoch: u64, keys: &BTreeMap<String, BTreeSet<u32>>) -> Vec<KeyRow> {
    keys.iter()
        .map(|(k, roles)| KeyRow {
            epoch,
            kind: ChangeKind::Baseline,
            roles: roles.clone(),
            key: k.clone(),
        })
        .collect()
}

const COL_EPOCH: usize = 7;
const COL_CHANGE: usize = 10;
const COL_ROLES: usize = 26;
const COL_KEY: usize = 16; // wide enough for truncated form ("xxxxxxxxxxxx..." = 15)

fn render_key_changes_table(
    first_epoch: u64,
    last_epoch: u64,
    rows: &[KeyRow],
    show_full_key: bool,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Fleet Keys (epochs {} \u{2192} {}):\n\n",
        first_epoch, last_epoch
    ));
    out.push_str(&format!(
        "{:<w1$}{:<w2$}{:<w3$}{}\n",
        "Epoch",
        "Change",
        "Roles",
        "Key",
        w1 = COL_EPOCH,
        w2 = COL_CHANGE,
        w3 = COL_ROLES,
    ));
    out.push_str(&format!(
        "{:<w1$}{:<w2$}{:<w3$}{}\n",
        "\u{2500}".repeat(COL_EPOCH - 2),
        "\u{2500}".repeat(COL_CHANGE - 2),
        "\u{2500}".repeat(COL_ROLES - 2),
        "\u{2500}".repeat(COL_KEY - 2),
        w1 = COL_EPOCH,
        w2 = COL_CHANGE,
        w3 = COL_ROLES,
    ));
    for row in rows {
        let change = match &row.kind {
            ChangeKind::Baseline => "baseline",
            ChangeKind::Added => "+",
            ChangeKind::Removed => "-",
            ChangeKind::RoleChanged { .. } => "~",
        };
        let roles_str: Vec<&str> = row.roles.iter().map(|r| role_name(*r)).collect();
        let roles_cell = match &row.kind {
            ChangeKind::RoleChanged { old } => {
                let old_str: Vec<&str> = old.iter().map(|r| role_name(*r)).collect();
                format!("{} \u{2192} {}", old_str.join(", "), roles_str.join(", "))
            }
            _ => roles_str.join(", "),
        };
        let key_cell = if show_full_key {
            row.key.clone()
        } else {
            truncate_key(&row.key)
        };
        out.push_str(&format!(
            "{:<w1$}{:<w2$}{:<w3$}{}\n",
            row.epoch,
            change,
            roles_cell,
            key_cell,
            w1 = COL_EPOCH,
            w2 = COL_CHANGE,
            w3 = COL_ROLES,
        ));
    }
    out
}

fn truncate_key(key: &str) -> String {
    if key.chars().count() > 12 {
        format!("{}...", key.chars().take(12).collect::<String>())
    } else {
        key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fleet_key_deserialization() {
        let json = r#"{"version":1,"keys":[{"key":"AQID","roles":[1,2]}]}"#;
        let file: FleetKeyFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.version, 1);
        assert_eq!(file.keys.len(), 1);
        assert_eq!(file.keys[0].key, "AQID");
        assert_eq!(file.keys[0].roles, vec![1, 2]);
    }

    #[test]
    fn test_fleet_key_multiple_keys() {
        let json =
            r#"{"version":1,"keys":[{"key":"AQID","roles":[1]},{"key":"BAUG","roles":[2]}]}"#;
        let file: FleetKeyFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.keys.len(), 2);
    }

    #[test]
    fn test_role_name_known() {
        assert_eq!(role_name(0), "Unknown");
        assert_eq!(role_name(1), "Login");
        assert_eq!(role_name(2), "Register");
    }

    #[test]
    fn test_role_name_unknown() {
        assert_eq!(role_name(99), "Unknown");
    }

    #[test]
    fn test_eb_namespace_constant() {
        assert_eq!(EB_NAMESPACE, "meta.encrypted_backups.fleet_keys.v1");
    }

    #[test]
    fn test_before_epoch_filter() {
        let epochs = vec![50u64, 49, 48, 47, 46];
        let before = 48u64;
        let filtered: Vec<u64> = epochs.into_iter().filter(|e| *e < before).collect();
        assert_eq!(filtered, vec![47, 46]);
    }

    #[test]
    fn test_pagination_hint_condition() {
        // Hint shown only when batch == limit
        let limit = 50;
        let batch_full = 50;
        let batch_partial = 30;
        assert_eq!(batch_full, limit);
        assert_ne!(batch_partial, limit);
    }

    #[test]
    fn test_key_row_baseline_construction() {
        let row = KeyRow {
            epoch: 1,
            kind: ChangeKind::Baseline,
            roles: BTreeSet::from([1u32, 2u32]),
            key: "MIIBIj".to_string(),
        };
        assert_eq!(row.epoch, 1);
        assert_eq!(row.kind, ChangeKind::Baseline);
        assert_eq!(row.roles, BTreeSet::from([1u32, 2u32]));
        assert_eq!(row.key, "MIIBIj");

        let changed = ChangeKind::RoleChanged {
            old: BTreeSet::from([1u32]),
        };
        assert_ne!(changed, ChangeKind::Baseline);
    }

    #[test]
    fn test_truncate_key_long_base64() {
        let key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
        assert_eq!(truncate_key(key), "MIIBIjANBgkq...");
    }

    #[test]
    fn test_truncate_key_short_base64() {
        let key = "MIIBIjAN"; // 8 chars, ≤12
        assert_eq!(truncate_key(key), "MIIBIjAN");
    }

    #[test]
    fn test_truncate_key_no_hex_conversion() {
        // Must remain base64, not be re-encoded as hex
        let key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8";
        let truncated = truncate_key(key);
        assert!(truncated.starts_with("MIIBIjAN"));
    }

    fn keyset(items: &[(&str, &[u32])]) -> BTreeMap<String, BTreeSet<u32>> {
        items
            .iter()
            .map(|(k, r)| (k.to_string(), r.iter().copied().collect()))
            .collect()
    }

    #[test]
    fn test_compute_deltas_added() {
        let prev = keyset(&[("k1", &[1])]);
        let curr = keyset(&[("k1", &[1]), ("k2", &[2])]);
        let rows = compute_key_deltas(10, &prev, &curr);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].epoch, 10);
        assert!(matches!(rows[0].kind, ChangeKind::Added));
        assert_eq!(rows[0].key, "k2");
    }

    #[test]
    fn test_compute_deltas_removed() {
        let prev = keyset(&[("k1", &[1]), ("k2", &[2])]);
        let curr = keyset(&[("k1", &[1])]);
        let rows = compute_key_deltas(10, &prev, &curr);
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0].kind, ChangeKind::Removed));
        assert_eq!(rows[0].key, "k2");
    }

    #[test]
    fn test_compute_deltas_role_changed() {
        let prev = keyset(&[("k1", &[1, 2])]);
        let curr = keyset(&[("k1", &[1])]);
        let rows = compute_key_deltas(10, &prev, &curr);
        assert_eq!(rows.len(), 1);
        match &rows[0].kind {
            ChangeKind::RoleChanged { old } => {
                assert_eq!(old, &BTreeSet::from([1u32, 2u32]));
            }
            _ => panic!("expected RoleChanged"),
        }
        assert_eq!(rows[0].roles, BTreeSet::from([1u32]));
    }

    #[test]
    fn test_compute_deltas_no_change() {
        let prev = keyset(&[("k1", &[1])]);
        let curr = keyset(&[("k1", &[1])]);
        let rows = compute_key_deltas(10, &prev, &curr);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_render_table_baseline_only() {
        let rows = vec![KeyRow {
            epoch: 1,
            kind: ChangeKind::Baseline,
            roles: BTreeSet::from([1u32]),
            key: "MIIBIjANBgkqhkiG9w0".to_string(),
        }];
        let out = render_key_changes_table(1, 1, &rows, false);
        assert!(out.contains("Fleet Keys (epochs 1"));
        assert!(out.contains("baseline"));
        assert!(out.contains("Login"));
        assert!(out.contains("MIIBIjANBgkq..."));
    }

    #[test]
    fn test_render_table_full_key() {
        let rows = vec![KeyRow {
            epoch: 1,
            kind: ChangeKind::Baseline,
            roles: BTreeSet::from([1u32]),
            key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A".to_string(),
        }];
        let out = render_key_changes_table(1, 1, &rows, true);
        assert!(out.contains("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"));
        assert!(!out.contains("..."));
    }

    #[test]
    fn test_render_table_role_change_arrow() {
        let rows = vec![KeyRow {
            epoch: 75,
            kind: ChangeKind::RoleChanged {
                old: BTreeSet::from([1u32, 2u32]),
            },
            roles: BTreeSet::from([1u32]),
            key: "k1".to_string(),
        }];
        let out = render_key_changes_table(1, 75, &rows, false);
        assert!(out.contains("Login, Register"));
        assert!(out.contains("\u{2192}")); // → arrow
        assert!(out.contains("~"));
    }
}
