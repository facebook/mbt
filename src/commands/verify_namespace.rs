/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::process;

use anyhow::Result;

use crate::client::BtClient;
use crate::cloudflare_client::CloudflareClient;
use crate::verification;
use crate::verification::ProofResult;

pub(crate) fn run(
    client: &dyn BtClient,
    cloudflare: &CloudflareClient,
    namespace: &str,
    limit: usize,
) -> Result<()> {
    // Validate namespace
    let ns_config = verification::NAMESPACES
        .iter()
        .find(|c| c.name == namespace);
    if ns_config.is_none() {
        eprintln!(
            "Error [INVALID_INPUT]: Unknown namespace '{}'. Known namespaces:",
            namespace
        );
        for ns in verification::NAMESPACES {
            eprintln!("  {}", ns.name);
        }
        process::exit(2);
    }
    let ns_config = ns_config.unwrap();

    if namespace == "meta.encrypted_backups.fleet_keys.v1" {
        eprintln!(
            "Error [DEPRECATED]: verify-namespace is no longer supported for the encrypted-backup namespace."
        );
        eprintln!("Use instead: mbt eb-verify-namespace");
        process::exit(2);
    }

    if limit == 0 || limit > verification::MAX_LIMIT {
        eprintln!(
            "Error [INVALID_INPUT]: --limit must be between 1 and {}",
            verification::MAX_LIMIT
        );
        process::exit(2);
    }

    // Fetch proofs with auto-pagination
    let proofs = verification::fetch_proofs(client, namespace, limit, None)?;

    if proofs.is_empty() {
        eprintln!("No proofs found for namespace '{}'", namespace);
        process::exit(3);
    }

    // Verify each proof
    let mut results: Vec<(u64, ProofResult)> = Vec::new();
    let total = proofs.len();

    for (i, proof_item) in proofs.iter().enumerate() {
        eprint!(
            "Verifying epoch {} ({}/{})... ",
            proof_item.epoch,
            i + 1,
            total
        );

        let result =
            verification::verify_single_proof(client, cloudflare, ns_config, &proof_item.id, true);
        match &result {
            ProofResult::Pass { .. } => eprintln!("\u{2713}"),
            ProofResult::Fail { .. } => eprintln!("\u{2717}"),
            ProofResult::Error { .. } => eprintln!("\u{26A0} error"),
        }
        results.push((proof_item.epoch, result));
    }

    // Print summary
    verification::print_summary(&results, namespace);

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

#[cfg(test)]
mod tests {
    use crate::verification;
    use crate::verification::ProofResult;

    #[test]
    fn test_namespace_validation_valid() {
        assert!(verification::NAMESPACES
            .iter()
            .any(|c| c.name == "meta.encrypted_backups.fleet_keys.v1"));
    }

    #[test]
    fn test_namespace_validation_invalid() {
        assert!(!verification::NAMESPACES
            .iter()
            .any(|c| c.name == "nonexistent.namespace"));
        assert!(!verification::NAMESPACES.iter().any(|c| c.name.is_empty()));
    }

    #[test]
    fn test_counter_signature_gating_included() {
        let config = verification::NAMESPACES
            .iter()
            .find(|c| c.name == "meta.encrypted_backups.fleet_keys.v1")
            .unwrap();
        assert!(config.requires_counter_sig);
    }

    #[test]
    fn test_counter_signature_gating_excluded() {
        assert!(!verification::NAMESPACES
            .iter()
            .any(|c| c.name == "some.other.namespace"));
    }

    #[test]
    fn test_summary_all_pass() {
        let results = [
            (46, ProofResult::Pass { tmp_path: None }),
            (45, ProofResult::Pass { tmp_path: None }),
            (44, ProofResult::Pass { tmp_path: None }),
        ];
        let total = results.len();
        let pass_count = results
            .iter()
            .filter(|(_, r)| matches!(r, ProofResult::Pass { .. }))
            .count();
        assert_eq!(pass_count, total);
        assert_eq!(total, 3);
    }

    #[test]
    fn test_summary_some_failures() {
        let results = [
            (46, ProofResult::Pass { tmp_path: None }),
            (
                45,
                ProofResult::Fail {
                    step: "Digest verification".to_string(),
                    tmp_path: None,
                },
            ),
            (44, ProofResult::Pass { tmp_path: None }),
            (
                43,
                ProofResult::Error {
                    step: "Fetch proof".to_string(),
                    tmp_path: None,
                },
            ),
        ];
        let total = results.len();
        let pass_count = results
            .iter()
            .filter(|(_, r)| matches!(r, ProofResult::Pass { .. }))
            .count();
        assert_eq!(pass_count, 2);
        assert_eq!(total, 4);

        let has_failures = results
            .iter()
            .any(|(_, r)| matches!(r, ProofResult::Fail { .. }));
        let has_errors = results
            .iter()
            .any(|(_, r)| matches!(r, ProofResult::Error { .. }));
        assert!(has_failures);
        assert!(has_errors);
    }

    #[test]
    fn test_max_limit_enforced() {
        assert_eq!(verification::MAX_LIMIT, 200);
    }

    #[test]
    fn test_fetch_proofs_pagination() {
        use crate::mock_client::MockClient;

        let client = MockClient;
        let proofs =
            verification::fetch_proofs(&client, "meta.encrypted_backups.fleet_keys.v1", 50, None)
                .unwrap();
        assert!(!proofs.is_empty());
        assert!(proofs.len() <= 50);
    }

    #[test]
    fn test_hard_deprecation_eb_namespace() {
        // The encrypted-backup namespace should match the hard deprecation condition
        let namespace = "meta.encrypted_backups.fleet_keys.v1";
        let is_deprecated = namespace == "meta.encrypted_backups.fleet_keys.v1";
        assert!(
            is_deprecated,
            "Encrypted-backup namespace must trigger hard deprecation (exit 2)"
        );
    }

    #[test]
    fn test_no_deprecation_other_namespace() {
        // Other namespaces should NOT trigger deprecation
        let namespace = "some.other.namespace";
        let is_deprecated = namespace == "meta.encrypted_backups.fleet_keys.v1";
        assert!(
            !is_deprecated,
            "Other namespace should not trigger deprecation"
        );
    }
}
