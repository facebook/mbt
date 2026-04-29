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
use base64::Engine;

use crate::client::BtClient;
use crate::cloudflare_client::CloudflareClient;
use crate::verification::decode_expected_digest;

/// Outcome of comparing one field across the Meta and Cloudflare records.
///
/// `DecodeError` is distinct from `Mismatch` because the two have different
/// causes: `Mismatch` means both sides decoded successfully but the resulting
/// bytes differ (a real audit failure), while `DecodeError` means at least one
/// side could not be parsed at all (a data-quality issue with the API
/// response). Surfacing them separately mirrors how `verification.rs` handles
/// the same distinction in its Cloudflare cross-check (see
/// `verify_cloudflare_cross_check`, which returns `StepResult::Error` on
/// decode failure and `StepResult::Fail` on byte mismatch).
#[derive(Debug, PartialEq, Eq)]
enum FieldComparison {
    Match,
    Mismatch,
    DecodeError,
}

/// Validates that a namespace contains only allowed characters: alphanumeric, `_`, `-`, `.`.
fn validate_namespace(namespace: &str) -> Result<()> {
    if namespace.is_empty() {
        anyhow::bail!("namespace must not be empty");
    }
    if !namespace
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        anyhow::bail!("namespace must contain only alphanumeric characters, '_', '-', or '.'");
    }
    Ok(())
}

pub(crate) fn run(
    client: &dyn BtClient,
    cloudflare: &CloudflareClient,
    namespace: &str,
    epoch: u64,
) -> Result<()> {
    if let Err(e) = validate_namespace(namespace) {
        eprintln!("Error [INVALID_INPUT]: {}", e);
        process::exit(2);
    }

    let meta_proof = client.get_proof_by_namespace_epoch(namespace, epoch)?;
    let cf_record = cloudflare.get_audit(namespace, epoch)?;

    // Compare namespace and epoch — string and integer equality, no decoding.
    let ns_match = meta_proof.namespace_name == cf_record.namespace;
    let epoch_match = meta_proof.epoch == cf_record.epoch;

    // Compare digest by decoded bytes: Meta returns hex for newer epochs and
    // base64 for early epochs; Cloudflare returns hex. A naive case-insensitive
    // string compare misses byte-equal pairs across the two encodings.
    let meta_digest_bytes = meta_proof
        .digest
        .as_deref()
        .and_then(decode_expected_digest);
    let cf_digest_bytes = decode_expected_digest(&cf_record.digest);
    let digest_result = compare_decoded(&meta_digest_bytes, &cf_digest_bytes);

    // Compare signature: Meta is Base64, Cloudflare is hex — decode both to bytes.
    let meta_sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&meta_proof.signature)
        .ok();
    let cf_sig_bytes = hex::decode(&cf_record.signature).ok();
    let sig_result = compare_decoded(&meta_sig_bytes, &cf_sig_bytes);

    // Compare serialized_message: Meta is Base64, Cloudflare is hex — decode both to bytes.
    let meta_msg_bytes = meta_proof
        .serialized_message
        .as_ref()
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok());
    let cf_msg_bytes = hex::decode(&cf_record.serialized_message).ok();
    let msg_result = compare_decoded(&meta_msg_bytes, &cf_msg_bytes);

    // Print results
    println!("{:<16}{:<28}Cloudflare AKD Auditor", "Source", "Meta API");
    println!("{}", "\u{2500}".repeat(66));

    print_field("Namespace", ns_match, &cf_record.namespace);
    print_field("Epoch", epoch_match, &cf_record.epoch.to_string());

    match digest_result {
        FieldComparison::Match => {
            let digest_display = truncate_hex(&cf_record.digest, 16);
            print_field("Digest", true, &digest_display);
        }
        FieldComparison::Mismatch => {
            println!("{:<16}\u{2717} MISMATCH", "Digest:");
            println!(
                "  Meta:         {}",
                meta_proof.digest.as_deref().unwrap_or("(none)")
            );
            println!("  Cloudflare:   {}", cf_record.digest);
        }
        FieldComparison::DecodeError => {
            println!("{:<16}\u{26A0} ERROR (failed to decode)", "Digest:");
            println!(
                "  Meta:         {}",
                meta_proof.digest.as_deref().unwrap_or("(none)")
            );
            println!("  Cloudflare:   {}", cf_record.digest);
        }
    }

    match sig_result {
        FieldComparison::Match => {
            let byte_len = cf_sig_bytes.as_ref().map(|b| b.len()).unwrap_or(0);
            print_field("Signature", true, &format!("(decoded, {} bytes)", byte_len));
        }
        FieldComparison::Mismatch => {
            println!("{:<16}\u{2717} MISMATCH", "Signature:");
            println!(
                "  Meta:         (base64) {}",
                truncate_str(&meta_proof.signature, 24)
            );
            println!(
                "  Cloudflare:   (hex) {}",
                truncate_hex(&cf_record.signature, 24)
            );
        }
        FieldComparison::DecodeError => {
            println!("{:<16}\u{26A0} ERROR (failed to decode)", "Signature:");
            println!(
                "  Meta:         (base64) {}",
                truncate_str(&meta_proof.signature, 24)
            );
            println!(
                "  Cloudflare:   (hex) {}",
                truncate_hex(&cf_record.signature, 24)
            );
        }
    }

    match msg_result {
        FieldComparison::Match => {
            let byte_len = cf_msg_bytes.as_ref().map(|b| b.len()).unwrap_or(0);
            print_field(
                "Serialized Msg",
                true,
                &format!("(decoded, {} bytes)", byte_len),
            );
        }
        FieldComparison::Mismatch => {
            println!("{:<16}\u{2717} MISMATCH", "Serialized Msg:");
            println!(
                "  Meta:         {}",
                meta_proof.serialized_message.as_deref().unwrap_or("(none)")
            );
            println!(
                "  Cloudflare:   {}",
                truncate_hex(&cf_record.serialized_message, 24)
            );
        }
        FieldComparison::DecodeError => {
            println!("{:<16}\u{26A0} ERROR (failed to decode)", "Serialized Msg:");
            println!(
                "  Meta:         {}",
                meta_proof.serialized_message.as_deref().unwrap_or("(none)")
            );
            println!(
                "  Cloudflare:   {}",
                truncate_hex(&cf_record.serialized_message, 24)
            );
        }
    }

    let comparisons = [&digest_result, &sig_result, &msg_result];
    let any_decode_error = comparisons
        .iter()
        .any(|c| matches!(c, FieldComparison::DecodeError));
    let any_mismatch = !ns_match
        || !epoch_match
        || comparisons
            .iter()
            .any(|c| matches!(c, FieldComparison::Mismatch));

    println!();
    if !any_mismatch && !any_decode_error {
        println!("Result:         PASS \u{2014} all fields match");
    } else if any_decode_error && !any_mismatch {
        println!("Result:         ERROR \u{2014} one or more fields failed to decode");
        process::exit(3);
    } else {
        println!("Result:         FAIL \u{2014} one or more fields mismatch");
        process::exit(1);
    }

    Ok(())
}

/// Three-state comparison for fields that require decoding both sides before
/// they can be compared. Returns `DecodeError` when at least one side did not
/// decode (i.e., neither was successfully parsed into bytes), `Mismatch` when
/// both decoded but the bytes differ, and `Match` when both decoded and the
/// bytes are equal.
fn compare_decoded(meta: &Option<Vec<u8>>, cf: &Option<Vec<u8>>) -> FieldComparison {
    match (meta, cf) {
        (Some(m), Some(c)) if m == c => FieldComparison::Match,
        (Some(_), Some(_)) => FieldComparison::Mismatch,
        _ => FieldComparison::DecodeError,
    }
}

fn print_field(name: &str, matches: bool, value: &str) {
    let label = format!("{}:", name);
    if matches {
        println!("{:<16}\u{2713} match{:>23}", label, value);
    } else {
        println!("{:<16}\u{2717} MISMATCH", label);
    }
}

fn truncate_hex(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare_client::CloudflareAuditRecord;
    use crate::types::ProofDetail;

    fn make_meta_proof(digest: &str, sig_b64: &str, msg_b64: Option<&str>) -> ProofDetail {
        ProofDetail {
            id: "proof-1".to_string(),
            namespace_name: "meta.encrypted_backups.fleet_keys.v1".to_string(),
            epoch: 49,
            signer: "signer".to_string(),
            version: "ProtobufEd25519".to_string(),
            timestamp: 1773077529794,
            key_id: Some(212),
            signature: sig_b64.to_string(),
            serialized_message: msg_b64.map(|s| s.to_string()),
            meta_signature: None,
            artifact_id: "art-1".to_string(),
            digest: Some(digest.to_string()),
        }
    }

    fn make_cf_record(digest: &str, sig_hex: &str, msg_hex: &str) -> CloudflareAuditRecord {
        CloudflareAuditRecord {
            version: 1,
            ciphersuite: 1,
            namespace: "meta.encrypted_backups.fleet_keys.v1".to_string(),
            timestamp: 1773077529794,
            epoch: 49,
            digest: digest.to_string(),
            signature: sig_hex.to_string(),
            key_id: 212,
            serialized_message: msg_hex.to_string(),
        }
    }

    #[test]
    fn test_validate_namespace_valid() {
        assert!(validate_namespace("meta.encrypted_backups.fleet_keys.v1").is_ok());
        assert!(validate_namespace("whatsapp-keys").is_ok());
        assert!(validate_namespace("test_ns").is_ok());
    }

    #[test]
    fn test_validate_namespace_invalid() {
        assert!(validate_namespace("").is_err());
        assert!(validate_namespace("ns with spaces").is_err());
        assert!(validate_namespace("ns/path").is_err());
        assert!(validate_namespace("ns@domain").is_err());
    }

    #[test]
    fn test_matching_fields_all_match() {
        // Raw bytes: [0xDE, 0xAD, 0xBE, 0xEF]
        // Base64: 3q2+7w==
        // Hex: deadbeef
        let meta = make_meta_proof(
            "30b426c4ef5f51a42e486042e0ddca72b81747c89d688121d07fca5039d454a3",
            "3q2+7w==",
            Some("3q2+7w=="),
        );
        let cf = make_cf_record(
            "30b426c4ef5f51a42e486042e0ddca72b81747c89d688121d07fca5039d454a3",
            "deadbeef",
            "deadbeef",
        );

        // Verify namespace match
        assert_eq!(meta.namespace_name, cf.namespace);

        // Verify epoch match
        assert_eq!(meta.epoch, cf.epoch);

        // Verify digest match (case-insensitive)
        assert!(meta
            .digest
            .as_ref()
            .unwrap()
            .eq_ignore_ascii_case(&cf.digest));

        // Verify signature match after decoding
        let meta_sig = base64::engine::general_purpose::STANDARD
            .decode(&meta.signature)
            .unwrap();
        let cf_sig = hex::decode(&cf.signature).unwrap();
        assert_eq!(meta_sig, cf_sig);

        // Verify serialized_message match after decoding
        let meta_msg = base64::engine::general_purpose::STANDARD
            .decode(meta.serialized_message.as_ref().unwrap())
            .unwrap();
        let cf_msg = hex::decode(&cf.serialized_message).unwrap();
        assert_eq!(meta_msg, cf_msg);
    }

    #[test]
    fn test_mismatching_digest() {
        let meta = make_meta_proof("aaaa", "3q2+7w==", Some("3q2+7w=="));
        let cf = make_cf_record("bbbb", "deadbeef", "deadbeef");

        assert!(!meta
            .digest
            .as_ref()
            .unwrap()
            .eq_ignore_ascii_case(&cf.digest));
    }

    #[test]
    fn test_mismatching_signature() {
        // Meta base64 "3q2+7w==" = [0xDE, 0xAD, 0xBE, 0xEF]
        // Cloudflare hex "cafebabe" = [0xCA, 0xFE, 0xBA, 0xBE]
        let meta_sig = base64::engine::general_purpose::STANDARD
            .decode("3q2+7w==")
            .unwrap();
        let cf_sig = hex::decode("cafebabe").unwrap();
        assert_ne!(meta_sig, cf_sig);
    }

    #[test]
    fn test_base64_to_hex_cross_decoding() {
        // Test that the same raw bytes produce consistent results through both encodings
        let raw_bytes: Vec<u8> = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        let b64_encoded = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
        let hex_encoded = hex::encode(&raw_bytes);

        let decoded_from_b64 = base64::engine::general_purpose::STANDARD
            .decode(&b64_encoded)
            .unwrap();
        let decoded_from_hex = hex::decode(&hex_encoded).unwrap();

        assert_eq!(decoded_from_b64, decoded_from_hex);
        assert_eq!(decoded_from_b64, raw_bytes);
    }

    #[test]
    fn test_digest_case_insensitive_comparison() {
        let lower = "30b426c4ef5f51a4";
        let upper = "30B426C4EF5F51A4";
        assert!(lower.eq_ignore_ascii_case(upper));
    }

    /// Regression: early epochs return the digest in base64 from Meta and hex
    /// from Cloudflare. A naive case-insensitive string compare reports
    /// MISMATCH even though the underlying bytes are identical. The audit
    /// command must decode both sides to bytes before comparing. Covers the
    /// real epoch-1, epoch-2, and epoch-3 digests captured during the
    /// investigation that motivated this fix.
    #[test]
    fn test_digest_match_across_base64_and_hex_encodings() {
        let cases: &[(u64, &str, &str)] = &[
            (
                1,
                "7WP8/16DV0n8RQNO3nJod+NBCrlJbD7w6IFLmCvwEVU=",
                "ed63fcff5e835749fc45034ede726877e3410ab9496c3ef0e8814b982bf01155",
            ),
            (
                2,
                "caQJHys6CE89HBhgwH9cblK1RD1oL6ZT6ElZZ5BXIDM=",
                "71a4091f2b3a084f3d1c1860c07f5c6e52b5443d682fa653e849596790572033",
            ),
            (
                3,
                "aM3t9Tbvs9KOkYER1Ny+T3yCsK3rxyRjkq9Oj9taE6A=",
                "68cdedf536efb3d28e918111d4dcbe4f7c82b0adebc7246392af4e8fdb5a13a0",
            ),
        ];

        for (epoch, meta_b64, cf_hex) in cases {
            let meta_bytes = decode_expected_digest(meta_b64)
                .unwrap_or_else(|| panic!("epoch {epoch}: base64 decode of meta digest failed"));
            let cf_bytes = decode_expected_digest(cf_hex)
                .unwrap_or_else(|| panic!("epoch {epoch}: hex decode of cf digest failed"));
            assert_eq!(
                meta_bytes, cf_bytes,
                "epoch {epoch}: meta base64 and cf hex digests should decode to identical bytes"
            );
        }
    }

    #[test]
    fn compare_decoded_returns_match_when_bytes_equal() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            compare_decoded(&Some(bytes.clone()), &Some(bytes)),
            FieldComparison::Match
        );
    }

    #[test]
    fn compare_decoded_returns_mismatch_when_both_decode_but_bytes_differ() {
        let meta = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let cf = vec![0xCA, 0xFE, 0xBA, 0xBE];
        assert_eq!(
            compare_decoded(&Some(meta), &Some(cf)),
            FieldComparison::Mismatch
        );
    }

    /// Addresses reviewer feedback on D102997818: a decode failure (one or
    /// both sides parse to `None`) is data-quality issue with the API
    /// response and must surface as ERROR, not MISMATCH. MISMATCH is reserved
    /// for the case where both sides decoded successfully but the resulting
    /// bytes diverge (a real audit failure).
    #[test]
    fn compare_decoded_returns_decode_error_when_either_side_fails() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            compare_decoded(&None, &Some(bytes.clone())),
            FieldComparison::DecodeError,
            "meta-side decode failure should be DecodeError, not Mismatch"
        );
        assert_eq!(
            compare_decoded(&Some(bytes), &None),
            FieldComparison::DecodeError,
            "cf-side decode failure should be DecodeError, not Mismatch"
        );
        assert_eq!(
            compare_decoded(&None, &None),
            FieldComparison::DecodeError,
            "both-sides decode failure should be DecodeError, not Mismatch"
        );
    }
}
