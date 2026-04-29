/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::process::Command;

use base64::Engine;
fn mbt_bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mbt"));
    cmd.env("MBT_USE_MOCK", "1");
    cmd
}

#[test]
fn namespaces_exits_zero_and_produces_output() {
    let output = mbt_bin()
        .arg("namespaces")
        .output()
        .expect("failed to run mbt");

    assert!(output.status.success(), "mbt namespaces should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "mbt namespaces should produce output listing namespaces"
    );
    assert!(
        stdout.contains("meta.encrypted_backups.fleet_keys.v1"),
        "should list meta.encrypted_backups.fleet_keys.v1 namespace"
    );
}

#[test]
fn no_subcommand_shows_usage_info() {
    let output = mbt_bin().output().expect("failed to run mbt");

    assert!(
        output.status.success(),
        "mbt with no subcommand should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage") || stdout.contains("usage"),
        "mbt with no subcommand should show usage info"
    );
}

#[test]
fn version_flag_prints_version() {
    let output = mbt_bin()
        .arg("--version")
        .output()
        .expect("failed to run mbt");

    assert!(output.status.success(), "mbt --version should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("0.1.0"),
        "mbt --version should print version 0.1.0"
    );
}

#[test]
fn proofs_exits_zero_with_valid_namespace() {
    let output = mbt_bin()
        .args([
            "proofs",
            "--namespace",
            "meta.encrypted_backups.fleet_keys.v1",
        ])
        .output()
        .expect("failed to run mbt");

    assert!(output.status.success(), "mbt proofs should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Epoch"),
        "table output should contain Epoch header"
    );
    assert!(
        stdout.contains("CLOUDFLARE"),
        "table output should contain signer"
    );
}

#[test]
fn proofs_json_format_produces_valid_json() {
    let output = mbt_bin()
        .args([
            "proofs",
            "--namespace",
            "meta.encrypted_backups.fleet_keys.v1",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run mbt");

    assert!(
        output.status.success(),
        "mbt proofs --format json should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert!(
        parsed.is_array(),
        "JSON output should be a top-level array of proof items"
    );
}

#[test]
fn proof_exits_zero_with_valid_namespace_epoch() {
    let output = mbt_bin()
        .args([
            "proof",
            "--namespace",
            "meta.encrypted_backups.fleet_keys.v1",
            "--epoch",
            "1709251200",
        ])
        .output()
        .expect("failed to run mbt");

    assert!(output.status.success(), "mbt proof should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("proof-001-abc"),
        "table output should contain proof ID"
    );
    assert!(
        stdout.contains("CLOUDFLARE"),
        "table output should contain signer"
    );
}

#[test]
fn proof_json_format_produces_valid_json() {
    let output = mbt_bin()
        .args([
            "proof",
            "--namespace",
            "meta.encrypted_backups.fleet_keys.v1",
            "--epoch",
            "1709251200",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run mbt");

    assert!(
        output.status.success(),
        "mbt proof --format json should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(parsed["id"], "proof-001-abc");
}

#[test]
fn artifacts_exits_zero_with_valid_proof_id() {
    let output = mbt_bin()
        .args(["artifacts", "--proof-id", "proof-001-abc"])
        .output()
        .expect("failed to run mbt");

    assert!(output.status.success(), "mbt artifacts should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("artifact-001-xyz"),
        "table output should contain artifact ID"
    );
    assert!(
        stdout.contains("SHA256"),
        "table output should contain algorithm"
    );
}

#[test]
fn artifacts_json_format_produces_valid_json() {
    let output = mbt_bin()
        .args([
            "artifacts",
            "--proof-id",
            "proof-001-abc",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run mbt");

    assert!(
        output.status.success(),
        "mbt artifacts --format json should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert!(
        parsed.is_array(),
        "JSON output should be a top-level array of artifact items"
    );
}

#[test]
fn artifact_exits_zero_with_valid_id() {
    let output = mbt_bin()
        .args(["artifact", "--id", "artifact-001-xyz"])
        .output()
        .expect("failed to run mbt");

    assert!(output.status.success(), "mbt artifact should exit 0");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("artifact-001-xyz"),
        "table output should contain artifact ID"
    );
    assert!(
        stdout.contains("cdn.example.com"),
        "table output should contain CDN URL"
    );
}

#[test]
fn artifact_json_format_produces_valid_json() {
    let output = mbt_bin()
        .args(["artifact", "--id", "artifact-001-xyz", "--format", "json"])
        .output()
        .expect("failed to run mbt");

    assert!(
        output.status.success(),
        "mbt artifact --format json should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(parsed["id"], "artifact-001-xyz");
}

#[test]
fn artifact_download_to_file_exits_zero() {
    let path = std::env::temp_dir().join("mbt_test_artifact_download");
    let _ = std::fs::remove_file(&path);

    let output = mbt_bin()
        .args([
            "artifact-download",
            "--id",
            "artifact-001-xyz",
            "--output",
            path.to_str().expect("temp path is valid utf-8"),
        ])
        .output()
        .expect("failed to run mbt");

    assert!(
        output.status.success(),
        "mbt artifact-download --output should exit 0"
    );

    let contents = std::fs::read(&path).expect("output file should exist");
    assert!(!contents.is_empty(), "downloaded file should be non-empty");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn artifact_download_to_stdout_exits_zero() {
    let output = mbt_bin()
        .args(["artifact-download", "--id", "artifact-001-xyz"])
        .output()
        .expect("failed to run mbt");

    assert!(
        output.status.success(),
        "mbt artifact-download to stdout should exit 0"
    );
    assert!(
        !output.stdout.is_empty(),
        "stdout should contain downloaded bytes"
    );
}

#[test]
fn verify_digest_match_exits_zero() {
    use std::io::Write;

    let dir = std::env::temp_dir().join("mbt_test_verify_digest_match");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.txt");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(b"hello world").unwrap();

    // SHA256("hello world")
    let digest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    let output = mbt_bin()
        .args(["verify-digest", "-f", path.to_str().unwrap(), "-d", digest])
        .output()
        .expect("failed to run mbt");

    assert!(
        output.status.success(),
        "verify-digest with matching digest should exit 0"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\u{2713}"), "should show match checkmark");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn verify_digest_mismatch_exits_nonzero() {
    use std::io::Write;

    let dir = std::env::temp_dir().join("mbt_test_verify_digest_mismatch");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.txt");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(b"hello world").unwrap();

    let wrong_digest = "0000000000000000000000000000000000000000000000000000000000000000";

    let output = mbt_bin()
        .args([
            "verify-digest",
            "-f",
            path.to_str().unwrap(),
            "-d",
            wrong_digest,
        ])
        .output()
        .expect("failed to run mbt");

    assert!(
        !output.status.success(),
        "verify-digest with mismatched digest should exit non-zero"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\u{2717}"),
        "should show mismatch cross mark"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn verify_digest_invalid_hex_exits_2() {
    let any_path = std::env::temp_dir().join("any");
    let output = mbt_bin()
        .args([
            "verify-digest",
            "-f",
            any_path.to_str().expect("temp path is valid utf-8"),
            "-d",
            "not-valid-hex!!",
        ])
        .output()
        .expect("failed to run mbt");

    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid hex digest should exit 2"
    );
}

#[test]
fn verify_digest_missing_file_exits_2() {
    let digest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    let missing_path = std::env::temp_dir().join("nonexistent_file_mbt_test_12345");

    let output = mbt_bin()
        .args([
            "verify-digest",
            "-f",
            missing_path.to_str().expect("temp path is valid utf-8"),
            "-d",
            digest,
        ])
        .output()
        .expect("failed to run mbt");

    assert_eq!(output.status.code(), Some(2), "missing file should exit 2");
}

#[test]
fn verify_digest_unsupported_algorithm_exits_2() {
    let any_path = std::env::temp_dir().join("any");
    let output = mbt_bin()
        .args([
            "verify-digest",
            "-f",
            any_path.to_str().expect("temp path is valid utf-8"),
            "-d",
            "abcd",
            "-a",
            "md5",
        ])
        .output()
        .expect("failed to run mbt");

    assert_eq!(
        output.status.code(),
        Some(2),
        "unsupported algorithm should exit 2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown digest algorithm"),
        "error should mention unknown algorithm"
    );
}

// Real Cloudflare AKD auditor test vector (epoch 2, key_id 212)
const CF_SIGNATURE: &str =
    "Yw91edzNnnoezHpUmY8w1Lho7hgS649XBqSrFskn8uMQaFyUN4OhKMj1JNp4DEwN83BIqLvOvGg6S3rmm9nRBw==";
const CF_SERIALIZED_MESSAGE: &str = "CAESJG1ldGEuZW5jcnlwdGVkX2JhY2t1cHMuZmxlZXRfa2V5cy52MRjThKP77jIiAggCKiBxpAkfKzoITz0cGGDAf1xuUrVEPWgvplPoSVlnkFcgMw==";
const CF_DIGEST: &str = "71a4091f2b3a084f3d1c1860c07f5c6e52b5443d682fa653e849596790572033";
// KEY_A hex (key_id 212)
const CF_KEY_A_HEX: &str = "2bbfbb39997fdb95feee40ef9f8827de0256732be06f64ed6408cc7e97c7f4d4";

#[test]
fn verify_signature_valid_exits_zero() {
    let output = mbt_bin()
        .args([
            "verify-signature",
            "-d",
            CF_DIGEST,
            "-s",
            CF_SIGNATURE,
            "-m",
            CF_SERIALIZED_MESSAGE,
            "--key-id",
            "212",
        ])
        .output()
        .expect("failed to run mbt");

    assert!(
        output.status.success(),
        "valid signature should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS"), "should show PASS");
    assert!(stdout.contains("\u{2713}"), "should show checkmark");
}

#[test]
fn verify_signature_invalid_sig_exits_nonzero() {
    // Tamper with signature by using a different base64 value (flip first byte)
    let bad_sig = {
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(CF_SIGNATURE)
            .unwrap();
        bytes[0] ^= 0xff;
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    };

    let output = mbt_bin()
        .args([
            "verify-signature",
            "-d",
            CF_DIGEST,
            "-s",
            &bad_sig,
            "-m",
            CF_SERIALIZED_MESSAGE,
            "--key-id",
            "212",
        ])
        .output()
        .expect("failed to run mbt");

    assert!(
        !output.status.success(),
        "tampered signature should exit non-zero"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FAIL"), "should show FAIL");
}

#[test]
fn verify_signature_digest_mismatch_exits_nonzero() {
    let wrong_digest = "0000000000000000000000000000000000000000000000000000000000000000";

    let output = mbt_bin()
        .args([
            "verify-signature",
            "-d",
            wrong_digest,
            "-s",
            CF_SIGNATURE,
            "-m",
            CF_SERIALIZED_MESSAGE,
            "--key-id",
            "212",
        ])
        .output()
        .expect("failed to run mbt");

    assert!(
        !output.status.success(),
        "digest mismatch should exit non-zero"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FAIL"), "should show FAIL");
    assert!(
        stdout.contains("(skipped)"),
        "signature check should be skipped on digest mismatch"
    );
}

#[test]
fn verify_signature_bad_hex_exits_2() {
    let output = mbt_bin()
        .args([
            "verify-signature",
            "-d",
            "not-valid-hex!!",
            "-s",
            CF_SIGNATURE,
            "-m",
            CF_SERIALIZED_MESSAGE,
        ])
        .output()
        .expect("failed to run mbt");

    assert_eq!(output.status.code(), Some(2), "bad hex input should exit 2");
}

#[test]
fn verify_signature_key_override_exits_zero_with_warning() {
    let output = mbt_bin()
        .args([
            "verify-signature",
            "-d",
            CF_DIGEST,
            "-s",
            CF_SIGNATURE,
            "-m",
            CF_SERIALIZED_MESSAGE,
            "-k",
            CF_KEY_A_HEX,
        ])
        .output()
        .expect("failed to run mbt");

    assert!(
        output.status.success(),
        "key override with correct key should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS"), "should show PASS");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Warning"),
        "stderr should contain warning about custom key"
    );
}

#[test]
fn eb_verify_namespace_default_shows_truncated_key() {
    let output = mbt_bin()
        .args(["eb-verify-namespace", "--limit", "5"])
        .output()
        .expect("failed to run mbt");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Fleet Keys (epochs"),
        "missing section header. stdout was: {stdout}"
    );
    assert!(
        stdout.contains("baseline"),
        "missing baseline rows. stdout was: {stdout}"
    );
    // truncate_key produces exactly 12 chars + "..." = 15 chars.
    // Look for a row whose last whitespace-separated token matches that shape.
    let has_truncated_key = stdout.lines().any(|l| {
        l.split_whitespace()
            .last()
            .is_some_and(|t| t.ends_with("...") && t.len() == 15)
    });
    assert!(
        has_truncated_key,
        "expected at least one truncated key matching shape `xxxxxxxxxxxx...` (12 chars + ellipsis). stdout was: {stdout}"
    );
}

#[test]
fn eb_verify_namespace_with_key_flag_shows_full_key() {
    let output = mbt_bin()
        .args(["eb-verify-namespace", "--limit", "5", "--key"])
        .output()
        .expect("failed to run mbt");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // With --key, the full base64 key appears as the last token on data rows.
    // The mock fixtures use 60-char base64 keys; the truncated form would be
    // 15 chars + "...". Verify we see a long key AND no truncation marker on
    // any row that ends with a base64-shaped token.
    let has_full_key = stdout.lines().any(|l| {
        l.split_whitespace()
            .last()
            .is_some_and(|t| t.len() > 30 && !t.ends_with("..."))
    });
    assert!(
        has_full_key,
        "expected at least one untruncated full key (>30 chars, no `...` suffix). stdout was: {stdout}"
    );
}

#[test]
fn eb_verify_namespace_verbose_flag_rejected() {
    let output = mbt_bin()
        .args(["eb-verify-namespace", "--verbose"])
        .output()
        .expect("failed to run mbt");
    assert!(!output.status.success(), "--verbose should be rejected");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // clap's exact wording for an unknown long flag is "unexpected argument".
    assert!(
        stderr.contains("unexpected argument"),
        "expected clap 'unexpected argument' rejection. stderr was: {stderr}"
    );
}
