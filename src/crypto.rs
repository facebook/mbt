/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::Signature;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use sha2::Digest;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::proto::SignatureMessage;

const MAX_FILE_SIZE: u64 = 500 * 1024 * 1024; // 500 MB

/// Supported digest algorithms. Only SHA256 is implemented in v1;
/// others will return an error with a clear message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestAlgorithm {
    Sha256,
    Sha512,
    Sha384,
    AndroidApkDigest,
    TeeCvmDigest,
}

impl DigestAlgorithm {
    pub(crate) fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            "sha384" => Ok(Self::Sha384),
            "android_apk_digest" => Ok(Self::AndroidApkDigest),
            "tee_cvm_digest" => Ok(Self::TeeCvmDigest),
            other => bail!(
                "Unknown digest algorithm '{}'. Known algorithms: sha256, sha512, sha384, android_apk_digest, tee_cvm_digest",
                other
            ),
        }
    }

    /// Expected digest length in bytes for this algorithm.
    pub(crate) fn digest_len(&self) -> Option<usize> {
        match self {
            Self::Sha256 => Some(32),
            Self::Sha512 => Some(64),
            Self::Sha384 => Some(48),
            Self::AndroidApkDigest | Self::TeeCvmDigest => None,
        }
    }
}

/// Supported digest encodings for input parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestEncoding {
    HexLowercase,
    HexUppercase,
    Base64,
}

impl DigestEncoding {
    pub(crate) fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "hex" | "hex_lowercase" => Ok(Self::HexLowercase),
            "hex_uppercase" => Ok(Self::HexUppercase),
            "base64" => Ok(Self::Base64),
            other => bail!(
                "Unknown encoding '{}'. Known encodings: hex, hex_lowercase, hex_uppercase, base64",
                other
            ),
        }
    }

    /// Decode a digest string into raw bytes using this encoding.
    pub(crate) fn decode(&self, input: &str) -> Result<Vec<u8>> {
        match self {
            Self::HexLowercase | Self::HexUppercase => {
                hex::decode(input).context("Invalid hex string for digest")
            }
            Self::Base64 => STANDARD
                .decode(input)
                .context("Invalid base64 string for digest"),
        }
    }
}

/// Compute a cryptographic digest of a file using the specified algorithm.
/// Currently only SHA256 is supported; other algorithms return an error.
pub(crate) fn compute_digest(path: &Path, algorithm: DigestAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        DigestAlgorithm::Sha256 => compute_sha256(path),
        other => bail!(
            "Algorithm '{:?}' is not currently supported. Supported algorithms: sha256",
            other
        ),
    }
}

fn compute_sha256(path: &Path) -> Result<Vec<u8>> {
    let metadata = path.metadata().context("Failed to read file metadata")?;
    if !metadata.file_type().is_file() {
        bail!("Path is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_FILE_SIZE {
        bail!(
            "File size {} exceeds maximum allowed size {}",
            metadata.len(),
            MAX_FILE_SIZE
        );
    }

    let file = File::open(path).context("Failed to open file")?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer).context("Failed to read file")?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().to_vec())
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Verify a signature using the algorithm indicated by the ciphersuite value
/// from the Cloudflare SignatureMessage protobuf.
/// Currently only Ed25519 (ciphersuite=1) is supported.
#[allow(dead_code)]
pub(crate) fn verify_signature_with_ciphersuite(
    ciphersuite: u32,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    match ciphersuite {
        1 => verify_ed25519(message, signature, public_key),
        other => bail!(
            "Unsupported ciphersuite {}. Only ciphersuite 1 (Ed25519) is currently supported",
            other
        ),
    }
}
pub(crate) fn verify_ed25519(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes, got {}", public_key.len()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).context("Invalid Ed25519 public key")?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes, got {}", signature.len()))?;
    let sig = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify Meta HSM counter-signature on a Cloudflare proof.
/// Meta's HSM signs Cloudflare's Ed25519 signature bytes as the message.
pub(crate) fn verify_counter_signature(
    cloudflare_signature: &[u8],
    meta_signature: &[u8],
    meta_public_key: &[u8; 32],
) -> Result<bool> {
    if cloudflare_signature.len() != 64 {
        bail!(
            "Cloudflare signature must be 64 bytes, got {}",
            cloudflare_signature.len()
        );
    }
    if meta_signature.len() != 64 {
        bail!(
            "Meta counter-signature must be 64 bytes, got {}",
            meta_signature.len()
        );
    }
    verify_ed25519(cloudflare_signature, meta_signature, meta_public_key)
}

#[allow(dead_code)]
pub(crate) fn parse_serialized_message(base64_input: &str) -> Result<SignatureMessage> {
    let bytes = STANDARD
        .decode(base64_input)
        .context("Failed to decode base64 input")?;
    let msg =
        prost::Message::decode(bytes.as_slice()).context("Failed to decode protobuf message")?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::Verifier;

    use super::*;
    use crate::keys;

    fn parse_serialized_message_hex(hex_input: &str) -> Result<SignatureMessage> {
        let bytes = hex::decode(hex_input).context("Failed to decode hex input")?;
        let msg = prost::Message::decode(bytes.as_slice())
            .context("Failed to decode protobuf message")?;
        Ok(msg)
    }

    // Real Cloudflare AKD auditor test vector (epoch 2, key_id 212)
    const TEST_SIGNATURE_HEX: &str = "630f7579dccd9e7a1ecc7a54998f30d4b868ee1812eb8f5706a4ab16c927f2e310685c943783a128c8f524da780c4c0df37048a8bbcebc683a4b7ae69bd9d107";
    const TEST_SERIALIZED_MESSAGE_HEX: &str = "080112246d6574612e656e637279707465645f6261636b7570732e666c6565745f6b6579732e763118d384a3fbee32220208022a2071a4091f2b3a084f3d1c1860c07f5c6e52b5443d682fa653e849596790572033";
    const TEST_DIGEST_HEX: &str =
        "71a4091f2b3a084f3d1c1860c07f5c6e52b5443d682fa653e849596790572033";

    #[test]
    fn test_compute_digest_sha256_valid_file() {
        let dir = std::env::temp_dir().join("mbt_test_sha256_valid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.txt");
        let mut f = File::create(&path).unwrap();
        f.write_all(b"hello world").unwrap();

        let hash = compute_digest(&path, DigestAlgorithm::Sha256).unwrap();
        let expected =
            hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .unwrap();
        assert_eq!(
            hash, expected,
            "SHA256 of 'hello world' should match known value"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_compute_digest_sha256_empty_file() {
        let dir = std::env::temp_dir().join("mbt_test_sha256_empty");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.txt");
        File::create(&path).unwrap();

        let hash = compute_digest(&path, DigestAlgorithm::Sha256).unwrap();
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(
            hash, expected,
            "SHA256 of empty file should match known value"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_compute_digest_rejects_directory() {
        let dir = std::env::temp_dir().join("mbt_test_sha256_dir");
        std::fs::create_dir_all(&dir).unwrap();

        let result = compute_digest(&dir, DigestAlgorithm::Sha256);
        assert!(result.is_err(), "Should reject directory path");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not a regular file"),
            "Error should mention not a regular file"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_compute_digest_unsupported_algorithm() {
        let dir = std::env::temp_dir().join("mbt_test_unsupported_algo");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.txt");
        let mut f = File::create(&path).unwrap();
        f.write_all(b"hello").unwrap();

        for algo in [
            DigestAlgorithm::Sha512,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::AndroidApkDigest,
            DigestAlgorithm::TeeCvmDigest,
        ] {
            let result = compute_digest(&path, algo);
            assert!(result.is_err(), "{:?} should not be supported yet", algo);
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("not currently supported"),
                "Error should mention not currently supported"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_digest_algorithm_from_str() {
        assert_eq!(
            DigestAlgorithm::from_str("sha256").unwrap(),
            DigestAlgorithm::Sha256
        );
        assert_eq!(
            DigestAlgorithm::from_str("SHA256").unwrap(),
            DigestAlgorithm::Sha256
        );
        assert_eq!(
            DigestAlgorithm::from_str("sha512").unwrap(),
            DigestAlgorithm::Sha512
        );
        assert_eq!(
            DigestAlgorithm::from_str("sha384").unwrap(),
            DigestAlgorithm::Sha384
        );
        assert_eq!(
            DigestAlgorithm::from_str("android_apk_digest").unwrap(),
            DigestAlgorithm::AndroidApkDigest
        );
        assert_eq!(
            DigestAlgorithm::from_str("tee_cvm_digest").unwrap(),
            DigestAlgorithm::TeeCvmDigest
        );
        assert!(DigestAlgorithm::from_str("md5").is_err());
    }

    #[test]
    fn test_digest_algorithm_digest_len() {
        assert_eq!(DigestAlgorithm::Sha256.digest_len(), Some(32));
        assert_eq!(DigestAlgorithm::Sha512.digest_len(), Some(64));
        assert_eq!(DigestAlgorithm::Sha384.digest_len(), Some(48));
        assert_eq!(DigestAlgorithm::AndroidApkDigest.digest_len(), None);
        assert_eq!(DigestAlgorithm::TeeCvmDigest.digest_len(), None);
    }

    #[test]
    fn test_digest_encoding_from_str() {
        assert_eq!(
            DigestEncoding::from_str("hex").unwrap(),
            DigestEncoding::HexLowercase
        );
        assert_eq!(
            DigestEncoding::from_str("hex_lowercase").unwrap(),
            DigestEncoding::HexLowercase
        );
        assert_eq!(
            DigestEncoding::from_str("hex_uppercase").unwrap(),
            DigestEncoding::HexUppercase
        );
        assert_eq!(
            DigestEncoding::from_str("base64").unwrap(),
            DigestEncoding::Base64
        );
        assert!(DigestEncoding::from_str("utf8").is_err());
    }

    #[test]
    fn test_digest_encoding_decode() {
        let expected = vec![0xab, 0xcd, 0xef];

        // Hex lowercase
        let decoded = DigestEncoding::HexLowercase.decode("abcdef").unwrap();
        assert_eq!(decoded, expected);

        // Hex uppercase
        let decoded = DigestEncoding::HexUppercase.decode("ABCDEF").unwrap();
        assert_eq!(decoded, expected);

        // Base64
        let b64 = base64::engine::general_purpose::STANDARD.encode(&expected);
        let decoded = DigestEncoding::Base64.decode(&b64).unwrap();
        assert_eq!(decoded, expected);

        // Invalid hex
        assert!(DigestEncoding::HexLowercase.decode("ZZZZ").is_err());
    }

    #[test]
    fn test_constant_time_eq_equal() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(constant_time_eq(a, b), "Equal slices should return true");
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        let a = b"hello world";
        let b = b"hello worle";
        assert!(
            !constant_time_eq(a, b),
            "Different slices should return false"
        );
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        let a = b"hello";
        let b = b"hello world";
        assert!(
            !constant_time_eq(a, b),
            "Different length slices should return false"
        );
    }

    #[test]
    fn test_verify_ed25519_valid_cloudflare() {
        // Real Cloudflare AKD auditor epoch 2 test vector
        let sig_bytes = hex::decode(TEST_SIGNATURE_HEX).unwrap();
        let msg_bytes = hex::decode(TEST_SERIALIZED_MESSAGE_HEX).unwrap();

        // Empirically verify which key is key_id 212
        let result_a = verify_ed25519(&msg_bytes, &sig_bytes, &keys::CLOUDFLARE_KEY_A).unwrap();
        let result_b = verify_ed25519(&msg_bytes, &sig_bytes, &keys::CLOUDFLARE_KEY_B).unwrap();

        // Exactly one key should verify
        assert!(
            result_a || result_b,
            "At least one Cloudflare key must verify the epoch 2 signature"
        );
        assert!(
            !(result_a && result_b),
            "Only one key should verify (keys are distinct)"
        );

        // Verify get_key(212) returns the correct key
        let key_212 = keys::get_key(212).expect("key_id 212 should exist");
        let result = verify_ed25519(&msg_bytes, &sig_bytes, key_212).unwrap();
        assert!(
            result,
            "get_key(212) must return the key that verifies epoch 2 signature"
        );
    }

    #[test]
    fn test_verify_ed25519_valid_generated() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let message = b"test message for ed25519 verification";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());

        let result =
            verify_ed25519(message, &signature.to_bytes(), verifying_key.as_bytes()).unwrap();
        assert!(result, "Valid Ed25519 signature should verify successfully");
    }

    #[test]
    fn test_verify_ed25519_invalid_signature() {
        let sig_bytes = hex::decode(TEST_SIGNATURE_HEX).unwrap();
        let msg_bytes = hex::decode(TEST_SERIALIZED_MESSAGE_HEX).unwrap();

        let mut bad_sig = sig_bytes.clone();
        bad_sig[0] ^= 0xff;

        let key_212 = keys::get_key(212).unwrap();
        let result = verify_ed25519(&msg_bytes, &bad_sig, key_212).unwrap();
        assert!(!result, "Tampered signature should fail verification");
    }

    #[test]
    fn test_verify_ed25519_wrong_key() {
        let sig_bytes = hex::decode(TEST_SIGNATURE_HEX).unwrap();
        let msg_bytes = hex::decode(TEST_SERIALIZED_MESSAGE_HEX).unwrap();

        // Use a random wrong key
        let wrong_key = [99u8; 32];
        let result = verify_ed25519(&msg_bytes, &sig_bytes, &wrong_key);
        // Wrong key may return Ok(false) or Err (invalid key point); either is acceptable.
        if let Ok(valid) = result {
            assert!(!valid, "Wrong key should fail verification");
        }
    }

    #[test]
    fn test_parse_serialized_message_hex_cloudflare() {
        let parsed = parse_serialized_message_hex(TEST_SERIALIZED_MESSAGE_HEX).unwrap();
        assert_eq!(parsed.ciphersuite, 1);
        assert_eq!(parsed.namespace, "meta.encrypted_backups.fleet_keys.v1");
        assert_eq!(parsed.epoch.as_ref().unwrap().inner, 2);
        let expected_digest = hex::decode(TEST_DIGEST_HEX).unwrap();
        assert_eq!(parsed.digest, expected_digest);
    }

    #[test]
    fn test_parse_serialized_message_base64() {
        use prost::Message;

        let msg = SignatureMessage {
            ciphersuite: 1,
            namespace: "meta.encrypted_backups.fleet_keys.v1".to_string(),
            timestamp: 1700000000,
            epoch: Some(crate::proto::Epoch { inner: 2 }),
            digest: vec![0xab; 32],
        };
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        let b64 = STANDARD.encode(&buf);

        let parsed = parse_serialized_message(&b64).unwrap();
        assert_eq!(parsed.ciphersuite, 1);
        assert_eq!(parsed.namespace, "meta.encrypted_backups.fleet_keys.v1");
        assert_eq!(parsed.timestamp, 1700000000);
        assert_eq!(parsed.epoch.unwrap().inner, 2);
        assert_eq!(parsed.digest, vec![0xab; 32]);
    }

    #[test]
    fn test_parse_serialized_message_invalid_base64() {
        let result = parse_serialized_message("!!!not-valid-base64!!!");
        assert!(result.is_err(), "Invalid base64 should return error");
    }

    #[test]
    fn test_parse_serialized_message_hex_invalid() {
        let result = parse_serialized_message_hex("ZZZZ");
        assert!(result.is_err(), "Invalid hex should return error");
    }

    /// Build a synthetic counter-signature triple `(cf_sig, meta_counter_sig,
    /// meta_public_key)` from a deterministic seed. The "Cloudflare signature"
    /// is just 64 arbitrary bytes treated as the message that Meta's HSM
    /// signs. Using a deterministic seed keeps the test fully reproducible
    /// without `rand`.
    fn synthetic_counter_signature(seed: u8) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let cf_signature: Vec<u8> = (0..64).map(|i| i ^ seed).collect();
        let meta_signature = signing_key.sign(&cf_signature).to_bytes().to_vec();
        let meta_public_key = signing_key.verifying_key().to_bytes();
        (cf_signature, meta_signature, meta_public_key)
    }

    #[test]
    fn test_verify_counter_signature_valid() {
        let (cf_sig, meta_sig, meta_pub_key) = synthetic_counter_signature(7);
        let result = verify_counter_signature(&cf_sig, &meta_sig, &meta_pub_key).unwrap();
        assert!(result, "Valid counter-signature should verify successfully");
    }

    #[test]
    fn test_verify_counter_signature_invalid_tampered() {
        let (cf_sig, mut meta_sig, meta_pub_key) = synthetic_counter_signature(7);
        meta_sig[0] ^= 0xff;
        let result = verify_counter_signature(&cf_sig, &meta_sig, &meta_pub_key).unwrap();
        assert!(
            !result,
            "Tampered counter-signature should fail verification"
        );
    }

    #[test]
    fn test_verify_counter_signature_wrong_key() {
        let (cf_sig, meta_sig, _) = synthetic_counter_signature(7);
        let (_, _, other_pub_key) = synthetic_counter_signature(42);
        let result = verify_counter_signature(&cf_sig, &meta_sig, &other_pub_key);
        // A different key may return Ok(false) or Err (invalid key point); either is acceptable.
        if let Ok(valid) = result {
            assert!(!valid, "Wrong key should fail verification");
        }
    }

    #[test]
    fn test_verify_signature_with_ciphersuite_ed25519() {
        let sig_bytes = hex::decode(TEST_SIGNATURE_HEX).unwrap();
        let msg_bytes = hex::decode(TEST_SERIALIZED_MESSAGE_HEX).unwrap();
        let key_212 = keys::get_key(212).unwrap();

        let result = verify_signature_with_ciphersuite(1, &msg_bytes, &sig_bytes, key_212).unwrap();
        assert!(result, "Ciphersuite 1 (Ed25519) should verify successfully");
    }

    #[test]
    fn test_verify_signature_with_unsupported_ciphersuite() {
        let sig_bytes = hex::decode(TEST_SIGNATURE_HEX).unwrap();
        let msg_bytes = hex::decode(TEST_SERIALIZED_MESSAGE_HEX).unwrap();
        let key_212 = keys::get_key(212).unwrap();

        let result = verify_signature_with_ciphersuite(99, &msg_bytes, &sig_bytes, key_212);
        assert!(
            result.is_err(),
            "Unsupported ciphersuite should return error"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported ciphersuite"),
            "Error should mention unsupported ciphersuite"
        );
    }

    #[test]
    fn test_get_key_valid() {
        let key = keys::get_key(212);
        assert!(key.is_some(), "key_id 212 should return a key");
        assert_eq!(key.unwrap().len(), 32, "Key should be 32 bytes");
    }

    #[test]
    fn test_get_key_invalid() {
        let key = keys::get_key(999);
        assert!(key.is_none(), "Unknown key_id should return None");
    }
}
