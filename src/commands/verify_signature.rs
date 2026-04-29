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

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::crypto;
use crate::keys;
use crate::proto::SignatureMessage;
use crate::proto::SignatureResponse;

pub(crate) struct VerifySignatureArgs {
    pub digest: String,
    pub signature: String,
    pub serialized_message: String,
    pub key_id: Option<u32>,
    pub key: Option<String>,
}

pub(crate) fn run(args: VerifySignatureArgs) -> anyhow::Result<()> {
    // Validate digest hex (64 hex chars = 32 bytes for SHA256)
    let expected_digest = match hex::decode(&args.digest) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(bytes) => {
            eprintln!(
                "Error: Digest must be 64 hex characters (32 bytes), got {} bytes",
                bytes.len()
            );
            process::exit(2);
        }
        Err(_) => {
            eprintln!("Error: Invalid hex string for digest");
            process::exit(2);
        }
    };

    // Validate and decode signature (base64, 64 bytes for Ed25519)
    let sig_bytes = match STANDARD.decode(&args.signature) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        Ok(bytes) => {
            eprintln!(
                "Error: Signature must be 64 bytes, got {} bytes",
                bytes.len()
            );
            process::exit(2);
        }
        Err(_) => {
            eprintln!("Error: Invalid base64 string for signature");
            process::exit(2);
        }
    };

    // Validate and decode serialized_message (base64)
    let msg_bytes = match STANDARD.decode(&args.serialized_message) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("Error: Invalid base64 string for serialized-message");
            process::exit(2);
        }
    };

    // Try to parse as SignatureResponse first (contains signature + serialized_message + key_id).
    // If that fails, fall back to parsing as raw SignatureMessage.
    let (parsed_msg, proto_key_id) =
        if let Ok(resp) = <SignatureResponse as prost::Message>::decode(msg_bytes.as_slice()) {
            // SignatureResponse parsed — extract the inner SignatureMessage
            let inner: SignatureMessage =
                match prost::Message::decode(resp.serialized_message.as_slice()) {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!(
                        "Error: Failed to parse inner SignatureMessage from SignatureResponse: {}",
                        e
                    );
                        process::exit(2);
                    }
                };
            (inner, Some(resp.key_id))
        } else {
            // Fall back to parsing as a raw SignatureMessage
            match <SignatureMessage as prost::Message>::decode(msg_bytes.as_slice()) {
                Ok(msg) => (msg, None),
                Err(e) => {
                    eprintln!("Error: Failed to parse serialized message: {}", e);
                    process::exit(2);
                }
            }
        };

    // Compare extracted digest with --digest
    let digest_matches = crypto::constant_time_eq(&expected_digest, &parsed_msg.digest);
    let expected_prefix = &args.digest[..16.min(args.digest.len())];
    let parsed_digest_hex = hex::encode(&parsed_msg.digest);
    let parsed_prefix = &parsed_digest_hex[..16.min(parsed_digest_hex.len())];

    if digest_matches {
        println!(
            "Digest Match:   \u{2713}  (expected: {}..., parsed: {}...)",
            expected_prefix, parsed_prefix
        );
    } else {
        println!(
            "Digest Match:   \u{2717}  (expected: {}..., parsed: {}...)",
            expected_prefix, parsed_prefix
        );
        println!("Signature:      (skipped)");
        println!("Result:         FAIL");
        process::exit(1);
    }

    // Determine public key.
    // Priority: --key (custom override) > --key-id (CLI override) > key_id from protobuf
    let public_key: Vec<u8> = if let Some(ref key_hex) = args.key {
        // Custom key override
        match hex::decode(key_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                eprintln!(
                    "Warning: Using custom public key instead of embedded Cloudflare key. Verification results may not be trustworthy."
                );
                bytes
            }
            Ok(bytes) => {
                eprintln!(
                    "Error: Public key must be 64 hex characters (32 bytes), got {} bytes",
                    bytes.len()
                );
                process::exit(2);
            }
            Err(_) => {
                eprintln!("Error: Invalid hex string for public key");
                process::exit(2);
            }
        }
    } else {
        // Use --key-id override if provided, otherwise use key_id from protobuf
        let key_id = match args.key_id.or(proto_key_id) {
            Some(id) => id,
            None => {
                eprintln!(
                    "Error: No key_id found in protobuf and --key-id not provided. \
                     Pass --key-id from the proof response or use --key to provide a custom key."
                );
                process::exit(2);
            }
        };
        match keys::get_key(key_id) {
            Some(key) => key.to_vec(),
            None => {
                eprintln!("Error: Unknown key_id {}", key_id);
                process::exit(2);
            }
        }
    };

    // Verify signature using the ciphersuite from the parsed protobuf
    match crypto::verify_signature_with_ciphersuite(
        parsed_msg.ciphersuite,
        &msg_bytes,
        &sig_bytes,
        &public_key,
    ) {
        Ok(true) => {
            println!("Signature:      \u{2713}");
            println!("Result:         PASS");
            process::exit(0);
        }
        Ok(false) => {
            println!("Signature:      \u{2717}");
            println!("Result:         FAIL");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: Signature verification failed: {}", e);
            process::exit(2);
        }
    }
}
