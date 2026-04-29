/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::path::Path;
use std::process;

use crate::crypto::compute_digest;
use crate::crypto::constant_time_eq;
use crate::crypto::DigestAlgorithm;
use crate::crypto::DigestEncoding;

pub(crate) struct VerifyDigestArgs {
    pub file: String,
    pub digest: String,
    pub algorithm: String,
    pub encoding: String,
}

pub(crate) fn run(args: VerifyDigestArgs) -> anyhow::Result<()> {
    // Validate algorithm
    let algorithm = match DigestAlgorithm::from_str(&args.algorithm) {
        Ok(algo) => algo,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(2);
        }
    };

    // Validate encoding
    let encoding = match DigestEncoding::from_str(&args.encoding) {
        Ok(enc) => enc,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(2);
        }
    };

    // Decode digest using the specified encoding
    let expected_bytes = match encoding.decode(&args.digest) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(2);
        }
    };

    // Validate digest length against algorithm
    if let Some(expected_len) = algorithm.digest_len() {
        if expected_bytes.len() != expected_len {
            eprintln!(
                "Error: {:?} digest must be {} bytes, got {} bytes",
                algorithm,
                expected_len,
                expected_bytes.len()
            );
            process::exit(2);
        }
    }

    // Validate file
    let path = Path::new(&args.file);
    if !path.exists() {
        eprintln!("Error: File not found: {}", args.file);
        process::exit(2);
    }
    let metadata = match path.metadata() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: Cannot read file metadata: {}", e);
            process::exit(2);
        }
    };
    if !metadata.file_type().is_file() {
        eprintln!("Error: Path is not a regular file: {}", args.file);
        process::exit(2);
    }

    // Compute digest
    let computed = match compute_digest(path, algorithm) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Error: Failed to compute digest: {}", e);
            process::exit(2);
        }
    };

    let computed_hex = hex::encode(&computed);
    let matches = constant_time_eq(&computed, &expected_bytes);
    let match_symbol = if matches { "\u{2713}" } else { "\u{2717}" };

    println!("File:            {}", args.file);
    println!("Algorithm:       {:?}", algorithm);
    println!("Computed Digest: {}", computed_hex);
    println!("Expected Digest: {}", args.digest);
    println!("Match:           {}", match_symbol);

    if matches {
        process::exit(0);
    } else {
        process::exit(1);
    }
}
