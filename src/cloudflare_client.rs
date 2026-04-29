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

use std::process;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use percent_encoding::utf8_percent_encode;
use percent_encoding::AsciiSet;
use percent_encoding::CONTROLS;
use serde::Deserialize;

/// Maximum number of retries on HTTP 429 (rate limited).
const MAX_RETRIES: u32 = 3;

/// Initial backoff delay for rate-limited retries.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Characters that must be percent-encoded in URL path segments.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'&')
    .add(b'=')
    .add(b'+')
    .add(b'@')
    .add(b':')
    .add(b'[')
    .add(b']');

#[derive(Debug, Deserialize)]
pub(crate) struct CloudflareAuditRecord {
    pub version: u32,
    pub ciphersuite: u32,
    pub namespace: String,
    pub timestamp: u64,
    pub epoch: u64,
    pub digest: String,
    pub signature: String,
    pub key_id: u64,
    pub serialized_message: String,
}

pub(crate) struct CloudflareClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl CloudflareClient {
    pub fn new() -> Self {
        Self {
            base_url: "https://akd-auditor.cloudflare.com".to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    #[cfg(test)]
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    pub fn get_audit(&self, namespace: &str, epoch: u64) -> anyhow::Result<CloudflareAuditRecord> {
        let url = self.build_url(namespace, epoch);
        self.get_with_retry(&url)
    }

    fn build_url(&self, namespace: &str, epoch: u64) -> String {
        let encoded_ns = utf8_percent_encode(namespace, PATH_SEGMENT_ENCODE_SET).to_string();
        format!(
            "{}/namespaces/{}/audits/{}",
            self.base_url, encoded_ns, epoch
        )
    }

    fn get_with_retry<T: serde::de::DeserializeOwned>(&self, url: &str) -> anyhow::Result<T> {
        let mut delay = INITIAL_BACKOFF;

        for attempt in 0..=MAX_RETRIES {
            let result = self.http.get(url).send();

            let response = match result {
                Ok(resp) => resp,
                Err(e) => {
                    eprintln!("Error [NETWORK_ERROR]: {}", describe_network_error(&e));
                    process::exit(3);
                }
            };

            let status = response.status();

            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                if attempt < MAX_RETRIES {
                    let jitter = Duration::from_millis(simple_jitter());
                    let wait = delay + jitter;
                    eprintln!(
                        "Error [RATE_LIMITED]: Rate limited, retrying in {}s...",
                        wait.as_secs_f32()
                    );
                    thread::sleep(wait);
                    delay *= 2;
                    continue;
                }
                eprintln!(
                    "Error [RATE_LIMITED]: Rate limited after {} retries",
                    MAX_RETRIES
                );
                process::exit(3);
            }

            if status.is_client_error() {
                let body = response.text().unwrap_or_default();
                eprintln!(
                    "Error [INVALID_INPUT]: API returned {}: {}",
                    status.as_u16(),
                    body
                );
                process::exit(2);
            }

            if status.is_server_error() {
                eprintln!("Error [SERVER_ERROR]: Server returned {}", status.as_u16());
                process::exit(4);
            }

            return response.json::<T>().context("Failed to parse API response");
        }

        unreachable!()
    }
}

/// Simple deterministic jitter (0-500ms) without pulling in rand.
fn simple_jitter() -> u64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (nanos % 500) as u64
}

fn describe_network_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "Connection timed out after 30s".to_string()
    } else if e.is_connect() {
        format!("Connection failed: {}", e)
    } else {
        format!("Network error: {}", e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_construction() {
        let client = CloudflareClient::with_base_url("https://akd-auditor.cloudflare.com");
        let url = client.build_url("meta.encrypted_backups.fleet_keys.v1", 49);
        assert_eq!(
            url,
            "https://akd-auditor.cloudflare.com/namespaces/meta.encrypted_backups.fleet_keys.v1/audits/49"
        );
    }

    #[test]
    fn test_url_construction_trailing_slash() {
        let client = CloudflareClient::with_base_url("https://akd-auditor.cloudflare.com/");
        let url = client.build_url("test.namespace", 1);
        assert_eq!(
            url,
            "https://akd-auditor.cloudflare.com/namespaces/test.namespace/audits/1"
        );
    }

    #[test]
    fn test_url_construction_epoch_zero() {
        let client = CloudflareClient::with_base_url("https://akd-auditor.cloudflare.com");
        let url = client.build_url("ns", 0);
        assert_eq!(
            url,
            "https://akd-auditor.cloudflare.com/namespaces/ns/audits/0"
        );
    }

    #[test]
    fn test_deserialize_audit_record() {
        let json = r#"{
            "version": 1,
            "ciphersuite": 1,
            "namespace": "meta.encrypted_backups.fleet_keys.v1",
            "timestamp": 1773077529794,
            "epoch": 49,
            "digest": "30b426c4ef5f51a42e486042e0ddca72b81747c89d688121d07fca5039d454a3",
            "signature": "b1e3704abcdef1234567890",
            "key_id": 212,
            "serialized_message": "0a0131deadbeef"
        }"#;

        let record: CloudflareAuditRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.version, 1);
        assert_eq!(record.ciphersuite, 1);
        assert_eq!(record.namespace, "meta.encrypted_backups.fleet_keys.v1");
        assert_eq!(record.timestamp, 1773077529794);
        assert_eq!(record.epoch, 49);
        assert_eq!(
            record.digest,
            "30b426c4ef5f51a42e486042e0ddca72b81747c89d688121d07fca5039d454a3"
        );
        assert_eq!(record.signature, "b1e3704abcdef1234567890");
        assert_eq!(record.key_id, 212);
        assert_eq!(record.serialized_message, "0a0131deadbeef");
    }

    #[test]
    fn test_deserialize_audit_record_large_epoch() {
        let json = r#"{
            "version": 1,
            "ciphersuite": 1,
            "namespace": "ns",
            "timestamp": 0,
            "epoch": 18446744073709551615,
            "digest": "aa",
            "signature": "bb",
            "key_id": 0,
            "serialized_message": "cc"
        }"#;

        let record: CloudflareAuditRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.epoch, u64::MAX);
    }

    #[test]
    fn test_namespace_with_special_characters() {
        let client = CloudflareClient::with_base_url("https://akd-auditor.cloudflare.com");
        let url = client.build_url("meta.encrypted_backups.fleet-keys.v1", 10);
        assert_eq!(
            url,
            "https://akd-auditor.cloudflare.com/namespaces/meta.encrypted_backups.fleet-keys.v1/audits/10"
        );
    }
}
