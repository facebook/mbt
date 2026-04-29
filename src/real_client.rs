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
use std::thread;
use std::time::Duration;

use anyhow::Context;
use percent_encoding::utf8_percent_encode;
use percent_encoding::AsciiSet;
use percent_encoding::CONTROLS;

use crate::client::BtClient;
use crate::types::ArtifactDetail;
use crate::types::ArtifactListItem;
use crate::types::PaginatedResponse;
use crate::types::ProofDetail;
use crate::types::ProofListItem;

/// Maximum number of retries on HTTP 429 (rate limited).
const MAX_RETRIES: u32 = 3;

/// Initial backoff delay for rate-limited retries.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

pub(crate) struct RealClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl RealClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    /// Send a GET request with retry/backoff on HTTP 429. Returns the successful response.
    fn get_with_retry(&self, url: &str) -> reqwest::blocking::Response {
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

            return response;
        }

        unreachable!()
    }

    fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> anyhow::Result<T> {
        self.get_with_retry(url)
            .json::<T>()
            .context("Failed to parse API response")
    }

    fn get_bytes(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        self.get_with_retry(url)
            .bytes()
            .map(|b| b.to_vec())
            .context("Failed to read response body")
    }

    /// Build URL with query parameters for list endpoints.
    fn build_list_url(
        &self,
        path: &str,
        namespace: Option<&str>,
        limit: Option<u32>,
        after: Option<&str>,
        before_epoch: Option<u64>,
    ) -> String {
        let mut url = format!("{}{}", self.base_url, path);
        let mut sep = '?';

        if let Some(ns) = namespace {
            url.push_str(&format!("{}namespace_name={}", sep, encode(ns)));
            sep = '&';
        }

        if let Some(lim) = limit {
            url.push_str(&format!("{}limit={}", sep, lim));
            sep = '&';
        }

        if let Some(cursor) = after {
            url.push_str(&format!("{}after={}", sep, encode(cursor)));
            sep = '&';
        }

        if let Some(epoch) = before_epoch {
            url.push_str(&format!("{}before_epoch={}", sep, epoch));
        }

        url
    }
}

impl BtClient for RealClient {
    fn list_proofs(
        &self,
        namespace: &str,
        limit: Option<u32>,
        after: Option<&str>,
        before_epoch: Option<u64>,
    ) -> anyhow::Result<PaginatedResponse<ProofListItem>> {
        let url = self.build_list_url(
            "/binary-transparency/proofs/",
            Some(namespace),
            limit,
            after,
            before_epoch,
        );
        self.get_json(&url)
    }

    fn get_proof(&self, proof_id: &str) -> anyhow::Result<ProofDetail> {
        let url = format!(
            "{}/binary-transparency/proofs/{}",
            self.base_url,
            encode(proof_id)
        );
        self.get_json(&url)
    }

    fn get_proof_by_namespace_epoch(
        &self,
        namespace: &str,
        epoch: u64,
    ) -> anyhow::Result<ProofDetail> {
        let url = format!(
            "{}/binary-transparency/proofs/by-namespace-epoch?namespace_name={}&epoch={}",
            self.base_url,
            encode(namespace),
            epoch
        );
        self.get_json(&url)
    }

    fn list_artifacts(
        &self,
        proof_id: &str,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> anyhow::Result<PaginatedResponse<ArtifactListItem>> {
        let path = format!(
            "/binary-transparency/artifacts/by-proof/{}",
            encode(proof_id)
        );
        let url = self.build_list_url(&path, None, limit, after, None);
        self.get_json(&url)
    }

    fn get_artifact(&self, artifact_id: &str) -> anyhow::Result<ArtifactDetail> {
        let url = format!(
            "{}/binary-transparency/artifacts/{}",
            self.base_url,
            encode(artifact_id)
        );
        self.get_json(&url)
    }

    fn download_artifact(&self, cdn_url: &str) -> anyhow::Result<Vec<u8>> {
        self.get_bytes(cdn_url)
    }
}

/// Characters that must be percent-encoded in URL path/query components per RFC 3986.
const PATH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'%')
    .add(b'&')
    .add(b'=')
    .add(b'?')
    .add(b'#')
    .add(b'/')
    .add(b'+')
    .add(b'@')
    .add(b':')
    .add(b'[')
    .add(b']');

/// Percent-encode a string for use in URL path/query components.
fn encode(s: &str) -> String {
    utf8_percent_encode(s, PATH_ENCODE_SET).to_string()
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
    fn test_url_construction_list_proofs() {
        let client = RealClient::new("https://api.facebook.com");
        let url = client.build_list_url(
            "/binary-transparency/proofs/",
            Some("whatsapp"),
            Some(10),
            Some("cursor123"),
            None,
        );
        assert_eq!(
            url,
            "https://api.facebook.com/binary-transparency/proofs/?namespace_name=whatsapp&limit=10&after=cursor123"
        );
    }

    #[test]
    fn test_url_construction_list_proofs_no_params() {
        let client = RealClient::new("https://api.facebook.com/");
        let url = client.build_list_url(
            "/binary-transparency/proofs/",
            Some("messenger"),
            None,
            None,
            None,
        );
        assert_eq!(
            url,
            "https://api.facebook.com/binary-transparency/proofs/?namespace_name=messenger"
        );
    }

    #[test]
    fn test_url_construction_get_proof() {
        let client = RealClient::new("https://api.facebook.com");
        let url = format!(
            "{}/binary-transparency/proofs/{}",
            client.base_url,
            encode("proof-42")
        );
        assert_eq!(
            url,
            "https://api.facebook.com/binary-transparency/proofs/proof-42"
        );
    }

    #[test]
    fn test_url_construction_get_proof_by_namespace_epoch() {
        let client = RealClient::new("https://api.facebook.com");
        let url = format!(
            "{}/binary-transparency/proofs/by-namespace-epoch?namespace_name={}&epoch={}",
            client.base_url,
            encode("whatsapp"),
            100
        );
        assert_eq!(
            url,
            "https://api.facebook.com/binary-transparency/proofs/by-namespace-epoch?namespace_name=whatsapp&epoch=100"
        );
    }

    #[test]
    fn test_url_construction_list_artifacts() {
        let client = RealClient::new("https://api.facebook.com");
        let path = format!(
            "/binary-transparency/artifacts/by-proof/{}",
            encode("proof-42")
        );
        let url = client.build_list_url(&path, None, Some(5), None, None);
        assert_eq!(
            url,
            "https://api.facebook.com/binary-transparency/artifacts/by-proof/proof-42?limit=5"
        );
    }

    #[test]
    fn test_url_construction_get_artifact() {
        let client = RealClient::new("https://api.facebook.com");
        let url = format!(
            "{}/binary-transparency/artifacts/{}",
            client.base_url,
            encode("artifact-99")
        );
        assert_eq!(
            url,
            "https://api.facebook.com/binary-transparency/artifacts/artifact-99"
        );
    }

    #[test]
    fn test_base_url_trailing_slash_stripped() {
        let client = RealClient::new("https://api.facebook.com/");
        assert_eq!(client.base_url, "https://api.facebook.com");
    }

    #[test]
    fn test_encode_special_chars() {
        assert_eq!(encode("a b"), "a%20b");
        assert_eq!(encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(encode("foo?bar#baz"), "foo%3Fbar%23baz");
        assert_eq!(encode("a/b+c"), "a%2Fb%2Bc");
    }

    #[test]
    fn test_simple_jitter_range() {
        let j = simple_jitter();
        assert!(j < 500, "jitter should be 0-499ms, got {}", j);
    }
}
