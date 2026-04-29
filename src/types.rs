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

use std::collections::HashMap;

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProofListItem {
    pub id: String,
    pub epoch: u64,
    pub signer: String,
    pub timestamp: i64,
    pub key_id: Option<i64>,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProofDetail {
    pub id: String,
    pub namespace_name: String,
    pub epoch: u64,
    pub signer: String,
    pub version: String,
    pub timestamp: i64,
    pub key_id: Option<i64>,
    pub signature: String,
    pub serialized_message: Option<String>,
    pub meta_signature: Option<String>,
    pub artifact_id: String,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ArtifactListItem {
    pub id: String,
    pub namespace_name: String,
    pub digest: String,
    pub digest_algorithm: String,
    pub additional_digests: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ArtifactDetail {
    pub id: String,
    pub namespace_name: String,
    pub digest: String,
    pub digest_algorithm: String,
    pub additional_digests: HashMap<String, String>,
    pub cdn_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PaginatedResponse<T> {
    pub data: Vec<T>,
    #[serde(default)]
    pub paging: Option<PagingInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PagingInfo {
    pub cursors: CursorInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CursorInfo {
    pub after: Option<String>,
    pub before: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paginated_response_deserializes_without_paging_field() {
        let json = r#"{"data":[]}"#;
        let resp: PaginatedResponse<ProofListItem> =
            serde_json::from_str(json).expect("missing paging field must not fail to deserialize");
        assert!(resp.data.is_empty());
        assert!(resp.paging.is_none());
    }

    #[test]
    fn paginated_response_deserializes_with_null_paging() {
        let json = r#"{"data":[],"paging":null}"#;
        let resp: PaginatedResponse<ProofListItem> =
            serde_json::from_str(json).expect("explicit null paging must deserialize");
        assert!(resp.paging.is_none());
    }

    #[test]
    fn paginated_response_deserializes_with_paging_cursors() {
        let json = r#"{"data":[],"paging":{"cursors":{"after":"abc","before":null}}}"#;
        let resp: PaginatedResponse<ProofListItem> =
            serde_json::from_str(json).expect("populated paging must deserialize");
        let cursors = resp.paging.expect("paging present").cursors;
        assert_eq!(cursors.after.as_deref(), Some("abc"));
        assert!(cursors.before.is_none());
    }
}
