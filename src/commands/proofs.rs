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

use crate::client::BtClient;
use crate::types::PaginatedResponse;
use crate::types::ProofListItem;

pub(crate) struct ProofsArgs {
    pub namespace: String,
    pub format: String,
    pub limit: Option<u32>,
    pub before_epoch: Option<u64>,
}

pub(crate) fn run(args: ProofsArgs, client: &dyn BtClient) -> anyhow::Result<()> {
    let result = client.list_proofs(&args.namespace, args.limit, None, args.before_epoch);

    let response = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(2);
        }
    };

    if response.data.is_empty() {
        eprintln!("No proofs found for namespace: {}", args.namespace);
        process::exit(1);
    }

    if args.format == "json" {
        // Emit just the data array — paging cursors are a CLI affordance and
        // would be noise for JSON consumers.
        let json = serde_json::to_string_pretty(&response.data)?;
        println!("{json}");
    } else {
        println!(
            "{:<15} {:<15} {:<20} {:<15} {:<10}",
            "Epoch", "Signer", "Version", "Timestamp", "Key ID"
        );
        println!("{}", "-".repeat(75));
        for item in &response.data {
            let key_id = item
                .key_id
                .map_or_else(|| "-".to_string(), |k| k.to_string());
            println!(
                "{:<15} {:<15} {:<20} {:<15} {:<10}",
                item.epoch, item.signer, item.version, item.timestamp, key_id
            );
        }
    }

    if let Some(min_epoch) = next_page_min_epoch(&response, &args.format) {
        println!(
            "\nNext page: mbt proofs -n {} --before-epoch {min_epoch}",
            args.namespace
        );
    }

    Ok(())
}

/// When the API signals more results exist (cursors.after is set) and the
/// caller is rendering the table format, return the smallest epoch in the
/// current page so it can be surfaced as a `--before-epoch` hint. Returns
/// `None` for JSON output, when no more results exist, when the page is
/// empty, or when the smallest epoch is already 1 (epochs are 1-indexed,
/// so `--before-epoch 1` would always return an empty page).
fn next_page_min_epoch(response: &PaginatedResponse<ProofListItem>, format: &str) -> Option<u64> {
    if format == "json" {
        return None;
    }
    response.paging.as_ref()?.cursors.after.as_ref()?;
    let min = response.data.iter().map(|p| p.epoch).min()?;
    (min > 1).then_some(min)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_client::MockClient;
    use crate::types::CursorInfo;
    use crate::types::PagingInfo;

    fn item(epoch: u64) -> ProofListItem {
        ProofListItem {
            id: format!("proof-{epoch}"),
            epoch,
            signer: "CLOUDFLARE".to_string(),
            timestamp: epoch as i64,
            key_id: Some(212),
            version: "ProtobufEd25519".to_string(),
        }
    }

    fn response_with_after(
        epochs: Vec<u64>,
        after: Option<&str>,
    ) -> PaginatedResponse<ProofListItem> {
        PaginatedResponse {
            data: epochs.into_iter().map(item).collect(),
            paging: Some(PagingInfo {
                cursors: CursorInfo {
                    after: after.map(str::to_string),
                    before: None,
                },
            }),
        }
    }

    #[test]
    fn test_proofs_table_format() {
        let args = ProofsArgs {
            namespace: "meta.encrypted_backups.fleet_keys.v1".to_string(),
            format: "table".to_string(),
            limit: None,
            before_epoch: None,
        };
        let client = MockClient;
        let result = run(args, &client);
        assert!(result.is_ok());
    }

    #[test]
    fn test_proofs_json_format() {
        let args = ProofsArgs {
            namespace: "meta.encrypted_backups.fleet_keys.v1".to_string(),
            format: "json".to_string(),
            limit: None,
            before_epoch: None,
        };
        let client = MockClient;
        let result = run(args, &client);
        assert!(result.is_ok());
    }

    #[test]
    fn next_page_min_epoch_returns_smallest_epoch_when_after_is_set() {
        // Out-of-order epochs to confirm we compute the min, not first/last.
        let response = response_with_after(vec![5, 3, 7, 4], Some("opaque-cursor"));
        assert_eq!(
            next_page_min_epoch(&response, "table"),
            Some(3),
            "min epoch in page should be surfaced as the --before-epoch hint"
        );
    }

    #[test]
    fn next_page_min_epoch_is_none_for_json_format() {
        // Hint is a CLI affordance — JSON consumers shouldn't see it even when
        // there's a next page available.
        let response = response_with_after(vec![5, 3, 7], Some("opaque-cursor"));
        assert_eq!(next_page_min_epoch(&response, "json"), None);
    }

    #[test]
    fn next_page_min_epoch_is_none_when_after_cursor_absent() {
        // No `after` cursor means the API has no more pages.
        let response = response_with_after(vec![5, 3, 7], None);
        assert_eq!(next_page_min_epoch(&response, "table"), None);
    }

    #[test]
    fn next_page_min_epoch_is_none_when_paging_field_missing() {
        // Server may omit the paging block entirely; treat as "no more pages".
        let response = PaginatedResponse {
            data: vec![item(5), item(3)],
            paging: None,
        };
        assert_eq!(next_page_min_epoch(&response, "table"), None);
    }

    #[test]
    fn next_page_min_epoch_is_none_when_data_is_empty() {
        // An empty page with an `after` cursor is degenerate but possible;
        // there's no epoch to suggest, so emit no hint rather than a bogus one.
        let response = response_with_after(vec![], Some("opaque-cursor"));
        assert_eq!(next_page_min_epoch(&response, "table"), None);
    }

    #[test]
    fn next_page_min_epoch_is_none_when_min_epoch_is_one() {
        // The Meta API may still return a `cursors.after` token even when the
        // page already includes epoch 1 (the lowest possible epoch). Surfacing
        // `--before-epoch 1` would always return an empty page, so suppress it.
        let response = response_with_after(vec![4, 3, 2, 1], Some("opaque-cursor"));
        assert_eq!(next_page_min_epoch(&response, "table"), None);
    }
}
