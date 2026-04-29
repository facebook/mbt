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

pub(crate) struct ArtifactsArgs {
    pub proof_id: String,
    pub format: String,
    pub limit: Option<u32>,
    pub after: Option<String>,
}

pub(crate) fn run(args: ArtifactsArgs, client: &dyn BtClient) -> anyhow::Result<()> {
    let result = client.list_artifacts(&args.proof_id, args.limit, args.after.as_deref());

    let response = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(2);
        }
    };

    if response.data.is_empty() {
        eprintln!("No artifacts found for proof: {}", args.proof_id);
        process::exit(1);
    }

    if args.format == "json" {
        // Emit just the data array — paging cursors are noise for JSON
        // consumers and the table view also no longer surfaces a next-page
        // hint for artifacts.
        let json = serde_json::to_string_pretty(&response.data)?;
        println!("{json}");
    } else {
        println!(
            "{:<20} {:<45} {:<20} {:<10}",
            "ID", "Namespace", "Digest", "Algorithm"
        );
        println!("{}", "-".repeat(95));
        for item in &response.data {
            let truncated_digest = if item.digest.len() > 16 {
                format!("{}...", &item.digest[..16])
            } else {
                item.digest.clone()
            };
            println!(
                "{:<20} {:<45} {:<20} {:<10}",
                item.id, item.namespace_name, truncated_digest, item.digest_algorithm
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_client::MockClient;

    #[test]
    fn test_artifacts_table_format() {
        let args = ArtifactsArgs {
            proof_id: "proof-001-abc".to_string(),
            format: "table".to_string(),
            limit: None,
            after: None,
        };
        let client = MockClient;
        let result = run(args, &client);
        assert!(result.is_ok());
    }

    #[test]
    fn test_artifacts_json_format() {
        let args = ArtifactsArgs {
            proof_id: "proof-001-abc".to_string(),
            format: "json".to_string(),
            limit: None,
            after: None,
        };
        let client = MockClient;
        let result = run(args, &client);
        assert!(result.is_ok());
    }
}
