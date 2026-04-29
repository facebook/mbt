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

pub(crate) struct ArtifactArgs {
    pub id: String,
    pub format: String,
}

pub(crate) fn run(args: ArtifactArgs, client: &dyn BtClient) -> anyhow::Result<()> {
    let result = client.get_artifact(&args.id);

    let detail = match result {
        Ok(d) => d,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                eprintln!("Artifact not found: {}", args.id);
                process::exit(1);
            }
            eprintln!("Error: {e}");
            process::exit(2);
        }
    };

    if args.format == "json" {
        let json = serde_json::to_string_pretty(&detail)?;
        println!("{json}");
    } else {
        println!("ID:                  {}", detail.id);
        println!("Namespace:           {}", detail.namespace_name);
        println!("Digest:              {}", detail.digest);
        println!("Digest Algorithm:    {}", detail.digest_algorithm);
        println!("CDN URL:             {}", detail.cdn_url);
        if detail.additional_digests.is_empty() {
            println!("Additional Digests:  (none)");
        } else {
            println!("Additional Digests:");
            for (algo, hash) in &detail.additional_digests {
                println!("  {}: {}", algo, hash);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_client::MockClient;

    #[test]
    fn test_artifact_table_format() {
        let args = ArtifactArgs {
            id: "artifact-001-xyz".to_string(),
            format: "table".to_string(),
        };
        let client = MockClient;
        let result = run(args, &client);
        assert!(result.is_ok());
    }

    #[test]
    fn test_artifact_json_format() {
        let args = ArtifactArgs {
            id: "artifact-001-xyz".to_string(),
            format: "json".to_string(),
        };
        let client = MockClient;
        let result = run(args, &client);
        assert!(result.is_ok());
    }
}
