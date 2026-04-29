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

pub(crate) struct ProofArgs {
    pub namespace: String,
    pub epoch: u64,
    pub format: String,
}

pub(crate) fn run(args: ProofArgs, client: &dyn BtClient) -> anyhow::Result<()> {
    let result = client.get_proof_by_namespace_epoch(&args.namespace, args.epoch);

    let detail = match result {
        Ok(d) => d,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                eprintln!(
                    "Proof not found for namespace={} epoch={}",
                    args.namespace, args.epoch
                );
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
        let key_id = detail
            .key_id
            .map_or_else(|| "-".to_string(), |k| k.to_string());
        let serialized_message = detail.serialized_message.as_deref().unwrap_or("-");
        let meta_signature = detail.meta_signature.as_deref().unwrap_or("-");
        let digest = detail.digest.as_deref().unwrap_or("-");

        println!("ID:                  {}", detail.id);
        println!("Namespace:           {}", detail.namespace_name);
        println!("Epoch:               {}", detail.epoch);
        println!("Signer:              {}", detail.signer);
        println!("Version:             {}", detail.version);
        println!("Timestamp:           {}", detail.timestamp);
        println!("Key ID:              {}", key_id);
        println!("Signature:           {}", detail.signature);
        println!("Serialized Message:  {}", serialized_message);
        println!("Meta Signature:      {}", meta_signature);
        println!("Artifact ID:         {}", detail.artifact_id);
        println!("Digest:              {}", digest);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_client::MockClient;

    #[test]
    fn test_proof_table_format() {
        let args = ProofArgs {
            namespace: "meta.encrypted_backups.fleet_keys.v1".to_string(),
            epoch: 1709251200,
            format: "table".to_string(),
        };
        let client = MockClient;
        let result = run(args, &client);
        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_json_format() {
        let args = ProofArgs {
            namespace: "meta.encrypted_backups.fleet_keys.v1".to_string(),
            epoch: 1709251200,
            format: "json".to_string(),
        };
        let client = MockClient;
        let result = run(args, &client);
        assert!(result.is_ok());
    }
}
