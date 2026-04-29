/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::io::Write;
use std::process;

use crate::client::BtClient;

pub(crate) struct ArtifactDownloadArgs {
    pub id: String,
    pub output: Option<String>,
}

pub(crate) fn run(args: ArtifactDownloadArgs, client: &dyn BtClient) -> anyhow::Result<()> {
    let detail = match client.get_artifact(&args.id) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error fetching artifact metadata: {e}");
            process::exit(2);
        }
    };

    if detail.cdn_url == "<restricted>" {
        eprintln!("Artifact download is restricted: {}", args.id);
        process::exit(1);
    }

    let bytes = match client.download_artifact(&detail.cdn_url) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error downloading artifact: {e}");
            process::exit(2);
        }
    };

    if bytes.is_empty() {
        eprintln!("Downloaded artifact is empty");
        process::exit(2);
    }

    if let Some(path) = &args.output {
        std::fs::write(path, &bytes)?;
        eprintln!("Downloaded {} bytes to {}", bytes.len(), path);
    } else {
        std::io::stdout().write_all(&bytes)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_client::MockClient;

    #[test]
    fn test_artifact_download_to_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("mbt_test_download_unit");
        let path_str = path.to_string_lossy().to_string();

        let args = ArtifactDownloadArgs {
            id: "artifact-001-xyz".to_string(),
            output: Some(path_str.clone()),
        };
        let client = MockClient;
        let result = run(args, &client);
        assert!(result.is_ok());

        let contents = std::fs::read(&path).expect("file should exist");
        assert!(!contents.is_empty(), "downloaded file should be non-empty");

        let _ = std::fs::remove_file(&path);
    }
}
