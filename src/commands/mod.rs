/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

mod artifact;
mod artifact_download;
mod artifacts;
pub(crate) mod audit;
mod eb_verify_namespace;
mod namespaces;
mod proof;
mod proofs;
mod verify_digest;
mod verify_namespace;
mod verify_signature;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Cross-verify a proof between Meta and Cloudflare AKD auditor
    Audit {
        /// Namespace to query
        #[arg(short, long)]
        namespace: String,
        /// Epoch number
        #[arg(short, long)]
        epoch: u64,
    },
    /// List known Binary Transparency namespaces
    Namespaces,
    /// List proofs for a namespace
    Proofs {
        /// Namespace to query
        #[arg(short, long)]
        namespace: String,
        /// Output format (table or json)
        #[arg(short, long, default_value = "table")]
        format: String,
        /// Maximum number of results
        #[arg(long, default_value = "10")]
        limit: u32,
        /// Start from this epoch (exclusive), going backwards
        #[arg(long)]
        before_epoch: Option<u64>,
    },
    /// Show detailed proof info for a namespace and epoch
    Proof {
        /// Namespace to query
        #[arg(short, long)]
        namespace: String,
        /// Epoch number
        #[arg(short, long)]
        epoch: u64,
        /// Output format (table or json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// List artifacts for a proof
    Artifacts {
        /// Proof ID to query
        #[arg(short, long)]
        proof_id: String,
        /// Output format (table or json)
        #[arg(short, long, default_value = "table")]
        format: String,
        /// Maximum number of results
        #[arg(long, default_value = "10")]
        limit: u32,
        /// Pagination cursor
        #[arg(long)]
        after: Option<String>,
    },
    /// Show detailed artifact info
    Artifact {
        /// Artifact ID
        #[arg(long)]
        id: String,
        /// Output format (table or json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Download artifact bytes
    ArtifactDownload {
        /// Artifact ID
        #[arg(long)]
        id: String,
        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Verify file digest against expected value
    VerifyDigest {
        /// Path to file
        #[arg(short, long)]
        file: String,
        /// Expected digest string
        #[arg(short, long)]
        digest: String,
        /// Hash algorithm (default: sha256)
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,
        /// Digest encoding: hex, hex_lowercase, hex_uppercase, base64 (default: hex)
        #[arg(short, long, default_value = "hex")]
        encoding: String,
    },
    /// Verify Ed25519 signature on a proof
    VerifySignature {
        /// Expected digest hex string
        #[arg(short, long)]
        digest: String,
        /// Signature hex string
        #[arg(short, long)]
        signature: String,
        /// Serialized message hex string
        #[arg(short = 'm', long)]
        serialized_message: String,
        /// Key ID to look up embedded key
        #[arg(long)]
        key_id: Option<u32>,
        /// Custom public key hex (overrides embedded key)
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Run full verification pipeline across recent proofs for a namespace
    VerifyNamespace {
        /// Namespace to verify
        #[arg(short, long)]
        namespace: String,
        /// Number of most recent proofs to verify (max 200)
        #[arg(short, long, default_value = "1")]
        limit: usize,
    },
    /// Encrypted backup E2E verification + key delta analysis
    EbVerifyNamespace {
        /// Number of most recent proofs to verify (max 200)
        #[arg(short, long, default_value = "50")]
        limit: usize,
        /// Start from this epoch (exclusive), going backwards
        #[arg(long)]
        before_epoch: Option<u64>,
        /// Output full base64 key instead of truncated
        #[arg(long)]
        key: bool,
    },
}

pub(crate) fn run(
    cmd: Commands,
    client: &dyn crate::client::BtClient,
    cloudflare: &crate::cloudflare_client::CloudflareClient,
) -> anyhow::Result<()> {
    match cmd {
        Commands::Audit { namespace, epoch } => audit::run(client, cloudflare, &namespace, epoch),
        Commands::Namespaces => namespaces::run(),
        Commands::Proofs {
            namespace,
            format,
            limit,
            before_epoch,
        } => proofs::run(
            proofs::ProofsArgs {
                namespace,
                format,
                limit: Some(limit),
                before_epoch,
            },
            client,
        ),
        Commands::Proof {
            namespace,
            epoch,
            format,
        } => proof::run(
            proof::ProofArgs {
                namespace,
                epoch,
                format,
            },
            client,
        ),
        Commands::Artifacts {
            proof_id,
            format,
            limit,
            after,
        } => artifacts::run(
            artifacts::ArtifactsArgs {
                proof_id,
                format,
                limit: Some(limit),
                after,
            },
            client,
        ),
        Commands::Artifact { id, format } => {
            artifact::run(artifact::ArtifactArgs { id, format }, client)
        }
        Commands::ArtifactDownload { id, output } => artifact_download::run(
            artifact_download::ArtifactDownloadArgs { id, output },
            client,
        ),
        Commands::VerifyDigest {
            file,
            digest,
            algorithm,
            encoding,
        } => verify_digest::run(verify_digest::VerifyDigestArgs {
            file,
            digest,
            algorithm,
            encoding,
        }),
        Commands::VerifySignature {
            digest,
            signature,
            serialized_message,
            key_id,
            key,
        } => verify_signature::run(verify_signature::VerifySignatureArgs {
            digest,
            signature,
            serialized_message,
            key_id,
            key,
        }),
        Commands::VerifyNamespace { namespace, limit } => {
            verify_namespace::run(client, cloudflare, &namespace, limit)
        }
        Commands::EbVerifyNamespace {
            limit,
            before_epoch,
            key,
        } => eb_verify_namespace::run(
            client,
            cloudflare,
            eb_verify_namespace::EbVerifyNamespaceArgs {
                limit,
                before_epoch,
                show_full_key: key,
            },
        ),
    }
}
