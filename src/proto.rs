/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

// Cloudflare SignatureMessage protobuf types, defined inline using prost derive macros.
// Field tags and types sourced from Cloudflare's open-source plexi repository:
// https://github.com/cloudflare/plexi/blob/main/plexi_core/src/proto/specs/types.proto

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Epoch {
    #[prost(uint64, tag = "1")]
    pub inner: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct SignatureMessage {
    #[prost(uint32, tag = "1")]
    pub ciphersuite: u32,
    #[prost(string, tag = "2")]
    pub namespace: String,
    #[prost(uint64, tag = "3")]
    pub timestamp: u64,
    #[prost(message, tag = "4")]
    pub epoch: Option<Epoch>,
    #[prost(bytes = "vec", tag = "5")]
    pub digest: Vec<u8>,
}

// Cloudflare SignatureResponse wraps a signature, the serialized SignatureMessage,
// and the key_id used to sign. Field tags sourced from Cloudflare's plexi repository.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct SignatureResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub serialized_message: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub key_id: u32,
}
