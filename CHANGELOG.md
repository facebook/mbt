# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `audit`: digest comparison now decodes both Meta (base64 for early epochs, hex for newer epochs) and Cloudflare (hex) digests to bytes before comparing, so byte-equal digests no longer report a spurious `MISMATCH` for epochs 1–3.
- `proofs`: the `Next page` hint now prints the full reproducible command (`mbt proofs -n <namespace> --before-epoch <n>`) instead of just the partial flag, and is suppressed when the page already includes epoch 1 (where `--before-epoch 1` would always return an empty page).
- `eb-verify-namespace`: the `Next page` hint is suppressed when the last fetched epoch is 1, for the same reason.

### Changed

- `proofs --format json` and `artifacts --format json`: output is now a top-level array of items. The `paging` block was removed because the cursors are a CLI affordance that doesn't apply to JSON consumers.
- `artifacts`: the `Next page` table hint was removed (artifact pages have not exceeded the default page size in practice).

## [0.1.0] - Initial public release

- Verify the SHA-256 digest of an artifact (`verify-digest`).
- Verify the Cloudflare Ed25519 signature on a proof (`verify-signature`).
- Cross-verify a Meta proof against the Cloudflare AKD auditor (`audit`).
- End-to-end pipeline for the encrypted backup namespace: `eb-verify-namespace` (downloads each artifact, verifies digest + signature + Meta HSM counter-signature + Cloudflare cross-check, plus a fleet-key delta analysis across the verified epoch range).
- Generic verification pipeline for any namespace (`verify-namespace`).
- Browse the transparency log (`namespaces`, `proofs`, `proof`, `artifacts`, `artifact`).
- Download an artifact binary (`artifact-download`).
