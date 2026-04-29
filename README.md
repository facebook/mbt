# mbt — Meta Binary Transparency CLI

A command-line tool for independently verifying Meta's Binary Transparency log. Designed for external security researchers and third-party auditors who want to confirm that the artifacts Meta publishes match what is recorded in Cloudflare's independent transparency log.

## Set up

Install Rust via [rustup](https://rustup.rs/), the official toolchain installer:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

This installs `cargo` and `rustc` to `~/.cargo/bin` and adds it to your shell's PATH. Open a new shell (or `source "$HOME/.cargo/env"`) to pick up the change.

Clone the repository:

```bash
git clone https://github.com/facebook/mbt.git
cd mbt
```

Build and install the `mbt` binary:

```bash
cargo install --path .
```

Verify the install:

```bash
mbt --version
```

## Quick Start

```bash
# Run the full encrypted backup verification pipeline (50 most recent epochs by default)
mbt eb-verify-namespace

# Verify a specific number of epochs
mbt eb-verify-namespace --limit 10

# Paginate to older epochs
mbt eb-verify-namespace --before-epoch 51 --limit 50

# Show full base64 keys in the delta table (instead of the truncated default)
mbt eb-verify-namespace --key
```

## How Verification Works

The `eb-verify-namespace` command is a dedicated end-to-end verifier for the encrypted backup namespace (`meta.encrypted_backups.fleet_keys.v1`).

It runs in two phases:

**Phase 1 — Verification** (per epoch, including Meta HSM counter-signature):

```
proof               → fetch proof detail (digest, signature, epoch, meta_signature)
    ↓
artifact-download   → download the fleet key artifact binary
    ↓
verify-digest       → SHA256 hash of downloaded file vs. proof metadata
    ↓
verify-signature    → Cloudflare Ed25519 signature verification
    ↓
counter-signature   → Meta HSM counter-signature on Cloudflare's signature bytes
    ↓
audit               → cross-verify proof against Cloudflare's independent log
```

**Phase 2 — Fleet Key Delta Analysis** (across all verified epochs):

```
parse fleet keys    → decode each artifact as fleet key JSON (keys + roles)
    ↓
baseline            → establish oldest epoch in batch as baseline
    ↓
walk forward        → diff each subsequent epoch against the previous one
    ↓
report deltas       → + key added, - key removed, ~ role changed
```

The output is a single unified table where each row represents one fleet key at one epoch. The columns are `Epoch | Change | Roles | Key`. The `Change` column takes one of four values: `baseline` (key present at the first verified epoch), `+` (added), `~` (roles changed — the Roles cell shows `old → new`), or `-` (removed). The Key column shows a truncated base64 key by default; pass `--key` to print the full base64 key. Other fields present in the artifact JSON (such as `padding`) are ignored.

## Commands

Commands are listed in the order the verification pipeline executes them.

---

### namespaces

List all available namespaces in the transparency log.

```bash
mbt namespaces
```

---

### proofs

List recent proofs for a namespace. Each proof represents a signed snapshot (epoch) of the transparency log.

```bash
mbt proofs -n <namespace>
mbt proofs -n <namespace> --limit 50 -f json
mbt proofs -n <namespace> --limit 20 --before-epoch 51
```

| Flag | Description |
|------|-------------|
| `-n, --namespace` | Namespace to query (required) |
| `-f, --format` | Output format: `table` (default) or `json` |
| `--limit` | Maximum results to return (default: 10) |
| `--before-epoch` | Start from this epoch (exclusive), going backwards |

When more proofs exist beyond the current page, the table output prints a `Next page: --before-epoch <N>` hint where `<N>` is the smallest epoch in the current page; passing it back to `--before-epoch` fetches strictly older proofs.

---

### proof

Fetch detailed information for a specific proof by namespace and epoch number. Returns the digest, signature, signer, timestamp, and linked artifact ID.

```bash
mbt proof -n <namespace> -e 49
mbt proof -n <namespace> -e 49 -f json
```

| Flag | Description |
|------|-------------|
| `-n, --namespace` | Namespace to query (required) |
| `-e, --epoch` | Epoch number (required) |
| `-f, --format` | Output format: `table` (default) or `json` |

---

### artifacts

List artifacts linked to a specific proof. Each proof typically has one artifact (the binary that was signed).

```bash
mbt artifacts -p <proof_id>
mbt artifacts -p <proof_id> --limit 5 -f json
```

| Flag | Description |
|------|-------------|
| `-p, --proof-id` | Proof ID to query (required) |
| `-f, --format` | Output format: `table` (default) or `json` |
| `--limit` | Maximum results to return (default: 10) |
| `--after` | Pagination cursor from a previous response |

---

### artifact

Fetch detailed metadata for a single artifact by ID, including namespace, digest, digest algorithm, and download URL.

```bash
mbt artifact --id <artifact_id>
mbt artifact --id <artifact_id> -f json
```

| Flag | Description |
|------|-------------|
| `--id` | Artifact ID (required) |
| `-f, --format` | Output format: `table` (default) or `json` |

---

### artifact-download

Download the raw binary for an artifact. Writes to a file or stdout.

```bash
# Download to a file
mbt artifact-download --id <artifact_id> -o artifact.bin

# Download to stdout (pipe to another tool)
mbt artifact-download --id <artifact_id> | sha256sum
```

| Flag | Description |
|------|-------------|
| `--id` | Artifact ID (required) |
| `-o, --output` | Output file path (default: stdout) |

---

### verify-digest

Verify the SHA256 digest of a downloaded file against an expected value. This confirms the binary you downloaded is byte-for-byte identical to what was recorded in the proof.

```bash
mbt verify-digest -f artifact.bin -d <expected_digest_hex>
mbt verify-digest -f artifact.bin -d <expected_digest> -a sha256 -e base64
```

| Flag | Description |
|------|-------------|
| `-f, --file` | Path to the downloaded file (required) |
| `-d, --digest` | Expected digest string (required) |
| `-a, --algorithm` | Hash algorithm (default: `sha256`) |
| `-e, --encoding` | Digest encoding: `hex`, `hex_lowercase`, `hex_uppercase`, `base64` (default: `hex`) |

Exit code 0 = match, exit code 1 = mismatch.

---

### verify-signature

Verify the Cloudflare Ed25519 signature on a proof. Confirms the proof was signed by Cloudflare's key and has not been tampered with.

```bash
mbt verify-signature \
  -d <digest_hex> \
  -s <signature_base64> \
  -m <serialized_message_base64> \
  --key-id 212
```

| Flag | Description |
|------|-------------|
| `-d, --digest` | Expected digest hex string (required) |
| `-s, --signature` | Signature base64 string (required) |
| `-m, --serialized-message` | Serialized message base64 string (required) |
| `--key-id` | Cloudflare key ID to look up embedded public key |
| `-k, --key` | Custom public key hex (overrides embedded key lookup) |

You can get the digest, signature, and serialized message from the `proof` command output.

---

### audit

Cross-verify a single proof between Meta's API and Cloudflare's independent AKD auditor log. Compares namespace, epoch, digest, signature, and serialized message across both sources.

```bash
mbt audit -n <namespace> -e 49
```

| Flag | Description |
|------|-------------|
| `-n, --namespace` | Namespace to query (required) |
| `-e, --epoch` | Epoch number to cross-verify (required) |

Prints a side-by-side comparison showing match/mismatch for each field.

---

### verify-namespace

The primary command. Runs the full verification pipeline across recent proofs for a namespace. For each proof it:

1. Fetches proof details (digest, signature, epoch)
2. Fetches the linked artifact metadata
3. Downloads the artifact binary
4. Verifies the SHA256 digest matches the proof
5. Verifies the Cloudflare Ed25519 signature
6. Verifies the Meta HSM counter-signature (for namespaces that require it)
7. Cross-verifies the proof against Cloudflare's independent log

```bash
# Verify the latest proof
mbt verify-namespace -n <namespace>

# Verify the 50 most recent proofs
mbt verify-namespace -n <namespace> -l 50

# Verify all 200 allowed in a single run
mbt verify-namespace -n <namespace> -l 200
```

| Flag | Description |
|------|-------------|
| `-n, --namespace` | Namespace to verify (required) |
| `-l, --limit` | Number of most recent proofs to verify, 1–200 (default: 1) |

**Output example:**

```
Verifying epoch 49 (1/3)... ✓
Verifying epoch 48 (2/3)... ✓
Verifying epoch 47 (3/3)... ✓

✓ All 3 proofs verified for <namespace>
```

If any proof fails:

```
✗ 2/3 proofs verified for <namespace>

Epoch  Step
─────  ───────────────────
48     Digest verification
```

---

### eb-verify-namespace

End-to-end verification command for the encrypted backup namespace (`meta.encrypted_backups.fleet_keys.v1`). Runs the full verification pipeline (same 7 steps as `verify-namespace`, including Meta HSM counter-signature) plus a fleet key delta analysis phase. The namespace is hardcoded — no `--namespace` flag is needed.

```bash
# Verify the 50 most recent epochs (default)
mbt eb-verify-namespace

# Verify a specific number of epochs
mbt eb-verify-namespace --limit 100

# Paginate to older epochs
mbt eb-verify-namespace --before-epoch 51 --limit 50

# Show full base64 keys (instead of truncated)
mbt eb-verify-namespace --key
```

| Flag | Description |
|------|-------------|
| `-l, --limit` | Number of epochs to verify, 1–200 (default: 50) |
| `--before-epoch` | Start from this epoch (exclusive), going backwards |
| `--key` | Output full base64 key instead of truncated |

**Output example:**

```
Verifying epoch 100 (1/50)... ✓
Verifying epoch 99 (2/50)... ✓
...

✓ All 50 proofs verified for meta.encrypted_backups.fleet_keys.v1

Fleet Keys (epochs 51 → 100):

Epoch  Change    Roles                     Key
─────  ────────  ────────────────────────  ──────────────
51     baseline  Login, Register           MIIBIjANBgkq...
51     baseline  Login                     MIICIjANBgkq...
51     baseline  Register                  MIIDIjANBgkq...
62     +         Register                  MIIEIjANBgkq...
75     ~         Login, Register → Login   MIIBIjANBgkq...
88     -         Login                     MIICIjANBgkq...
```

The Key column shows the first 12 characters of the base64-encoded key followed by `...`. Pass `--key` to print the full base64 key string in each row.

## License

`mbt` is dual-licensed under your choice of either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in `mbt` by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.
