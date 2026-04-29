# ZDL Verify Spec v1.0

**Status:** Stable
**Last Updated:** 2026-04-28
**Reference Implementation:** [`@zdottedline/verify`](https://github.com/zdottedline/zdl-verify)

> This document specifies the data formats, protocols, and verification procedure for ZDottedLine signed documents. It is the authoritative reference. The reference implementation can be replaced; this spec cannot.

---

## 1. Goals

The ZDL Verify protocol exists to make one promise structurally true:

> **A ZDottedLine-signed document remains independently verifiable indefinitely, with no dependence on ZDottedLine, Inc.**

To deliver that, every signed document is anchored to two independent public networks (Polygon + Bitcoin via OpenTimestamps) and the verification procedure is fully specified here so that any third party can reimplement it.

If ZDottedLine, Inc. ceases to exist tomorrow, every previously signed document remains verifiable using:

- This document
- A copy of the signed PDF
- A copy of the `.ots` proof file (downloadable from the verify endpoint, or from the signer's local files, or from anywhere they were preserved)
- Public read access to a Polygon RPC node and a Bitcoin node (or any of the dozens of free public APIs for either)

No private API. No vendor key. No license check.

---

## 2. Threat Model

The protocol defends against:

| Adversary | Defense |
|---|---|
| ZDottedLine going out of business | Polygon contract + Bitcoin OTS proofs both readable from public networks |
| ZDottedLine retroactively altering server records | On-chain Merkle root commits to the document's events at sign-time |
| Polygon Labs pivoting / chain reorg / vendor risk | Bitcoin is the secondary anchor; Polygon failure does not invalidate documents |
| OTS calendar operators going offline | Multiple calendars used for redundancy; any one verifying is sufficient |
| Forged "signed" documents (not actually signed via ZDottedLine) | Document hash must match, hash chain must link to genesis, on-chain Merkle root must match |
| Partial tampering (single event modified after the fact) | SHA-256 hash chain breaks at the modified event; verifyHashChain returns brokenAt |

The protocol does NOT defend against:

- Physical coercion of the signer
- Compromise of the signer's account credentials at signing time
- Bitcoin / Polygon both being compromised simultaneously by an attacker capable of >51% mining + >34% Polygon validator stake (cosmically improbable; out of scope)

---

## 3. Data Formats

### 3.1 Document Identifier

A UUID v4. Format: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` (lowercase hex, RFC 4122).

### 3.2 SHA-256 Hash Chain

Every meaningful document event (created, signed, completed) generates one entry in the chain. Each entry is computed as:

```
dataHash = SHA-256(JSON.stringify({
  prev: previousHash || "genesis",
  doc: documentId,
  event: eventType,
  data: eventData,
  ts: ISO8601Timestamp
}))
```

Where:
- `previousHash` is the `dataHash` of the immediately preceding entry, or `null` for the first entry (in which case the literal string `"genesis"` is used).
- `eventType` is one of `document_created`, `document_signed`, `document_completed`.
- `eventData` is an event-specific JSON object. Field order is preserved exactly (this matters because `JSON.stringify` is order-sensitive).
- `ts` is an ISO 8601 timestamp (e.g. `2026-04-28T23:35:13.645Z`).

A chain is **valid** iff every entry's recorded `previousHash` equals the prior entry's `dataHash`. The verifier MUST walk the chain in `createdAt` order and emit `valid: false` with a 1-based `brokenAt` index on the first violation.

### 3.3 Polygon Anchor

A Merkle root over the SHA-256 hashes of all events in the document's chain (as of completion time) is submitted to the `ZdottedlineAnchor` smart contract on Polygon mainnet:

```solidity
contract ZdottedlineAnchor {
    function anchorDocument(bytes32 documentId, bytes32 merkleRoot) external;
    function verify(bytes32 documentId)
        external view
        returns (bytes32 merkleRoot, uint256 timestamp);
}
```

- **Contract address:** `0x15C38E819B63a7B2c393D009e0c8155bb18eC806`
- **`documentId` parameter:** SHA-256 of the document UUID string, padded to 32 bytes (no leading `0x` in the hash; the contract takes `bytes32`).
- **`merkleRoot` parameter:** SHA-256 Merkle root over event `dataHash` values, computed per §3.4.
- **Network:** Polygon PoS mainnet (chain ID 137).

Verification: call `verify(documentIdBytes32)` via `eth_call` against any public Polygon RPC endpoint. Compare the returned `merkleRoot` to the server-reported one. The two MUST match.

Polygon anchoring is gated to Professional+ plans. Free and Starter tier documents will report `polygon.anchored: false`; this is not an error.

### 3.4 Merkle Root Computation

Algorithm (binary tree, SHA-256, hex concatenation):

```
function computeMerkleRoot(hashes: hex[]): hex {
    if (hashes.length == 0) return SHA-256("empty")
    if (hashes.length == 1) return hashes[0]
    const next = []
    for i in 0..hashes.length step 2:
        const left  = hashes[i]
        const right = hashes[i+1] ?? hashes[i]   // odd: pair last with itself
        next.push(SHA-256(left + right))         // hex strings concatenated as UTF-8
    return computeMerkleRoot(next)
}
```

Note: hashes are concatenated as **hex strings** (UTF-8), not as raw bytes. This matches the server's `computeMerkleRoot` in `apps/web/src/server/services/blockchain.ts` and is part of the spec — verifiers MUST use the same encoding.

### 3.5 OpenTimestamps Anchor

Bitcoin anchoring uses the [OpenTimestamps protocol](https://opentimestamps.org). At document completion, the SHA-256 Merkle root (§3.4) is submitted to multiple OTS calendars in parallel. Each calendar returns a partial proof committing the digest to a future Bitcoin block.

#### 3.5.1 Multi-Calendar Wrapper

To allow a single binary blob to carry proofs from multiple calendars, ZDottedLine wraps them with this format:

```
+---+----+-------+----+-------+----+-------+----+-------+
| 1 |  2 |  url  |  4 | proof | 2  |  url  |  4 | proof |
+---+----+-------+----+-------+----+-------+----+-------+
 ^   ^   ^        ^   ^
 |   |   |        |   per-calendar OTS proof bytes
 |   |   |        u32 BE: length of proof
 |   |   utf-8 calendar URL
 |   u16 BE: length of url
 u8: number of calendar segments
```

A standalone OTS proof file (per the standard OTS spec) begins with the magic bytes `\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94`. If the first byte is not `0x00` (i.e. not a standard OTS file header), the data is treated as a multi-calendar wrapper.

The reference implementation auto-detects which format it has been given.

#### 3.5.2 OTS Proof Walking

For each calendar segment, the verifier walks the OTS operation tree starting from the document's Merkle root:

- Operations: `OP_APPEND` (0xf0), `OP_PREPEND` (0xf1), `OP_REVERSE` (0xf2), `OP_HEXLIFY` (0xf3), `OP_SHA1` (0x02), `OP_RIPEMD160` (0x03), `OP_SHA256` (0x08), `OP_KECCAK256` (0x67).
- Forks: `0xff` byte begins a new branch.
- Attestations: `0x00` byte introduces an attestation. Attestations are tagged with an 8-byte prefix; the two relevant prefixes:
  - **Pending:** `83 df e3 0d 2e f9 0c 8e` — calendar URL follows; proof not yet on Bitcoin.
  - **Bitcoin Block Header:** `05 88 96 0d 73 d7 19 01` — varint block height follows.

When a Bitcoin attestation is reached:

1. Note the digest at that point in the walk.
2. Note the block height from the attestation.
3. Fetch the Bitcoin block header from any public Bitcoin API.
4. Confirm the walked digest equals the block's Merkle root (or its byte-reverse — Bitcoin little-endian quirk).

If the digest matches the block's Merkle root, the document was provably anchored to that Bitcoin block at that block's timestamp. Done.

If only Pending attestations are found, the proof has not yet been confirmed on-chain — typical for the first 6-24 hours after signing. The proof remains valid; just retry verification later.

The full OTS spec is at: https://github.com/opentimestamps/python-opentimestamps

### 3.6 Verify Endpoint Response Schema

`GET https://zdottedline.com/api/verify/{documentId}` returns JSON of this shape:

```typescript
{
  spec: "https://github.com/zdottedline/zdl-verify",
  specVersion: "1.0.0",
  documentId: string,                 // UUIDv4
  hashChain: {
    valid: boolean,
    length: number,
    latestHash: string | null,        // hex SHA-256
    brokenAt?: number                 // 1-based index of first chain failure
  },
  events: Array<{
    type: "document_created" | "document_signed" | "document_completed",
    network: "polygon" | "bitcoin_ots",
    dataHash: string,                 // hex SHA-256
    previousHash: string | null,      // hex SHA-256, null for genesis
    createdAt: string                 // ISO 8601 UTC
  }>,
  polygon: {
    anchored: boolean,
    transactionHash: string | null,   // 0x-prefixed
    blockNumber: number | null,
    merkleRoot: string | null,        // hex SHA-256, no 0x prefix
    polygonscanUrl: string | null
  },
  bitcoin: {
    anchored: boolean,                // true once status='upgraded'
    status: "none" | "pending" | "upgraded" | "failed",
    merkleRoot: string | null,        // hex SHA-256, no 0x prefix
    blockHeight: number | null,
    blockHash: string | null,
    upgradedAt: string | null,        // ISO 8601 UTC
    calendars: string[],
    proofDownloadUrl: string,         // typically "/api/verify/{id}?proof=ots"
    verifyInstructions?: string
  },
  notFound?: boolean                  // true if 404; other fields absent
}
```

Privacy: the response contains hashes, on-chain references, and timestamps — **no PII**. No signer emails, no IP addresses, no document title.

`GET https://zdottedline.com/api/verify/{documentId}?proof=ots` returns the binary OTS proof (per §3.5.1).

---

## 4. Verification Procedure

A conformant verifier MUST perform these checks in order. Each check is independent — a failure on one anchor does not invalidate other anchors.

1. **Fetch verify JSON** from the endpoint. Status 404 → not found. Status 200 → continue.
2. **Walk hash chain** per §3.2. Report `valid: true|false` with `brokenAt` if invalid.
3. **Polygon anchor**: if `polygon.anchored == true`, perform `eth_call` per §3.3 against any Polygon RPC and confirm the on-chain Merkle root matches `polygon.merkleRoot`.
4. **Bitcoin anchor**: if `bitcoin.status` is `upgraded` or `pending`, fetch the OTS proof, decode the wrapper per §3.5.1, walk each calendar segment per §3.5.2. Any one segment producing a Bitcoin attestation that matches the block's Merkle root is sufficient.

A document is **VERIFIED** iff: hash chain is valid AND every present anchor verifies.
A document is **PARTIAL** iff: hash chain is valid AND at least one anchor verifies (others may be pending or skipped).
A document is **FAILED** iff: hash chain is invalid OR a present anchor fails verification.
A document is **NOT FOUND** iff: the endpoint returns 404.

---

## 5. Spec Versioning

This is **v1.0.0**. Future versions follow [SemVer](https://semver.org):

- **MAJOR** bump: breaking change to data formats or verification procedure. Old verifiers won't validate new documents.
- **MINOR** bump: additive change (new fields, new optional anchors). Old verifiers continue to validate documents at the level they understand.
- **PATCH** bump: clarifications, typo fixes, normative editorial changes.

The current spec version is reported in the `specVersion` field of every verify endpoint response.

---

## 6. Reference Implementation

[`github.com/zdottedline/zdl-verify`](https://github.com/zdottedline/zdl-verify) — TypeScript / Node.js, MIT-licensed.

Install: `npm install -g @zdottedline/verify`

Use:
```
zdl verify <documentId>
zdl verify <documentId> --json
zdl verify <documentId> --polygon-rpc https://your-node --btc-api https://your-node
zdl info <documentId>
```

The reference implementation is deliberately small and audit-friendly. It depends on:

- Node 20+ (for built-in `fetch`, `crypto`, `Buffer`)
- `commander` (CLI argument parsing)

That's it. No transitive dependency on ZDottedLine, no telemetry, no auto-update.

---

## 7. Errata, Discussion, Future Work

Open issues, spec discussion, and proposed amendments live in the GitHub repo Issues. Anyone can open a discussion. Spec changes go through PR review with at least one ZDottedLine maintainer + at least one external reviewer before merge.

Known limitations of v1.0:

- The OTS proof walker handles linear (single-attestation-per-branch) proofs, which is the common case for our calendars. Multi-attestation forking proofs verify the first Bitcoin attestation found; this is sufficient for our use case but is technically a subset of the full OTS protocol.
- The Bitcoin block API is fetched via HTTPS by default — for the highest-trust verification, point `--btc-api` at your own Bitcoin Core full node.
- The Polygon RPC is similarly fetched via HTTPS — point `--polygon-rpc` at your own Polygon full node for full self-sufficient verification.

---

*ZDottedLine, Inc. — 2026.*
