# zdl-verify

> **Independent verification CLI for ZDottedLine signed documents.**
> Confirms hash chain, Polygon anchor, and Bitcoin (OpenTimestamps) anchor.
> Open source. MIT-licensed. **No dependency on ZDottedLine infrastructure.**

If ZDottedLine, Inc. ceases to exist tomorrow, every signed document remains independently verifiable using this tool, the published spec, the signed PDF, and any public Bitcoin / Polygon node.

That's the whole point.

[Spec v1.0](./SPEC.md) | [Issues](https://github.com/zdottedline/zdl-verify/issues) | [npm](https://www.npmjs.com/package/@zdottedline/verify)

---

## Install

```bash
npm install -g @zdottedline/verify
```

Or run without installing:

```bash
npx @zdottedline/verify verify <document-id>
```

Requires **Node.js 20+**. No other dependencies beyond `commander` for CLI parsing.

## Quick start

```bash
$ zdl verify efca4f81-1ac4-4b40-a595-0dc51d0752c0

=== ZDL VERIFY === [VERIFIED]
  document: efca4f81-1ac4-4b40-a595-0dc51d0752c0
  endpoint: https://zdottedline.com

  [PASS] verify-endpoint    https://zdottedline.com/api/verify/efca4f81-...
  [PASS] hash-chain         4 events linked correctly
  [PASS] polygon-anchor     on-chain Merkle root matches (block 54221098)
  [PASS] bitcoin-anchor     confirmed at Bitcoin block 850123 — calendar: alice.btc

  Result: VERIFIED. The signed document's integrity is independently confirmed
  via public Polygon RPC + public Bitcoin block data. ZDottedLine does not
  need to be in the loop for this verification to be valid.
```

## What this tool does

```
                              You
                               |
                               | (1) GET verify JSON
                               v
                    +-------------------+
                    | zdottedline.com   |  ← only this one server call to ZDL
                    +-------------------+
                               |
                  ┌────────────┼─────────────┐
                  | (2)         (3)          (4)
                  v            v             v
            (hash chain)  Polygon RPC     Bitcoin API
              [LOCAL]     [PUBLIC]         [PUBLIC]
                          polygon-rpc.com   blockstream.info
                          (or yours)        (or yours)
                  |            |             |
                  v            v             v
              VERIFIED     VERIFIED      VERIFIED
```

Step 1 retrieves the document's hash chain + on-chain anchor references. Steps 2-4 perform the cryptographic checks against **public networks**. ZDottedLine's server is involved in step 1 only, and only for read access to publicly-hashed data.

## Commands

### `zdl verify <documentId>`

Full verification: hash chain + Polygon anchor + Bitcoin anchor.

```bash
zdl verify efca4f81-1ac4-4b40-a595-0dc51d0752c0
zdl verify efca4f81-1ac4-4b40-a595-0dc51d0752c0 --json   # machine-readable
zdl verify efca4f81-1ac4-4b40-a595-0dc51d0752c0 --skip-bitcoin
```

**Exit codes:**
- `0` — verified
- `1` — failed
- `2` — partial (some anchors verified, others pending)

### `zdl info <documentId>`

Show the verify endpoint's JSON response without performing verification. Useful for debugging or for consuming the data in other tools.

```bash
zdl info efca4f81-1ac4-4b40-a595-0dc51d0752c0
zdl info efca4f81-1ac4-4b40-a595-0dc51d0752c0 --json
```

## Self-sufficient verification (highest trust)

By default, `zdl-verify` uses public RPCs / APIs for Polygon and Bitcoin. For verification with no third-party dependencies at all, point at your own nodes:

```bash
zdl verify <id> \
  --polygon-rpc http://localhost:8545 \
  --btc-api http://localhost:3000/api
```

Or via environment variables:

```bash
export ZDL_POLYGON_RPC=http://localhost:8545
export ZDL_BITCOIN_API=http://localhost:3000/api
zdl verify <id>
```

For self-hosted ZDottedLine deployments, also override the verify endpoint:

```bash
zdl verify <id> --endpoint https://signing.your-company.com
# or: export ZDL_VERIFY_ENDPOINT=...
```

## Programmatic use

```typescript
import { verify } from "@zdottedline/verify";

const result = await verify({
  documentId: "efca4f81-1ac4-4b40-a595-0dc51d0752c0",
  endpoint: "https://zdottedline.com",
  polygonRpc: "https://polygon-rpc.com",
  bitcoinApi: "https://blockstream.info/api",
});

console.log(result.overall); // "verified" | "partial" | "failed" | "not_found"
console.log(result.checks);  // detailed per-anchor results
```

Lower-level building blocks (`parseOtsProof`, `readAnchorOnChain`, `walkHashChain`, `computeMerkleRoot`) are also exported for custom integrations.

## How verification works

See [SPEC.md](./SPEC.md) for the full protocol specification (data formats, threat model, verification procedure).

The tl;dr:

- **Hash chain.** Every document event (created, signed, completed) is SHA-256-hashed along with the prior event's hash, forming a tamper-evident linked list. The tool walks this chain locally; any break is reported with the exact event index.
- **Polygon anchor.** The Merkle root of all events is committed to the `ZdottedlineAnchor` smart contract on Polygon. The tool reads this directly via `eth_call` against any public Polygon RPC and compares to the server-reported root.
- **Bitcoin anchor.** The same Merkle root is timestamped to Bitcoin via [OpenTimestamps](https://opentimestamps.org). The tool downloads the `.ots` proof, walks its operations, fetches the referenced Bitcoin block from any public Bitcoin API, and confirms the proof commits to that block's Merkle root.

Each anchor independently proves the document's state at its block's timestamp. Compromising verification would require an attacker to produce a Bitcoin block AND modify a Polygon contract AND tamper with the local hash chain, which is roughly equivalent to "solve cryptographic primitives that secure ~$1T of value."

## Why we built this

Most e-signature platforms tell you "we're tamper-proof" and ask you to trust their audit log. If the vendor goes away, gets breached, or simply changes their terms, the audit log goes with them.

We're trying to build the version where you don't have to trust us. The `.ots` proof file in your matter folder, plus this CLI, plus public Bitcoin and Polygon nodes, is sufficient to prove a document was signed at a specific moment — forever — with or without ZDottedLine, Inc. existing.

If you find a way to break that promise, [please open an issue](https://github.com/zdottedline/zdl-verify/issues). We mean it.

## Audit trail / contributing

This is a small codebase by design. Read it. Audit it. Fork it. PR it.

```
src/
├── cli.ts              ~120 lines  CLI dispatch
├── index.ts            ~20 lines   programmatic API exports
└── lib/
    ├── api.ts          ~60 lines   public verify endpoint client
    ├── hash.ts         ~80 lines   SHA-256 + Merkle + chain walker
    ├── polygon.ts      ~110 lines  ZdottedlineAnchor contract reader
    ├── ots.ts          ~280 lines  OpenTimestamps proof walker
    ├── orchestrator.ts ~190 lines  end-to-end coordinator
    └── types.ts        ~50 lines   shared types
```

Total: ~900 lines of TypeScript. No transitive dependencies beyond `commander` (CLI parsing).

## License

[MIT](./LICENSE) © ZDottedLine, Inc.
