/**
 * OpenTimestamps proof parser + verifier.
 *
 * Implements the subset of the OpenTimestamps protocol needed to verify
 * ZDottedLine proofs: linear operation chains terminating in a Bitcoin
 * Block Header attestation (or a Pending attestation, indicating the
 * proof has not yet been confirmed on-chain).
 *
 * Reference (Python implementation):
 *   https://github.com/opentimestamps/python-opentimestamps/blob/master/opentimestamps/core/timestamp.py
 *   https://github.com/opentimestamps/python-opentimestamps/blob/master/opentimestamps/core/op.py
 *   https://github.com/opentimestamps/python-opentimestamps/blob/master/opentimestamps/core/notary.py
 *
 * Wire-format unique to ZDottedLine:
 *   We POST a digest to multiple OTS calendars at sign time and concatenate
 *   their responses with a small wrapper so a single bytea column can hold
 *   N calendar proofs. zdl-verify decodes the wrapper, then walks each
 *   calendar's standard-OTS sub-proof.
 *
 *   Wrapper format (big-endian):
 *     [u8: count]
 *     [u16: url_len][url_utf8][u32: proof_len][proof_bytes]   * count
 */

import { createHash } from "node:crypto";

// ============================================================================
// Multi-calendar wrapper (ZDottedLine-specific)
// ============================================================================

export interface CalendarSegment {
  calendar: string;
  proof: Buffer;
}

export function decodeMultiCalendarWrapper(buf: Buffer): CalendarSegment[] {
  if (buf.length < 1) return [];
  // Heuristic: standard OTS proof files start with the magic
  // "\x00OpenTimestamps\x00\x00Proof\x00..." — if we see that, this is NOT
  // our wrapper and we treat it as a single standard proof.
  if (buf.length >= 31 && buf.slice(0, 16).toString("ascii", 0, 14) === "\x00OpenTimestamps") {
    return [{ calendar: "(embedded)", proof: buf }];
  }

  const segments: CalendarSegment[] = [];
  const count = buf.readUInt8(0);
  let off = 1;
  for (let i = 0; i < count; i++) {
    if (off + 2 > buf.length) break;
    const urlLen = buf.readUInt16BE(off);
    off += 2;
    if (off + urlLen > buf.length) break;
    const calendar = buf.slice(off, off + urlLen).toString("utf8");
    off += urlLen;
    if (off + 4 > buf.length) break;
    const proofLen = buf.readUInt32BE(off);
    off += 4;
    if (off + proofLen > buf.length) break;
    const proof = buf.slice(off, off + proofLen);
    off += proofLen;
    segments.push({ calendar, proof });
  }
  return segments;
}

// ============================================================================
// OTS varbytes (LEB128-style varint length prefix)
// ============================================================================

function readVarint(buf: Buffer, offset: number): { value: number; bytes: number } {
  let result = 0;
  let shift = 0;
  let bytes = 0;
  while (offset + bytes < buf.length && bytes < 9) {
    const b = buf[offset + bytes]!;
    bytes += 1;
    result |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) return { value: result, bytes };
    shift += 7;
    if (shift > 56) throw new Error("varint overflow");
  }
  throw new Error("varint: unexpected EOF");
}

function readVarbytes(buf: Buffer, offset: number): { bytes: Buffer; consumed: number } {
  const len = readVarint(buf, offset);
  const start = offset + len.bytes;
  const end = start + len.value;
  if (end > buf.length) throw new Error("varbytes: unexpected EOF");
  return { bytes: buf.slice(start, end), consumed: len.bytes + len.value };
}

// ============================================================================
// Operation tags + crypto
// ============================================================================

const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const OP_REVERSE = 0xf2; // deprecated
const OP_HEXLIFY = 0xf3; // deprecated

const OP_SHA1 = 0x02; // collision-broken; not trusted but parseable
const OP_RIPEMD160 = 0x03;
const OP_SHA256 = 0x08;
const OP_KECCAK256 = 0x67;

const TAG_ATTESTATION = 0x00;
const TAG_FORK = 0xff;

// Attestation tag prefixes (8 bytes each).
const ATT_PENDING = Buffer.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
const ATT_BITCOIN_BLOCK = Buffer.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);

// ============================================================================
// Proof file framing: standalone .ots files have a header before the timestamp.
// Calendar HTTP responses do NOT have the file header — they begin directly
// with the operation list.
// ============================================================================

const OTS_FILE_MAGIC = Buffer.from([
  // "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);

interface ProofFileHeader {
  version: number;
  fileHashOpTag: number;
  fileDigest: Buffer;
  bodyOffset: number;
}

function tryReadFileHeader(buf: Buffer): ProofFileHeader | null {
  if (buf.length < OTS_FILE_MAGIC.length + 2) return null;
  for (let i = 0; i < OTS_FILE_MAGIC.length; i++) {
    if (buf[i] !== OTS_FILE_MAGIC[i]) return null;
  }
  let off = OTS_FILE_MAGIC.length;
  const versionV = readVarint(buf, off);
  off += versionV.bytes;
  const fileHashOpTag = buf[off]!;
  off += 1;
  const digestSize = digestSizeForOp(fileHashOpTag);
  if (digestSize === 0) return null;
  if (off + digestSize > buf.length) return null;
  const fileDigest = buf.slice(off, off + digestSize);
  off += digestSize;
  return { version: versionV.value, fileHashOpTag, fileDigest, bodyOffset: off };
}

function digestSizeForOp(tag: number): number {
  switch (tag) {
    case OP_SHA1:
      return 20;
    case OP_RIPEMD160:
      return 20;
    case OP_SHA256:
      return 32;
    case OP_KECCAK256:
      return 32;
    default:
      return 0;
  }
}

// ============================================================================
// Walk the operation tree.
//
// We maintain a "current digest" stack and walk every branch. At each
// 0x00 (attestation) we emit the attestation along with the digest reached
// at that point. Forks (0xff) duplicate the current digest and walk both
// branches. Crypto ops update the digest.
// ============================================================================

export type AttestationKind = "pending" | "bitcoin" | "unknown";

export interface FoundAttestation {
  kind: AttestationKind;
  digest: Buffer;
  // For Pending: calendar URL string (utf-8).
  pendingCalendarUrl?: string;
  // For Bitcoin: block height.
  bitcoinBlockHeight?: number;
}

interface WalkState {
  buf: Buffer;
  off: number;
  attestations: FoundAttestation[];
}

function walkBranch(state: WalkState, currentDigest: Buffer): void {
  let digest = currentDigest;
  while (state.off < state.buf.length) {
    const tag = state.buf[state.off]!;
    state.off += 1;

    if (tag === TAG_ATTESTATION) {
      const att = readAttestation(state, digest);
      state.attestations.push(att);
      // After an attestation, if more bytes remain at this level they are
      // a sibling fork from a higher level — not our concern here. Return.
      return;
    }

    if (tag === TAG_FORK) {
      // Fork: walk one branch, then return so the caller (which sees the
      // remaining bytes after this fork closed) processes the next branch.
      // The Python ref serializes forks as:
      //   for op in ops[:-1]: 0xff <op-and-subtree>
      //   <last-op-and-subtree>     <-- no 0xff prefix
      // So we recursively walk this fork and then continue at the same
      // level for the next.
      walkBranch(state, digest);
      continue;
    }

    // Otherwise it's an op tag.
    digest = applyOp(state, tag, digest);
  }
}

function applyOp(state: WalkState, tag: number, digest: Buffer): Buffer {
  switch (tag) {
    case OP_APPEND: {
      const arg = readVarbytes(state.buf, state.off);
      state.off += arg.consumed;
      return Buffer.concat([digest, arg.bytes]);
    }
    case OP_PREPEND: {
      const arg = readVarbytes(state.buf, state.off);
      state.off += arg.consumed;
      return Buffer.concat([arg.bytes, digest]);
    }
    case OP_REVERSE: {
      const r = Buffer.from(digest);
      r.reverse();
      return r;
    }
    case OP_HEXLIFY: {
      return Buffer.from(digest.toString("hex"), "utf8");
    }
    case OP_SHA1:
      return createHash("sha1").update(digest).digest();
    case OP_RIPEMD160:
      return createHash("ripemd160").update(digest).digest();
    case OP_SHA256:
      return createHash("sha256").update(digest).digest();
    case OP_KECCAK256:
      throw new Error("KECCAK-256 op not supported by Node crypto (rare in OTS proofs)");
    default:
      throw new Error(`Unknown OTS op tag 0x${tag.toString(16)}`);
  }
}

function readAttestation(state: WalkState, digest: Buffer): FoundAttestation {
  const buf = state.buf;
  if (state.off + 8 > buf.length) {
    throw new Error("attestation: truncated tag prefix");
  }
  const prefix = buf.slice(state.off, state.off + 8);
  state.off += 8;
  // Attestation payload is length-prefixed varbytes containing the
  // attestation-specific encoding.
  const payload = readVarbytes(buf, state.off);
  state.off += payload.consumed;

  if (prefix.equals(ATT_PENDING)) {
    // Pending: payload contains a varbytes utf-8 calendar URL.
    const url = readVarbytes(payload.bytes, 0);
    return {
      kind: "pending",
      digest,
      pendingCalendarUrl: url.bytes.toString("utf8"),
    };
  }

  if (prefix.equals(ATT_BITCOIN_BLOCK)) {
    // Bitcoin: payload is a varint block height.
    const h = readVarint(payload.bytes, 0);
    return {
      kind: "bitcoin",
      digest,
      bitcoinBlockHeight: h.value,
    };
  }

  return { kind: "unknown", digest };
}

// ============================================================================
// Public: parse a calendar's OTS proof bytes (with or without file header)
// ============================================================================

export interface ParsedProof {
  initialDigest: Buffer;
  attestations: FoundAttestation[];
  fileHeader: ProofFileHeader | null;
}

export function parseOtsProof(buf: Buffer, initialDigestHex?: string): ParsedProof {
  const fileHeader = tryReadFileHeader(buf);
  let bodyOffset = 0;
  let initialDigest: Buffer;

  if (fileHeader) {
    bodyOffset = fileHeader.bodyOffset;
    initialDigest = fileHeader.fileDigest;
  } else {
    if (!initialDigestHex) {
      throw new Error(
        "Calendar response without file header — initial digest must be provided",
      );
    }
    if (!/^[0-9a-fA-F]{64}$/.test(initialDigestHex)) {
      throw new Error("initialDigestHex must be 64 hex chars (SHA-256)");
    }
    initialDigest = Buffer.from(initialDigestHex, "hex");
  }

  const state: WalkState = {
    buf,
    off: bodyOffset,
    attestations: [],
  };

  try {
    walkBranch(state, initialDigest);
  } catch (err) {
    // Surface parse errors but include any attestations we already collected.
    state.attestations.push({
      kind: "unknown",
      digest: initialDigest,
      // Stash the error in the digest hex via a helper — keep type clean.
    });
    throw err instanceof Error ? err : new Error(String(err));
  }

  return {
    initialDigest,
    attestations: state.attestations,
    fileHeader,
  };
}

// ============================================================================
// Bitcoin block verification.
//
// Fetch the block header from a public Bitcoin API and confirm the Merkle
// root commitment in the proof matches the block's actual Merkle root.
//
// Default API: blockstream.info (free, no auth). Override with --btc-api or
// the ZDL_BITCOIN_API env var (e.g. mempool.space, your own bitcoind, etc.).
// ============================================================================

const DEFAULT_BTC_API = "https://blockstream.info/api";

export function resolveBitcoinApi(explicit?: string): string {
  const env = process.env.ZDL_BITCOIN_API;
  return (explicit ?? env ?? DEFAULT_BTC_API).replace(/\/+$/, "");
}

export interface BitcoinBlockInfo {
  height: number;
  hash: string;
  merkleRoot: string;
  timestamp: number;
}

export async function fetchBitcoinBlock(
  height: number,
  apiBase: string,
): Promise<BitcoinBlockInfo> {
  const hashRes = await fetch(`${apiBase}/block-height/${height}`, {
    headers: { "User-Agent": "zdl-verify/1.0" },
  });
  if (!hashRes.ok) {
    throw new Error(`Bitcoin API: block-height/${height} → HTTP ${hashRes.status}`);
  }
  const hash = (await hashRes.text()).trim();

  const blockRes = await fetch(`${apiBase}/block/${hash}`, {
    headers: { Accept: "application/json", "User-Agent": "zdl-verify/1.0" },
  });
  if (!blockRes.ok) {
    throw new Error(`Bitcoin API: block/${hash} → HTTP ${blockRes.status}`);
  }
  const block = (await blockRes.json()) as {
    height: number;
    id: string;
    merkle_root: string;
    timestamp: number;
  };

  return {
    height: block.height,
    hash: block.id,
    merkleRoot: block.merkle_root,
    timestamp: block.timestamp,
  };
}

/**
 * Confirm that the digest produced by walking the OTS proof matches the
 * Bitcoin block's Merkle root.
 *
 * Note: Bitcoin Merkle roots in block headers are stored little-endian, but
 * APIs (and our walker output) typically present them big-endian. We
 * compare both orderings to be tolerant.
 */
export function digestMatchesBlockMerkleRoot(
  walkedDigest: Buffer,
  blockMerkleRootHex: string,
): boolean {
  const expected = blockMerkleRootHex.toLowerCase().replace(/^0x/, "");
  const got = walkedDigest.toString("hex").toLowerCase();
  if (got === expected) return true;
  const reversed = Buffer.from(walkedDigest);
  reversed.reverse();
  return reversed.toString("hex").toLowerCase() === expected;
}
