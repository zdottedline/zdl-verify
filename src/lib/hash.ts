/**
 * SHA-256 + Merkle tree helpers.
 *
 * Mirrors the algorithm in apps/web/src/server/services/blockchain.ts so
 * verification matches anchoring exactly. Any divergence between this file
 * and the server's implementation is a SPEC bug — fix the server, not this.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export function sha256Hex(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * Compute SHA-256 of a file by streaming. Used to hash signed PDFs without
 * loading them entirely into memory.
 */
export async function sha256File(path: string): Promise<string> {
  const buf = await readFile(path);
  return sha256Hex(buf);
}

/**
 * Build a Merkle tree from an array of hex hashes. Returns the root.
 *
 * Algorithm (must match server-side computeMerkleRoot exactly):
 *   - empty input → SHA-256("empty")
 *   - single input → input itself
 *   - otherwise pair adjacent hashes, hash the concatenation as hex, recurse
 *   - odd-length levels: pair the last hash with itself
 */
export function computeMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) return sha256Hex("empty");
  if (hashes.length === 1) return hashes[0]!;

  const next: string[] = [];
  for (let i = 0; i < hashes.length; i += 2) {
    const left = hashes[i]!;
    const right = hashes[i + 1] ?? left;
    next.push(sha256Hex(left + right));
  }
  return computeMerkleRoot(next);
}

/**
 * Compute the chain hash for an event, matching server-side createChainHash.
 *
 * SHA256 over JSON.stringify({ prev, doc, event, data, ts }) — order-stable
 * because keys are inserted in the same order on both sides.
 */
export function computeChainHash(params: {
  previousHash: string | null;
  documentId: string;
  eventType: string;
  data: Record<string, unknown>;
  timestamp: string;
}): string {
  return sha256Hex(
    JSON.stringify({
      prev: params.previousHash ?? "genesis",
      doc: params.documentId,
      event: params.eventType,
      data: params.data,
      ts: params.timestamp,
    }),
  );
}

/**
 * Walk a hash chain (events in createdAt order) and report whether each
 * link is intact.
 *
 * Returns valid=true if every entry's previousHash matches the prior
 * entry's dataHash. brokenAt is the (1-based) index of the first failure.
 */
export function walkHashChain(
  events: Array<{ dataHash: string; previousHash: string | null }>,
): { valid: boolean; length: number; brokenAt?: number } {
  if (events.length === 0) return { valid: true, length: 0 };
  for (let i = 1; i < events.length; i++) {
    const cur = events[i]!;
    const prev = events[i - 1]!;
    if (cur.previousHash !== prev.dataHash) {
      return { valid: false, length: events.length, brokenAt: i };
    }
  }
  return { valid: true, length: events.length };
}
