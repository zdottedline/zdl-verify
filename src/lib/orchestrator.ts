/**
 * Verification orchestrator.
 *
 * Fetches the public verify JSON for a document, then independently
 * confirms each anchor:
 *
 *   1. Hash chain: walks every event's previousHash → dataHash linkage.
 *   2. Polygon: reads the ZdottedlineAnchor contract directly via a public
 *      RPC and compares the on-chain Merkle root to the server-reported one.
 *   3. Bitcoin (OTS): downloads the .ots proof, walks the proof operations,
 *      fetches the Bitcoin block header from a public Bitcoin API, and
 *      confirms the proof commits to that block's Merkle root.
 *
 * Each check is independent — partial verification is reported when some
 * anchors are not yet upgraded (e.g. Bitcoin proof still pending).
 */

import { fetchOtsProof, fetchVerifyJson } from "./api.js";
import { walkHashChain } from "./hash.js";
import { readAnchorOnChain } from "./polygon.js";
import {
  decodeMultiCalendarWrapper,
  digestMatchesBlockMerkleRoot,
  fetchBitcoinBlock,
  parseOtsProof,
} from "./ots.js";
import type { CheckResult, VerifyApiResponse, VerifyOutcome } from "./types.js";

export interface OrchestratorOptions {
  documentId: string;
  endpoint: string;
  polygonRpc: string;
  bitcoinApi: string;
  skipPolygon?: boolean;
  skipBitcoin?: boolean;
}

export async function verify(opts: OrchestratorOptions): Promise<VerifyOutcome> {
  const checks: CheckResult[] = [];
  const warnings: string[] = [];

  // -------- Step 1: fetch the public verify JSON --------
  let api: VerifyApiResponse;
  try {
    const res = await fetchVerifyJson(opts.documentId, opts.endpoint);
    if (res.status === 404) {
      return {
        documentId: opts.documentId,
        endpoint: opts.endpoint,
        overall: "not_found",
        checks: [
          {
            name: "verify-endpoint",
            ok: false,
            detail: `Document not found at ${opts.endpoint}`,
          },
        ],
        warnings,
      };
    }
    if (res.status !== 200) {
      return {
        documentId: opts.documentId,
        endpoint: opts.endpoint,
        overall: "failed",
        checks: [
          {
            name: "verify-endpoint",
            ok: false,
            detail: `HTTP ${res.status}: ${JSON.stringify(res.body).slice(0, 200)}`,
          },
        ],
        warnings,
      };
    }
    api = res.body as VerifyApiResponse;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      documentId: opts.documentId,
      endpoint: opts.endpoint,
      overall: "failed",
      checks: [{ name: "verify-endpoint", ok: false, detail: msg }],
      warnings,
    };
  }

  checks.push({
    name: "verify-endpoint",
    ok: true,
    detail: `${opts.endpoint}/api/verify/${opts.documentId}`,
    data: { spec: api.spec, specVersion: api.specVersion },
  });

  // -------- Step 2: hash chain --------
  if (api.events && api.events.length > 0) {
    const result = walkHashChain(api.events);
    checks.push({
      name: "hash-chain",
      ok: result.valid,
      detail: result.valid
        ? `${result.length} events linked correctly`
        : `chain broken at event #${result.brokenAt} of ${result.length}`,
      data: { length: result.length, brokenAt: result.brokenAt ?? null },
    });
  } else {
    warnings.push("no events present — document may be in a draft state");
  }

  // -------- Step 3: Polygon anchor (independent on-chain read) --------
  if (!opts.skipPolygon && api.polygon?.anchored) {
    try {
      const onChain = await readAnchorOnChain(opts.documentId, opts.polygonRpc);
      const matches =
        onChain.exists &&
        api.polygon.merkleRoot &&
        normalizeHex(onChain.merkleRoot ?? "") === normalizeHex(api.polygon.merkleRoot);
      checks.push({
        name: "polygon-anchor",
        ok: !!matches,
        detail: matches
          ? `on-chain Merkle root matches (block ${api.polygon.blockNumber}, tx ${api.polygon.transactionHash})`
          : onChain.exists
            ? `MISMATCH: on-chain root ${onChain.merkleRoot} ≠ server root ${api.polygon.merkleRoot}`
            : "contract has no record for this document ID",
        data: {
          onChain,
          server: api.polygon,
        },
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      checks.push({
        name: "polygon-anchor",
        ok: false,
        detail: `RPC error: ${msg}`,
      });
    }
  } else if (api.polygon && !api.polygon.anchored) {
    warnings.push("Polygon anchor not present (free/Starter tier; OTS-only)");
  }

  // -------- Step 4: Bitcoin (OTS) anchor --------
  if (!opts.skipBitcoin && api.bitcoin && api.bitcoin.status !== "none") {
    try {
      const proofBytes = await fetchOtsProof(opts.documentId, opts.endpoint);
      if (!proofBytes) {
        checks.push({
          name: "bitcoin-anchor",
          ok: false,
          detail: "OTS proof not available from server",
        });
      } else {
        const segments = decodeMultiCalendarWrapper(proofBytes);
        const merkleRoot = api.bitcoin.merkleRoot;
        if (!merkleRoot || merkleRoot.length !== 64) {
          throw new Error("OTS Merkle root missing from server response");
        }

        let bitcoinResult: CheckResult | null = null;
        let pendingCount = 0;
        const errors: string[] = [];

        for (const seg of segments) {
          try {
            const parsed = parseOtsProof(seg.proof, merkleRoot);
            const bitcoinAtt = parsed.attestations.find((a) => a.kind === "bitcoin");
            if (!bitcoinAtt) {
              pendingCount += 1;
              continue;
            }
            const block = await fetchBitcoinBlock(
              bitcoinAtt.bitcoinBlockHeight!,
              opts.bitcoinApi,
            );
            const ok = digestMatchesBlockMerkleRoot(bitcoinAtt.digest, block.merkleRoot);
            if (ok) {
              bitcoinResult = {
                name: "bitcoin-anchor",
                ok: true,
                detail: `confirmed at Bitcoin block ${block.height} (${block.hash}) — calendar: ${seg.calendar}`,
                data: {
                  block,
                  calendar: seg.calendar,
                },
              };
              break; // any one calendar verifying is sufficient
            }
            errors.push(`${seg.calendar}: digest does not match block merkle root`);
          } catch (segErr) {
            const msg = segErr instanceof Error ? segErr.message : String(segErr);
            errors.push(`${seg.calendar}: ${msg}`);
          }
        }

        if (bitcoinResult) {
          checks.push(bitcoinResult);
        } else if (pendingCount === segments.length && segments.length > 0) {
          checks.push({
            name: "bitcoin-anchor",
            ok: false,
            detail: `pending — none of ${segments.length} calendars have Bitcoin confirmation yet (typical first 6-24h)`,
            data: { pending: true, calendars: segments.map((s) => s.calendar) },
          });
        } else {
          checks.push({
            name: "bitcoin-anchor",
            ok: false,
            detail: `verification failed: ${errors.join("; ").slice(0, 400)}`,
            data: { errors },
          });
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      checks.push({ name: "bitcoin-anchor", ok: false, detail: msg });
    }
  } else if (api.bitcoin?.status === "none") {
    warnings.push(
      "no Bitcoin anchor present (document predates the multi-anchor architecture, or Bitcoin anchoring was disabled)",
    );
  }

  const required = checks.filter((c) =>
    ["hash-chain", "polygon-anchor", "bitcoin-anchor"].includes(c.name),
  );
  const allOk = required.length > 0 && required.every((c) => c.ok);
  const someOk = required.some((c) => c.ok);

  return {
    documentId: opts.documentId,
    endpoint: opts.endpoint,
    overall: allOk ? "verified" : someOk ? "partial" : "failed",
    checks,
    warnings,
  };
}

function normalizeHex(hex: string): string {
  return hex.toLowerCase().replace(/^0x/, "");
}
