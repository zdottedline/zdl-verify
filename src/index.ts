/**
 * Public programmatic API.
 *
 * For users who want to embed verification in their own tools (e.g. a
 * custom audit dashboard), import from here:
 *
 *   import { verify } from "@zdottedline/verify";
 *   const result = await verify({ documentId, endpoint, ... });
 *
 * The CLI (bin/zdl) is a thin wrapper over this module.
 */

export { verify } from "./lib/orchestrator.js";
export type { OrchestratorOptions } from "./lib/orchestrator.js";
export type { VerifyOutcome, CheckResult, VerifyApiResponse } from "./lib/types.js";
export { resolveEndpoint, fetchVerifyJson, fetchOtsProof, VERSION } from "./lib/api.js";
export { resolvePolygonRpc, readAnchorOnChain } from "./lib/polygon.js";
export {
  decodeMultiCalendarWrapper,
  parseOtsProof,
  fetchBitcoinBlock,
  resolveBitcoinApi,
  digestMatchesBlockMerkleRoot,
} from "./lib/ots.js";
export { walkHashChain, computeMerkleRoot, sha256Hex, sha256File } from "./lib/hash.js";
