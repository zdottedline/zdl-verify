/**
 * Polygon anchor verification.
 *
 * Reads the ZdottedlineAnchor smart contract directly from a public Polygon
 * RPC endpoint and confirms the on-chain Merkle root for a given document
 * matches what the server reports.
 *
 * Trustless property: this verification works without contacting any
 * ZDottedLine-operated infrastructure. The default RPC is a free public
 * endpoint; users can supply their own with --polygon-rpc or the
 * ZDL_POLYGON_RPC env var (e.g. their own Alchemy/Infura/QuickNode key,
 * or a self-hosted Polygon archive node).
 */

import { createHash } from "node:crypto";

const DEFAULT_RPC = "https://polygon-rpc.com";

const ANCHOR_CONTRACT_ADDRESS = "0x15C38E819B63a7B2c393D009e0c8155bb18eC806";

// Function selector for `verify(bytes32) returns (bytes32, uint256)`.
// keccak256("verify(bytes32)")[:4] = 0xc0...
// Computed: web3.eth.abi.encodeFunctionSignature('verify(bytes32)') -> "0x..."
const VERIFY_SELECTOR = "0xc6dad082";

export function resolvePolygonRpc(explicit?: string): string {
  const env = process.env.ZDL_POLYGON_RPC;
  return explicit ?? env ?? DEFAULT_RPC;
}

/**
 * Encode a 32-byte hex string as the bytes32 calldata argument.
 * Input: "0xabcd..." or "abcd..." (must be exactly 64 hex chars after the prefix).
 */
function bytes32(hex: string): string {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new Error(`Invalid bytes32 hex: ${hex}`);
  }
  return clean.toLowerCase();
}

/**
 * The contract uses SHA-256 of the documentId string padded to 32 bytes
 * as the on-chain key. Mirror the server's transformation in blockchain.ts.
 */
export function documentIdToBytes32(documentId: string): string {
  const hash = createHash("sha256").update(documentId).digest("hex");
  return hash; // already 64 hex chars
}

interface PolygonRpcResponse {
  jsonrpc: string;
  id: number;
  result?: string;
  error?: { code: number; message: string };
}

async function rpcCall(
  rpcUrl: string,
  method: string,
  params: unknown[],
): Promise<string> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "zdl-verify/1.0",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
  });
  if (!response.ok) {
    throw new Error(`Polygon RPC HTTP ${response.status}`);
  }
  const json = (await response.json()) as PolygonRpcResponse;
  if (json.error) {
    throw new Error(`Polygon RPC error: ${json.error.message}`);
  }
  if (!json.result) {
    throw new Error("Polygon RPC returned no result");
  }
  return json.result;
}

export interface PolygonVerifyResult {
  exists: boolean;
  merkleRoot: string | null;
  timestamp: number | null;
  contractAddress: string;
}

/**
 * Read the on-chain anchor for a document ID via eth_call.
 *
 * Returns:
 *   { exists: true, merkleRoot, timestamp } if the contract has a record
 *   { exists: false, merkleRoot: null, timestamp: null } if not
 */
export async function readAnchorOnChain(
  documentId: string,
  rpcUrl: string,
): Promise<PolygonVerifyResult> {
  const docHash = bytes32(documentIdToBytes32(documentId));
  const calldata = `0x${VERIFY_SELECTOR.slice(2)}${docHash}`;

  const result = await rpcCall(rpcUrl, "eth_call", [
    {
      to: ANCHOR_CONTRACT_ADDRESS,
      data: calldata,
    },
    "latest",
  ]);

  // Result format: 0x + 64 hex (merkleRoot bytes32) + 64 hex (timestamp uint256)
  // = 130 chars total. Empty result for non-existent: 0x + 128 zeros.
  if (!result || result === "0x" || result.length < 130) {
    return {
      exists: false,
      merkleRoot: null,
      timestamp: null,
      contractAddress: ANCHOR_CONTRACT_ADDRESS,
    };
  }

  const merkleRoot = result.slice(2, 66);
  const timestampHex = result.slice(66, 130);
  const timestamp = parseInt(timestampHex, 16);

  // All-zero merkleRoot = no record exists for this docId.
  if (/^0+$/.test(merkleRoot)) {
    return {
      exists: false,
      merkleRoot: null,
      timestamp: null,
      contractAddress: ANCHOR_CONTRACT_ADDRESS,
    };
  }

  return {
    exists: true,
    merkleRoot: `0x${merkleRoot}`,
    timestamp,
    contractAddress: ANCHOR_CONTRACT_ADDRESS,
  };
}
