/**
 * Public types for the ZDL Verify protocol.
 *
 * The shape of the JSON returned by GET /api/verify/{id} is the source of
 * truth for what zdl-verify consumes. Mirrored here for type safety.
 *
 * Spec version: 1.0.0
 */

export interface VerifyApiResponse {
  spec: string;
  specVersion: string;
  documentId: string;
  hashChain?: {
    valid: boolean;
    length: number;
    latestHash: string | null;
    brokenAt?: number;
  };
  events?: Array<{
    type: string;
    network: string;
    dataHash: string;
    previousHash: string | null;
    createdAt: string;
  }>;
  polygon?: {
    anchored: boolean;
    transactionHash: string | null;
    blockNumber: number | null;
    merkleRoot: string | null;
    polygonscanUrl: string | null;
  };
  bitcoin?: {
    anchored: boolean;
    status: "none" | "pending" | "upgraded" | "failed";
    merkleRoot: string | null;
    blockHeight: number | null;
    blockHash: string | null;
    upgradedAt: string | null;
    calendars: string[];
    proofDownloadUrl: string;
    verifyInstructions?: string;
  };
  notFound?: boolean;
}

export interface CheckResult {
  name: string;
  ok: boolean;
  detail?: string;
  data?: Record<string, unknown>;
}

export interface VerifyOutcome {
  documentId: string;
  endpoint: string;
  overall: "verified" | "partial" | "failed" | "not_found";
  checks: CheckResult[];
  warnings: string[];
}
