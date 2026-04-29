/**
 * ZDottedLine public verify endpoint client.
 *
 * Talks to GET /api/verify/{id} to fetch document state, and to
 * GET /api/verify/{id}?proof=ots to download the binary OTS proof.
 *
 * Default endpoint: https://zdottedline.com — overridable via --endpoint
 * flag or ZDL_VERIFY_ENDPOINT env var. Useful for self-hosters and
 * staging environments.
 */

import type { VerifyApiResponse } from "./types.js";

export const DEFAULT_ENDPOINT = "https://zdottedline.com";

export function resolveEndpoint(explicit?: string): string {
  const env = process.env.ZDL_VERIFY_ENDPOINT;
  return (explicit ?? env ?? DEFAULT_ENDPOINT).replace(/\/+$/, "");
}

export async function fetchVerifyJson(
  documentId: string,
  endpoint: string,
): Promise<{ status: number; body: VerifyApiResponse | { error?: string; message?: string } }> {
  const url = `${endpoint}/api/verify/${encodeURIComponent(documentId)}`;
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": `zdl-verify/${VERSION}`,
    },
  });
  const text = await response.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = { error: "invalid_response", message: text.slice(0, 200) };
  }
  return { status: response.status, body: body as VerifyApiResponse };
}

export async function fetchOtsProof(
  documentId: string,
  endpoint: string,
): Promise<Buffer | null> {
  const url = `${endpoint}/api/verify/${encodeURIComponent(documentId)}?proof=ots`;
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.opentimestamps.v1",
      "User-Agent": `zdl-verify/${VERSION}`,
    },
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Failed to fetch OTS proof: HTTP ${response.status}`);
  }
  const arr = await response.arrayBuffer();
  return Buffer.from(arr);
}

// Bumped on each release. Keep in sync with package.json version.
export const VERSION = "1.0.0";
