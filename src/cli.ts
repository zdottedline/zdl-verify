#!/usr/bin/env node
/**
 * zdl — ZDottedLine independent verification CLI.
 *
 *   zdl verify <documentId>          # verify a document end-to-end
 *   zdl verify <documentId> --json   # machine-readable output
 *   zdl info <documentId>            # show document metadata only
 *   zdl --version | -v
 *
 * No login. No API key. No dependency on ZDottedLine infrastructure beyond
 * a single GET to the public verify endpoint to read the document's hash
 * chain. All cryptographic verification (Bitcoin block lookup, Polygon
 * contract read) happens against public networks via configurable RPCs.
 */

import { Command } from "commander";
import { verify } from "./lib/orchestrator.js";
import { resolveEndpoint, fetchVerifyJson, VERSION } from "./lib/api.js";
import { resolvePolygonRpc } from "./lib/polygon.js";
import { resolveBitcoinApi } from "./lib/ots.js";

const program = new Command();

program
  .name("zdl")
  .description(
    "Independent verification of ZDottedLine signed documents.\n" +
      "Confirms hash chain + Polygon anchor + Bitcoin (OpenTimestamps) anchor\n" +
      "without depending on ZDottedLine infrastructure.",
  )
  .version(VERSION, "-v, --version");

program
  .command("verify")
  .description("Verify a document by ID. Default output: human-readable.")
  .argument("<documentId>", "document UUID")
  .option(
    "-e, --endpoint <url>",
    "ZDottedLine verify endpoint (default: https://zdottedline.com or $ZDL_VERIFY_ENDPOINT)",
  )
  .option(
    "--polygon-rpc <url>",
    "Polygon JSON-RPC endpoint (default: https://polygon-rpc.com or $ZDL_POLYGON_RPC)",
  )
  .option(
    "--btc-api <url>",
    "Bitcoin block API base URL (default: https://blockstream.info/api or $ZDL_BITCOIN_API)",
  )
  .option("--skip-polygon", "skip the Polygon on-chain verification step")
  .option("--skip-bitcoin", "skip the Bitcoin (OTS) verification step")
  .option("--json", "emit machine-readable JSON")
  .action(
    async (
      documentId: string,
      options: {
        endpoint?: string;
        polygonRpc?: string;
        btcApi?: string;
        skipPolygon?: boolean;
        skipBitcoin?: boolean;
        json?: boolean;
      },
    ) => {
      const endpoint = resolveEndpoint(options.endpoint);
      const polygonRpc = resolvePolygonRpc(options.polygonRpc);
      const bitcoinApi = resolveBitcoinApi(options.btcApi);

      const outcome = await verify({
        documentId,
        endpoint,
        polygonRpc,
        bitcoinApi,
        skipPolygon: options.skipPolygon,
        skipBitcoin: options.skipBitcoin,
      });

      if (options.json) {
        process.stdout.write(JSON.stringify(outcome, null, 2) + "\n");
      } else {
        printHuman(outcome);
      }

      const exitCode =
        outcome.overall === "verified" ? 0 : outcome.overall === "partial" ? 2 : 1;
      process.exit(exitCode);
    },
  );

program
  .command("info")
  .description("Show document metadata from the public verify endpoint (no verification).")
  .argument("<documentId>", "document UUID")
  .option("-e, --endpoint <url>", "ZDottedLine verify endpoint")
  .option("--json", "emit machine-readable JSON")
  .action(
    async (
      documentId: string,
      options: { endpoint?: string; json?: boolean },
    ) => {
      const endpoint = resolveEndpoint(options.endpoint);
      const res = await fetchVerifyJson(documentId, endpoint);

      if (options.json) {
        process.stdout.write(JSON.stringify(res.body, null, 2) + "\n");
      } else {
        process.stdout.write(`Endpoint: ${endpoint}\nHTTP: ${res.status}\n`);
        process.stdout.write(JSON.stringify(res.body, null, 2) + "\n");
      }
      process.exit(res.status === 200 ? 0 : 1);
    },
  );

await program.parseAsync(process.argv);

// ---------------------------------------------------------------------------

function printHuman(outcome: {
  documentId: string;
  endpoint: string;
  overall: string;
  checks: Array<{ name: string; ok: boolean; detail?: string }>;
  warnings: string[];
}): void {
  const sym = (ok: boolean) => (ok ? "PASS" : "FAIL");
  const banner = bannerFor(outcome.overall);

  process.stdout.write(`\n${banner}\n`);
  process.stdout.write(`  document: ${outcome.documentId}\n`);
  process.stdout.write(`  endpoint: ${outcome.endpoint}\n\n`);

  for (const c of outcome.checks) {
    process.stdout.write(`  [${sym(c.ok)}] ${c.name.padEnd(18)} ${c.detail ?? ""}\n`);
  }

  if (outcome.warnings.length > 0) {
    process.stdout.write("\n  warnings:\n");
    for (const w of outcome.warnings) {
      process.stdout.write(`    - ${w}\n`);
    }
  }

  process.stdout.write("\n");
  if (outcome.overall === "verified") {
    process.stdout.write(
      "  Result: VERIFIED. The signed document's integrity is independently confirmed\n" +
        "  via public Polygon RPC + public Bitcoin block data. ZDottedLine does not\n" +
        "  need to be in the loop for this verification to be valid.\n",
    );
  } else if (outcome.overall === "partial") {
    process.stdout.write(
      "  Result: PARTIAL. Some anchors verified, others are still pending or skipped.\n" +
        "  This is normal in the first 6-24 hours after signing while the Bitcoin proof\n" +
        "  is being upgraded.\n",
    );
  } else if (outcome.overall === "not_found") {
    process.stdout.write(
      "  Result: NOT FOUND. The endpoint has no record of this document ID.\n",
    );
  } else {
    process.stdout.write(
      "  Result: FAILED. One or more anchors could not be verified — see check details above.\n",
    );
  }
  process.stdout.write("\n");
}

function bannerFor(overall: string): string {
  switch (overall) {
    case "verified":
      return "=== ZDL VERIFY === [VERIFIED]";
    case "partial":
      return "=== ZDL VERIFY === [PARTIAL]";
    case "not_found":
      return "=== ZDL VERIFY === [NOT FOUND]";
    default:
      return "=== ZDL VERIFY === [FAILED]";
  }
}
