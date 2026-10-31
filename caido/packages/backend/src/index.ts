/**
 * Titus Secret Scanner - Caido Backend Plugin
 *
 * Scans HTTP response (and optionally request) content for secrets using
 * the Titus detection engine via its `titus serve` NDJSON subprocess.
 *
 * Architecture mirrors the Burp Suite extension:
 *   1. Spawns `titus serve` as a long-lived subprocess
 *   2. Intercepts HTTP responses flowing through the Caido proxy
 *   3. Filters out non-scannable content (images, fonts, etc.)
 *   4. Sends scannable content to Titus via NDJSON over stdin/stdout
 *   5. Reports findings via Caido's findings API
 *   6. Deduplicates findings across URLs
 */

import type { SDK, DefineAPI } from "caido:plugin";
import { TitusScanner } from "./scanner.js";
import { FastPathFilter } from "./filter.js";
import { DedupCache } from "./dedup.js";
import type { TitusMatch, ScanStats, FindingRecord } from "./types.js";

// --- State ---

let scanner: TitusScanner | null = null;
let filter: FastPathFilter;
let dedupCache: DedupCache;
let stats: ScanStats = {
  totalScanned: 0,
  totalFindings: 0,
  uniqueFindings: 0,
  isRunning: false,
  titusVersion: "unknown",
};

// Settings
let passiveScanEnabled = true;
let scanRequests = false;
let scopeOnly = false;

// --- Helpers ---

/**
 * Decode a base64-encoded string, returning the UTF-8 text.
 * Uses atob() which is available in most JS runtimes including QuickJS.
 */
function decodeBase64(b64: string): string {
  try {
    return Buffer.from(b64, "base64").toString("utf-8");
  } catch {
    return b64;
  }
}

/**
 * Extract the matched secret content from a Titus match.
 * Mirrors TitusProcessScanner.java's parseMatch logic.
 */
function extractMatchContent(match: TitusMatch): string {
  // Prefer NamedGroups (current Titus convention)
  if (match.NamedGroups) {
    const values = Object.values(match.NamedGroups);
    if (values.length > 0 && values[0]) {
      return decodeBase64(values[0]);
    }
  }

  // Fall back to positional Groups
  if (match.Groups && match.Groups.length > 0) {
    return decodeBase64(match.Groups[0]!);
  }

  // Fall back to Snippet.Matching
  if (match.Snippet?.Matching) {
    return decodeBase64(match.Snippet.Matching);
  }

  return "[no content]";
}

/**
 * Determine severity from rule ID category.
 * Mirrors SeverityConfig.java's category-based severity mapping.
 */
function getSeverity(
  ruleId: string
): "info" | "low" | "medium" | "high" {
  const lower = ruleId.toLowerCase();

  // Extract category from "np.category.number" pattern
  let category = "";
  if (lower.startsWith("np.")) {
    const parts = lower.split(".");
    category = parts[1] ?? "";
  }

  // High severity: cloud, auth, database, private keys
  const highCategories = [
    "aws", "azure", "gcp", "cloud", "auth", "oauth", "jwt",
    "database", "db", "postgres", "mysql", "mongodb",
    "private", "ssh", "rsa",
  ];
  if (highCategories.some((c) => category === c || lower.includes(c))) {
    return "high";
  }

  // Medium severity: third-party services
  const mediumCategories = [
    "slack", "github", "gitlab", "npm", "pypi",
    "password", "secret", "api",
  ];
  if (mediumCategories.some((c) => category === c || lower.includes(c))) {
    return "medium";
  }

  // Low severity: generic patterns
  if (category === "generic" || lower.includes("generic")) {
    return "low";
  }

  return "medium";
}

// --- API functions exposed to frontend ---

async function getStats(_sdk: SDK<API>): Promise<ScanStats> {
  return {
    ...stats,
    uniqueFindings: dedupCache.uniqueCount(),
    isRunning: scanner?.isAlive() ?? false,
    titusVersion: scanner?.getVersion() ?? "unknown",
  };
}

function getFindings(_sdk: SDK<API>): FindingRecord[] {
  return dedupCache.getAllFindings();
}

function clearFindings(_sdk: SDK<API>): void {
  dedupCache.clear();
  stats.totalFindings = 0;
  stats.uniqueFindings = 0;
}

function setPassiveScan(_sdk: SDK<API>, enabled: boolean): void {
  passiveScanEnabled = enabled;
}

function setScanRequests(_sdk: SDK<API>, enabled: boolean): void {
  scanRequests = enabled;
}

function setScopeOnly(_sdk: SDK<API>, enabled: boolean): void {
  scopeOnly = enabled;
}

function getSettings(
  _sdk: SDK<API>
): {
  passiveScanEnabled: boolean;
  scanRequests: boolean;
  scopeOnly: boolean;
} {
  return { passiveScanEnabled, scanRequests, scopeOnly };
}

// --- API definition ---

export type API = DefineAPI<{
  getStats: typeof getStats;
  getFindings: typeof getFindings;
  clearFindings: typeof clearFindings;
  setPassiveScan: typeof setPassiveScan;
  setScanRequests: typeof setScanRequests;
  setScopeOnly: typeof setScopeOnly;
  getSettings: typeof getSettings;
}>;

// --- Init ---

export async function init(sdk: SDK<API>) {
  filter = new FastPathFilter();
  dedupCache = new DedupCache();

  // Register API handlers for frontend communication
  sdk.api.register("getStats", getStats);
  sdk.api.register("getFindings", getFindings);
  sdk.api.register("clearFindings", clearFindings);
  sdk.api.register("setPassiveScan", setPassiveScan);
  sdk.api.register("setScanRequests", setScanRequests);
  sdk.api.register("setScopeOnly", setScopeOnly);
  sdk.api.register("getSettings", getSettings);

  // Initialize scanner
  scanner = new TitusScanner();
  try {
    await scanner.initialize();
    stats.isRunning = true;
    stats.titusVersion = scanner.getVersion();
    sdk.console.log(
      `Titus Secret Scanner initialized (v${scanner.getVersion()})`
    );
    sdk.console.log("  - Passive scanning: ENABLED");
    sdk.console.log("  - 444+ detection rules loaded");
  } catch (err) {
    sdk.console.error(
      `Failed to initialize Titus scanner: ${err instanceof Error ? err.message : String(err)}`
    );
    sdk.console.error(
      "Install titus to ~/.titus/titus or ensure it is on PATH."
    );
    sdk.console.error(
      "Download from: https://github.com/praetorian-inc/titus/releases"
    );
    return;
  }

  // Register passive scan handler on intercepted HTTP responses
  sdk.events.onInterceptResponse(async (sdk, request, response) => {
    if (!passiveScanEnabled || !scanner?.isAlive()) return;

    try {
      const url = request.getUrl();
      const host = request.getHost();

      // Scope filter: check if the request host is in scope
      if (scopeOnly) {
        const inScope = sdk.requests.inScope(url);
        if (!inScope) return;
      }

      // Get response body as string
      const responseBody = response.getBody();
      if (!responseBody) return;

      const bodyStr =
        typeof responseBody === "string"
          ? responseBody
          : new TextDecoder().decode(responseBody as ArrayBuffer);

      // Content-type filter
      const contentType = response.getHeader("content-type") ?? undefined;
      if (!filter.shouldScan(contentType, bodyStr.length)) return;

      // URL extension filter
      if (!filter.shouldScanUrl(url)) return;

      stats.totalScanned++;

      // Scan response body
      const matches = await scanner.scan(bodyStr, url);

      // Optionally scan request body
      let requestMatches: TitusMatch[] = [];
      if (scanRequests) {
        const requestBody = request.getBody();
        if (requestBody) {
          const reqStr =
            typeof requestBody === "string"
              ? requestBody
              : new TextDecoder().decode(requestBody as ArrayBuffer);
          const reqContentType =
            request.getHeader("content-type") ?? undefined;
          if (
            filter.shouldScan(reqContentType, reqStr.length) &&
            reqStr.length > 10
          ) {
            requestMatches = await scanner.scan(reqStr, `${url} [request]`);
          }
        }
      }

      const allMatches = [...matches, ...requestMatches];
      if (allMatches.length === 0) return;

      // Process matches
      for (const match of allMatches) {
        const secretContent = extractMatchContent(match);
        const isNew = dedupCache.recordIfNew(
          url,
          secretContent,
          match.RuleID,
          match.RuleName
        );

        stats.totalFindings++;

        if (isNew) {
          stats.uniqueFindings++;
          const severity = getSeverity(match.RuleID);

          // Create a Caido finding
          await sdk.findings.create({
            title: `${match.RuleName} detected`,
            description: [
              `**Rule:** ${match.RuleName} (\`${match.RuleID}\`)`,
              `**Secret:** \`${secretContent.substring(0, 40)}${secretContent.length > 40 ? "..." : ""}\``,
              `**URL:** ${url}`,
              `**Severity:** ${severity.toUpperCase()}`,
            ].join("\n\n"),
            reporter: "Titus Secret Scanner",
            request,
            dedupeKey: `titus-${match.RuleID}-${secretContent.substring(0, 64)}`,
          });

          // Notify frontend of new finding
          sdk.api.send("newFinding" as any, {
            ruleId: match.RuleID,
            ruleName: match.RuleName,
            secretPreview:
              secretContent.substring(0, 20) +
              (secretContent.length > 20 ? "..." : ""),
            url,
            host,
            severity,
          } as any);
        }
      }
    } catch (err) {
      // Log but don't crash on individual scan errors
      sdk.console.error(
        `Scan error: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  });

  sdk.console.log("Titus passive scanning registered on HTTP responses");
}
