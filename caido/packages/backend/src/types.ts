/**
 * NDJSON protocol types for communicating with `titus serve`.
 * Mirrors the Go types in pkg/serve/types.go.
 */

// --- Requests ---

export interface ScanRequest {
  type: "scan";
  payload: {
    content: string;
    source: string;
  };
}

export interface ScanBatchRequest {
  type: "scan_batch";
  payload: {
    items: ContentItem[];
  };
}

export interface ValidateRequest {
  type: "validate";
  payload: {
    rule_id: string;
    secret: string;
    named_groups: Record<string, string>;
  };
}

export interface CloseRequest {
  type: "close";
  payload: Record<string, never>;
}

export type TitusRequest =
  | ScanRequest
  | ScanBatchRequest
  | ValidateRequest
  | CloseRequest;

export interface ContentItem {
  source: string;
  content: string;
}

// --- Responses ---

export interface TitusResponse {
  success: boolean;
  type: "ready" | "scan" | "scan_batch" | "validate" | "error";
  data?: unknown;
  error?: string;
}

export interface ReadyData {
  version: string;
}

export interface ScanData {
  matches: TitusMatch[] | null;
}

export interface ScanBatchData {
  results: Array<{
    source: string;
    matches: TitusMatch[] | null;
  }>;
}

export interface ValidateData {
  status: string;
  confidence: number;
  message: string;
  details?: Record<string, string>;
}

export interface TitusMatch {
  RuleID: string;
  RuleName: string;
  StructuralID: string;
  Groups: string[] | null; // base64-encoded capture groups
  NamedGroups: Record<string, string> | null; // base64-encoded named groups
  Snippet: {
    Before?: string;
    Matching?: string;
    After?: string;
  } | null;
  Location: {
    Offset: { Start: number; End: number };
    Source?: {
      Start?: { Line: number; Column: number };
      End?: { Line: number; Column: number };
    };
  } | null;
}

// --- Plugin state ---

export interface FindingRecord {
  ruleId: string;
  ruleName: string;
  secretPreview: string;
  secretContent: string;
  url: string;
  host: string;
  urls: Set<string>;
  occurrenceCount: number;
  firstSeen: string;
}

export interface ScanStats {
  totalScanned: number;
  totalFindings: number;
  uniqueFindings: number;
  isRunning: boolean;
  titusVersion: string;
}
