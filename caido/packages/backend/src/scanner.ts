/**
 * TitusScanner - spawns `titus serve` and communicates via NDJSON.
 *
 * Mirrors the architecture of the Burp extension's TitusProcessScanner.java.
 * The titus binary must be installed on the system (e.g., ~/.titus/titus).
 */

import { spawn, type ChildProcess } from "child_process";
import { homedir } from "os";
import { join } from "path";
import { existsSync } from "fs";
import type {
  TitusRequest,
  TitusResponse,
  TitusMatch,
  ScanData,
  ScanBatchData,
  ValidateData,
  ReadyData,
  ContentItem,
} from "./types.js";

const READY_TIMEOUT_MS = 30_000;
const REQUEST_TIMEOUT_MS = 30_000;

interface PendingRequest {
  resolve: (resp: TitusResponse) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class TitusScanner {
  private process: ChildProcess | null = null;
  private initialized = false;
  private closed = false;
  private version = "unknown";
  private buffer = "";
  private pending: PendingRequest | null = null;
  private queue: Array<{
    request: TitusRequest;
    resolve: (resp: TitusResponse) => void;
    reject: (err: Error) => void;
  }> = [];

  /**
   * Find the titus binary on the system.
   * Searches common install locations, matching the Burp extension's logic.
   */
  static findBinary(): string | null {
    const home = homedir();
    const isWin = process.platform === "win32";
    const exe = isWin ? ".exe" : "";

    const paths = isWin
      ? [
          join(home, ".titus", `titus${exe}`),
          join(home, "bin", `titus${exe}`),
        ]
      : [
          join(home, ".titus", "titus"),
          join(home, "bin", "titus"),
          "/usr/local/bin/titus",
        ];

    for (const p of paths) {
      if (existsSync(p)) {
        return p;
      }
    }

    // Fall back to PATH lookup (spawn will resolve it)
    return "titus";
  }

  /**
   * Initialize the scanner by spawning the titus serve process.
   */
  async initialize(binaryPath?: string): Promise<void> {
    if (this.initialized) return;

    const titusPath = binaryPath ?? TitusScanner.findBinary();
    if (!titusPath) {
      throw new Error(
        "Titus binary not found. Install it to ~/.titus/titus or ensure it is on PATH."
      );
    }

    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.close();
        reject(new Error("Timeout waiting for titus serve ready signal"));
      }, READY_TIMEOUT_MS);

      try {
        this.process = spawn(titusPath, ["serve"], {
          stdio: ["pipe", "pipe", "pipe"],
        });
      } catch (err) {
        clearTimeout(timeout);
        reject(
          new Error(
            `Failed to spawn titus: ${err instanceof Error ? err.message : String(err)}`
          )
        );
        return;
      }

      this.process.on("error", (err) => {
        clearTimeout(timeout);
        this.rejectPending(new Error(`Titus process error: ${err.message}`));
        reject(new Error(`Titus process error: ${err.message}`));
      });

      this.process.on("exit", (code) => {
        if (!this.closed) {
          this.initialized = false;
          this.rejectPending(
            new Error(`Titus process exited unexpectedly (code ${code})`)
          );
        }
      });

      // Drain stderr to prevent backpressure stalls
      this.process.stderr?.on("data", () => {});

      // Read the ready signal from stdout
      const onData = (chunk: Buffer) => {
        this.buffer += chunk.toString("utf-8");
        const lines = this.buffer.split("\n");
        this.buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const resp: TitusResponse = JSON.parse(line);
            if (
              resp.success &&
              resp.type === "ready" &&
              !this.initialized
            ) {
              const data = resp.data as ReadyData;
              this.version = data?.version ?? "unknown";
              this.initialized = true;
              clearTimeout(timeout);

              // Switch to normal response handling
              this.process!.stdout!.removeListener("data", onData);
              this.process!.stdout!.on("data", (chunk: Buffer) =>
                this.handleData(chunk)
              );

              resolve();
              return;
            }
          } catch {
            // Ignore malformed lines during startup
          }
        }
      };

      this.process.stdout!.on("data", onData);
    });
  }

  /**
   * Handle incoming data from the titus process stdout.
   */
  private handleData(chunk: Buffer): void {
    this.buffer += chunk.toString("utf-8");
    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() ?? "";

    for (const line of lines) {
      if (!line.trim()) continue;
      if (!this.pending) continue;

      const { resolve, reject, timer } = this.pending;
      this.pending = null;
      clearTimeout(timer);

      try {
        const resp: TitusResponse = JSON.parse(line);
        resolve(resp);
      } catch {
        reject(new Error(`Malformed response: ${line}`));
      }

      // Process next queued request
      this.processQueue();
    }
  }

  /**
   * Reject the currently pending request (e.g., on process death).
   */
  private rejectPending(err: Error): void {
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(err);
      this.pending = null;
    }
    // Reject all queued requests too
    for (const queued of this.queue) {
      queued.reject(err);
    }
    this.queue = [];
  }

  /**
   * Process the next request in the queue if no request is in flight.
   */
  private processQueue(): void {
    if (this.pending || this.queue.length === 0) return;

    const next = this.queue.shift()!;
    this.dispatchRequest(next.request, next.resolve, next.reject);
  }

  /**
   * Send a request and wait for the response.
   */
  /**
   * Send a request, queuing it if another request is already in flight.
   * Enforces serial communication matching the Java synchronized behavior.
   */
  private async sendRequest(request: TitusRequest): Promise<TitusResponse> {
    if (!this.initialized || !this.process?.stdin) {
      throw new Error("Scanner not initialized");
    }

    return new Promise<TitusResponse>((resolve, reject) => {
      if (this.pending) {
        // Queue behind the in-flight request
        this.queue.push({ request, resolve, reject });
      } else {
        this.dispatchRequest(request, resolve, reject);
      }
    });
  }

  /**
   * Actually write a request to stdin and set up the pending handler.
   */
  private dispatchRequest(
    request: TitusRequest,
    resolve: (resp: TitusResponse) => void,
    reject: (err: Error) => void
  ): void {
    const timer = setTimeout(() => {
      if (this.pending?.timer === timer) {
        this.pending = null;
        reject(new Error("Titus request timed out"));
        this.processQueue();
      }
    }, REQUEST_TIMEOUT_MS);

    this.pending = { resolve, reject, timer };

    const json = JSON.stringify(request) + "\n";
    this.process!.stdin!.write(json, "utf-8", (err) => {
      if (err) {
        if (this.pending?.timer === timer) {
          clearTimeout(timer);
          this.pending = null;
        }
        reject(new Error(`Failed to write to titus: ${err.message}`));
        this.processQueue();
      }
    });
  }

  /**
   * Scan a single content string for secrets.
   */
  async scan(content: string, source: string): Promise<TitusMatch[]> {
    const resp = await this.sendRequest({
      type: "scan",
      payload: { content, source },
    });

    if (!resp.success) {
      throw new Error(`Scan failed: ${resp.error}`);
    }

    const data = resp.data as ScanData;
    return data?.matches ?? [];
  }

  /**
   * Batch scan multiple content items.
   */
  async scanBatch(
    items: ContentItem[]
  ): Promise<Map<string, TitusMatch[]>> {
    const resp = await this.sendRequest({
      type: "scan_batch",
      payload: { items },
    });

    if (!resp.success) {
      throw new Error(`Batch scan failed: ${resp.error}`);
    }

    const data = resp.data as ScanBatchData;
    const results = new Map<string, TitusMatch[]>();
    if (data?.results) {
      for (const result of data.results) {
        if (result.matches && result.matches.length > 0) {
          results.set(result.source, result.matches);
        }
      }
    }
    return results;
  }

  /**
   * Validate a detected secret against its source API.
   */
  async validate(
    ruleId: string,
    secret: string,
    namedGroups: Record<string, string>
  ): Promise<ValidateData> {
    const resp = await this.sendRequest({
      type: "validate",
      payload: { rule_id: ruleId, secret, named_groups: namedGroups },
    });

    if (!resp.success) {
      throw new Error(`Validation failed: ${resp.error}`);
    }

    return resp.data as ValidateData;
  }

  /**
   * Get the titus version reported at startup.
   */
  getVersion(): string {
    return this.version;
  }

  /**
   * Check if the scanner process is alive.
   */
  isAlive(): boolean {
    return (
      this.initialized &&
      !this.closed &&
      this.process !== null &&
      this.process.exitCode === null
    );
  }

  /**
   * Gracefully close the scanner process.
   */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.initialized = false;
    this.rejectPending(new Error("Scanner closed"));

    if (this.process?.stdin) {
      try {
        const closeReq = JSON.stringify({ type: "close", payload: {} }) + "\n";
        this.process.stdin.write(closeReq);
        this.process.stdin.end();
      } catch {
        // Process may already be dead
      }
    }

    if (this.process) {
      setTimeout(() => {
        if (this.process && this.process.exitCode === null) {
          this.process.kill("SIGTERM");
        }
      }, 5000);
    }
  }
}
