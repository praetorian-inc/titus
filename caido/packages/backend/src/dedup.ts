/**
 * Deduplication cache for secret findings.
 *
 * Deduplicates by rule ID + secret content (same secret at different URLs = one finding).
 * Mirrors the Burp extension's DedupCache.java.
 */

import type { FindingRecord } from "./types.js";

const MAX_CACHE_SIZE = 50_000;

export class DedupCache {
  private cache = new Map<string, FindingRecord>();

  /**
   * Record a finding. Returns true if this is a NEW finding (first occurrence).
   */
  recordIfNew(
    url: string,
    secretContent: string,
    ruleId: string,
    ruleName: string
  ): boolean {
    const key = this.computeKey(secretContent, ruleId);
    const normalizedUrl = this.normalizeUrl(url);
    const host = this.extractHost(url);

    // Evict oldest entries if at capacity
    if (!this.cache.has(key) && this.cache.size >= MAX_CACHE_SIZE) {
      this.evictOldest();
    }

    const existing = this.cache.get(key);
    if (existing) {
      if (!existing.urls.includes(normalizedUrl)) {
        existing.urls.push(normalizedUrl);
      }
      existing.occurrenceCount++;
      return false;
    }

    const record: FindingRecord = {
      ruleId,
      ruleName,
      secretPreview: this.createPreview(secretContent),
      secretContent,
      url: normalizedUrl,
      host,
      urls: [normalizedUrl],
      occurrenceCount: 1,
      firstSeen: new Date().toISOString(),
    };

    this.cache.set(key, record);
    return true;
  }

  /**
   * Get all unique findings.
   */
  getAllFindings(): FindingRecord[] {
    return Array.from(this.cache.values());
  }

  /**
   * Get findings for a specific URL.
   */
  getFindingsForUrl(url: string): FindingRecord[] {
    const normalized = this.normalizeUrl(url);
    return this.getAllFindings().filter((f) => f.urls.includes(normalized));
  }

  /**
   * Get unique finding count.
   */
  uniqueCount(): number {
    return this.cache.size;
  }

  /**
   * Clear all findings.
   */
  clear(): void {
    this.cache.clear();
  }

  private computeKey(secretContent: string, ruleId: string): string {
    return `${ruleId}:${secretContent}`;
  }

  private normalizeUrl(url: string): string {
    if (!url) return "";
    const queryIndex = url.indexOf("?");
    return queryIndex > 0 ? url.substring(0, queryIndex) : url;
  }

  private extractHost(url: string): string {
    try {
      const u = new URL(url);
      return u.host;
    } catch {
      return "unknown";
    }
  }

  private createPreview(secret: string): string {
    if (!secret) return "[empty]";
    if (secret.length <= 20) return secret;
    return secret.substring(0, 20) + "...";
  }

  private evictOldest(): void {
    const toEvict = Math.max(1, Math.floor(MAX_CACHE_SIZE / 10));
    const entries = Array.from(this.cache.entries()).sort(
      (a, b) =>
        new Date(a[1].firstSeen).getTime() -
        new Date(b[1].firstSeen).getTime()
    );
    for (let i = 0; i < toEvict && i < entries.length; i++) {
      this.cache.delete(entries[i]![0]);
    }
  }
}
