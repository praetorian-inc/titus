/**
 * Fast-path filter to skip non-scannable content.
 *
 * Mirrors the Burp extension's FastPathFilter.java.
 * Eliminates ~60-70% of traffic before it reaches the scan queue.
 */

/** Content-Type prefixes that cannot contain text secrets. */
const SKIP_CONTENT_TYPES = [
  "image/",
  "video/",
  "audio/",
  "font/",
  "application/octet-stream",
  "application/zip",
  "application/gzip",
  "application/x-gzip",
  "application/pdf",
  "application/x-shockwave-flash",
];

/** File extensions that cannot contain text secrets. */
const SKIP_EXTENSIONS =
  /\.(png|jpg|jpeg|gif|ico|svg|webp|bmp|tiff|woff|woff2|ttf|otf|eot|mp3|mp4|webm|ogg|wav|avi|mov|zip|gz|tar|rar|7z|pdf|swf)$/i;

const MIN_RESPONSE_SIZE = 10;
const DEFAULT_MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10 MB

export class FastPathFilter {
  private maxResponseSize = DEFAULT_MAX_RESPONSE_SIZE;

  setMaxResponseSize(bytes: number): void {
    this.maxResponseSize = bytes;
  }

  /**
   * Check if a response should be scanned based on content-type and size.
   */
  shouldScan(contentType: string | undefined, bodyLength: number): boolean {
    if (bodyLength < MIN_RESPONSE_SIZE || bodyLength > this.maxResponseSize) {
      return false;
    }

    if (contentType) {
      const lower = contentType.toLowerCase();
      for (const skip of SKIP_CONTENT_TYPES) {
        if (lower.startsWith(skip)) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Check if a URL should be scanned based on file extension.
   */
  shouldScanUrl(url: string): boolean {
    if (!url) return true;
    const path = url.split("?")[0] ?? url;
    return !SKIP_EXTENSIONS.test(path);
  }
}
