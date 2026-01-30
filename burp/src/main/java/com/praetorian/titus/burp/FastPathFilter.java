package com.praetorian.titus.burp;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * Fast-path filter to skip non-scannable content before queuing.
 *
 * This runs on the Burp thread so must be fast. Eliminates ~60-70% of traffic
 * before it hits the scan queue.
 */
public class FastPathFilter {

    // Content-Types that cannot contain text secrets
    private static final Set<String> SKIP_CONTENT_TYPES = Set.of(
        "image/",
        "video/",
        "audio/",
        "font/",
        "application/octet-stream",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/pdf",
        "application/x-shockwave-flash"
    );

    // File extensions that cannot contain text secrets
    private static final Pattern SKIP_EXTENSIONS = Pattern.compile(
        "\\.(png|jpg|jpeg|gif|ico|svg|webp|bmp|tiff|" +
        "woff|woff2|ttf|otf|eot|" +
        "mp3|mp4|webm|ogg|wav|avi|mov|" +
        "zip|gz|tar|rar|7z|" +
        "pdf|swf)$",
        Pattern.CASE_INSENSITIVE
    );

    // Minimum response size to scan (too small = unlikely to have secrets)
    private static final int MIN_RESPONSE_SIZE = 10;

    // Maximum response size to scan (avoid memory issues)
    private static final int MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB

    /**
     * Check if a response should be scanned.
     *
     * @param response The HTTP response
     * @return true if the response should be queued for scanning
     */
    public boolean shouldScan(HttpResponse response) {
        if (response == null) {
            return false;
        }

        // Check response size
        int bodyLength = response.body() != null ? response.body().length() : 0;
        if (bodyLength < MIN_RESPONSE_SIZE || bodyLength > MAX_RESPONSE_SIZE) {
            return false;
        }

        // Check Content-Type header
        String contentType = getContentType(response);
        if (contentType != null && !contentType.isEmpty()) {
            String lowerContentType = contentType.toLowerCase();
            for (String skipType : SKIP_CONTENT_TYPES) {
                if (lowerContentType.startsWith(skipType)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Check if a URL should be scanned based on extension.
     *
     * @param url The URL to check
     * @return true if the URL should be scanned
     */
    public boolean shouldScanUrl(String url) {
        if (url == null || url.isEmpty()) {
            return true; // Scan if no URL to check
        }

        // Extract path from URL
        String path = url;
        int queryIndex = url.indexOf('?');
        if (queryIndex > 0) {
            path = url.substring(0, queryIndex);
        }

        // Check extension
        return !SKIP_EXTENSIONS.matcher(path).find();
    }

    private String getContentType(HttpResponse response) {
        return response.headers().stream()
            .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
            .map(h -> h.value())
            .findFirst()
            .orElse(null);
    }
}
