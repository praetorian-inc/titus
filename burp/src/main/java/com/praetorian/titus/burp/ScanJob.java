package com.praetorian.titus.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Represents a scan job to be processed by the worker pool.
 *
 * IMPORTANT: This class extracts and stores primitive data from Burp API objects
 * immediately upon construction. It does NOT hold references to HttpRequest or
 * HttpResponse objects, which is required for BApp Store compliance to avoid
 * memory issues with large projects.
 *
 * @see <a href="https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria">BApp Store Acceptance Criteria</a>
 */
public record ScanJob(
    String url,
    String method,
    int statusCode,
    int responseSize,
    byte[] requestBytes,
    byte[] responseBytes,
    Source source,
    long queuedAt,
    boolean scanRequest
) {
    /**
     * Source of the scan job.
     */
    public enum Source {
        PASSIVE,  // From HTTP proxy listener
        ACTIVE    // From context menu selection
    }

    /**
     * Create a scan job by extracting data from Burp API objects.
     * The Burp objects are NOT stored - only their data is extracted.
     */
    public static ScanJob fromBurpObjects(HttpRequest request, HttpResponse response, Source source, boolean scanRequest) {
        return fromBurpObjects(request, response, source, System.currentTimeMillis(), scanRequest);
    }

    /**
     * Create a scan job by extracting data from Burp API objects with specified timestamp.
     * The Burp objects are NOT stored - only their data is extracted.
     */
    public static ScanJob fromBurpObjects(HttpRequest request, HttpResponse response, Source source, long queuedAt, boolean scanRequest) {
        String url = request != null ? request.url() : "";
        String method = request != null ? request.method() : "";
        int statusCode = response != null ? response.statusCode() : 0;
        int responseSize = (response != null && response.body() != null) ? response.body().length() : 0;
        byte[] requestBytes = request != null ? request.toByteArray().getBytes() : new byte[0];
        byte[] responseBytes = response != null ? response.toByteArray().getBytes() : new byte[0];

        return new ScanJob(url, method, statusCode, responseSize, requestBytes, responseBytes, source, queuedAt, scanRequest);
    }

    /**
     * Create a scan job from raw data (used for restoring from persistence).
     */
    public static ScanJob fromRawData(String url, String method, int statusCode, int responseSize,
                                       byte[] requestBytes, byte[] responseBytes, Source source,
                                       long queuedAt, boolean scanRequest) {
        return new ScanJob(url, method, statusCode, responseSize, requestBytes, responseBytes, source, queuedAt, scanRequest);
    }

    /**
     * Get age of job in milliseconds.
     */
    public long ageMillis() {
        return System.currentTimeMillis() - queuedAt;
    }

    /**
     * Get the request content as a string.
     */
    public String requestContent() {
        return requestBytes != null ? new String(requestBytes) : "";
    }

    /**
     * Get the response content as a string.
     */
    public String responseContent() {
        return responseBytes != null ? new String(responseBytes) : "";
    }
}
