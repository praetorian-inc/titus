package com.praetorian.titus.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Represents a scan job to be processed by the worker pool.
 */
public record ScanJob(
    HttpRequest request,
    HttpResponse response,
    Source source,
    long queuedAt
) {
    /**
     * Source of the scan job.
     */
    public enum Source {
        PASSIVE,  // From HTTP proxy listener
        ACTIVE    // From context menu selection
    }

    /**
     * Create a scan job with current timestamp.
     */
    public ScanJob(HttpRequest request, HttpResponse response, Source source) {
        this(request, response, source, System.currentTimeMillis());
    }

    /**
     * Get the URL being scanned.
     */
    public String url() {
        return request.url();
    }

    /**
     * Get age of job in milliseconds.
     */
    public long ageMillis() {
        return System.currentTimeMillis() - queuedAt;
    }
}
