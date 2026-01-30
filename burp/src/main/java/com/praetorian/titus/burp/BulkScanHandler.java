package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import javax.swing.*;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/**
 * Handler for bulk scanning all in-scope responses from proxy history.
 */
public class BulkScanHandler {

    private final MontoyaApi api;
    private final ScanQueue scanQueue;
    private final FastPathFilter fastPathFilter;
    private final DedupCache dedupCache;
    private final SettingsTab settingsTab;

    public BulkScanHandler(MontoyaApi api, ScanQueue scanQueue,
                           FastPathFilter fastPathFilter, DedupCache dedupCache,
                           SettingsTab settingsTab) {
        this.api = api;
        this.scanQueue = scanQueue;
        this.fastPathFilter = fastPathFilter;
        this.dedupCache = dedupCache;
        this.settingsTab = settingsTab;
    }

    /**
     * Scan all in-scope responses from proxy history.
     * Runs in a background thread to avoid UI freeze.
     */
    public void scanAllInScope() {
        api.logging().logToOutput("Starting bulk scan of in-scope proxy history...");

        SwingWorker<BulkScanResult, Void> worker = new SwingWorker<>() {
            @Override
            protected BulkScanResult doInBackground() {
                int queued = 0;
                int skipped = 0;
                int outOfScope = 0;
                int alreadyScanned = 0;

                List<ProxyHttpRequestResponse> history = api.proxy().history();
                int total = history.size();

                api.logging().logToOutput("Bulk scan: Processing " + total + " proxy history items");

                boolean scanRequest = settingsTab != null && settingsTab.isRequestScanEnabled();

                for (int i = 0; i < history.size(); i++) {
                    ProxyHttpRequestResponse item = history.get(i);

                    // Check scope
                    if (!api.scope().isInScope(item.request().url())) {
                        outOfScope++;
                        continue;
                    }

                    // Check if response exists
                    if (item.response() == null) {
                        skipped++;
                        continue;
                    }

                    // Fast-path filter
                    if (!fastPathFilter.shouldScan(item.response())) {
                        skipped++;
                        continue;
                    }

                    // Check content hash to avoid rescanning identical content
                    String contentHash = hashContent(item.response().body().toString());
                    String url = item.request().url();

                    // Use dedup cache to check if already processed
                    if (dedupCache.hasProcessedUrl(url, contentHash)) {
                        alreadyScanned++;
                        continue;
                    }

                    // Queue for scanning
                    ScanJob job = new ScanJob(
                        item.request(),
                        item.response(),
                        ScanJob.Source.ACTIVE,
                        scanRequest
                    );

                    if (scanQueue.enqueue(job)) {
                        queued++;
                        dedupCache.markUrlProcessed(url, contentHash);
                    } else {
                        skipped++;
                    }

                    // Progress logging every 500 items
                    if ((i + 1) % 500 == 0) {
                        api.logging().logToOutput(String.format(
                            "Bulk scan progress: %d/%d (queued=%d, skipped=%d)",
                            i + 1, total, queued, skipped
                        ));
                    }
                }

                return new BulkScanResult(queued, skipped, outOfScope, alreadyScanned, total);
            }

            @Override
            protected void done() {
                try {
                    BulkScanResult result = get();
                    String message = String.format(
                        "Bulk scan complete:\n" +
                        "  Total items: %d\n" +
                        "  Queued: %d\n" +
                        "  Skipped (filtered): %d\n" +
                        "  Out of scope: %d\n" +
                        "  Already scanned: %d",
                        result.total(), result.queued(), result.skipped(),
                        result.outOfScope(), result.alreadyScanned()
                    );

                    api.logging().logToOutput(message);

                    JOptionPane.showMessageDialog(
                        null,
                        message,
                        "Bulk Scan Complete",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception e) {
                    api.logging().logToError("Bulk scan failed: " + e.getMessage());
                    JOptionPane.showMessageDialog(
                        null,
                        "Bulk scan failed: " + e.getMessage(),
                        "Bulk Scan Error",
                        JOptionPane.ERROR_MESSAGE
                    );
                }
            }
        };

        worker.execute();
    }

    private String hashContent(String content) {
        if (content == null || content.isEmpty()) {
            return "";
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes());
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            // Fallback to simple hash
            return String.valueOf(content.hashCode());
        }
    }

    /**
     * Result of a bulk scan operation.
     */
    public record BulkScanResult(
        int queued,
        int skipped,
        int outOfScope,
        int alreadyScanned,
        int total
    ) {}
}
