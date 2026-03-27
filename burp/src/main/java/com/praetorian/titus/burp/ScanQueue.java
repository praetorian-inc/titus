package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bounded queue with worker pool for scanning HTTP responses.
 */
public class ScanQueue implements AutoCloseable {

    private static final int QUEUE_CAPACITY = 10000;
    private static final int BATCH_SIZE = 10;
    private static final long BATCH_TIMEOUT_MS = 100;

    private final MontoyaApi api;
    private final SafeLogger logger;
    private final DedupCache dedupCache;
    private final IssueReporter issueReporter;
    private final ProcessManager processManager;
    private final BlockingQueue<ScanJob> queue;
    private final ExecutorService executor;
    private final List<Worker> workers;
    private final int workerCount;

    private volatile boolean shutdown = false;

    // Stats
    private final AtomicLong totalScanned = new AtomicLong(0);
    private final AtomicLong totalMatches = new AtomicLong(0);
    private final AtomicLong totalDropped = new AtomicLong(0);

    // Listener for UI updates
    private volatile ScanQueueListener listener;

    /**
     * Listener interface for scan queue events.
     */
    public interface ScanQueueListener {
        /**
         * Called when a job is enqueued.
         * This is called on the enqueueing thread - use SwingUtilities.invokeLater for UI updates.
         */
        void onJobEnqueued(ScanJob job);

        /**
         * Called when secrets are found for a URL.
         * This is called on the worker thread - use SwingUtilities.invokeLater for UI updates.
         *
         * @param url       The URL where secrets were found
         * @param count     Number of unique secrets found
         * @param types     Comma-separated list of secret types
         * @param category  The primary category of secrets found
         */
        default void onSecretsFound(String url, int count, String types, SecretCategoryMapper.Category category) {}

        /**
         * Called when a batch of jobs has been scanned (whether or not secrets were found).
         * This is called on the worker thread - use SwingUtilities.invokeLater for UI updates.
         *
         * @param jobCount      Number of jobs in the batch
         * @param secretsFound  Total new unique secrets found in this batch
         * @param source        The scan source (PASSIVE or ACTIVE)
         */
        default void onScanComplete(int jobCount, int secretsFound, ScanJob.Source source) {}

        /**
         * Called for each URL after it has been scanned, with the number of new secrets found.
         * Useful for annotating individual requests.
         */
        default void onUrlScanned(String url, int secretsFound, ScanJob.Source source) {}
    }

    /**
     * Set the listener for scan queue events.
     */
    public void setListener(ScanQueueListener listener) {
        this.listener = listener;
    }

    public ScanQueue(MontoyaApi api, DedupCache dedupCache, IssueReporter issueReporter,
                     ProcessManager processManager, int workerCount) {
        this.api = api;
        this.logger = new SafeLogger(api, "Titus");
        this.dedupCache = dedupCache;
        this.issueReporter = issueReporter;
        this.processManager = processManager;
        this.workerCount = workerCount;
        this.queue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
        this.executor = Executors.newFixedThreadPool(workerCount, new WorkerThreadFactory());
        this.workers = new ArrayList<>();

        // Start worker threads
        for (int i = 0; i < workerCount; i++) {
            Worker worker = new Worker(i);
            workers.add(worker);
            executor.submit(worker);
        }

        logger.info("ScanQueue started with " + workerCount + " workers");
    }

    /**
     * Enqueue a scan job. Returns false if queue is full.
     */
    public boolean enqueue(ScanJob job) {
        if (shutdown) {
            return false;
        }

        boolean added = queue.offer(job);
        if (!added) {
            totalDropped.incrementAndGet();
            logger.info("Queue full, dropped: " + job.url());
        } else {
            // Notify listener on successful enqueue
            ScanQueueListener l = listener;
            if (l != null) {
                l.onJobEnqueued(job);
            }
        }
        return added;
    }

    /**
     * Get current queue size.
     */
    public int queueSize() {
        return queue.size();
    }

    /**
     * Get total items scanned.
     */
    public long totalScanned() {
        return totalScanned.get();
    }

    /**
     * Get total matches found.
     */
    public long totalMatches() {
        return totalMatches.get();
    }

    /**
     * Get total items dropped due to full queue.
     */
    public long totalDropped() {
        return totalDropped.get();
    }

    @Override
    public void close() {
        shutdown = true;
        logger.invalidate(); // Mark logger as invalid before shutdown
        executor.shutdownNow();

        for (Worker worker : workers) {
            worker.close();
        }

        try {
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Worker thread that processes scan jobs.
     */
    private class Worker implements Runnable, AutoCloseable {
        private final int id;

        Worker(int id) {
            this.id = id;
        }

        @Override
        public void run() {
            try {
                List<ScanJob> batch = new ArrayList<>(BATCH_SIZE);

                while (!shutdown && !Thread.currentThread().isInterrupted()) {
                    // Collect a batch of jobs
                    batch.clear();

                    ScanJob job = queue.poll(BATCH_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    if (job != null) {
                        batch.add(job);

                        // Try to fill the batch
                        queue.drainTo(batch, BATCH_SIZE - 1);
                    }

                    if (batch.isEmpty()) {
                        continue;
                    }

                    // Process the batch
                    processBatch(batch);
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                logError("Worker " + id + " error: " + e.getMessage());
            }
        }

        private void processBatch(List<ScanJob> batch) {
            try {
                // Get scanner from ProcessManager
                TitusProcessScanner scanner = processManager.getScanner();

                // Build content items for batch scan
                List<TitusProcessScanner.ContentItem> items = new ArrayList<>();
                for (ScanJob job : batch) {
                    String content = buildScanContent(job);
                    items.add(new TitusProcessScanner.ContentItem(job.url(), content));
                }

                // Scan batch - returns map of source URL -> matches
                java.util.Map<String, java.util.List<TitusProcessScanner.Match>> matchesBySource = scanner.scanBatch(items);

                totalScanned.addAndGet(batch.size());

                int batchSecretsFound = 0;

                // Process matches for each job
                for (ScanJob job : batch) {
                    String url = job.url();
                    dedupCache.markUrlScanned(url);
                    java.util.List<TitusProcessScanner.Match> matches = matchesBySource.get(url);

                    if (matches == null || matches.isEmpty()) {
                        // Notify that URL was scanned but nothing found
                        ScanQueueListener l = listener;
                        if (l != null) {
                            l.onUrlScanned(url, 0, job.source());
                        }
                        continue;
                    }

                    log("Worker " + id + " found " + matches.size() + " matches for " + url);

                    // Build request/response content for storage
                    String requestContent = buildRequestContent(job);
                    String responseContent = buildResponseContent(job);

                    // Track unique secrets for this URL (for UI update)
                    int secretCount = 0;
                    java.util.Set<String> secretTypes = new java.util.HashSet<>();
                    SecretCategoryMapper.Category primaryCategory = null;

                    for (TitusProcessScanner.Match match : matches) {
                        // Atomic check-and-record: eliminates TOCTOU race between isNewFinding/recordOccurrence
                        boolean isNew = dedupCache.recordIfNew(url, match.matchedContent(), match.ruleId(), match.ruleName(),
                                                              requestContent, responseContent, match.namedGroups());

                        if (!isNew) {
                            log("Worker " + id + " duplicate at new URL: " + match.ruleId());
                            continue;
                        }

                        totalMatches.incrementAndGet();
                        secretCount++;

                        // Track types and category for UI
                        String displayName = SecretCategoryMapper.getDisplayName(match.ruleId(), match.ruleName());
                        secretTypes.add(displayName);
                        SecretCategoryMapper.Category category = SecretCategoryMapper.getCategory(match.ruleId());
                        if (primaryCategory == null || category.ordinal() < primaryCategory.ordinal()) {
                            primaryCategory = category;
                        }

                        issueReporter.reportIssue(job, match);
                    }

                    batchSecretsFound += secretCount;

                    // Notify listener of secrets found (for UI update)
                    if (secretCount > 0) {
                        ScanQueueListener l = listener;
                        if (l != null) {
                            String types = String.join(", ", secretTypes);
                            l.onSecretsFound(url, secretCount, types, primaryCategory);
                        }
                    }

                    // Notify per-URL scan result (for annotations)
                    {
                        ScanQueueListener l = listener;
                        if (l != null) {
                            l.onUrlScanned(url, secretCount, job.source());
                        }
                    }
                }

                // Notify listener that batch is complete
                ScanQueueListener l = listener;
                if (l != null) {
                    // Use the source from the first job in the batch
                    ScanJob.Source source = batch.get(0).source();
                    l.onScanComplete(batch.size(), batchSecretsFound, source);
                }

            } catch (IOException e) {
                logError("Worker " + id + " batch scan error: " + e.getMessage());
                e.printStackTrace();
                // Ensure per-URL callbacks fire even on error, to prevent pendingAnnotations leaks
                ScanQueueListener l = listener;
                if (l != null) {
                    for (ScanJob job : batch) {
                        l.onUrlScanned(job.url(), 0, job.source());
                    }
                }
            }
        }

        // Delegate to shared SafeLogger which handles Burp API invalidation
        private void log(String msg) {
            logger.info(msg);
        }

        private void logError(String msg) {
            logger.error(msg);
        }

        private String buildScanContent(ScanJob job) {
            StringBuilder sb = new StringBuilder();

            // Add request content if scanRequest is enabled
            if (job.scanRequest()) {
                sb.append("=== REQUEST ===\n");
                sb.append(buildRequestContent(job));
                sb.append("\n\n=== RESPONSE ===\n");
            }

            sb.append(buildResponseContent(job));
            return sb.toString();
        }

        private String buildRequestContent(ScanJob job) {
            // Return the raw request bytes as a string
            // ScanJob extracts and stores the full HTTP request on creation
            return job.requestContent();
        }

        private String buildResponseContent(ScanJob job) {
            // Return the raw response bytes as a string
            // ScanJob extracts and stores the full HTTP response on creation
            return job.responseContent();
        }

        @Override
        public void close() {
            // No per-worker cleanup needed - ProcessManager handles it
        }
    }

    /**
     * Thread factory for worker threads.
     */
    private static class WorkerThreadFactory implements ThreadFactory {
        private final AtomicInteger counter = new AtomicInteger(0);

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "titus-worker-" + counter.incrementAndGet());
            t.setDaemon(true);
            return t;
        }
    }
}
