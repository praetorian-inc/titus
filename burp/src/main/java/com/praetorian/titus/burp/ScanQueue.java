package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;

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

                // Process matches for each job
                for (ScanJob job : batch) {
                    String url = job.url();
                    java.util.List<TitusProcessScanner.Match> matches = matchesBySource.get(url);

                    if (matches == null || matches.isEmpty()) {
                        continue;
                    }

                    log("Worker " + id + " found " + matches.size() + " matches for " + url);

                    // Build request/response content for storage
                    String requestContent = buildRequestContent(job);
                    String responseContent = buildResponseContent(job);

                    for (TitusProcessScanner.Match match : matches) {
                        // Check dedup
                        if (!dedupCache.isNewFinding(url, match.matchedContent(), match.ruleId())) {
                            log("Worker " + id + " skipping duplicate: " + match.ruleId());
                            continue;
                        }

                        totalMatches.incrementAndGet();

                        // Record and report with HTTP content
                        dedupCache.recordOccurrence(url, match.matchedContent(), match.ruleId(), match.ruleName(),
                                                   requestContent, responseContent);
                        issueReporter.reportIssue(job, match);
                    }
                }

            } catch (IOException e) {
                logError("Worker " + id + " batch scan error: " + e.getMessage());
                e.printStackTrace();
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
            StringBuilder sb = new StringBuilder();

            // Request line
            sb.append(job.request().method()).append(" ");
            sb.append(job.request().path()).append(" ");
            sb.append(job.request().httpVersion()).append("\n");

            // Request headers
            for (HttpHeader header : job.request().headers()) {
                sb.append(header.name()).append(": ").append(header.value()).append("\n");
            }

            sb.append("\n");

            // Request body
            if (job.request().body() != null && job.request().body().length() > 0) {
                sb.append(job.request().body().toString());
            }

            return sb.toString();
        }

        private String buildResponseContent(ScanJob job) {
            StringBuilder sb = new StringBuilder();

            // Response status line
            sb.append("HTTP/").append(job.response().httpVersion()).append(" ");
            sb.append(job.response().statusCode()).append(" ");
            sb.append(job.response().reasonPhrase()).append("\n");

            // Response headers
            for (HttpHeader header : job.response().headers()) {
                sb.append(header.name()).append(": ").append(header.value()).append("\n");
            }

            sb.append("\n");

            // Response body
            if (job.response().body() != null) {
                sb.append(job.response().body().toString());
            }

            return sb.toString();
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
