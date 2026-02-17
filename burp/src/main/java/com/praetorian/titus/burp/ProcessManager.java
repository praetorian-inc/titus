package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Manages the Titus process lifecycle with automatic restart on failure.
 *
 * Features:
 * - Single process shared across all workers
 * - Automatic restart with exponential backoff
 * - Health monitoring
 */
public class ProcessManager implements AutoCloseable {

    private static final int MAX_RESTART_ATTEMPTS = 3;
    private static final long INITIAL_BACKOFF_MS = 1000;
    private static final long MAX_BACKOFF_MS = 30000;

    private final MontoyaApi api;
    private final String titusPath;
    private final ReentrantLock lock = new ReentrantLock();
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    private final AtomicInteger restartCount = new AtomicInteger(0);

    private TitusProcessScanner scanner;

    public ProcessManager(MontoyaApi api, String titusPath) {
        this.api = api;
        this.titusPath = titusPath;
    }

    /**
     * Initialize the scanner process.
     *
     * @throws IOException If initialization fails after retries
     */
    public void initialize() throws IOException {
        lock.lock();
        try {
            // Validate titus binary exists
            if (!Files.exists(Path.of(titusPath))) {
                throw new IOException("Titus binary not found: " + titusPath);
            }

            startProcess();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Get the scanner, restarting if necessary.
     *
     * @return The scanner instance
     * @throws IOException If scanner is unavailable
     */
    public TitusProcessScanner getScanner() throws IOException {
        if (shutdown.get()) {
            throw new IOException("ProcessManager is shutdown");
        }

        lock.lock();
        try {
            if (scanner == null || !scanner.isAlive()) {
                restartWithBackoff();
            }
            return scanner;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Check if scanner is healthy.
     */
    public boolean isHealthy() {
        return scanner != null && scanner.isAlive() && !shutdown.get();
    }

    /**
     * Get restart count for diagnostics.
     */
    public int getRestartCount() {
        return restartCount.get();
    }

    @Override
    public void close() {
        shutdown.set(true);
        lock.lock();
        try {
            if (scanner != null) {
                scanner.close();
                scanner = null;
            }
        } finally {
            lock.unlock();
        }
    }

    private void startProcess() throws IOException {
        api.logging().logToOutput("Starting Titus process: " + titusPath);
        scanner = new TitusProcessScanner(titusPath);
        api.logging().logToOutput("Titus process started, version: " + scanner.getVersion());
    }

    private void restartWithBackoff() throws IOException {
        if (shutdown.get()) {
            throw new IOException("ProcessManager is shutdown");
        }

        // Close existing scanner if any
        if (scanner != null) {
            try {
                scanner.close();
            } catch (Exception ignored) {
            }
            scanner = null;
        }

        int attempts = 0;
        long backoff = INITIAL_BACKOFF_MS;

        while (attempts < MAX_RESTART_ATTEMPTS && !shutdown.get()) {
            attempts++;
            restartCount.incrementAndGet();

            try {
                api.logging().logToOutput("Attempting to restart Titus process (attempt " + attempts + ")");
                startProcess();
                return;
            } catch (IOException e) {
                api.logging().logToError("Failed to start Titus process: " + e.getMessage());

                if (attempts < MAX_RESTART_ATTEMPTS) {
                    try {
                        Thread.sleep(backoff);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted during restart backoff");
                    }
                    backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
                }
            }
        }

        throw new IOException("Failed to start Titus process after " + MAX_RESTART_ATTEMPTS + " attempts");
    }
}
