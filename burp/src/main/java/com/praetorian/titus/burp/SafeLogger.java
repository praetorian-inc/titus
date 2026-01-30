package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Thread-safe logger that handles Burp API becoming unavailable during extension unload.
 * Falls back to System.err when Burp API throws exceptions.
 */
public class SafeLogger {

    private volatile MontoyaApi api;
    private final AtomicBoolean burpApiValid = new AtomicBoolean(true);
    private final String prefix;

    public SafeLogger(MontoyaApi api, String prefix) {
        this.api = api;
        this.prefix = prefix;
    }

    /**
     * Mark the Burp API as invalid (call during shutdown).
     */
    public void invalidate() {
        burpApiValid.set(false);
    }

    /**
     * Log an info message.
     * Only uses System.out - Burp API is unreliable from worker threads.
     */
    public void info(String msg) {
        String fullMsg = "[" + prefix + "] " + msg;
        System.out.println(fullMsg);
    }

    /**
     * Log an error message.
     * Only uses System.err - Burp API is unreliable from worker threads.
     */
    public void error(String msg) {
        String fullMsg = "[" + prefix + "] " + msg;
        System.err.println(fullMsg);
    }

    /**
     * Log an error with exception.
     */
    public void error(String msg, Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        error(msg + ": " + e.getMessage() + "\n" + sw.toString());
    }
}
