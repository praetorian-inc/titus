package com.praetorian.titus.burp;

import javax.swing.table.AbstractTableModel;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Custom TableModel for the HTTP requests table.
 * Stores scanned HTTP requests with method, URL, status, size, and time.
 */
public class RequestsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"#", "Method", "URL", "Status", "Size", "Time"};
    private static final int MAX_ROWS = 1000;

    private final List<RequestEntry> entries = new ArrayList<>();
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    /**
     * Entry record for table data.
     */
    public record RequestEntry(
        int index,
        String method,
        String url,
        int status,
        int size,
        long timestamp,
        ScanJob scanJob
    ) {}

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return switch (column) {
            case 0, 3, 4 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int row, int column) {
        if (row < 0 || row >= entries.size()) {
            return null;
        }

        RequestEntry entry = entries.get(row);
        return switch (column) {
            case 0 -> entry.index();
            case 1 -> entry.method();
            case 2 -> truncateUrl(entry.url(), 80);
            case 3 -> entry.status();
            case 4 -> entry.size();
            case 5 -> formatTime(entry.timestamp());
            default -> null;
        };
    }

    /**
     * Add an entry from a scan job.
     * Must be called on EDT (Event Dispatch Thread).
     */
    public void addEntry(ScanJob job) {
        // Enforce max rows (FIFO - remove oldest)
        if (entries.size() >= MAX_ROWS) {
            entries.remove(0);
            fireTableRowsDeleted(0, 0);
        }

        int responseSize = 0;
        int status = 0;

        if (job.response() != null) {
            status = job.response().statusCode();
            if (job.response().body() != null) {
                responseSize = job.response().body().length();
            }
        }

        RequestEntry entry = new RequestEntry(
            entries.size() + 1,
            job.request().method(),
            job.url(),
            status,
            responseSize,
            job.queuedAt(),
            job
        );

        entries.add(entry);
        int lastRow = entries.size() - 1;
        fireTableRowsInserted(lastRow, lastRow);
    }

    /**
     * Get the scan job at the specified row.
     */
    public ScanJob getJobAt(int row) {
        if (row < 0 || row >= entries.size()) {
            return null;
        }
        return entries.get(row).scanJob();
    }

    /**
     * Get all entries (for persistence).
     */
    public List<RequestEntry> getEntries() {
        return new ArrayList<>(entries);
    }

    /**
     * Clear all entries.
     */
    public void clear() {
        int size = entries.size();
        if (size > 0) {
            entries.clear();
            fireTableRowsDeleted(0, size - 1);
        }
    }

    /**
     * Get the number of entries.
     */
    public int getEntryCount() {
        return entries.size();
    }

    private String truncateUrl(String url, int maxLength) {
        if (url == null) {
            return "";
        }
        if (url.length() <= maxLength) {
            return url;
        }
        return url.substring(0, maxLength - 3) + "...";
    }

    private String formatTime(long timestamp) {
        return timeFormat.format(new Date(timestamp));
    }
}
