package com.praetorian.titus.burp;

import javax.swing.table.AbstractTableModel;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Custom TableModel for the HTTP requests table.
 * Stores scanned HTTP requests with method, URL, status, size, time, and secrets.
 */
public class RequestsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"#", "Method", "URL", "Status", "Size", "Time", "Secrets"};
    private static final int MAX_ROWS = 1000;

    private final List<RequestEntry> entries = new ArrayList<>();
    private final List<RequestEntry> filteredEntries = new ArrayList<>();
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
    private final Map<String, SecretInfo> secretsByUrl = new ConcurrentHashMap<>();
    private RequestsFilterPanel.FilterCriteria currentFilter;
    private boolean filteringEnabled = false;

    /**
     * Secret info for a URL.
     */
    public record SecretInfo(int count, String types, SecretCategoryMapper.Category primaryCategory) {}

    /**
     * Entry record for table data.
     */
    public record RequestEntry(
        int index,
        String method,
        String url,
        String host,
        int status,
        int size,
        long timestamp,
        ScanJob scanJob,
        SecretInfo secretInfo
    ) {}

    @Override
    public int getRowCount() {
        return filteringEnabled ? filteredEntries.size() : entries.size();
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
            case 0, 3, 4, 6 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int row, int column) {
        List<RequestEntry> source = filteringEnabled ? filteredEntries : entries;
        if (row < 0 || row >= source.size()) {
            return null;
        }

        RequestEntry entry = source.get(row);
        return switch (column) {
            case 0 -> entry.index();
            case 1 -> entry.method();
            case 2 -> truncateUrl(entry.url(), 80);
            case 3 -> entry.status();
            case 4 -> entry.size();
            case 5 -> formatTime(entry.timestamp());
            case 6 -> entry.secretInfo() != null ? entry.secretInfo().count() : 0;
            default -> null;
        };
    }

    /**
     * Get the secret info for display purposes (for custom cell renderer).
     */
    public SecretInfo getSecretInfoAt(int row) {
        List<RequestEntry> source = filteringEnabled ? filteredEntries : entries;
        if (row < 0 || row >= source.size()) {
            return null;
        }
        return source.get(row).secretInfo();
    }

    /**
     * Add an entry from a scan job.
     * Must be called on EDT (Event Dispatch Thread).
     */
    public void addEntry(ScanJob job) {
        // Enforce max rows (FIFO - remove oldest)
        if (entries.size() >= MAX_ROWS) {
            entries.remove(0);
            if (!filteringEnabled) {
                fireTableRowsDeleted(0, 0);
            }
        }

        int responseSize = 0;
        int status = 0;

        if (job.response() != null) {
            status = job.response().statusCode();
            if (job.response().body() != null) {
                responseSize = job.response().body().length();
            }
        }

        String url = job.url();
        String host = SecretCategoryMapper.extractHost(url);
        SecretInfo secretInfo = secretsByUrl.get(url);

        RequestEntry entry = new RequestEntry(
            entries.size() + 1,
            job.request().method(),
            url,
            host,
            status,
            responseSize,
            job.queuedAt(),
            job,
            secretInfo
        );

        entries.add(entry);

        if (filteringEnabled) {
            if (matchesFilter(entry)) {
                filteredEntries.add(entry);
                int lastRow = filteredEntries.size() - 1;
                fireTableRowsInserted(lastRow, lastRow);
            }
        } else {
            int lastRow = entries.size() - 1;
            fireTableRowsInserted(lastRow, lastRow);
        }
    }

    /**
     * Update secret info for a URL.
     */
    public void updateSecretInfo(String url, int count, String types, SecretCategoryMapper.Category category) {
        secretsByUrl.put(url, new SecretInfo(count, types, category));
        // Update any existing entries with this URL
        for (int i = 0; i < entries.size(); i++) {
            RequestEntry entry = entries.get(i);
            if (url.equals(entry.url())) {
                RequestEntry updated = new RequestEntry(
                    entry.index(), entry.method(), entry.url(), entry.host(),
                    entry.status(), entry.size(), entry.timestamp(),
                    entry.scanJob(), secretsByUrl.get(url)
                );
                entries.set(i, updated);
            }
        }
        // Reapply filter if active
        if (filteringEnabled) {
            applyFilter(currentFilter);
        } else {
            fireTableDataChanged();
        }
    }

    /**
     * Set filter criteria.
     */
    public void setFilter(RequestsFilterPanel.FilterCriteria filter) {
        this.currentFilter = filter;
        if (filter == null || isEmptyFilter(filter)) {
            filteringEnabled = false;
            filteredEntries.clear();
        } else {
            filteringEnabled = true;
            applyFilter(filter);
        }
        fireTableDataChanged();
    }

    private boolean isEmptyFilter(RequestsFilterPanel.FilterCriteria filter) {
        return filter.host() == null && filter.secretType() == null &&
               filter.hasSecrets() == null && filter.method() == null &&
               filter.status() == null &&
               (filter.searchText() == null || filter.searchText().isEmpty());
    }

    private void applyFilter(RequestsFilterPanel.FilterCriteria filter) {
        filteredEntries.clear();
        for (RequestEntry entry : entries) {
            if (matchesFilter(entry)) {
                filteredEntries.add(entry);
            }
        }
    }

    private boolean matchesFilter(RequestEntry entry) {
        if (currentFilter == null) {
            return true;
        }
        int secretCount = entry.secretInfo() != null ? entry.secretInfo().count() : 0;
        String secretTypes = entry.secretInfo() != null ? entry.secretInfo().types() : null;
        return currentFilter.matches(
            entry.host(), entry.method(), entry.status(),
            entry.url(), secretCount, secretTypes
        );
    }

    /**
     * Get the scan job at the specified row.
     */
    public ScanJob getJobAt(int row) {
        List<RequestEntry> source = filteringEnabled ? filteredEntries : entries;
        if (row < 0 || row >= source.size()) {
            return null;
        }
        return source.get(row).scanJob();
    }

    /**
     * Get the entry at the specified row.
     */
    public RequestEntry getEntryAt(int row) {
        List<RequestEntry> source = filteringEnabled ? filteredEntries : entries;
        if (row < 0 || row >= source.size()) {
            return null;
        }
        return source.get(row);
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
