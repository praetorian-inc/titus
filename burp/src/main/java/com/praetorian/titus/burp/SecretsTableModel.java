package com.praetorian.titus.burp;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Table model for the Secrets tab showing deduplicated findings.
 */
public class SecretsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"#", "Type", "Secret Preview", "Host", "Count", "Validation"};

    private final List<DedupCache.FindingRecord> findings = new ArrayList<>();
    private final DedupCache dedupCache;

    public SecretsTableModel(DedupCache dedupCache) {
        this.dedupCache = dedupCache;
    }

    /**
     * Refresh the table data from the dedup cache.
     */
    public void refresh() {
        findings.clear();
        findings.addAll(dedupCache.getAllFindings());
        // Sort by occurrence count descending
        findings.sort((a, b) -> Integer.compare(b.occurrenceCount, a.occurrenceCount));
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return findings.size();
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
            case 0, 4 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public Object getValueAt(int row, int column) {
        if (row < 0 || row >= findings.size()) {
            return null;
        }

        DedupCache.FindingRecord record = findings.get(row);
        return switch (column) {
            case 0 -> row + 1;
            case 1 -> record.ruleName != null ? record.ruleName : SecretCategoryMapper.getDisplayName(record.ruleId, null);
            case 2 -> record.secretPreview;
            case 3 -> record.primaryHost != null ? record.primaryHost : "unknown";
            case 4 -> record.occurrenceCount;
            case 5 -> record.validationStatus.getDisplayText();
            default -> null;
        };
    }

    /**
     * Get the finding record at the specified row.
     */
    public DedupCache.FindingRecord getRecordAt(int row) {
        if (row < 0 || row >= findings.size()) {
            return null;
        }
        return findings.get(row);
    }

    /**
     * Get the category for the finding at the specified row.
     */
    public SecretCategoryMapper.Category getCategoryAt(int row) {
        if (row < 0 || row >= findings.size()) {
            return SecretCategoryMapper.Category.GENERIC;
        }
        return SecretCategoryMapper.getCategory(findings.get(row).ruleId);
    }

    /**
     * Get all unique secret types.
     */
    public Set<String> getUniqueTypes() {
        Set<String> types = new TreeSet<>();
        for (DedupCache.FindingRecord record : findings) {
            String type = record.ruleName != null ? record.ruleName : SecretCategoryMapper.getDisplayName(record.ruleId, null);
            types.add(type);
        }
        return types;
    }

    /**
     * Get all unique hosts.
     */
    public Set<String> getUniqueHosts() {
        Set<String> hosts = new TreeSet<>();
        for (DedupCache.FindingRecord record : findings) {
            if (record.hosts != null) {
                hosts.addAll(record.hosts);
            }
            if (record.primaryHost != null) {
                hosts.add(record.primaryHost);
            }
        }
        return hosts;
    }

    /**
     * Get count of findings by host.
     */
    public Map<String, Integer> getCountByHost() {
        Map<String, Integer> counts = new HashMap<>();
        for (DedupCache.FindingRecord record : findings) {
            String host = record.primaryHost != null ? record.primaryHost : "unknown";
            counts.merge(host, 1, Integer::sum);
        }
        return counts;
    }

    /**
     * Get count of findings by type.
     */
    public Map<String, Integer> getCountByType() {
        Map<String, Integer> counts = new HashMap<>();
        for (DedupCache.FindingRecord record : findings) {
            String type = record.ruleName != null ? record.ruleName : SecretCategoryMapper.getDisplayName(record.ruleId, null);
            counts.merge(type, 1, Integer::sum);
        }
        return counts;
    }

    /**
     * Get count of findings by category.
     */
    public Map<SecretCategoryMapper.Category, Integer> getCountByCategory() {
        Map<SecretCategoryMapper.Category, Integer> counts = new EnumMap<>(SecretCategoryMapper.Category.class);
        for (DedupCache.FindingRecord record : findings) {
            SecretCategoryMapper.Category category = SecretCategoryMapper.getCategory(record.ruleId);
            counts.merge(category, 1, Integer::sum);
        }
        return counts;
    }

    /**
     * Get total number of findings.
     */
    public int getTotalCount() {
        return findings.size();
    }

    /**
     * Get validated counts.
     */
    public int[] getValidationCounts() {
        int valid = 0, invalid = 0, undetermined = 0, notChecked = 0;
        for (DedupCache.FindingRecord record : findings) {
            switch (record.validationStatus) {
                case VALID -> valid++;
                case INVALID -> invalid++;
                case UNDETERMINED -> undetermined++;
                default -> notChecked++;
            }
        }
        return new int[]{valid, invalid, undetermined, notChecked};
    }
}
