package com.praetorian.titus.burp;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Table model for the Secrets tab showing deduplicated findings.
 */
public class SecretsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"#", "Type", "Severity", "Secret Preview", "Host", "Count", "Checked", "Result", "False Positive"};

    private final List<DedupCache.FindingRecord> findings = new ArrayList<>();
    private final DedupCache dedupCache;
    private SeverityConfig severityConfig;

    public SecretsTableModel(DedupCache dedupCache) {
        this.dedupCache = dedupCache;
    }

    /**
     * Set the severity config for determining finding severity.
     */
    public void setSeverityConfig(SeverityConfig config) {
        this.severityConfig = config;
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
            case 0, 5 -> Integer.class;  // # and Count columns
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
            case 2 -> getSeverityDisplay(record.ruleId);  // Severity column
            case 3 -> record.secretPreview;
            case 4 -> record.primaryHost != null ? record.primaryHost : "unknown";
            case 5 -> record.occurrenceCount;
            case 6 -> // Checked column - was validation attempted?
                record.validatedAt != null ? "Yes" : "No";
            case 7 -> {
                // Result column - show validation result
                if (record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE) {
                    yield "-";
                }
                if (record.validatedAt == null) {
                    yield "-";
                }
                yield switch (record.validationStatus) {
                    case VALID -> "Active";
                    case INVALID -> "Inactive";
                    case UNDETERMINED -> "Unknown";
                    case VALIDATING -> "...";
                    default -> "Unknown"; // Should not happen if validatedAt is set
                };
            }
            case 8 -> record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE ? "Yes" : "No";
            default -> null;
        };
    }

    /**
     * Get severity display text for a rule ID.
     */
    private String getSeverityDisplay(String ruleId) {
        if (severityConfig == null) {
            return "Medium";
        }
        AuditIssueSeverity severity = severityConfig.getSeverity(ruleId);
        return switch (severity) {
            case HIGH -> "High";
            case MEDIUM -> "Medium";
            case LOW -> "Low";
            case INFORMATION -> "Info";
            case FALSE_POSITIVE -> "FP";
        };
    }

    /**
     * Get severity for a rule ID.
     */
    public AuditIssueSeverity getSeverityAt(int row) {
        if (row < 0 || row >= findings.size() || severityConfig == null) {
            return AuditIssueSeverity.MEDIUM;
        }
        return severityConfig.getSeverity(findings.get(row).ruleId);
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
     * Returns: [valid, invalid, undetermined, notChecked, falsePositive]
     */
    public int[] getValidationCounts() {
        int valid = 0, invalid = 0, undetermined = 0, notChecked = 0, falsePositive = 0;
        for (DedupCache.FindingRecord record : findings) {
            switch (record.validationStatus) {
                case VALID -> valid++;
                case INVALID -> invalid++;
                case UNDETERMINED -> undetermined++;
                case FALSE_POSITIVE -> falsePositive++;
                default -> notChecked++;
            }
        }
        return new int[]{valid, invalid, undetermined, notChecked, falsePositive};
    }
}
