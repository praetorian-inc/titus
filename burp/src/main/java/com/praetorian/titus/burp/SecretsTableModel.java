package com.praetorian.titus.burp;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Table model for the Secrets tab showing deduplicated findings.
 */
public class SecretsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"#", "Type", "Severity", "Secret Preview", "Host", "Path", "Count", "Checked", "Result", "False Positive"};

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
            case 0, 6 -> Integer.class;  // # and Count columns
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
            case 2 -> getSeverityDisplay(record);  // Severity column
            case 3 -> getSecretPreview(record);
            case 4 -> record.primaryHost != null ? record.primaryHost : "unknown";
            case 5 -> extractPath(record);  // Path column
            case 6 -> record.urls != null ? record.urls.size() : record.occurrenceCount;
            case 7 -> // Checked column - was validation attempted?
                record.validatedAt != null ? "Yes" : "No";
            case 8 -> {
                // Result column - show validation result (preserved even when marked FP)
                DedupCache.ValidationStatus effectiveStatus = record.validationStatus;
                if (effectiveStatus == DedupCache.ValidationStatus.FALSE_POSITIVE) {
                    effectiveStatus = record.preMarkFPStatus;
                }
                if (effectiveStatus == null || effectiveStatus == DedupCache.ValidationStatus.NOT_CHECKED) {
                    yield "-";
                }
                yield switch (effectiveStatus) {
                    case VALID -> "Active";
                    case INVALID -> "Inactive";
                    case UNDETERMINED -> "Unknown";
                    case VALIDATING -> "...";
                    default -> "-";
                };
            }
            case 9 -> record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE ? "Yes" : "No";
            default -> null;
        };
    }

    /**
     * Get the secret preview, showing paired values for multi-group findings.
     * Returns the full content so wider columns show more text.
     */
    private static final int MAX_PREVIEW_LENGTH = 120;

    private String getSecretPreview(DedupCache.FindingRecord record) {
        String preview;

        // For findings with multiple named groups, show paired values
        Map<String, String> groups = record.getNamedGroups();
        if (groups != null && groups.size() > 1) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> entry : groups.entrySet()) {
                if (sb.length() > 0) sb.append(" : ");
                sb.append(entry.getValue());
            }
            preview = sb.toString();
        } else if (record.secretContent != null && !record.secretContent.isEmpty()) {
            preview = record.secretContent;
        } else {
            return record.secretPreview != null ? record.secretPreview : "[empty]";
        }

        if (preview.length() > MAX_PREVIEW_LENGTH) {
            return preview.substring(0, MAX_PREVIEW_LENGTH) + "...";
        }
        return preview;
    }

    /**
     * Extract the path from the first URL in the finding record.
     */
    private String extractPath(DedupCache.FindingRecord record) {
        if (record.urls == null || record.urls.isEmpty()) {
            return "/";
        }
        String url = record.urls.iterator().next();
        String path = extractPathFromUrl(url);
        int urlCount = record.urls.size();
        if (urlCount > 1) {
            return path + " (+" + (urlCount - 1) + " more)";
        }
        return path;
    }

    private String extractPathFromUrl(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd > 0) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart > 0) {
                    int queryStart = url.indexOf('?', pathStart);
                    if (queryStart > 0) {
                        return url.substring(pathStart, queryStart);
                    }
                    return url.substring(pathStart);
                }
            }
            return "/";
        } catch (Exception e) {
            return "/";
        }
    }

    /**
     * Get effective severity for a finding, checking per-finding override first.
     */
    private AuditIssueSeverity getEffectiveSeverity(DedupCache.FindingRecord record) {
        if (record.severityOverride != null) {
            try {
                return AuditIssueSeverity.valueOf(record.severityOverride);
            } catch (IllegalArgumentException ignored) {}
        }
        if (severityConfig == null) {
            return AuditIssueSeverity.MEDIUM;
        }
        return severityConfig.getSeverity(record.ruleId);
    }

    /**
     * Get severity display text for a finding.
     */
    private String getSeverityDisplay(DedupCache.FindingRecord record) {
        AuditIssueSeverity severity = getEffectiveSeverity(record);
        return switch (severity) {
            case HIGH -> "High";
            case MEDIUM -> "Medium";
            case LOW -> "Low";
            case INFORMATION -> "Info";
            case FALSE_POSITIVE -> "FP";
        };
    }

    /**
     * Get severity at a row.
     */
    public AuditIssueSeverity getSeverityAt(int row) {
        if (row < 0 || row >= findings.size()) {
            return AuditIssueSeverity.MEDIUM;
        }
        return getEffectiveSeverity(findings.get(row));
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
