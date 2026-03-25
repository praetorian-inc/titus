package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Statistics view showing secrets grouped by host and type.
 */
public class StatisticsView extends JPanel {

    private final MontoyaApi api;
    private final SecretsTableModel secretsModel;
    private final SeverityConfig severityConfig;

    private final DefaultTableModel hostTableModel;
    private final DefaultTableModel typeTableModel;
    private final JTable hostTable;
    private final JTable typeTable;
    private final JLabel summaryLabel;
    private final JButton refreshButton;

    public StatisticsView(MontoyaApi api, SecretsTableModel secretsModel, SeverityConfig severityConfig) {
        this.api = api;
        this.secretsModel = secretsModel;
        this.severityConfig = severityConfig;

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        refreshButton = new JButton("Refresh Statistics");
        refreshButton.addActionListener(e -> refresh());
        toolbar.add(refreshButton);

        // Summary bar at top
        summaryLabel = new JLabel("No statistics available");
        summaryLabel.setBorder(BorderFactory.createCompoundBorder(
            new TitledBorder("Summary"),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
        summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.BOLD));

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(toolbar, BorderLayout.NORTH);
        topPanel.add(summaryLabel, BorderLayout.SOUTH);
        add(topPanel, BorderLayout.NORTH);

        // Main content - two tables side by side
        JPanel tablesPanel = new JPanel(new GridLayout(1, 2, 10, 0));

        // Type statistics table (on left)
        typeTableModel = new DefaultTableModel(new String[]{"Type", "Count", "Severity"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            @Override
            public Class<?> getColumnClass(int column) {
                return column == 1 ? Integer.class : String.class;
            }
        };
        typeTable = new JTable(typeTableModel);
        typeTable.setAutoCreateRowSorter(true);
        typeTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        typeTable.getColumnModel().getColumn(1).setMaxWidth(80);
        typeTable.getColumnModel().getColumn(2).setPreferredWidth(120);
        centerColumn(typeTable, 1);

        // Color the severity column
        typeTable.getColumnModel().getColumn(2).setCellRenderer(new SeverityColorCellRenderer());

        JPanel typePanel = new JPanel(new BorderLayout());
        typePanel.setBorder(new TitledBorder("Secrets by Type"));
        typePanel.add(new JScrollPane(typeTable), BorderLayout.CENTER);
        tablesPanel.add(typePanel);

        // Host statistics table (on right)
        hostTableModel = new DefaultTableModel(new String[]{"Host", "Secrets"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            @Override
            public Class<?> getColumnClass(int column) {
                return column == 1 ? Integer.class : String.class;
            }
        };
        hostTable = new JTable(hostTableModel);
        hostTable.setAutoCreateRowSorter(true);
        hostTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        hostTable.getColumnModel().getColumn(1).setMaxWidth(80);
        centerColumn(hostTable, 1);

        JPanel hostPanel = new JPanel(new BorderLayout());
        hostPanel.setBorder(new TitledBorder("Secrets by Host"));
        hostPanel.add(new JScrollPane(hostTable), BorderLayout.CENTER);
        tablesPanel.add(hostPanel);

        add(tablesPanel, BorderLayout.CENTER);

        // Initial refresh
        refresh();
    }

    private void centerColumn(JTable table, int column) {
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        table.getColumnModel().getColumn(column).setCellRenderer(centerRenderer);
    }

    /**
     * Refresh statistics from the secrets model.
     * Note: Does NOT call secretsModel.refresh() to avoid clearing table selection in SecretsView.
     */
    public void refresh() {
        // Update host table
        hostTableModel.setRowCount(0);
        Map<String, Integer> hostCounts = secretsModel.getCountByHost();
        List<Map.Entry<String, Integer>> sortedHosts = new ArrayList<>(hostCounts.entrySet());
        sortedHosts.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));

        for (Map.Entry<String, Integer> entry : sortedHosts) {
            hostTableModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
        }

        // Update type table
        typeTableModel.setRowCount(0);
        Map<String, Integer> typeCounts = secretsModel.getCountByType();
        List<Map.Entry<String, Integer>> sortedTypes = new ArrayList<>(typeCounts.entrySet());
        sortedTypes.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));

        for (Map.Entry<String, Integer> entry : sortedTypes) {
            // Find severity for this type from actual config
            String severity = findSeverityForType(entry.getKey());
            typeTableModel.addRow(new Object[]{entry.getKey(), entry.getValue(), severity});
        }

        // Update summary
        updateSummary();
    }

    /**
     * Find the severity label for a type by looking up the first matching finding's ruleId
     * in the severity config.
     */
    private String findSeverityForType(String typeName) {
        // Find a finding record that matches this type to get the ruleId
        for (int i = 0; i < secretsModel.getRowCount(); i++) {
            DedupCache.FindingRecord record = secretsModel.getRecordAt(i);
            if (record != null) {
                String recordType = record.ruleName != null ? record.ruleName : SecretCategoryMapper.getDisplayName(record.ruleId, null);
                if (recordType.equals(typeName)) {
                    AuditIssueSeverity severity = secretsModel.getSeverityAt(i);
                    return switch (severity) {
                        case HIGH -> "High";
                        case MEDIUM -> "Medium";
                        case LOW -> "Low";
                        case INFORMATION -> "Info";
                        case FALSE_POSITIVE -> "FP";
                    };
                }
            }
        }
        return "Medium";
    }

    private void updateSummary() {
        int totalSecrets = secretsModel.getTotalCount();
        int totalHosts = secretsModel.getUniqueHosts().size();
        int[] validationCounts = secretsModel.getValidationCounts();
        // [valid, invalid, undetermined, notChecked, falsePositive]
        int valid = validationCounts[0];
        int invalid = validationCounts[1];
        int undetermined = validationCounts[2];
        int falsePositive = validationCounts[4];
        int validated = valid + invalid + undetermined;

        StringBuilder sb = new StringBuilder();
        sb.append(totalSecrets).append(" unique secret").append(totalSecrets != 1 ? "s" : "");
        sb.append(" across ").append(totalHosts).append(" host").append(totalHosts != 1 ? "s" : "");

        sb.append(" | Validated: ").append(validated);
        if (validated > 0) {
            sb.append(" (").append(valid).append(" active, ");
            sb.append(invalid).append(" inactive)");
        }

        sb.append(" | False Positive: ").append(falsePositive);

        summaryLabel.setText(sb.toString());
    }

    /**
     * Custom renderer for severity column with color coding based on actual severity level.
     */
    private static class SeverityColorCellRenderer extends DefaultTableCellRenderer {
        private static final Color HIGH_COLOR = new Color(220, 53, 69, 100);    // Red
        private static final Color MEDIUM_COLOR = new Color(255, 152, 0, 100);  // Orange
        private static final Color LOW_COLOR = new Color(91, 192, 222, 100);    // Blue
        private static final Color INFO_COLOR = new Color(91, 192, 222, 60);    // Light blue

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected && value != null) {
                String severity = value.toString();
                c.setBackground(switch (severity) {
                    case "High" -> HIGH_COLOR;
                    case "Medium" -> MEDIUM_COLOR;
                    case "Low" -> LOW_COLOR;
                    case "Info" -> INFO_COLOR;
                    default -> null;
                });
            } else if (!isSelected) {
                c.setBackground(null);
            }

            return c;
        }
    }
}
