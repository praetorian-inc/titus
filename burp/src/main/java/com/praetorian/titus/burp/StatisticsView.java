package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;

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

    private final DefaultTableModel hostTableModel;
    private final DefaultTableModel typeTableModel;
    private final JTable hostTable;
    private final JTable typeTable;
    private final JLabel summaryLabel;
    private final JButton refreshButton;

    public StatisticsView(MontoyaApi api, SecretsTableModel secretsModel) {
        this.api = api;
        this.secretsModel = secretsModel;

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        refreshButton = new JButton("Refresh Statistics");
        refreshButton.addActionListener(e -> refresh());
        toolbar.add(refreshButton);
        add(toolbar, BorderLayout.NORTH);

        // Main content - two tables side by side
        JPanel tablesPanel = new JPanel(new GridLayout(1, 2, 10, 0));

        // Host statistics table
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

        // Type statistics table
        typeTableModel = new DefaultTableModel(new String[]{"Type", "Count", "Category"}, 0) {
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

        // Color the category column
        typeTable.getColumnModel().getColumn(2).setCellRenderer(new CategoryColorCellRenderer());

        JPanel typePanel = new JPanel(new BorderLayout());
        typePanel.setBorder(new TitledBorder("Secrets by Type"));
        typePanel.add(new JScrollPane(typeTable), BorderLayout.CENTER);
        tablesPanel.add(typePanel);

        add(tablesPanel, BorderLayout.CENTER);

        // Summary bar
        summaryLabel = new JLabel("No statistics available");
        summaryLabel.setBorder(BorderFactory.createCompoundBorder(
            new TitledBorder("Summary"),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
        summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.BOLD));
        add(summaryLabel, BorderLayout.SOUTH);

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
     */
    public void refresh() {
        secretsModel.refresh(); // Ensure data is current

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
            // Find category for this type
            String category = findCategoryForType(entry.getKey());
            typeTableModel.addRow(new Object[]{entry.getKey(), entry.getValue(), category});
        }

        // Update summary
        updateSummary();
    }

    private String findCategoryForType(String typeName) {
        // This is a simplified lookup - ideally we'd track ruleId -> type mapping
        Map<SecretCategoryMapper.Category, Integer> categoryCounts = secretsModel.getCountByCategory();
        // Return most likely category based on type name
        String lower = typeName.toLowerCase();
        if (lower.contains("aws") || lower.contains("azure") || lower.contains("gcp") || lower.contains("cloud")) {
            return SecretCategoryMapper.Category.CLOUD.getDisplayName();
        } else if (lower.contains("database") || lower.contains("postgres") || lower.contains("mysql") || lower.contains("password")) {
            return SecretCategoryMapper.Category.DATABASE.getDisplayName();
        } else if (lower.contains("private") || lower.contains("ssh") || lower.contains("rsa") || lower.contains("key")) {
            return SecretCategoryMapper.Category.PRIVATE_KEY.getDisplayName();
        } else if (lower.contains("api") || lower.contains("token") || lower.contains("slack") || lower.contains("stripe")) {
            return SecretCategoryMapper.Category.API_KEY.getDisplayName();
        }
        return SecretCategoryMapper.Category.GENERIC.getDisplayName();
    }

    private void updateSummary() {
        int totalSecrets = secretsModel.getTotalCount();
        int totalHosts = secretsModel.getUniqueHosts().size();
        int[] validationCounts = secretsModel.getValidationCounts();

        StringBuilder sb = new StringBuilder();
        sb.append(totalSecrets).append(" unique secret").append(totalSecrets != 1 ? "s" : "");
        sb.append(" across ").append(totalHosts).append(" host").append(totalHosts != 1 ? "s" : "");

        int validated = validationCounts[0] + validationCounts[1] + validationCounts[2];
        if (validated > 0) {
            sb.append(" | ").append(validated).append(" validated");
            sb.append(" (").append(validationCounts[0]).append(" active, ");
            sb.append(validationCounts[1]).append(" inactive)");
        }

        summaryLabel.setText(sb.toString());
    }

    /**
     * Custom renderer for category column with color coding.
     */
    private static class CategoryColorCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected && value != null) {
                String categoryName = value.toString();
                for (SecretCategoryMapper.Category cat : SecretCategoryMapper.Category.values()) {
                    if (cat.getDisplayName().equals(categoryName)) {
                        c.setBackground(cat.getLightColor());
                        break;
                    }
                }
            }

            return c;
        }
    }
}
