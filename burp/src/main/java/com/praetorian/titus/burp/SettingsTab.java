package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Settings tab UI for the Titus extension.
 */
public class SettingsTab extends JPanel {

    private static final String SETTINGS_PASSIVE_ENABLED = "titus.passive_enabled";

    private final MontoyaApi api;
    private final SeverityConfig severityConfig;
    private final ScanQueue scanQueue;
    private final DedupCache dedupCache;

    private JCheckBox passiveScanCheckbox;
    private JLabel queueSizeLabel;
    private JLabel scannedCountLabel;
    private JLabel matchCountLabel;
    private JLabel findingsCountLabel;
    private JTable severityTable;
    private DefaultTableModel severityTableModel;

    private Timer statsTimer;

    public SettingsTab(MontoyaApi api, SeverityConfig severityConfig,
                       ScanQueue scanQueue, DedupCache dedupCache) {
        this.api = api;
        this.severityConfig = severityConfig;
        this.scanQueue = scanQueue;
        this.dedupCache = dedupCache;

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create main content panel
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        mainPanel.add(createHeaderPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createScanSettingsPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createStatsPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createSeverityPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createActionsPanel());

        // Wrap in scroll pane
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        add(scrollPane, BorderLayout.CENTER);

        // Load settings
        loadSettings();

        // Start stats update timer
        startStatsTimer();
    }

    public boolean isPassiveScanEnabled() {
        return passiveScanCheckbox != null && passiveScanCheckbox.isSelected();
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 60));

        JLabel titleLabel = new JLabel("Titus Secret Scanner");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 18f));

        JLabel descLabel = new JLabel("Scans HTTP responses for secrets using NoseyParker rules");
        descLabel.setForeground(Color.GRAY);

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.add(titleLabel);
        textPanel.add(descLabel);

        panel.add(textPanel, BorderLayout.WEST);
        return panel;
    }

    private JPanel createScanSettingsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new TitledBorder("Scan Settings"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 100));

        passiveScanCheckbox = new JCheckBox("Enable passive scanning (scan all proxy traffic)");
        passiveScanCheckbox.setSelected(true);
        passiveScanCheckbox.addActionListener(e -> saveSettings());

        JLabel hint = new JLabel("Tip: Right-click items in HTTP history to scan manually");
        hint.setForeground(Color.GRAY);
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 11f));

        panel.add(passiveScanCheckbox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(hint);

        return panel;
    }

    private JPanel createStatsPanel() {
        JPanel panel = new JPanel(new GridLayout(2, 4, 10, 5));
        panel.setBorder(new TitledBorder("Statistics"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 100));

        panel.add(new JLabel("Queue Size:"));
        queueSizeLabel = new JLabel("0");
        queueSizeLabel.setFont(queueSizeLabel.getFont().deriveFont(Font.BOLD));
        panel.add(queueSizeLabel);

        panel.add(new JLabel("Items Scanned:"));
        scannedCountLabel = new JLabel("0");
        scannedCountLabel.setFont(scannedCountLabel.getFont().deriveFont(Font.BOLD));
        panel.add(scannedCountLabel);

        panel.add(new JLabel("Matches Found:"));
        matchCountLabel = new JLabel("0");
        matchCountLabel.setFont(matchCountLabel.getFont().deriveFont(Font.BOLD));
        panel.add(matchCountLabel);

        panel.add(new JLabel("Unique Findings:"));
        findingsCountLabel = new JLabel("0");
        findingsCountLabel.setFont(findingsCountLabel.getFont().deriveFont(Font.BOLD));
        panel.add(findingsCountLabel);

        return panel;
    }

    private JPanel createSeverityPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new TitledBorder("Severity Configuration"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 250));

        // Create table
        String[] columns = {"Category", "Severity"};
        severityTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 1; // Only severity column is editable
            }
        };

        severityTable = new JTable(severityTableModel);
        severityTable.getColumnModel().getColumn(1).setCellEditor(
            new DefaultCellEditor(new JComboBox<>(AuditIssueSeverity.values()))
        );

        // Populate table
        populateSeverityTable();

        // Add listener for changes
        severityTableModel.addTableModelListener(e -> {
            if (e.getColumn() == 1) {
                int row = e.getFirstRow();
                String category = (String) severityTableModel.getValueAt(row, 0);
                Object value = severityTableModel.getValueAt(row, 1);
                AuditIssueSeverity severity = value instanceof AuditIssueSeverity
                    ? (AuditIssueSeverity) value
                    : AuditIssueSeverity.valueOf(value.toString());
                severityConfig.setCategorySeverity(category, severity);
            }
        });

        JScrollPane tableScroll = new JScrollPane(severityTable);
        panel.add(tableScroll, BorderLayout.CENTER);

        JLabel hint = new JLabel("Edit severity levels by clicking the Severity column");
        hint.setForeground(Color.GRAY);
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 11f));
        panel.add(hint, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createActionsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(new TitledBorder("Actions"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));

        JButton clearCacheButton = new JButton("Clear Finding Cache");
        clearCacheButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(
                this,
                "Clear all cached findings? This will allow duplicate issues to be reported again.",
                "Clear Cache",
                JOptionPane.YES_NO_OPTION
            );
            if (result == JOptionPane.YES_OPTION) {
                dedupCache.clear();
                api.logging().logToOutput("Finding cache cleared");
                updateStats();
            }
        });

        JButton resetSeverityButton = new JButton("Reset Severities to Defaults");
        resetSeverityButton.addActionListener(e -> {
            severityConfig.resetToDefaults();
            populateSeverityTable();
            api.logging().logToOutput("Severity configuration reset to defaults");
        });

        panel.add(clearCacheButton);
        panel.add(resetSeverityButton);

        return panel;
    }

    private void populateSeverityTable() {
        severityTableModel.setRowCount(0);

        Map<String, AuditIssueSeverity> defaults = severityConfig.getCategoryDefaults();
        for (Map.Entry<String, AuditIssueSeverity> entry : defaults.entrySet()) {
            severityTableModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
        }
    }

    private void loadSettings() {
        try {
            String enabled = api.persistence().extensionData().getString(SETTINGS_PASSIVE_ENABLED);
            if (enabled != null) {
                passiveScanCheckbox.setSelected(Boolean.parseBoolean(enabled));
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load settings: " + e.getMessage());
        }
    }

    private void saveSettings() {
        try {
            api.persistence().extensionData().setString(
                SETTINGS_PASSIVE_ENABLED,
                String.valueOf(passiveScanCheckbox.isSelected())
            );
        } catch (Exception e) {
            api.logging().logToError("Failed to save settings: " + e.getMessage());
        }
    }

    private void startStatsTimer() {
        statsTimer = new Timer("titus-stats", true);
        statsTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                SwingUtilities.invokeLater(() -> updateStats());
            }
        }, 1000, 1000); // Update every second
    }

    private void updateStats() {
        if (scanQueue != null) {
            queueSizeLabel.setText(String.valueOf(scanQueue.queueSize()));
            scannedCountLabel.setText(String.valueOf(scanQueue.totalScanned()));
            matchCountLabel.setText(String.valueOf(scanQueue.totalMatches()));
        }
        if (dedupCache != null) {
            findingsCountLabel.setText(String.valueOf(dedupCache.uniqueFindingsCount()));
        }
    }
}
