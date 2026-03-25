package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.PatternSyntaxException;

/**
 * Settings tab UI for the Titus extension.
 */
public class SettingsTab extends JPanel {

    private static final String SETTINGS_PASSIVE_ENABLED = "titus.passive_enabled";
    private static final String SETTINGS_SCAN_REQUESTS = "titus.scan_requests";

    private final MontoyaApi api;
    private final SeverityConfig severityConfig;
    private final ScanQueue scanQueue;
    private final DedupCache dedupCache;

    private JCheckBox passiveScanCheckbox;
    private JCheckBox scanRequestsCheckbox;
    private JCheckBox validationEnabledCheckbox;
    private ScanParametersPanel parametersPanel;
    private RequestsTableModel requestsTableModel;
    private RequestsView requestsView;
    private SecretsView secretsView;
    private StatisticsView statisticsView;
    private MessagePersistence messagePersistence;
    private FindingsExporter findingsExporter;
    private ValidationManager validationManager;
    private JTable severityTable;
    private DefaultTableModel severityTableModel;
    private TableRowSorter<DefaultTableModel> severityRowSorter;
    private JTextField severitySearchField;

    private Timer statsTimer;

    public SettingsTab(MontoyaApi api, SeverityConfig severityConfig,
                       ScanQueue scanQueue, DedupCache dedupCache) {
        this.api = api;
        this.severityConfig = severityConfig;
        this.scanQueue = scanQueue;
        this.dedupCache = dedupCache;

        setLayout(new BorderLayout());

        // Create tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();

        // Initialize requests model (used internally for scanning, but tab hidden)
        requestsTableModel = new RequestsTableModel();
        requestsView = new RequestsView(api, requestsTableModel);

        // Secrets tab (first)
        secretsView = new SecretsView(api, dedupCache);
        secretsView.setSeverityConfig(severityConfig);
        tabbedPane.addTab("Secrets", secretsView);

        // Statistics tab (second)
        statisticsView = new StatisticsView(api, secretsView.getTableModel());
        tabbedPane.addTab("Statistics", statisticsView);

        // Settings tab (last)
        JPanel settingsPanel = createSettingsPanel();
        tabbedPane.addTab("Settings", settingsPanel);

        add(tabbedPane, BorderLayout.CENTER);

        // Initialize message persistence
        messagePersistence = new MessagePersistence(api);

        // Initialize findings exporter
        findingsExporter = new FindingsExporter(api);

        // Restore persisted messages
        restorePersistedMessages();

        // Wire up scan queue listener to populate table and refresh secrets
        scanQueue.setListener(new ScanQueue.ScanQueueListener() {
            @Override
            public void onJobEnqueued(ScanJob job) {
                SwingUtilities.invokeLater(() -> {
                    requestsTableModel.addEntry(job);
                    requestsView.updateStatus();
                    // Refresh secrets view periodically (every 5 jobs to avoid excessive updates)
                    if (requestsTableModel.getEntryCount() % 5 == 0) {
                        secretsView.refresh();
                    }
                });
            }

            @Override
            public void onSecretsFound(String url, int count, String types, SecretCategoryMapper.Category category) {
                SwingUtilities.invokeLater(() -> {
                    requestsTableModel.updateSecretInfo(url, count, types, category);
                    // Also refresh secrets view when new secrets are found
                    secretsView.refresh();
                });
            }
        });

        // Load settings
        loadSettings();

        // Start stats update timer
        startStatsTimer();
    }

    private JPanel createSettingsPanel() {
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top row: Scan Settings (left) and Scan Parameters (right) side by side
        JPanel topRow = new JPanel(new GridLayout(1, 2, 10, 0));
        topRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200));

        JPanel scanSettingsPanel = createScanSettingsPanel();
        parametersPanel = new ScanParametersPanel(api);

        topRow.add(scanSettingsPanel);
        topRow.add(parametersPanel);

        mainPanel.add(topRow);
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createSeverityPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createActionsPanel());

        // Wrap in scroll pane
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    public boolean isPassiveScanEnabled() {
        return passiveScanCheckbox != null && passiveScanCheckbox.isSelected();
    }

    public boolean isRequestScanEnabled() {
        return scanRequestsCheckbox != null && scanRequestsCheckbox.isSelected();
    }

    /**
     * Get the scan parameters panel for accessing current settings.
     */
    public ScanParametersPanel getParametersPanel() {
        return parametersPanel;
    }

    /**
     * Get the requests table model.
     */
    public RequestsTableModel getRequestsTableModel() {
        return requestsTableModel;
    }

    /**
     * Get the requests view.
     */
    public RequestsView getRequestsView() {
        return requestsView;
    }

    /**
     * Get the secrets view.
     */
    public SecretsView getSecretsView() {
        return secretsView;
    }

    /**
     * Set the validation manager.
     */
    public void setValidationManager(ValidationManager validationManager) {
        this.validationManager = validationManager;
        if (validationEnabledCheckbox != null) {
            validationEnabledCheckbox.setSelected(validationManager.isValidationEnabled());
        }

        // Wire up secrets view validation listener
        if (secretsView != null) {
            secretsView.setValidationListener(record -> {
                if (validationManager == null) {
                    api.logging().logToError("Validation manager not initialized");
                    return;
                }
                if (!validationManager.isValidationEnabled()) {
                    javax.swing.JOptionPane.showMessageDialog(
                        secretsView,
                        "Validation is not enabled.\n\nGo to Settings tab and check 'Enable secret validation' to use this feature.",
                        "Validation Disabled",
                        javax.swing.JOptionPane.WARNING_MESSAGE
                    );
                    return;
                }
                validationManager.validateAsync(record, r -> {
                    secretsView.refresh();
                });
            });
        }
    }

    /**
     * Get the validation manager.
     */
    public ValidationManager getValidationManager() {
        return validationManager;
    }

    /**
     * Check if validation is enabled.
     */
    public boolean isValidationEnabled() {
        return validationManager != null && validationManager.isValidationEnabled();
    }

    /**
     * Get the message persistence handler.
     */
    public MessagePersistence getMessagePersistence() {
        return messagePersistence;
    }

    /**
     * Save current messages to persistence.
     */
    public void saveMessages() {
        if (messagePersistence != null && requestsTableModel != null) {
            messagePersistence.persistMessages(requestsTableModel.getEntries());
        }
    }

    /**
     * Restore messages from persistence to table.
     */
    private void restorePersistedMessages() {
        if (messagePersistence == null || requestsTableModel == null) {
            return;
        }

        java.util.List<ScanJob> jobs = messagePersistence.restoreMessages();
        for (ScanJob job : jobs) {
            requestsTableModel.addEntry(job);
        }
        requestsView.updateStatus();
    }

    private JPanel createScanSettingsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new TitledBorder("Scan Settings"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 180));

        passiveScanCheckbox = new JCheckBox("Enable passive scanning (scan all proxy traffic)");
        passiveScanCheckbox.setSelected(true);
        passiveScanCheckbox.addActionListener(e -> saveSettings());

        scanRequestsCheckbox = new JCheckBox("Scan request bodies (in addition to responses)");
        scanRequestsCheckbox.setSelected(false);
        scanRequestsCheckbox.addActionListener(e -> saveSettings());

        validationEnabledCheckbox = new JCheckBox("Enable secret validation (makes outbound API requests)");
        validationEnabledCheckbox.setSelected(false);
        validationEnabledCheckbox.addActionListener(e -> {
            if (validationManager != null) {
                validationManager.setValidationEnabled(validationEnabledCheckbox.isSelected());
            }
        });

        JLabel hint = new JLabel("Tip: Right-click items in HTTP history to scan manually");
        hint.setForeground(Color.GRAY);
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 11f));

        JLabel validationWarning = new JLabel("Warning: Validation may trigger alerts (e.g., AWS CloudTrail) and makes requests to external services.");
        validationWarning.setForeground(new Color(200, 100, 0));
        validationWarning.setFont(validationWarning.getFont().deriveFont(Font.ITALIC, 10f));

        panel.add(passiveScanCheckbox);
        panel.add(Box.createVerticalStrut(3));
        panel.add(scanRequestsCheckbox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(validationEnabledCheckbox);
        panel.add(Box.createVerticalStrut(2));
        panel.add(validationWarning);
        panel.add(Box.createVerticalStrut(5));
        panel.add(hint);

        return panel;
    }

    private JPanel createSeverityPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 5));
        panel.setBorder(new TitledBorder("Severity Configuration"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 280));

        // Create table model
        String[] columns = {"Category", "Severity"};
        severityTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 1; // Only severity column is editable
            }
        };

        severityTable = new JTable(severityTableModel);

        // Add row sorter for sorting columns
        severityRowSorter = new TableRowSorter<>(severityTableModel);
        severityTable.setRowSorter(severityRowSorter);

        // Custom comparator for severity column to sort by severity order
        severityRowSorter.setComparator(1, (o1, o2) -> {
            AuditIssueSeverity s1 = o1 instanceof AuditIssueSeverity ? (AuditIssueSeverity) o1 : AuditIssueSeverity.valueOf(o1.toString());
            AuditIssueSeverity s2 = o2 instanceof AuditIssueSeverity ? (AuditIssueSeverity) o2 : AuditIssueSeverity.valueOf(o2.toString());
            return s1.ordinal() - s2.ordinal();
        });

        severityTable.getColumnModel().getColumn(1).setCellEditor(
            new DefaultCellEditor(new JComboBox<>(AuditIssueSeverity.values()))
        );

        // Set preferred column widths
        severityTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        severityTable.getColumnModel().getColumn(1).setPreferredWidth(100);

        // Populate table
        populateSeverityTable();

        // Add listener for changes
        severityTableModel.addTableModelListener(e -> {
            if (e.getColumn() == 1) {
                int viewRow = e.getFirstRow();
                // Convert to model row since we have sorting
                String category = (String) severityTableModel.getValueAt(viewRow, 0);
                Object value = severityTableModel.getValueAt(viewRow, 1);
                AuditIssueSeverity severity = value instanceof AuditIssueSeverity
                    ? (AuditIssueSeverity) value
                    : AuditIssueSeverity.valueOf(value.toString());
                severityConfig.setCategorySeverity(category, severity);
            }
        });

        // Table in scroll pane - constrain width
        JScrollPane tableScroll = new JScrollPane(severityTable);
        tableScroll.setPreferredSize(new Dimension(350, 180));

        // Left panel: table with constrained width
        JPanel tablePanel = new JPanel(new BorderLayout(5, 5));

        // Top: search bar
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        searchPanel.add(new JLabel("Search:"));
        severitySearchField = new JTextField(15);
        severitySearchField.setToolTipText("Filter categories");
        severitySearchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { filterSeverityTable(); }
            @Override
            public void removeUpdate(DocumentEvent e) { filterSeverityTable(); }
            @Override
            public void changedUpdate(DocumentEvent e) { filterSeverityTable(); }
        });
        searchPanel.add(severitySearchField);

        tablePanel.add(searchPanel, BorderLayout.NORTH);
        tablePanel.add(tableScroll, BorderLayout.CENTER);

        // Bottom: buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));

        JButton addButton = new JButton("+");
        addButton.setToolTipText("Add custom category");
        addButton.setMargin(new Insets(2, 6, 2, 6));
        addButton.addActionListener(e -> addCustomCategory());

        JButton removeButton = new JButton("-");
        removeButton.setToolTipText("Remove selected category");
        removeButton.setMargin(new Insets(2, 6, 2, 6));
        removeButton.addActionListener(e -> removeSelectedCategory());

        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);

        tablePanel.add(buttonPanel, BorderLayout.SOUTH);

        // Right panel: hints/info
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 5));

        JLabel hint1 = new JLabel("Click column headers to sort");
        hint1.setForeground(Color.GRAY);
        hint1.setFont(hint1.getFont().deriveFont(Font.ITALIC, 11f));

        JLabel hint2 = new JLabel("Click Severity column to edit");
        hint2.setForeground(Color.GRAY);
        hint2.setFont(hint2.getFont().deriveFont(Font.ITALIC, 11f));

        JLabel hint3 = new JLabel("Use + to add custom categories");
        hint3.setForeground(Color.GRAY);
        hint3.setFont(hint3.getFont().deriveFont(Font.ITALIC, 11f));

        infoPanel.add(hint1);
        infoPanel.add(Box.createVerticalStrut(5));
        infoPanel.add(hint2);
        infoPanel.add(Box.createVerticalStrut(5));
        infoPanel.add(hint3);
        infoPanel.add(Box.createVerticalGlue());

        // Main layout: table on left, info on right
        panel.add(tablePanel, BorderLayout.WEST);
        panel.add(infoPanel, BorderLayout.CENTER);

        return panel;
    }

    private void filterSeverityTable() {
        String text = severitySearchField.getText().trim();
        if (text.isEmpty()) {
            severityRowSorter.setRowFilter(null);
        } else {
            try {
                severityRowSorter.setRowFilter(RowFilter.regexFilter("(?i)" + text, 0));
            } catch (PatternSyntaxException e) {
                // Invalid regex, ignore
            }
        }
    }

    private void addCustomCategory() {
        String categoryName = JOptionPane.showInputDialog(
            this,
            "Enter category name (e.g., 'stripe', 'sendgrid'):",
            "Add Custom Category",
            JOptionPane.PLAIN_MESSAGE
        );

        if (categoryName != null && !categoryName.trim().isEmpty()) {
            String category = categoryName.trim().toLowerCase();

            // Check if already exists
            Map<String, AuditIssueSeverity> existing = severityConfig.getCategoryDefaults();
            if (existing.containsKey(category)) {
                JOptionPane.showMessageDialog(
                    this,
                    "Category '" + category + "' already exists.",
                    "Category Exists",
                    JOptionPane.WARNING_MESSAGE
                );
                return;
            }

            // Add with default severity MEDIUM
            severityConfig.setCategorySeverity(category, AuditIssueSeverity.MEDIUM);
            populateSeverityTable();

            // Find and scroll to the newly added category
            SwingUtilities.invokeLater(() -> {
                for (int i = 0; i < severityTable.getRowCount(); i++) {
                    String cat = (String) severityTable.getValueAt(i, 0);
                    if (cat.equals(category)) {
                        severityTable.setRowSelectionInterval(i, i);
                        severityTable.scrollRectToVisible(severityTable.getCellRect(i, 0, true));
                        break;
                    }
                }
            });

            api.logging().logToOutput("Added custom category: " + category);
        }
    }

    private void removeSelectedCategory() {
        int selectedRow = severityTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(
                this,
                "Please select a category to remove.",
                "No Selection",
                JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        String category = (String) severityTableModel.getValueAt(selectedRow, 0);

        int result = JOptionPane.showConfirmDialog(
            this,
            "Remove category '" + category + "'?",
            "Remove Category",
            JOptionPane.YES_NO_OPTION
        );

        if (result == JOptionPane.YES_OPTION) {
            severityConfig.removeCategory(category);
            populateSeverityTable();
            api.logging().logToOutput("Removed category: " + category);
        }
    }

    private JPanel createActionsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(new TitledBorder("Actions"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));

        JButton clearCacheButton = new JButton("Clear Findings");
        clearCacheButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(
                this,
                "Clear all findings and stored requests? This will allow duplicate issues to be reported again.",
                "Clear Findings",
                JOptionPane.YES_NO_OPTION
            );
            if (result == JOptionPane.YES_OPTION) {
                dedupCache.clear();
                requestsView.clear();
                messagePersistence.clear();
                api.logging().logToOutput("Findings and requests cleared");
                updateStats();
            }
        });

        JButton resetSeverityButton = new JButton("Reset Severities to Defaults");
        resetSeverityButton.addActionListener(e -> {
            severityConfig.resetToDefaults();
            populateSeverityTable();
            api.logging().logToOutput("Severity configuration reset to defaults");
        });

        JButton saveMessagesButton = new JButton("Save Requests");
        saveMessagesButton.addActionListener(e -> {
            saveMessages();
            JOptionPane.showMessageDialog(
                this,
                "Requests saved. They will be restored when the extension reloads.",
                "Requests Saved",
                JOptionPane.INFORMATION_MESSAGE
            );
        });

        JButton exportButton = new JButton("Export Findings to JSON");
        exportButton.addActionListener(e -> findingsExporter.exportFindings(dedupCache, this));

        panel.add(clearCacheButton);
        panel.add(resetSeverityButton);
        panel.add(saveMessagesButton);
        panel.add(exportButton);

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

            String scanRequests = api.persistence().extensionData().getString(SETTINGS_SCAN_REQUESTS);
            if (scanRequests != null) {
                scanRequestsCheckbox.setSelected(Boolean.parseBoolean(scanRequests));
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
            api.persistence().extensionData().setString(
                SETTINGS_SCAN_REQUESTS,
                String.valueOf(scanRequestsCheckbox.isSelected())
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
        // Stats are now shown in the Statistics tab, refresh it periodically
        if (statisticsView != null) {
            statisticsView.refresh();
        }
    }
}
