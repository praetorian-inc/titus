package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * View panel for the Secrets tab showing deduplicated findings.
 */
public class SecretsView extends JPanel {

    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final MontoyaApi api;
    private final SecretsTableModel tableModel;
    private final DedupCache dedupCache;
    private JTable secretsTable;
    private TableRowSorter<SecretsTableModel> rowSorter;
    private JTextArea detailArea;
    private JTextArea urlsArea;
    private JTabbedPane detailTabbedPane;
    private JLabel statusLabel;
    private JButton validateButton;
    private JButton falsePositiveButton;
    private JButton copyButton;
    private JButton refreshButton;

    // Filter components
    private JComboBox<String> typeFilter;
    private JComboBox<String> hostFilter;
    private JComboBox<String> validationFilter;

    private ValidationListener validationListener;
    private FalsePositiveListener falsePositiveListener;

    /**
     * Listener for false positive marking requests.
     */
    public interface FalsePositiveListener {
        void onFalsePositiveRequested(List<DedupCache.FindingRecord> records);
    }

    /**
     * Listener for validation requests.
     */
    public interface ValidationListener {
        void onValidateRequested(DedupCache.FindingRecord record);
    }

    public SecretsView(MontoyaApi api, DedupCache dedupCache) {
        this.api = api;
        this.dedupCache = dedupCache;
        this.tableModel = new SecretsTableModel(dedupCache);

        setLayout(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Create table with row sorter for filtering
        secretsTable = new JTable(tableModel);
        rowSorter = new TableRowSorter<>(tableModel);
        secretsTable.setRowSorter(rowSorter);
        secretsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        secretsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        secretsTable.getSelectionModel().addListSelectionListener(this::onSelectionChanged);

        // Configure column widths
        configureColumnWidths();

        // Custom renderer for category colors
        secretsTable.setDefaultRenderer(Object.class, new CategoryColorRenderer());
        secretsTable.setDefaultRenderer(Integer.class, new CategoryColorRenderer());

        JScrollPane tableScroll = new JScrollPane(secretsTable);
        tableScroll.setPreferredSize(new Dimension(800, 250));

        // Detail panel with tabs
        JPanel detailPanel = createDetailPanel();

        // Split pane: table above, details below
        JSplitPane splitPane = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            tableScroll,
            detailPanel
        );
        splitPane.setResizeWeight(0.6);
        splitPane.setOneTouchExpandable(true);

        add(splitPane, BorderLayout.CENTER);

        // Top panel with toolbar and filters
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(createToolbar(), BorderLayout.NORTH);
        topPanel.add(createFilterPanel(), BorderLayout.SOUTH);
        add(topPanel, BorderLayout.NORTH);

        // Status bar
        statusLabel = new JLabel("0 secrets");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        add(statusLabel, BorderLayout.SOUTH);

        // Initial refresh
        refresh();
    }

    private void configureColumnWidths() {
        secretsTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
        secretsTable.getColumnModel().getColumn(0).setMaxWidth(50);
        secretsTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // Type
        secretsTable.getColumnModel().getColumn(2).setPreferredWidth(200);  // Preview
        secretsTable.getColumnModel().getColumn(3).setPreferredWidth(150);  // Host
        secretsTable.getColumnModel().getColumn(4).setPreferredWidth(60);   // Count
        secretsTable.getColumnModel().getColumn(4).setMaxWidth(80);
        secretsTable.getColumnModel().getColumn(5).setPreferredWidth(80);   // Validation
        secretsTable.getColumnModel().getColumn(5).setMaxWidth(100);
    }

    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));

        refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> refresh());

        validateButton = new JButton("Validate Selected");
        validateButton.setEnabled(false);
        validateButton.addActionListener(e -> validateSelected());

        falsePositiveButton = new JButton("Mark False Positive");
        falsePositiveButton.setEnabled(false);
        falsePositiveButton.addActionListener(e -> markFalsePositive());

        copyButton = new JButton("Copy Secret");
        copyButton.setEnabled(false);
        copyButton.addActionListener(e -> copySelectedSecret());

        toolbar.add(refreshButton);
        toolbar.add(validateButton);
        toolbar.add(falsePositiveButton);
        toolbar.add(copyButton);

        return toolbar;
    }

    private JPanel createFilterPanel() {
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        filterPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));

        // Type filter
        filterPanel.add(new JLabel("Type:"));
        typeFilter = new JComboBox<>();
        typeFilter.addItem("All Types");
        typeFilter.setPreferredSize(new Dimension(150, 25));
        typeFilter.addActionListener(e -> applyFilters());
        filterPanel.add(typeFilter);

        // Host filter
        filterPanel.add(new JLabel("Host:"));
        hostFilter = new JComboBox<>();
        hostFilter.addItem("All Hosts");
        hostFilter.setPreferredSize(new Dimension(200, 25));
        hostFilter.addActionListener(e -> applyFilters());
        filterPanel.add(hostFilter);

        // Validation filter
        filterPanel.add(new JLabel("Status:"));
        validationFilter = new JComboBox<>();
        validationFilter.addItem("All");
        validationFilter.addItem("Not Checked");
        validationFilter.addItem("Active");
        validationFilter.addItem("Inactive");
        validationFilter.addItem("False Positive");
        validationFilter.setPreferredSize(new Dimension(120, 25));
        validationFilter.addActionListener(e -> applyFilters());
        filterPanel.add(validationFilter);

        // Clear filters button
        JButton clearButton = new JButton("Clear Filters");
        clearButton.addActionListener(e -> clearFilters());
        filterPanel.add(clearButton);

        return filterPanel;
    }

    private void updateFilterDropdowns() {
        // Save current selections
        Object selectedType = typeFilter.getSelectedItem();
        Object selectedHost = hostFilter.getSelectedItem();

        // Update type filter
        typeFilter.removeAllItems();
        typeFilter.addItem("All Types");
        for (String type : tableModel.getUniqueTypes()) {
            typeFilter.addItem(type);
        }
        if (selectedType != null) {
            typeFilter.setSelectedItem(selectedType);
        }

        // Update host filter
        hostFilter.removeAllItems();
        hostFilter.addItem("All Hosts");
        for (String host : tableModel.getUniqueHosts()) {
            hostFilter.addItem(host);
        }
        if (selectedHost != null) {
            hostFilter.setSelectedItem(selectedHost);
        }
    }

    private void applyFilters() {
        List<RowFilter<SecretsTableModel, Integer>> filters = new ArrayList<>();

        // Type filter
        String selectedType = (String) typeFilter.getSelectedItem();
        if (selectedType != null && !selectedType.equals("All Types")) {
            filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(selectedType) + "$", 1));
        }

        // Host filter
        String selectedHost = (String) hostFilter.getSelectedItem();
        if (selectedHost != null && !selectedHost.equals("All Hosts")) {
            filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(selectedHost) + "$", 3));
        }

        // Validation filter
        String selectedValidation = (String) validationFilter.getSelectedItem();
        if (selectedValidation != null && !selectedValidation.equals("All")) {
            String statusText = switch (selectedValidation) {
                case "Not Checked" -> "-";
                case "Active" -> "Active";
                case "Inactive" -> "Inactive";
                case "False Positive" -> "False Positive";
                default -> "";
            };
            if (!statusText.isEmpty()) {
                filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(statusText) + "$", 5));
            }
        }

        if (filters.isEmpty()) {
            rowSorter.setRowFilter(null);
        } else {
            rowSorter.setRowFilter(RowFilter.andFilter(filters));
        }

        updateStatus();
    }

    private void clearFilters() {
        typeFilter.setSelectedIndex(0);
        hostFilter.setSelectedIndex(0);
        validationFilter.setSelectedIndex(0);
        rowSorter.setRowFilter(null);
        updateStatus();
    }

    private JPanel createDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Secret Details"));

        detailTabbedPane = new JTabbedPane();

        // Details tab
        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailTabbedPane.addTab("Details", detailScroll);

        // URLs tab
        urlsArea = new JTextArea();
        urlsArea.setEditable(false);
        urlsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        urlsArea.setLineWrap(true);
        urlsArea.setWrapStyleWord(true);
        JScrollPane urlsScroll = new JScrollPane(urlsArea);
        detailTabbedPane.addTab("URLs", urlsScroll);

        panel.add(detailTabbedPane, BorderLayout.CENTER);
        panel.setPreferredSize(new Dimension(800, 150));

        return panel;
    }

    private void onSelectionChanged(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) {
            return;
        }

        int[] selectedRows = secretsTable.getSelectedRows();
        if (selectedRows.length == 0) {
            detailArea.setText("");
            urlsArea.setText("");
            validateButton.setEnabled(false);
            falsePositiveButton.setEnabled(false);
            copyButton.setEnabled(false);
            return;
        }

        // Convert view rows to model rows
        int[] modelRows = new int[selectedRows.length];
        for (int i = 0; i < selectedRows.length; i++) {
            modelRows[i] = secretsTable.convertRowIndexToModel(selectedRows[i]);
        }

        // Enable buttons based on selection
        boolean anyValidatable = false;
        for (int row : modelRows) {
            DedupCache.FindingRecord record = tableModel.getRecordAt(row);
            if (record != null && record.validationStatus == DedupCache.ValidationStatus.NOT_CHECKED) {
                anyValidatable = true;
                break;
            }
        }

        validateButton.setEnabled(anyValidatable);
        falsePositiveButton.setEnabled(true);
        copyButton.setEnabled(modelRows.length == 1);

        // Show details for single selection
        if (modelRows.length == 1) {
            DedupCache.FindingRecord record = tableModel.getRecordAt(modelRows[0]);
            if (record != null) {
                displayRecordDetails(record);
            }
        } else {
            detailArea.setText(modelRows.length + " secrets selected");
            urlsArea.setText("");
        }
    }

    private void displayRecordDetails(DedupCache.FindingRecord record) {
        StringBuilder sb = new StringBuilder();

        sb.append("Rule ID: ").append(record.ruleId).append("\n");
        sb.append("Rule Name: ").append(record.ruleName != null ? record.ruleName : "N/A").append("\n");
        sb.append("Category: ").append(SecretCategoryMapper.getCategory(record.ruleId).getDisplayName()).append("\n");
        sb.append("\n");

        sb.append("Secret Preview: ").append(record.secretPreview).append("\n");
        sb.append("Occurrences: ").append(record.occurrenceCount).append("\n");
        sb.append("First Seen: ").append(record.firstSeen != null ? TIME_FORMAT.format(record.firstSeen.atZone(java.time.ZoneId.systemDefault())) : "N/A").append("\n");
        sb.append("\n");

        sb.append("Primary Host: ").append(record.primaryHost != null ? record.primaryHost : "N/A").append("\n");
        if (record.hosts != null && record.hosts.size() > 1) {
            sb.append("All Hosts: ").append(String.join(", ", record.hosts)).append("\n");
        }
        sb.append("\n");

        sb.append("Validation Status: ").append(record.validationStatus.getDisplayText()).append("\n");
        if (record.validationMessage != null && !record.validationMessage.isEmpty()) {
            sb.append("Validation Message: ").append(record.validationMessage).append("\n");
        }
        if (record.validatedAt != null) {
            sb.append("Validated At: ").append(TIME_FORMAT.format(record.validatedAt.atZone(java.time.ZoneId.systemDefault()))).append("\n");
        }

        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);

        // URLs tab
        StringBuilder urlsSb = new StringBuilder();
        urlsSb.append("URLs where this secret was found:\n\n");
        if (record.urls != null) {
            int i = 1;
            for (String url : record.urls) {
                urlsSb.append(i++).append(". ").append(url).append("\n");
            }
        }
        urlsArea.setText(urlsSb.toString());
        urlsArea.setCaretPosition(0);
    }

    private void validateSelected() {
        int[] selectedRows = secretsTable.getSelectedRows();
        if (selectedRows.length == 0 || validationListener == null) {
            return;
        }

        for (int row : selectedRows) {
            int modelRow = secretsTable.convertRowIndexToModel(row);
            DedupCache.FindingRecord record = tableModel.getRecordAt(modelRow);
            if (record != null && record.validationStatus == DedupCache.ValidationStatus.NOT_CHECKED) {
                validationListener.onValidateRequested(record);
            }
        }
    }

    private void markFalsePositive() {
        int[] selectedRows = secretsTable.getSelectedRows();
        if (selectedRows.length == 0) {
            return;
        }

        List<DedupCache.FindingRecord> records = new ArrayList<>();
        for (int row : selectedRows) {
            int modelRow = secretsTable.convertRowIndexToModel(row);
            DedupCache.FindingRecord record = tableModel.getRecordAt(modelRow);
            if (record != null) {
                records.add(record);
            }
        }

        if (!records.isEmpty()) {
            if (falsePositiveListener != null) {
                falsePositiveListener.onFalsePositiveRequested(records);
            } else {
                // Default behavior - mark as false positive directly
                for (DedupCache.FindingRecord record : records) {
                    record.setValidation(DedupCache.ValidationStatus.FALSE_POSITIVE, "Marked by user");
                }
                dedupCache.saveToSettings();
                refresh();
            }
        }
    }

    private void copySelectedSecret() {
        int selectedRow = secretsTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }

        int modelRow = secretsTable.convertRowIndexToModel(selectedRow);
        DedupCache.FindingRecord record = tableModel.getRecordAt(modelRow);
        if (record != null && record.secretContent != null) {
            java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(record.secretContent);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            api.logging().logToOutput("Copied secret to clipboard");
        }
    }

    /**
     * Refresh the table data.
     */
    public void refresh() {
        tableModel.refresh();
        updateFilterDropdowns();
        updateStatus();
    }

    /**
     * Update the status label.
     */
    public void updateStatus() {
        int totalCount = tableModel.getTotalCount();
        int visibleCount = secretsTable.getRowCount();
        int[] validationCounts = tableModel.getValidationCounts();

        String status;
        if (visibleCount != totalCount) {
            status = "Showing " + visibleCount + " of " + totalCount + " secrets";
        } else {
            status = totalCount + " secret" + (totalCount != 1 ? "s" : "");
        }

        if (validationCounts[0] > 0 || validationCounts[1] > 0) {
            status += " (" + validationCounts[0] + " active, " + validationCounts[1] + " inactive)";
        }

        statusLabel.setText(status);
    }

    /**
     * Set the validation listener.
     */
    public void setValidationListener(ValidationListener listener) {
        this.validationListener = listener;
    }

    /**
     * Set the false positive listener.
     */
    public void setFalsePositiveListener(FalsePositiveListener listener) {
        this.falsePositiveListener = listener;
    }

    /**
     * Get the table model.
     */
    public SecretsTableModel getTableModel() {
        return tableModel;
    }

    /**
     * Custom cell renderer that colors rows by category.
     */
    private class CategoryColorRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                // Convert view row to model row for correct category lookup
                int modelRow = table.convertRowIndexToModel(row);
                SecretCategoryMapper.Category category = tableModel.getCategoryAt(modelRow);
                Color bgColor = category.getLightColor();
                if (bgColor != null) {
                    c.setBackground(bgColor);
                } else {
                    // Use default table background
                    c.setBackground(table.getBackground());
                }
            }

            // Center align numeric columns
            if (column == 0 || column == 4) {
                setHorizontalAlignment(JLabel.CENTER);
            } else {
                setHorizontalAlignment(JLabel.LEFT);
            }

            return c;
        }
    }
}
