package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.time.format.DateTimeFormatter;

/**
 * View panel for the Secrets tab showing deduplicated findings.
 */
public class SecretsView extends JPanel {

    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final MontoyaApi api;
    private final SecretsTableModel tableModel;
    private final DedupCache dedupCache;
    private final JTable secretsTable;
    private final JTextArea detailArea;
    private final JLabel statusLabel;
    private final JButton validateButton;
    private final JButton copyButton;
    private final JButton refreshButton;

    private ValidationListener validationListener;

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
        setBorder(new TitledBorder("Detected Secrets"));

        // Create table
        secretsTable = new JTable(tableModel);
        secretsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        secretsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        secretsTable.getSelectionModel().addListSelectionListener(this::onSelectionChanged);

        // Configure column widths
        configureColumnWidths();

        // Custom renderer for category colors
        secretsTable.setDefaultRenderer(Object.class, new CategoryColorRenderer());
        secretsTable.setDefaultRenderer(Integer.class, new CategoryColorRenderer());

        JScrollPane tableScroll = new JScrollPane(secretsTable);
        tableScroll.setPreferredSize(new Dimension(800, 250));

        // Detail panel
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

        // Toolbar
        JPanel toolbar = createToolbar();
        add(toolbar, BorderLayout.NORTH);

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

        copyButton = new JButton("Copy Secret");
        copyButton.setEnabled(false);
        copyButton.addActionListener(e -> copySelectedSecret());

        toolbar.add(refreshButton);
        toolbar.add(validateButton);
        toolbar.add(copyButton);

        return toolbar;
    }

    private JPanel createDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Secret Details"));

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);

        JScrollPane scroll = new JScrollPane(detailArea);
        scroll.setPreferredSize(new Dimension(800, 150));
        panel.add(scroll, BorderLayout.CENTER);

        return panel;
    }

    private void onSelectionChanged(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) {
            return;
        }

        int selectedRow = secretsTable.getSelectedRow();
        if (selectedRow >= 0) {
            DedupCache.FindingRecord record = tableModel.getRecordAt(selectedRow);
            if (record != null) {
                displayRecordDetails(record);
                validateButton.setEnabled(record.validationStatus == DedupCache.ValidationStatus.NOT_CHECKED);
                copyButton.setEnabled(true);
                return;
            }
        }

        detailArea.setText("");
        validateButton.setEnabled(false);
        copyButton.setEnabled(false);
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

        sb.append("URLs Found:\n");
        if (record.urls != null) {
            for (String url : record.urls) {
                sb.append("  - ").append(url).append("\n");
            }
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
    }

    private void validateSelected() {
        int selectedRow = secretsTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }

        DedupCache.FindingRecord record = tableModel.getRecordAt(selectedRow);
        if (record != null && validationListener != null) {
            validationListener.onValidateRequested(record);
        }
    }

    private void copySelectedSecret() {
        int selectedRow = secretsTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }

        DedupCache.FindingRecord record = tableModel.getRecordAt(selectedRow);
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
        updateStatus();
    }

    /**
     * Update the status label.
     */
    public void updateStatus() {
        int count = tableModel.getTotalCount();
        int[] validationCounts = tableModel.getValidationCounts();
        String status = count + " secret" + (count != 1 ? "s" : "");

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
                SecretCategoryMapper.Category category = tableModel.getCategoryAt(row);
                c.setBackground(category.getLightColor());
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
