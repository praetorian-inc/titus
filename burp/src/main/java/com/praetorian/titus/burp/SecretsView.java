package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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
    private JTextPane requestPane;
    private JTextPane responsePane;
    private JTabbedPane detailTabbedPane;
    private JLabel statusLabel;
    private JButton validateButton;
    private JButton falsePositiveButton;
    private JButton unmarkFPButton;
    private JButton copyButton;
    private JButton refreshButton;

    // Filter components
    private JList<String> typeFilterList;
    private JList<String> hostFilterList;
    private JList<String> statusFilterList;
    private DefaultListModel<String> typeListModel;
    private DefaultListModel<String> hostListModel;
    private DefaultListModel<String> statusListModel;
    private JTextField searchField;
    private JCheckBox regexCheckbox;
    private JCheckBox negateCheckbox;
    private JButton typeFilterButton;
    private JButton hostFilterButton;
    private JButton statusFilterButton;
    private JPopupMenu typePopup;
    private JPopupMenu hostPopup;
    private JPopupMenu statusPopup;

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

        // Create table with row sorter for filtering and sorting
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
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.add(createToolbar());
        topPanel.add(createFilterPanel());
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

        validateButton = new JButton("Validate");
        validateButton.setEnabled(false);
        validateButton.addActionListener(e -> validateSelected());

        falsePositiveButton = new JButton("Mark False Positive");
        falsePositiveButton.setEnabled(false);
        falsePositiveButton.addActionListener(e -> markFalsePositive());

        unmarkFPButton = new JButton("Unmark False Positive");
        unmarkFPButton.setEnabled(false);
        unmarkFPButton.addActionListener(e -> unmarkFalsePositive());

        copyButton = new JButton("Copy Secret");
        copyButton.setEnabled(false);
        copyButton.addActionListener(e -> copySelectedSecret());

        toolbar.add(refreshButton);
        toolbar.add(validateButton);
        toolbar.add(falsePositiveButton);
        toolbar.add(unmarkFPButton);
        toolbar.add(copyButton);

        return toolbar;
    }

    private JPanel createFilterPanel() {
        JPanel mainPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));

        // Search field
        mainPanel.add(new JLabel("Search:"));
        searchField = new JTextField(20);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyFilters(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyFilters(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyFilters(); }
        });
        mainPanel.add(searchField);

        regexCheckbox = new JCheckBox("Regex");
        regexCheckbox.addActionListener(e -> applyFilters());
        mainPanel.add(regexCheckbox);

        negateCheckbox = new JCheckBox("Negate");
        negateCheckbox.addActionListener(e -> applyFilters());
        mainPanel.add(negateCheckbox);

        // Type filter dropdown button
        typeListModel = new DefaultListModel<>();
        typeFilterList = new JList<>(typeListModel);
        typeFilterList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        typeFilterList.setVisibleRowCount(8);
        typeFilterList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                applyFilters();
                updateFilterButtonText(typeFilterButton, "Type", typeFilterList.getSelectedValuesList());
            }
        });
        typePopup = new JPopupMenu();
        JScrollPane typeScroll = new JScrollPane(typeFilterList);
        typeScroll.setPreferredSize(new Dimension(180, 150));
        typePopup.add(typeScroll);
        typeFilterButton = new JButton("Type \u25BC");
        typeFilterButton.addActionListener(e -> typePopup.show(typeFilterButton, 0, typeFilterButton.getHeight()));
        mainPanel.add(typeFilterButton);

        // Host filter dropdown button
        hostListModel = new DefaultListModel<>();
        hostFilterList = new JList<>(hostListModel);
        hostFilterList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        hostFilterList.setVisibleRowCount(8);
        hostFilterList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                applyFilters();
                updateFilterButtonText(hostFilterButton, "Host", hostFilterList.getSelectedValuesList());
            }
        });
        hostPopup = new JPopupMenu();
        JScrollPane hostScroll = new JScrollPane(hostFilterList);
        hostScroll.setPreferredSize(new Dimension(220, 150));
        hostPopup.add(hostScroll);
        hostFilterButton = new JButton("Host \u25BC");
        hostFilterButton.addActionListener(e -> hostPopup.show(hostFilterButton, 0, hostFilterButton.getHeight()));
        mainPanel.add(hostFilterButton);

        // Status filter dropdown button
        statusListModel = new DefaultListModel<>();
        statusListModel.addElement("Not Checked");
        statusListModel.addElement("Active");
        statusListModel.addElement("Inactive");
        statusListModel.addElement("False Positive");
        statusListModel.addElement("Unknown");
        statusFilterList = new JList<>(statusListModel);
        statusFilterList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        statusFilterList.setVisibleRowCount(5);
        statusFilterList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                applyFilters();
                updateFilterButtonText(statusFilterButton, "Status", statusFilterList.getSelectedValuesList());
            }
        });
        statusPopup = new JPopupMenu();
        JScrollPane statusScroll = new JScrollPane(statusFilterList);
        statusScroll.setPreferredSize(new Dimension(140, 120));
        statusPopup.add(statusScroll);
        statusFilterButton = new JButton("Status \u25BC");
        statusFilterButton.addActionListener(e -> statusPopup.show(statusFilterButton, 0, statusFilterButton.getHeight()));
        mainPanel.add(statusFilterButton);

        // Clear button
        JButton clearButton = new JButton("Clear All");
        clearButton.addActionListener(e -> clearFilters());
        mainPanel.add(clearButton);

        return mainPanel;
    }

    private void updateFilterButtonText(JButton button, String label, List<String> selected) {
        if (selected.isEmpty()) {
            button.setText(label + " \u25BC");
        } else if (selected.size() == 1) {
            String text = selected.get(0);
            if (text.length() > 15) {
                text = text.substring(0, 12) + "...";
            }
            button.setText(label + ": " + text + " \u25BC");
        } else {
            button.setText(label + ": " + selected.size() + " selected \u25BC");
        }
    }

    private void updateFilterDropdowns() {
        // Save current selections
        List<String> selectedTypes = typeFilterList.getSelectedValuesList();
        List<String> selectedHosts = hostFilterList.getSelectedValuesList();

        // Update type filter
        typeListModel.clear();
        for (String type : tableModel.getUniqueTypes()) {
            typeListModel.addElement(type);
        }

        // Update host filter
        hostListModel.clear();
        for (String host : tableModel.getUniqueHosts()) {
            hostListModel.addElement(host);
        }

        // Restore selections
        restoreSelection(typeFilterList, selectedTypes);
        restoreSelection(hostFilterList, selectedHosts);
    }

    private void restoreSelection(JList<String> list, List<String> selected) {
        ListModel<String> model = list.getModel();
        List<Integer> indices = new ArrayList<>();
        for (int i = 0; i < model.getSize(); i++) {
            if (selected.contains(model.getElementAt(i))) {
                indices.add(i);
            }
        }
        if (!indices.isEmpty()) {
            int[] indicesArray = indices.stream().mapToInt(Integer::intValue).toArray();
            list.setSelectedIndices(indicesArray);
        }
    }

    private void applyFilters() {
        List<RowFilter<SecretsTableModel, Integer>> filters = new ArrayList<>();

        // Type filter (multi-select)
        List<String> selectedTypes = typeFilterList.getSelectedValuesList();
        if (!selectedTypes.isEmpty()) {
            List<RowFilter<SecretsTableModel, Integer>> typeFilters = new ArrayList<>();
            for (String type : selectedTypes) {
                typeFilters.add(RowFilter.regexFilter("^" + Pattern.quote(type) + "$", 1));
            }
            filters.add(RowFilter.orFilter(typeFilters));
        }

        // Host filter (multi-select)
        List<String> selectedHosts = hostFilterList.getSelectedValuesList();
        if (!selectedHosts.isEmpty()) {
            List<RowFilter<SecretsTableModel, Integer>> hostFilters = new ArrayList<>();
            for (String host : selectedHosts) {
                hostFilters.add(RowFilter.regexFilter("^" + Pattern.quote(host) + "$", 3));
            }
            filters.add(RowFilter.orFilter(hostFilters));
        }

        // Status filter (multi-select)
        List<String> selectedStatuses = statusFilterList.getSelectedValuesList();
        if (!selectedStatuses.isEmpty()) {
            List<RowFilter<SecretsTableModel, Integer>> statusFilters = new ArrayList<>();
            for (String status : selectedStatuses) {
                String statusText = switch (status) {
                    case "Not Checked" -> "-";
                    case "Active" -> "Active";
                    case "Inactive" -> "Inactive";
                    case "False Positive" -> "False Positive";
                    case "Unknown" -> "Unknown";
                    default -> "";
                };
                if (!statusText.isEmpty()) {
                    statusFilters.add(RowFilter.regexFilter("^" + Pattern.quote(statusText) + "$", 5));
                }
            }
            if (!statusFilters.isEmpty()) {
                filters.add(RowFilter.orFilter(statusFilters));
            }
        }

        // Text search
        String searchText = searchField.getText().trim();
        if (!searchText.isEmpty()) {
            try {
                RowFilter<SecretsTableModel, Integer> searchFilter;
                if (regexCheckbox.isSelected()) {
                    searchFilter = RowFilter.regexFilter(searchText);
                } else {
                    searchFilter = RowFilter.regexFilter("(?i)" + Pattern.quote(searchText));
                }

                if (negateCheckbox.isSelected()) {
                    searchFilter = RowFilter.notFilter(searchFilter);
                }

                filters.add(searchFilter);
            } catch (PatternSyntaxException ex) {
                // Invalid regex, ignore
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
        searchField.setText("");
        regexCheckbox.setSelected(false);
        negateCheckbox.setSelected(false);
        typeFilterList.clearSelection();
        hostFilterList.clearSelection();
        statusFilterList.clearSelection();
        typeFilterButton.setText("Type \u25BC");
        hostFilterButton.setText("Host \u25BC");
        statusFilterButton.setText("Status \u25BC");
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

        // Request tab
        requestPane = new JTextPane();
        requestPane.setEditable(false);
        requestPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane requestScroll = new JScrollPane(requestPane);
        detailTabbedPane.addTab("Request", requestScroll);

        // Response tab
        responsePane = new JTextPane();
        responsePane.setEditable(false);
        responsePane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane responseScroll = new JScrollPane(responsePane);
        detailTabbedPane.addTab("Response", responseScroll);

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
            requestPane.setText("");
            responsePane.setText("");
            validateButton.setEnabled(false);
            falsePositiveButton.setEnabled(false);
            unmarkFPButton.setEnabled(false);
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
        boolean anyFalsePositive = false;
        boolean anyNotFalsePositive = false;

        for (int row : modelRows) {
            DedupCache.FindingRecord record = tableModel.getRecordAt(row);
            if (record != null) {
                if (record.validationStatus == DedupCache.ValidationStatus.NOT_CHECKED) {
                    anyValidatable = true;
                }
                if (record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE) {
                    anyFalsePositive = true;
                } else {
                    anyNotFalsePositive = true;
                }
            }
        }

        validateButton.setEnabled(anyValidatable);
        falsePositiveButton.setEnabled(anyNotFalsePositive);
        unmarkFPButton.setEnabled(anyFalsePositive);
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
            requestPane.setText("");
            responsePane.setText("");
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
        if (record.validationDetails != null && !record.validationDetails.isEmpty()) {
            sb.append("\nValidation Details:\n");
            for (Map.Entry<String, String> entry : record.validationDetails.entrySet()) {
                String key = entry.getKey();
                // Format key nicely (e.g., "user_id" -> "User ID")
                String displayKey = key.substring(0, 1).toUpperCase() + key.substring(1).replace("_", " ");
                sb.append("  ").append(displayKey).append(": ").append(entry.getValue()).append("\n");
            }
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

        // Request tab - show full request with highlighted secret
        displayContentWithHighlight(requestPane, record.requestContent, record.secretContent,
                                   "(Request not available)");

        // Response tab - show full response with highlighted secret
        displayContentWithHighlight(responsePane, record.responseContent, record.secretContent,
                                   "(Response not available)");
    }

    /**
     * Display content in a JTextPane with the secret highlighted.
     */
    private void displayContentWithHighlight(JTextPane pane, String content, String secretContent, String fallbackMessage) {
        pane.setText("");

        if (content == null || content.isEmpty()) {
            pane.setText(fallbackMessage);
            return;
        }

        javax.swing.text.StyledDocument doc = pane.getStyledDocument();

        // Define highlight style
        javax.swing.text.Style highlightStyle = pane.addStyle("highlight", null);
        javax.swing.text.StyleConstants.setBackground(highlightStyle, new Color(255, 255, 0)); // Yellow background
        javax.swing.text.StyleConstants.setForeground(highlightStyle, Color.BLACK);
        javax.swing.text.StyleConstants.setBold(highlightStyle, true);

        // Define normal style
        javax.swing.text.Style normalStyle = pane.addStyle("normal", null);
        javax.swing.text.StyleConstants.setFontFamily(normalStyle, Font.MONOSPACED);
        javax.swing.text.StyleConstants.setFontSize(normalStyle, 12);

        try {
            if (secretContent != null && !secretContent.isEmpty() && content.contains(secretContent)) {
                // Find and highlight all occurrences
                int lastEnd = 0;
                int index;
                while ((index = content.indexOf(secretContent, lastEnd)) >= 0) {
                    // Add text before the match
                    if (index > lastEnd) {
                        doc.insertString(doc.getLength(), content.substring(lastEnd, index), normalStyle);
                    }
                    // Add highlighted match
                    doc.insertString(doc.getLength(), secretContent, highlightStyle);
                    lastEnd = index + secretContent.length();
                }
                // Add remaining text
                if (lastEnd < content.length()) {
                    doc.insertString(doc.getLength(), content.substring(lastEnd), normalStyle);
                }
            } else {
                // No secret to highlight, just show content
                doc.insertString(doc.getLength(), content, normalStyle);
            }
        } catch (javax.swing.text.BadLocationException e) {
            pane.setText(content);
        }

        pane.setCaretPosition(0);
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
            if (record != null && record.validationStatus != DedupCache.ValidationStatus.FALSE_POSITIVE) {
                records.add(record);
            }
        }

        if (!records.isEmpty()) {
            if (falsePositiveListener != null) {
                falsePositiveListener.onFalsePositiveRequested(records);
            } else {
                for (DedupCache.FindingRecord record : records) {
                    record.setValidation(DedupCache.ValidationStatus.FALSE_POSITIVE, "Marked by user");
                }
                dedupCache.saveToSettings();
                refresh();
            }
        }
    }

    private void unmarkFalsePositive() {
        int[] selectedRows = secretsTable.getSelectedRows();
        if (selectedRows.length == 0) {
            return;
        }

        for (int row : selectedRows) {
            int modelRow = secretsTable.convertRowIndexToModel(row);
            DedupCache.FindingRecord record = tableModel.getRecordAt(modelRow);
            if (record != null && record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE) {
                record.setValidation(DedupCache.ValidationStatus.NOT_CHECKED, null);
            }
        }
        dedupCache.saveToSettings();
        refresh();
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

        // validationCounts: [valid, invalid, undetermined, notChecked, falsePositive]
        List<String> parts = new ArrayList<>();
        if (validationCounts[0] > 0) parts.add(validationCounts[0] + " active");
        if (validationCounts[1] > 0) parts.add(validationCounts[1] + " inactive");
        if (validationCounts[4] > 0) parts.add(validationCounts[4] + " false positive");

        if (!parts.isEmpty()) {
            status += " (" + String.join(", ", parts) + ")";
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
