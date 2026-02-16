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
    private JTextArea validationArea;
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
    private JTextField searchField;
    private JCheckBox regexCheckbox;
    private JCheckBox negateCheckbox;
    private JButton typeFilterButton;
    private JButton hostFilterButton;
    private JButton statusFilterButton;
    private JPopupMenu typePopup;
    private JPopupMenu hostPopup;
    private JPopupMenu statusPopup;
    private JPanel typeCheckboxPanel;
    private JPanel hostCheckboxPanel;
    private JPanel statusCheckboxPanel;
    private JCheckBox typeAllCheckbox;
    private JCheckBox hostAllCheckbox;
    private JCheckBox statusAllCheckbox;
    private List<JCheckBox> typeCheckboxes = new ArrayList<>();
    private List<JCheckBox> hostCheckboxes = new ArrayList<>();
    private List<JCheckBox> statusCheckboxes = new ArrayList<>();

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
        secretsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        secretsTable.getTableHeader().setReorderingAllowed(true);
        secretsTable.getTableHeader().setResizingAllowed(true);
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
        secretsTable.getColumnModel().getColumn(2).setPreferredWidth(60);   // Severity
        secretsTable.getColumnModel().getColumn(2).setMaxWidth(70);
        secretsTable.getColumnModel().getColumn(3).setPreferredWidth(200);  // Preview
        secretsTable.getColumnModel().getColumn(4).setPreferredWidth(150);  // Host
        secretsTable.getColumnModel().getColumn(5).setPreferredWidth(50);   // Count
        secretsTable.getColumnModel().getColumn(5).setMaxWidth(60);
        secretsTable.getColumnModel().getColumn(6).setPreferredWidth(60);   // Checked
        secretsTable.getColumnModel().getColumn(6).setMaxWidth(70);
        secretsTable.getColumnModel().getColumn(7).setPreferredWidth(70);   // Result
        secretsTable.getColumnModel().getColumn(7).setMaxWidth(80);
        secretsTable.getColumnModel().getColumn(8).setPreferredWidth(80);   // False Positive
        secretsTable.getColumnModel().getColumn(8).setMaxWidth(100);
    }

    /**
     * Set the severity config for the table model.
     */
    public void setSeverityConfig(SeverityConfig config) {
        tableModel.setSeverityConfig(config);
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

        // Type filter dropdown
        typeCheckboxPanel = new JPanel();
        typeCheckboxPanel.setLayout(new BoxLayout(typeCheckboxPanel, BoxLayout.Y_AXIS));
        typeAllCheckbox = new JCheckBox("All");
        typeAllCheckbox.setSelected(true);
        typeAllCheckbox.addActionListener(e -> {
            boolean selected = typeAllCheckbox.isSelected();
            for (JCheckBox cb : typeCheckboxes) {
                cb.setSelected(selected);
            }
            applyFilters();
            updateFilterButtonText(typeFilterButton, "Type", getSelectedItems(typeCheckboxes, typeAllCheckbox));
        });
        typePopup = new JPopupMenu();
        JScrollPane typeScroll = new JScrollPane(typeCheckboxPanel);
        typeScroll.setPreferredSize(new Dimension(200, 180));
        typePopup.add(typeScroll);
        typeFilterButton = new JButton("Type");
        typeFilterButton.addActionListener(e -> typePopup.show(typeFilterButton, 0, typeFilterButton.getHeight()));
        mainPanel.add(typeFilterButton);

        // Host filter dropdown
        hostCheckboxPanel = new JPanel();
        hostCheckboxPanel.setLayout(new BoxLayout(hostCheckboxPanel, BoxLayout.Y_AXIS));
        hostAllCheckbox = new JCheckBox("All");
        hostAllCheckbox.setSelected(true);
        hostAllCheckbox.addActionListener(e -> {
            boolean selected = hostAllCheckbox.isSelected();
            for (JCheckBox cb : hostCheckboxes) {
                cb.setSelected(selected);
            }
            applyFilters();
            updateFilterButtonText(hostFilterButton, "Host", getSelectedItems(hostCheckboxes, hostAllCheckbox));
        });
        hostPopup = new JPopupMenu();
        JScrollPane hostScroll = new JScrollPane(hostCheckboxPanel);
        hostScroll.setPreferredSize(new Dimension(250, 180));
        hostPopup.add(hostScroll);
        hostFilterButton = new JButton("Host");
        hostFilterButton.addActionListener(e -> hostPopup.show(hostFilterButton, 0, hostFilterButton.getHeight()));
        mainPanel.add(hostFilterButton);

        // Status filter dropdown (fixed options)
        statusCheckboxPanel = new JPanel();
        statusCheckboxPanel.setLayout(new BoxLayout(statusCheckboxPanel, BoxLayout.Y_AXIS));
        statusAllCheckbox = new JCheckBox("All");
        statusAllCheckbox.setSelected(true);
        statusAllCheckbox.addActionListener(e -> {
            boolean selected = statusAllCheckbox.isSelected();
            for (JCheckBox cb : statusCheckboxes) {
                cb.setSelected(selected);
            }
            applyFilters();
            updateFilterButtonText(statusFilterButton, "Status", getSelectedItems(statusCheckboxes, statusAllCheckbox));
        });
        statusCheckboxPanel.add(statusAllCheckbox);
        // Status options: False Positive, True Positive (not FP), Valid (active), Invalid (inactive)
        String[] statuses = {"False Positive", "True Positive", "Valid", "Invalid"};
        for (String status : statuses) {
            JCheckBox cb = new JCheckBox(status);
            cb.setSelected(true);
            cb.addActionListener(e -> {
                updateAllCheckbox(statusAllCheckbox, statusCheckboxes);
                applyFilters();
                updateFilterButtonText(statusFilterButton, "Status", getSelectedItems(statusCheckboxes, statusAllCheckbox));
            });
            statusCheckboxes.add(cb);
            statusCheckboxPanel.add(cb);
        }
        statusPopup = new JPopupMenu();
        JScrollPane statusScroll = new JScrollPane(statusCheckboxPanel);
        statusScroll.setPreferredSize(new Dimension(150, 160));
        statusPopup.add(statusScroll);
        statusFilterButton = new JButton("Status");
        statusFilterButton.addActionListener(e -> statusPopup.show(statusFilterButton, 0, statusFilterButton.getHeight()));
        mainPanel.add(statusFilterButton);

        // Clear button
        JButton clearButton = new JButton("Clear All");
        clearButton.addActionListener(e -> clearFilters());
        mainPanel.add(clearButton);

        return mainPanel;
    }

    private List<String> getSelectedItems(List<JCheckBox> checkboxes, JCheckBox allCheckbox) {
        if (allCheckbox.isSelected()) {
            return new ArrayList<>(); // Empty means all selected
        }
        List<String> selected = new ArrayList<>();
        for (JCheckBox cb : checkboxes) {
            if (cb.isSelected()) {
                selected.add(cb.getText());
            }
        }
        return selected;
    }

    private void updateAllCheckbox(JCheckBox allCheckbox, List<JCheckBox> checkboxes) {
        boolean allSelected = true;
        for (JCheckBox cb : checkboxes) {
            if (!cb.isSelected()) {
                allSelected = false;
                break;
            }
        }
        allCheckbox.setSelected(allSelected);
    }

    private void updateFilterButtonText(JButton button, String label, List<String> selected) {
        if (selected.isEmpty()) {
            button.setText(label);
        } else if (selected.size() == 1) {
            String text = selected.get(0);
            if (text.length() > 12) {
                text = text.substring(0, 10) + "...";
            }
            button.setText(label + ": " + text);
        } else {
            button.setText(label + ": " + selected.size());
        }
    }

    private void updateFilterDropdowns() {
        // Save current selected types and hosts
        Set<String> selectedTypes = new java.util.HashSet<>();
        for (JCheckBox cb : typeCheckboxes) {
            if (cb.isSelected()) {
                selectedTypes.add(cb.getText());
            }
        }
        Set<String> selectedHosts = new java.util.HashSet<>();
        for (JCheckBox cb : hostCheckboxes) {
            if (cb.isSelected()) {
                selectedHosts.add(cb.getText());
            }
        }

        // Update type filter checkboxes
        typeCheckboxPanel.removeAll();
        typeCheckboxPanel.add(typeAllCheckbox);
        typeCheckboxes.clear();
        for (String type : tableModel.getUniqueTypes()) {
            JCheckBox cb = new JCheckBox(type);
            cb.setSelected(selectedTypes.isEmpty() || selectedTypes.contains(type) || typeAllCheckbox.isSelected());
            cb.addActionListener(e -> {
                updateAllCheckbox(typeAllCheckbox, typeCheckboxes);
                applyFilters();
                updateFilterButtonText(typeFilterButton, "Type", getSelectedItems(typeCheckboxes, typeAllCheckbox));
            });
            typeCheckboxes.add(cb);
            typeCheckboxPanel.add(cb);
        }
        typeCheckboxPanel.revalidate();
        typeCheckboxPanel.repaint();

        // Update host filter checkboxes
        hostCheckboxPanel.removeAll();
        hostCheckboxPanel.add(hostAllCheckbox);
        hostCheckboxes.clear();
        for (String host : tableModel.getUniqueHosts()) {
            JCheckBox cb = new JCheckBox(host);
            cb.setSelected(selectedHosts.isEmpty() || selectedHosts.contains(host) || hostAllCheckbox.isSelected());
            cb.addActionListener(e -> {
                updateAllCheckbox(hostAllCheckbox, hostCheckboxes);
                applyFilters();
                updateFilterButtonText(hostFilterButton, "Host", getSelectedItems(hostCheckboxes, hostAllCheckbox));
            });
            hostCheckboxes.add(cb);
            hostCheckboxPanel.add(cb);
        }
        hostCheckboxPanel.revalidate();
        hostCheckboxPanel.repaint();
    }

    private void applyFilters() {
        List<RowFilter<SecretsTableModel, Integer>> filters = new ArrayList<>();

        // Type filter (checkboxes) - only apply if not "All" selected
        List<String> selectedTypes = getSelectedItems(typeCheckboxes, typeAllCheckbox);
        if (!selectedTypes.isEmpty()) {
            List<RowFilter<SecretsTableModel, Integer>> typeFilters = new ArrayList<>();
            for (String type : selectedTypes) {
                typeFilters.add(RowFilter.regexFilter("^" + Pattern.quote(type) + "$", 1));
            }
            filters.add(RowFilter.orFilter(typeFilters));
        }

        // Host filter (checkboxes) - only apply if not "All" selected
        List<String> selectedHosts = getSelectedItems(hostCheckboxes, hostAllCheckbox);
        if (!selectedHosts.isEmpty()) {
            List<RowFilter<SecretsTableModel, Integer>> hostFilters = new ArrayList<>();
            for (String host : selectedHosts) {
                hostFilters.add(RowFilter.regexFilter("^" + Pattern.quote(host) + "$", 4));  // Host is column 4
            }
            filters.add(RowFilter.orFilter(hostFilters));
        }

        // Status filter (checkboxes) - only apply if not "All" selected
        // Options: False Positive, True Positive, Valid, Invalid
        List<String> selectedStatuses = getSelectedItems(statusCheckboxes, statusAllCheckbox);
        if (!selectedStatuses.isEmpty()) {
            List<RowFilter<SecretsTableModel, Integer>> statusFilters = new ArrayList<>();
            for (String status : selectedStatuses) {
                switch (status) {
                    case "False Positive" -> // Column 8 (FP) = "Yes"
                        statusFilters.add(RowFilter.regexFilter("^Yes$", 8));
                    case "True Positive" -> // Column 8 (FP) = "No"
                        statusFilters.add(RowFilter.regexFilter("^No$", 8));
                    case "Valid" -> // Column 7 (Result) = "Active"
                        statusFilters.add(RowFilter.regexFilter("^Active$", 7));
                    case "Invalid" -> // Column 7 (Result) = "Inactive"
                        statusFilters.add(RowFilter.regexFilter("^Inactive$", 7));
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
        // Reset all checkboxes to selected (All)
        typeAllCheckbox.setSelected(true);
        for (JCheckBox cb : typeCheckboxes) cb.setSelected(true);
        hostAllCheckbox.setSelected(true);
        for (JCheckBox cb : hostCheckboxes) cb.setSelected(true);
        statusAllCheckbox.setSelected(true);
        for (JCheckBox cb : statusCheckboxes) cb.setSelected(true);
        typeFilterButton.setText("Type");
        hostFilterButton.setText("Host");
        statusFilterButton.setText("Status");
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

        // Validation tab
        validationArea = new JTextArea();
        validationArea.setEditable(false);
        validationArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        validationArea.setLineWrap(true);
        validationArea.setWrapStyleWord(true);
        JScrollPane validationScroll = new JScrollPane(validationArea);
        detailTabbedPane.addTab("Validation", validationScroll);

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
            validationArea.setText("");
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
            validationArea.setText("");
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

        // Brief validation summary
        boolean wasValidated = record.validatedAt != null;
        sb.append("Validated: ").append(wasValidated ? "Yes" : "No").append("\n");
        if (wasValidated) {
            sb.append("Validation Result: ").append(getValidationResultDisplay(record.validationStatus)).append("\n");
        }
        sb.append("False Positive: ").append(record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE ? "Yes" : "No").append("\n");

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

        // Validation tab - detailed validation info
        StringBuilder validSb = new StringBuilder();
        validSb.append("=== Validation Information ===\n\n");

        if (record.validatedAt == null) {
            validSb.append("Status: Not Checked\n\n");
            validSb.append("Click 'Validate' to check if this secret is active.\n");
        } else {
            // Determine meaningful status display
            String statusDisplay = getValidationResultDisplay(record.validationStatus);
            validSb.append("Checked: Yes\n");
            validSb.append("Result: ").append(statusDisplay).append("\n");
            validSb.append("Validated At: ").append(TIME_FORMAT.format(record.validatedAt.atZone(java.time.ZoneId.systemDefault()))).append("\n\n");

            if (record.validationMessage != null && !record.validationMessage.isEmpty()) {
                validSb.append("Message: ").append(record.validationMessage).append("\n\n");
            }

            if (record.validationDetails != null && !record.validationDetails.isEmpty()) {
                validSb.append("=== Details ===\n");
                for (Map.Entry<String, String> entry : record.validationDetails.entrySet()) {
                    String key = entry.getKey();
                    // Format key nicely (e.g., "user_id" -> "User ID")
                    String displayKey = key.substring(0, 1).toUpperCase() + key.substring(1).replace("_", " ");
                    validSb.append(displayKey).append(": ").append(entry.getValue()).append("\n");
                }
            }
        }

        if (record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE) {
            validSb.append("\n=== False Positive ===\n");
            validSb.append("This finding has been marked as a false positive.\n");
        }

        validationArea.setText(validSb.toString());
        validationArea.setCaretPosition(0);

        // Request tab - show full request with highlighted secret
        displayContentWithHighlight(requestPane, record.requestContent, record.secretContent,
                                   "(Request not available - this finding may have been loaded from cache)");

        // Response tab - show full response with highlighted secret
        displayContentWithHighlight(responsePane, record.responseContent, record.secretContent,
                                   "(Response not available - this finding may have been loaded from cache)");
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

    /**
     * Get a user-friendly display text for validation status.
     */
    private String getValidationResultDisplay(DedupCache.ValidationStatus status) {
        return switch (status) {
            case VALID -> "Valid (Active Credentials)";
            case INVALID -> "Invalid (Inactive/Revoked)";
            case UNDETERMINED -> "Unknown (Could not determine)";
            case FALSE_POSITIVE -> "False Positive";
            case VALIDATING -> "Validating...";
            case NOT_CHECKED -> "Not Checked";
        };
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
     * Custom cell renderer that colors rows by severity.
     */
    private class CategoryColorRenderer extends DefaultTableCellRenderer {
        // Severity colors - darker muted tones for dark theme
        private static final Color HIGH_COLOR = new Color(140, 70, 70);        // Dark maroon/burgundy
        private static final Color MEDIUM_COLOR = new Color(140, 130, 60);     // Dark olive/amber

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                // Convert view row to model row for correct severity lookup
                int modelRow = table.convertRowIndexToModel(row);
                burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity = tableModel.getSeverityAt(modelRow);

                // Only set background for HIGH and MEDIUM
                Color bgColor = getSeverityColor(severity);
                if (bgColor != null) {
                    c.setBackground(bgColor);
                    c.setForeground(Color.WHITE);  // White text on dark colored backgrounds
                } else {
                    // Use UIManager's default colors for consistent appearance
                    Color defaultBg = UIManager.getColor("Table.background");
                    if (defaultBg == null) {
                        defaultBg = Color.WHITE;
                    }
                    c.setBackground(defaultBg);
                    Color defaultFg = UIManager.getColor("Table.foreground");
                    if (defaultFg == null) {
                        defaultFg = Color.BLACK;
                    }
                    c.setForeground(defaultFg);
                }
            }

            // Center align small columns: #, Severity, Count, Checked, Result, False Positive
            if (column == 0 || column == 2 || column == 5 || column == 6 || column == 7 || column == 8) {
                setHorizontalAlignment(JLabel.CENTER);
            } else {
                setHorizontalAlignment(JLabel.LEFT);
            }

            return c;
        }

        /**
         * Get color for severity. Returns null for Low/Info/FP (use default).
         */
        private Color getSeverityColor(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity) {
            return switch (severity) {
                case HIGH -> HIGH_COLOR;
                case MEDIUM -> MEDIUM_COLOR;
                case LOW, INFORMATION, FALSE_POSITIVE -> null;  // No custom color
            };
        }
    }
}
