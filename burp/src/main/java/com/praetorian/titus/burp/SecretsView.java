package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.EditorOptions;

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
import java.util.*;
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
    private JEditorPane detailArea;
    private HttpRequestEditor nativeRequestEditor;
    private HttpResponseEditor nativeResponseEditor;
    private String currentSecret;
    private JTabbedPane detailTabbedPane;
    private JLabel statusLabel;
    private JButton validateButton;
    private JButton falsePositiveButton;
    private JButton unmarkFPButton;
    private JButton copyButton;
    private JLabel selectionLabel;
    private JPopupMenu tableContextMenu;
    private final Map<Integer, javax.swing.table.TableColumn> allColumns = new LinkedHashMap<>();
    private final Set<Integer> hiddenColumns = new HashSet<>();

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

        // Custom comparator for Severity column (column 2) to sort by severity order: Info < Low < Medium < High
        rowSorter.setComparator(2, (o1, o2) -> {
            int rank1 = getSeverityRank((String) o1);
            int rank2 = getSeverityRank((String) o2);
            return Integer.compare(rank1, rank2);
        });

        secretsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        secretsTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        secretsTable.getTableHeader().setReorderingAllowed(true);
        secretsTable.getTableHeader().setResizingAllowed(true);
        secretsTable.getSelectionModel().addListSelectionListener(this::onSelectionChanged);

        // Configure column widths
        configureColumnWidths();

        // Right-click context menu for table rows
        createTableContextMenu();
        secretsTable.setComponentPopupMenu(tableContextMenu);

        // Right-click context menu on table header for column visibility
        createHeaderContextMenu();

        // Custom renderer for category colors
        secretsTable.setDefaultRenderer(Object.class, new CategoryColorRenderer());
        secretsTable.setDefaultRenderer(Integer.class, new CategoryColorRenderer());

        JScrollPane tableScroll = new JScrollPane(secretsTable);
        tableScroll.setPreferredSize(new Dimension(600, 400));

        // Detail panel with tabs
        JPanel detailPanel = createDetailPanel();

        // Split pane: table on left, details on right
        JSplitPane splitPane = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            tableScroll,
            detailPanel
        );
        splitPane.setResizeWeight(0.5);
        splitPane.setOneTouchExpandable(false);

        add(splitPane, BorderLayout.CENTER);

        // Top panel with header, toolbar and filters
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.add(createHeaderPanel());
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
        // All columns are resizable - only set preferred widths, no max widths
        secretsTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
        secretsTable.getColumnModel().getColumn(1).setPreferredWidth(180);  // Type
        secretsTable.getColumnModel().getColumn(2).setPreferredWidth(65);   // Severity
        secretsTable.getColumnModel().getColumn(3).setPreferredWidth(180);  // Preview
        secretsTable.getColumnModel().getColumn(4).setPreferredWidth(100);  // Host
        secretsTable.getColumnModel().getColumn(5).setPreferredWidth(120);  // Path
        secretsTable.getColumnModel().getColumn(6).setPreferredWidth(55);   // Count
        secretsTable.getColumnModel().getColumn(7).setPreferredWidth(65);   // Checked
        secretsTable.getColumnModel().getColumn(8).setPreferredWidth(70);   // Result
        secretsTable.getColumnModel().getColumn(9).setPreferredWidth(95);   // False Positive

        // Store references to all columns for visibility toggling
        for (int i = 0; i < secretsTable.getColumnModel().getColumnCount(); i++) {
            allColumns.put(i, secretsTable.getColumnModel().getColumn(i));
        }
    }

    /**
     * Create right-click context menu on the table header for column visibility.
     */
    private void createHeaderContextMenu() {
        JPopupMenu headerMenu = new JPopupMenu();

        secretsTable.getTableHeader().addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) { showIfPopup(e); }
            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) { showIfPopup(e); }
            private void showIfPopup(java.awt.event.MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                headerMenu.removeAll();
                for (int i = 0; i < COLUMN_NAMES.length; i++) {
                    if (i == 0) continue; // # always visible
                    final int colIndex = i;
                    JCheckBoxMenuItem item = new JCheckBoxMenuItem(COLUMN_NAMES[i], !hiddenColumns.contains(colIndex));
                    item.addActionListener(a -> toggleColumn(colIndex));
                    headerMenu.add(item);
                }
                headerMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });
    }

    private static final String[] COLUMN_NAMES = {"#", "Type", "Severity", "Secret Preview", "Host", "Path", "Count", "Checked", "Result", "False Positive"};

    /**
     * Show column visibility popup from the Columns button.
     */
    private JWindow columnsWindow;

    private void showColumnsPopup(JButton anchor) {
        // Close existing popup if open
        if (columnsWindow != null && columnsWindow.isVisible()) {
            columnsWindow.dispose();
            columnsWindow = null;
            return;
        }

        // Use a JWindow with checkboxes — stays open on click
        java.awt.Window parentWindow = SwingUtilities.getWindowAncestor(anchor);
        columnsWindow = new JWindow(parentWindow);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));

        for (int i = 0; i < COLUMN_NAMES.length; i++) {
            if (i == 0) continue; // # always visible
            final int colIndex = i;
            JCheckBox cb = new JCheckBox(COLUMN_NAMES[i], !hiddenColumns.contains(colIndex));
            cb.addActionListener(a -> toggleColumn(colIndex));
            panel.add(cb);
        }

        columnsWindow.setContentPane(panel);
        columnsWindow.pack();

        // Position below the anchor button
        java.awt.Point loc = anchor.getLocationOnScreen();
        columnsWindow.setLocation(loc.x, loc.y + anchor.getHeight());
        columnsWindow.setVisible(true);

        // Close when clicking outside
        columnsWindow.addWindowFocusListener(new java.awt.event.WindowFocusListener() {
            @Override
            public void windowGainedFocus(java.awt.event.WindowEvent e) {}
            @Override
            public void windowLostFocus(java.awt.event.WindowEvent e) {
                if (columnsWindow != null) {
                    columnsWindow.dispose();
                    columnsWindow = null;
                }
            }
        });
    }

    /**
     * Toggle column visibility.
     */
    private void toggleColumn(int modelIndex) {
        javax.swing.table.TableColumn col = allColumns.get(modelIndex);
        if (col == null) return;

        if (hiddenColumns.contains(modelIndex)) {
            // Show column — insert at the right position
            hiddenColumns.remove(modelIndex);
            // Find the correct insert position based on model order
            int insertPos = 0;
            for (int i = 0; i < modelIndex; i++) {
                if (!hiddenColumns.contains(i)) insertPos++;
            }
            secretsTable.getColumnModel().addColumn(col);
            int currentPos = secretsTable.getColumnModel().getColumnCount() - 1;
            if (insertPos < currentPos) {
                secretsTable.getColumnModel().moveColumn(currentPos, insertPos);
            }
        } else {
            // Hide column
            hiddenColumns.add(modelIndex);
            secretsTable.getColumnModel().removeColumn(col);
        }
    }

    /**
     * Set the severity config for the table model.
     */
    public void setSeverityConfig(SeverityConfig config) {
        tableModel.setSeverityConfig(config);
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 10, 5));

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

    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout());

        // Left side: action buttons
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));

        validateButton = new JButton("Validate");
        validateButton.setEnabled(false);
        validateButton.addActionListener(e -> validateSelected());

        falsePositiveButton = new JButton("Mark False Positive");
        falsePositiveButton.setEnabled(false);
        falsePositiveButton.setToolTipText("Mark selected secrets as False Positive");
        falsePositiveButton.addActionListener(e -> markFalsePositive());

        unmarkFPButton = new JButton("Unmark False Positive");
        unmarkFPButton.setEnabled(false);
        unmarkFPButton.setToolTipText("Unmark False Positive status");
        unmarkFPButton.addActionListener(e -> unmarkFalsePositive());

        copyButton = new JButton("Copy");
        copyButton.setEnabled(false);
        copyButton.setToolTipText("Copy secret value to clipboard");
        copyButton.addActionListener(e -> copySelectedSecret());

        leftPanel.add(validateButton);
        leftPanel.add(falsePositiveButton);
        leftPanel.add(unmarkFPButton);
        leftPanel.add(copyButton);

        // Right side: selection indicator
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));

        selectionLabel = new JLabel("");
        selectionLabel.setFont(selectionLabel.getFont().deriveFont(Font.BOLD));
        rightPanel.add(selectionLabel);

        toolbar.add(leftPanel, BorderLayout.WEST);
        toolbar.add(rightPanel, BorderLayout.EAST);

        return toolbar;
    }

    private void createTableContextMenu() {
        tableContextMenu = new JPopupMenu();

        // Add a listener that dynamically builds menu items before showing
        tableContextMenu.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                buildContextMenuItems();
            }
            @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });
    }

    /**
     * Build context menu items dynamically based on selected findings' state.
     */
    private void buildContextMenuItems() {
        tableContextMenu.removeAll();

        int[] selectedRows = secretsTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        // Determine aggregate state of selected findings
        boolean anyNotValidated = false;
        boolean anyValidated = false;
        boolean anyFP = false;
        boolean anyNotFP = false;
        for (int row : selectedRows) {
            int modelRow = secretsTable.convertRowIndexToModel(row);
            DedupCache.FindingRecord record = tableModel.getRecordAt(modelRow);
            if (record == null) continue;
            if (record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE) {
                anyFP = true;
            } else {
                anyNotFP = true;
            }
            if (record.validatedAt != null) {
                anyValidated = true;
            } else {
                anyNotValidated = true;
            }
        }

        // Copy actions — always available
        JMenuItem copySecretItem = new JMenuItem("Copy Secret");
        copySecretItem.addActionListener(e -> copySelectedSecret());
        tableContextMenu.add(copySecretItem);

        JMenuItem copyPreviewItem = new JMenuItem("Copy Preview");
        copyPreviewItem.addActionListener(e -> copySelectedPreview());
        tableContextMenu.add(copyPreviewItem);

        tableContextMenu.addSeparator();

        // Validate / Revalidate — show based on validation state
        if (anyNotValidated && !anyValidated) {
            JMenuItem validateItem = new JMenuItem("Validate");
            validateItem.addActionListener(e -> validateSelected());
            tableContextMenu.add(validateItem);
        } else if (anyValidated && !anyNotValidated) {
            JMenuItem revalidateItem = new JMenuItem("Revalidate");
            revalidateItem.addActionListener(e -> validateSelected());
            tableContextMenu.add(revalidateItem);
        } else {
            // Mixed selection
            JMenuItem validateItem = new JMenuItem("Validate / Revalidate");
            validateItem.addActionListener(e -> validateSelected());
            tableContextMenu.add(validateItem);
        }

        tableContextMenu.addSeparator();

        // Change Severity — always available
        JMenu changeSeverityMenu = new JMenu("Change Severity");
        for (var sev : new String[]{"High", "Medium", "Low", "Info"}) {
            JMenuItem item = new JMenuItem(sev);
            item.addActionListener(e -> changeSeverityOfSelected(sev));
            changeSeverityMenu.add(item);
        }
        changeSeverityMenu.addSeparator();
        JMenuItem resetSevItem = new JMenuItem("Reset to Default");
        resetSevItem.addActionListener(e -> changeSeverityOfSelected(null));
        changeSeverityMenu.add(resetSevItem);
        tableContextMenu.add(changeSeverityMenu);

        tableContextMenu.addSeparator();

        // FP actions — show only relevant option(s)
        if (anyNotFP) {
            JMenuItem markFPItem = new JMenuItem("Mark as False Positive");
            markFPItem.addActionListener(e -> markFalsePositive());
            tableContextMenu.add(markFPItem);
        }
        if (anyFP) {
            JMenuItem unmarkFPItem = new JMenuItem("Unmark False Positive");
            unmarkFPItem.addActionListener(e -> unmarkFalsePositive());
            tableContextMenu.add(unmarkFPItem);
        }
    }

    private void copySelectedPreview() {
        int selectedRow = secretsTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }

        int modelRow = secretsTable.convertRowIndexToModel(selectedRow);
        DedupCache.FindingRecord record = tableModel.getRecordAt(modelRow);
        if (record != null && record.secretPreview != null) {
            java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(record.secretPreview);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            api.logging().logToOutput("Copied secret preview to clipboard");
        }
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

        // Columns visibility button
        JButton columnsButton = new JButton("Columns");
        columnsButton.setToolTipText("Show/hide table columns");
        columnsButton.addActionListener(e -> showColumnsPopup(columnsButton));
        mainPanel.add(columnsButton);

        // Clear button
        JButton clearButton = new JButton("Clear Filters");
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

        // Update button text to reflect current filter state
        updateFilterButtonText(typeFilterButton, "Type", getSelectedItems(typeCheckboxes, typeAllCheckbox));
        updateFilterButtonText(hostFilterButton, "Host", getSelectedItems(hostCheckboxes, hostAllCheckbox));
        updateFilterButtonText(statusFilterButton, "Status", getSelectedItems(statusCheckboxes, statusAllCheckbox));
    }

    private void applyFilters() {
        List<RowFilter<SecretsTableModel, Integer>> filters = new ArrayList<>();

        // Type filter (checkboxes)
        List<String> selectedTypes = getSelectedItems(typeCheckboxes, typeAllCheckbox);
        if (!typeAllCheckbox.isSelected()) {
            if (selectedTypes.isEmpty()) {
                // Nothing selected = show nothing (filter that matches nothing)
                filters.add(RowFilter.regexFilter("^$IMPOSSIBLE_MATCH$", 1));
            } else {
                List<RowFilter<SecretsTableModel, Integer>> typeFilters = new ArrayList<>();
                for (String type : selectedTypes) {
                    typeFilters.add(RowFilter.regexFilter("^" + Pattern.quote(type) + "$", 1));
                }
                filters.add(RowFilter.orFilter(typeFilters));
            }
        }

        // Host filter (checkboxes)
        List<String> selectedHosts = getSelectedItems(hostCheckboxes, hostAllCheckbox);
        if (!hostAllCheckbox.isSelected()) {
            if (selectedHosts.isEmpty()) {
                // Nothing selected = show nothing
                filters.add(RowFilter.regexFilter("^$IMPOSSIBLE_MATCH$", 4));
            } else {
                List<RowFilter<SecretsTableModel, Integer>> hostFilters = new ArrayList<>();
                for (String host : selectedHosts) {
                    hostFilters.add(RowFilter.regexFilter("^" + Pattern.quote(host) + "$", 4));  // Host is column 4
                }
                filters.add(RowFilter.orFilter(hostFilters));
            }
        }

        // Status filter (checkboxes)
        // Options: False Positive, True Positive, Valid, Invalid
        List<String> selectedStatuses = getSelectedItems(statusCheckboxes, statusAllCheckbox);
        if (!statusAllCheckbox.isSelected()) {
            if (selectedStatuses.isEmpty()) {
                // Nothing selected = show nothing
                filters.add(RowFilter.regexFilter("^$IMPOSSIBLE_MATCH$", 8));
            } else {
                List<RowFilter<SecretsTableModel, Integer>> statusFilters = new ArrayList<>();
                for (String status : selectedStatuses) {
                    switch (status) {
                        case "False Positive" -> // Column 9 (FP) = "Yes"
                            statusFilters.add(RowFilter.regexFilter("^Yes$", 9));
                        case "True Positive" -> // Column 9 (FP) = "No"
                            statusFilters.add(RowFilter.regexFilter("^No$", 9));
                        case "Valid" -> // Column 8 (Result) = "Active"
                            statusFilters.add(RowFilter.regexFilter("^Active$", 8));
                        case "Invalid" -> // Column 8 (Result) = "Inactive"
                            statusFilters.add(RowFilter.regexFilter("^Inactive$", 8));
                    }
                }
                if (!statusFilters.isEmpty()) {
                    filters.add(RowFilter.orFilter(statusFilters));
                }
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
        // Restore all hidden columns
        for (int colIndex : new ArrayList<>(hiddenColumns)) {
            toggleColumn(colIndex);
        }
        applyFilters();
        updateStatus();
    }

    private JPanel createDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        // Create titled border with larger, bold font
        TitledBorder titleBorder = new TitledBorder("Secret Details");
        titleBorder.setTitleFont(titleBorder.getTitleFont().deriveFont(Font.BOLD, 14f));
        panel.setBorder(titleBorder);

        detailTabbedPane = new JTabbedPane();

        // Details tab - HTML formatted (combines Details, URLs, Advisory, Validation)
        detailArea = new JEditorPane();
        detailArea.setContentType("text/html");
        detailArea.setEditable(false);
        detailArea.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailTabbedPane.addTab("Details", detailScroll);

        // Request tab - use Burp's native editor
        nativeRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        detailTabbedPane.addTab("Request", nativeRequestEditor.uiComponent());

        // Response tab - use Burp's native editor
        nativeResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        detailTabbedPane.addTab("Response", nativeResponseEditor.uiComponent());

        panel.add(detailTabbedPane, BorderLayout.CENTER);
        panel.setPreferredSize(new Dimension(500, 400));

        return panel;
    }
    private void onSelectionChanged(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) {
            return;
        }

        int[] selectedRows = secretsTable.getSelectedRows();
        if (selectedRows.length == 0) {
            String[] t = getThemeColors();
            detailArea.setText("<html><body style='font-family: sans-serif; font-size: 10px; padding: 6px; color: " + t[1] + ";'>Select a secret to view details</body></html>");
            // Clear native editors
            nativeRequestEditor.setRequest(HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: none\r\n\r\n"));
            nativeResponseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n"));
            validateButton.setEnabled(false);
            falsePositiveButton.setEnabled(false);
            unmarkFPButton.setEnabled(false);
            copyButton.setEnabled(false);
            selectionLabel.setText("");
            return;
        }

        // Update selection label
        selectionLabel.setText(selectedRows.length + " secret" + (selectedRows.length > 1 ? "s" : "") + " selected");

        // Convert view rows to model rows
        int[] modelRows = new int[selectedRows.length];
        for (int i = 0; i < selectedRows.length; i++) {
            modelRows[i] = secretsTable.convertRowIndexToModel(selectedRows[i]);
        }

        // Enable buttons based on selection
        boolean anyNotChecked = false;
        boolean anyValidated = false;
        boolean anyFalsePositive = false;
        boolean anyNotFalsePositive = false;

        for (int row : modelRows) {
            DedupCache.FindingRecord record = tableModel.getRecordAt(row);
            if (record != null) {
                if (record.validationStatus == DedupCache.ValidationStatus.NOT_CHECKED) {
                    anyNotChecked = true;
                }
                if (record.validatedAt != null || record.validationStatus == DedupCache.ValidationStatus.VALID
                        || record.validationStatus == DedupCache.ValidationStatus.INVALID
                        || record.validationStatus == DedupCache.ValidationStatus.UNDETERMINED) {
                    anyValidated = true;
                }
                if (record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE) {
                    anyFalsePositive = true;
                } else {
                    anyNotFalsePositive = true;
                }
            }
        }

        // Update validate button label and enable state
        boolean canValidate = anyNotChecked || anyValidated;
        validateButton.setEnabled(canValidate);
        if (anyValidated && !anyNotChecked) {
            validateButton.setText("Revalidate");
        } else {
            validateButton.setText("Validate");
        }
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
            detailArea.setText("<html><body style='font-family: sans-serif; font-size: 10px; padding: 6px;'><b>" + modelRows.length + " secrets selected</b><br/><span style='color: #888;'>Select a single secret to view details</span></body></html>");
            // Clear native editors for multi-selection
            nativeRequestEditor.setRequest(HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: multiple\r\n\r\n" + modelRows.length + " secrets selected"));
            nativeResponseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n" + modelRows.length + " secrets selected"));
        }
    }

    /**
     * Get CSS colors adapted to the current theme (light or dark).
     */
    private String[] getThemeColors() {
        boolean dark = isDarkTheme();
        // [textColor, mutedColor, codeBg, codeFg]
        if (dark) {
            return new String[]{"#dcdcdc", "#888888", "#2a2a2a", "#e0e0e0"};
        } else {
            return new String[]{"#1a1a1a", "#666666", "#f4f4f4", "#1a1a1a"};
        }
    }

    private void displayRecordDetails(DedupCache.FindingRecord record) {
        // Build combined HTML for Details tab - includes Advisory, Details, URLs, Validation
        StringBuilder html = new StringBuilder();
        String[] theme = getThemeColors(); // [text, muted, codeBg, codeFg]
        html.append("<html><body style='font-family: sans-serif; font-size: 9px; padding: 8px; color: ").append(theme[0]).append(";'>");

        // === ADVISORY SECTION ===
        // Header with severity indicator and title
        String severityColor = getSeverityIndicatorColor(record);
        String displayName = record.ruleName != null ? record.ruleName : SecretCategoryMapper.getDisplayName(record.ruleId, record.ruleName);
        html.append("<div style='margin-bottom: 8px;'>");
        html.append("<span style='color: ").append(severityColor).append("; font-size: 12px;'>&#9679;</span> ");
        html.append("<b style='font-size: 11px;'>Secret Detected: ").append(escapeHtml(displayName)).append("</b>");
        html.append("</div>");

        // Severity, Confidence, Host
        String severity = getSeverityName(record);
        html.append("<table cellpadding='1' cellspacing='0' style='margin-bottom: 8px;'>");
        html.append("<tr><td style='color: ").append(theme[1]).append(";'>Severity:</td><td style='padding-left: 8px;'>").append(severity).append("</td></tr>");
        html.append("<tr><td style='color: ").append(theme[1]).append(";'>Confidence:</td><td style='padding-left: 8px;'>Certain</td></tr>");
        html.append("<tr><td style='color: ").append(theme[1]).append(";'>Host:</td><td style='padding-left: 8px;'>").append(escapeHtml(record.primaryHost != null ? record.primaryHost : "N/A")).append("</td></tr>");
        html.append("</table>");

        // === ISSUE DETAIL SECTION ===
        html.append("<div style='margin-bottom: 8px;'>");
        html.append("<div style='font-size: 10px; font-weight: bold; margin-bottom: 4px;'>Issue detail</div>");
        html.append("<table cellpadding='1' cellspacing='0'>");
        html.append("<tr><td><b>Rule:</b></td><td style='padding-left: 8px; font-family: monospace;'>").append(escapeHtml(record.ruleId)).append("</td></tr>");
        html.append("<tr><td><b>Rule Name:</b></td><td style='padding-left: 8px;'>").append(escapeHtml(displayName)).append("</td></tr>");
        html.append("<tr><td><b>Category:</b></td><td style='padding-left: 8px;'>").append(escapeHtml(SecretCategoryMapper.getCategory(record.ruleId).getDisplayName())).append("</td></tr>");
        html.append("<tr><td><b>Occurrences:</b></td><td style='padding-left: 8px;'>").append(record.occurrenceCount).append("</td></tr>");
        html.append("<tr><td><b>First Seen:</b></td><td style='padding-left: 8px;'>").append(record.firstSeen != null ? TIME_FORMAT.format(record.firstSeen.atZone(java.time.ZoneId.systemDefault())) : "N/A").append("</td></tr>");
        html.append("</table>");
        html.append("</div>");

        // === SECRET/CONTEXT SECTION ===
        html.append("<div style='margin-bottom: 8px;'>");
        java.util.Map<String, String> groups = record.getNamedGroups();
        if (groups != null && groups.size() > 1) {
            // Paired secret — show each named group with its label
            html.append("<div style='font-weight: bold; margin-bottom: 2px;'>Secret (paired):</div>");
            for (java.util.Map.Entry<String, String> entry : groups.entrySet()) {
                html.append("<div style='margin-bottom: 2px;'>");
                html.append("<span style='font-size: 9px; color: ").append(theme[1]).append(";'>").append(escapeHtml(entry.getKey())).append(":</span> ");
                html.append("<span style='font-family: monospace; font-size: 9px; padding: 2px 4px; background: ").append(theme[2]).append("; color: ").append(theme[3]).append("; border-radius: 2px; word-wrap: break-word;'>");
                html.append(escapeHtml(entry.getValue()));
                html.append("</span>");
                html.append("</div>");
            }
        } else {
            html.append("<div style='font-weight: bold; margin-bottom: 2px;'>Secret:</div>");
            String secretValue = record.secretContent != null ? record.secretContent : record.secretPreview;
            html.append("<div style='font-family: monospace; font-size: 9px; padding: 4px; background: ").append(theme[2]).append("; color: ").append(theme[3]).append("; border-radius: 2px; word-wrap: break-word;'>");
            html.append(escapeHtml(secretValue));
            html.append("</div>");
        }
        html.append("</div>");

        // === URLs SECTION ===
        html.append("<div style='margin-bottom: 8px;'>");
        html.append("<div style='font-size: 10px; font-weight: bold; margin-bottom: 4px;'>URLs</div>");
        if (record.urls != null && !record.urls.isEmpty()) {
            html.append("<ol style='margin: 0; padding-left: 16px;'>");
            for (String url : record.urls) {
                html.append("<li style='margin-bottom: 1px; font-family: monospace; font-size: 9px;'>").append(escapeHtml(url)).append("</li>");
            }
            html.append("</ol>");
        } else {
            html.append("<div style='color: ").append(theme[1]).append(";'>No URLs recorded</div>");
        }
        html.append("</div>");

        // === VALIDATION SECTION ===
        html.append("<div style='margin-bottom: 8px;'>");
        html.append("<div style='font-size: 10px; font-weight: bold; margin-bottom: 4px;'>Validation</div>");
        if (record.validatedAt == null) {
            html.append("<div>Status: <b>Not Checked</b></div>");
            html.append("<div style='color: ").append(theme[1]).append("; margin-top: 2px;'>Click 'Validate' to check if this secret is active.</div>");
        } else {
            String statusDisplay = getValidationResultDisplay(record.validationStatus);
            html.append("<table cellpadding='1' cellspacing='0'>");
            html.append("<tr><td>Status:</td><td style='padding-left: 8px;'><b>").append(statusDisplay).append("</b></td></tr>");
            html.append("<tr><td>Validated:</td><td style='padding-left: 8px;'>").append(TIME_FORMAT.format(record.validatedAt.atZone(java.time.ZoneId.systemDefault()))).append("</td></tr>");
            html.append("</table>");

            if (record.validationMessage != null && !record.validationMessage.isEmpty()) {
                html.append("<div style='margin-top: 2px;'>Message: ").append(escapeHtml(record.validationMessage)).append("</div>");
            }

            if (record.validationDetails != null && !record.validationDetails.isEmpty()) {
                html.append("<table cellpadding='1' cellspacing='0' style='margin-top: 2px;'>");
                for (Map.Entry<String, String> entry : record.validationDetails.entrySet()) {
                    String key = entry.getKey();
                    String displayKey = key.substring(0, 1).toUpperCase() + key.substring(1).replace("_", " ");
                    html.append("<tr><td>").append(escapeHtml(displayKey)).append(":</td>");
                    html.append("<td style='padding-left: 8px; font-family: monospace;'>").append(escapeHtml(entry.getValue())).append("</td></tr>");
                }
                html.append("</table>");
            }
        }
        if (record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE) {
            html.append("<div style='margin-top: 4px; color: ").append(theme[1]).append(";'>This finding has been marked as a false positive.</div>");
        }
        html.append("</div>");

        html.append("</body></html>");
        detailArea.setText(html.toString());
        detailArea.setCaretPosition(0);

        // Request tab - use native Burp editor
        if (record.requestContent != null && !record.requestContent.isEmpty()) {
            try {
                HttpRequest request = HttpRequest.httpRequest(record.requestContent);
                nativeRequestEditor.setRequest(request);
            } catch (Exception e) {
                HttpRequest request = HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: error\r\n\r\n" + record.requestContent);
                nativeRequestEditor.setRequest(request);
            }
        } else {
            nativeRequestEditor.setRequest(HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: unavailable\r\n\r\n(Request not available)"));
        }

        // Response tab - use native Burp editor
        if (record.responseContent != null && !record.responseContent.isEmpty()) {
            try {
                HttpResponse response = HttpResponse.httpResponse(record.responseContent);
                nativeResponseEditor.setResponse(response);
            } catch (Exception e) {
                HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n" + record.responseContent);
                nativeResponseEditor.setResponse(response);
            }
        } else {
            nativeResponseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n(Response not available)"));
        }

        // Highlight the secret in both editors
        String searchTerm = record.secretContent != null ? record.secretContent : record.secretPreview;
        if (searchTerm != null && !searchTerm.isEmpty()) {
            nativeRequestEditor.setSearchExpression(searchTerm);
            nativeResponseEditor.setSearchExpression(searchTerm);
        }
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

    /**
     * Get HTML color code for validation status.
     */
    private String getStatusColor(DedupCache.ValidationStatus status) {
        return switch (status) {
            case VALID -> "#d9534f";      // Red - active credentials are dangerous
            case INVALID -> "#5cb85c";    // Green - inactive is safe
            case UNDETERMINED -> "#f0ad4e"; // Orange - unknown
            case FALSE_POSITIVE -> "#999999"; // Gray
            case VALIDATING -> "#5bc0de"; // Blue - in progress
            case NOT_CHECKED -> "#999999"; // Gray
        };
    }

    /**
     * Escape HTML special characters.
     */
    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }

    /**
     * Get severity indicator color for advisory display.
     */
    private String getSeverityIndicatorColor(DedupCache.FindingRecord record) {
        int modelRow = findings_indexOf(record);
        burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity =
            modelRow >= 0 ? tableModel.getSeverityAt(modelRow) : burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.MEDIUM;
        return switch (severity) {
            case HIGH -> "#d9534f";
            case MEDIUM -> "#f0ad4e";
            case LOW, INFORMATION -> "#5bc0de";
            case FALSE_POSITIVE -> "#999999";
        };
    }

    /**
     * Get severity name for advisory display.
     */
    private String getSeverityName(DedupCache.FindingRecord record) {
        int modelRow = findings_indexOf(record);
        burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity =
            modelRow >= 0 ? tableModel.getSeverityAt(modelRow) : burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.MEDIUM;
        return switch (severity) {
            case HIGH -> "High";
            case MEDIUM -> "Medium";
            case LOW -> "Low";
            case INFORMATION -> "Info";
            case FALSE_POSITIVE -> "FP";
        };
    }

    /**
     * Find model row index for a record.
     */
    private int findings_indexOf(DedupCache.FindingRecord record) {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            if (tableModel.getRecordAt(i) == record) return i;
        }
        return -1;
    }

    private void validateSelected() {
        int[] selectedRows = secretsTable.getSelectedRows();
        if (selectedRows.length == 0 || validationListener == null) {
            return;
        }

        // Collect eligible findings (skip currently validating)
        List<DedupCache.FindingRecord> toValidate = new ArrayList<>();
        boolean anyAlreadyValidated = false;
        for (int row : selectedRows) {
            int modelRow = secretsTable.convertRowIndexToModel(row);
            DedupCache.FindingRecord record = tableModel.getRecordAt(modelRow);
            if (record == null || record.validationStatus == DedupCache.ValidationStatus.VALIDATING) {
                continue;
            }
            if (record.validatedAt != null || record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE) {
                anyAlreadyValidated = true;
            }
            toValidate.add(record);
        }

        if (toValidate.isEmpty()) return;

        // Confirm revalidation
        if (anyAlreadyValidated) {
            int result = javax.swing.JOptionPane.showConfirmDialog(this,
                "This will re-check the secret and send new requests to the target. Current results may change.",
                "Revalidate Secret", javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.QUESTION_MESSAGE);
            if (result != javax.swing.JOptionPane.OK_OPTION) {
                return;
            }
        }

        for (DedupCache.FindingRecord record : toValidate) {
            validationListener.onValidateRequested(record);
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
                    record.preMarkFPStatus = record.validationStatus;
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
                DedupCache.ValidationStatus restored = record.preMarkFPStatus != null
                    ? record.preMarkFPStatus : DedupCache.ValidationStatus.NOT_CHECKED;
                record.setValidation(restored, record.validationMessage);
                record.preMarkFPStatus = null;
            }
        }
        dedupCache.saveToSettings();
        refresh();
    }

    private void changeSeverityOfSelected(String severityLabel) {
        int[] selectedRows = secretsTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        String override = severityLabel != null ? switch (severityLabel) {
            case "High" -> "HIGH";
            case "Medium" -> "MEDIUM";
            case "Low" -> "LOW";
            case "Info" -> "INFORMATION";
            default -> null;
        } : null;

        for (int row : selectedRows) {
            int modelRow = secretsTable.convertRowIndexToModel(row);
            DedupCache.FindingRecord record = tableModel.getRecordAt(modelRow);
            if (record != null) {
                record.severityOverride = override;
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
     * Refresh the table data, preserving the current selection.
     */
    public void refresh() {
        // Save selected records before refresh
        List<DedupCache.FindingRecord> selectedRecords = new ArrayList<>();
        for (int viewRow : secretsTable.getSelectedRows()) {
            int modelRow = secretsTable.convertRowIndexToModel(viewRow);
            DedupCache.FindingRecord record = tableModel.getRecordAt(modelRow);
            if (record != null) {
                selectedRecords.add(record);
            }
        }

        tableModel.refresh();
        updateFilterDropdowns();

        // Restore selection by finding the same records in the refreshed table
        if (!selectedRecords.isEmpty()) {
            secretsTable.clearSelection();
            for (DedupCache.FindingRecord saved : selectedRecords) {
                for (int modelRow = 0; modelRow < tableModel.getRowCount(); modelRow++) {
                    DedupCache.FindingRecord current = tableModel.getRecordAt(modelRow);
                    if (current == saved) {  // Same object from DedupCache
                        try {
                            int viewRow = secretsTable.convertRowIndexToView(modelRow);
                            secretsTable.addRowSelectionInterval(viewRow, viewRow);
                        } catch (IndexOutOfBoundsException ignored) {
                            // Row may be filtered out
                        }
                        break;
                    }
                }
            }
        }

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
     * Get numeric rank for severity string for sorting.
     * Lower values sort first: Info(0) < Low(1) < Medium(2) < High(3)
     */
    private static int getSeverityRank(String severity) {
        if (severity == null) return 1;
        return switch (severity) {
            case "Info", "FP" -> 0;
            case "Low" -> 1;
            case "Medium" -> 2;
            case "High" -> 3;
            default -> 1;
        };
    }

    /**
     * Detect whether the current Look and Feel is a dark theme.
     */
    private static boolean isDarkTheme() {
        Color bg = UIManager.getColor("Table.background");
        if (bg == null) return false;
        // Perceived brightness: dark if below ~128
        double brightness = (bg.getRed() * 0.299 + bg.getGreen() * 0.587 + bg.getBlue() * 0.114);
        return brightness < 128;
    }

    /**
     * Custom cell renderer that colors rows by severity, adapting to light/dark themes.
     */
    private class CategoryColorRenderer extends DefaultTableCellRenderer {
        // Dark theme: muted darker tones
        private static final Color HIGH_COLOR_DARK = new Color(140, 70, 70);
        private static final Color MEDIUM_COLOR_DARK = new Color(140, 130, 60);

        // Light theme: soft pastel tones
        private static final Color HIGH_COLOR_LIGHT = new Color(255, 200, 200);
        private static final Color MEDIUM_COLOR_LIGHT = new Color(255, 243, 200);

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                // Convert view row to model row for correct severity lookup
                int modelRow = table.convertRowIndexToModel(row);
                burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity = tableModel.getSeverityAt(modelRow);

                boolean dark = isDarkTheme();
                Color bgColor = getSeverityColor(severity, dark);
                if (bgColor != null) {
                    c.setBackground(bgColor);
                    // Dark backgrounds need white text; light backgrounds need dark text
                    c.setForeground(dark ? Color.WHITE : Color.BLACK);
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
            // Use model column index since view columns may shift when columns are hidden
            int modelCol = table.convertColumnIndexToModel(column);
            if (modelCol == 0 || modelCol == 2 || modelCol == 6 || modelCol == 7 || modelCol == 8 || modelCol == 9) {
                setHorizontalAlignment(JLabel.CENTER);
            } else {
                setHorizontalAlignment(JLabel.LEFT);
            }

            return c;
        }

        /**
         * Get color for severity, adapted to current theme. Returns null for Low/Info/FP (use default).
         */
        private Color getSeverityColor(burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity, boolean dark) {
            return switch (severity) {
                case HIGH -> dark ? HIGH_COLOR_DARK : HIGH_COLOR_LIGHT;
                case MEDIUM -> dark ? MEDIUM_COLOR_DARK : MEDIUM_COLOR_LIGHT;
                case LOW, INFORMATION, FALSE_POSITIVE -> null;
            };
        }
    }
}
