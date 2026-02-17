package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Main panel containing the requests table and split request/response viewers.
 */
public class RequestsView extends JPanel {

    private final MontoyaApi api;
    private final RequestsTableModel tableModel;
    private final JTable requestsTable;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JLabel statusLabel;
    private final RequestsFilterPanel filterPanel;

    public RequestsView(MontoyaApi api, RequestsTableModel tableModel) {
        this.api = api;
        this.tableModel = tableModel;

        setLayout(new BorderLayout());
        setBorder(new TitledBorder("Scanned Requests"));

        // Filter panel
        filterPanel = new RequestsFilterPanel();
        filterPanel.setFilterChangeListener(tableModel::setFilter);
        add(filterPanel, BorderLayout.NORTH);

        // Create table
        requestsTable = new JTable(tableModel);
        requestsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        requestsTable.getSelectionModel().addListSelectionListener(this::onSelectionChanged);

        // Configure column widths
        configureColumnWidths();

        // Center-align numeric columns
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        requestsTable.getColumnModel().getColumn(0).setCellRenderer(centerRenderer); // #
        requestsTable.getColumnModel().getColumn(3).setCellRenderer(centerRenderer); // Status
        requestsTable.getColumnModel().getColumn(4).setCellRenderer(centerRenderer); // Size

        // Custom renderer for Secrets column
        requestsTable.getColumnModel().getColumn(6).setCellRenderer(new SecretsCellRenderer());

        JScrollPane tableScroll = new JScrollPane(requestsTable);
        tableScroll.setPreferredSize(new Dimension(800, 200));

        // Create Burp editors (read-only)
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();

        // Wrap editors in panels with labels
        JPanel requestPanel = createEditorPanel("Request", requestEditor.uiComponent());
        JPanel responsePanel = createEditorPanel("Response", responseEditor.uiComponent());

        // Split pane for request/response (horizontal)
        JSplitPane viewerSplit = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            requestPanel,
            responsePanel
        );
        viewerSplit.setResizeWeight(0.5);
        viewerSplit.setOneTouchExpandable(true);

        // Main split: table above, viewers below (vertical)
        JSplitPane mainSplit = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            tableScroll,
            viewerSplit
        );
        mainSplit.setResizeWeight(0.35);
        mainSplit.setOneTouchExpandable(true);

        // Wrap in panel for proper layout with filter
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(mainSplit, BorderLayout.CENTER);
        add(contentPanel, BorderLayout.CENTER);

        // Status bar
        statusLabel = new JLabel("0 requests");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        add(statusLabel, BorderLayout.SOUTH);
    }

    private void configureColumnWidths() {
        requestsTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
        requestsTable.getColumnModel().getColumn(0).setMaxWidth(60);
        requestsTable.getColumnModel().getColumn(1).setPreferredWidth(60);   // Method
        requestsTable.getColumnModel().getColumn(1).setMaxWidth(80);
        requestsTable.getColumnModel().getColumn(2).setPreferredWidth(350);  // URL
        requestsTable.getColumnModel().getColumn(3).setPreferredWidth(50);   // Status
        requestsTable.getColumnModel().getColumn(3).setMaxWidth(70);
        requestsTable.getColumnModel().getColumn(4).setPreferredWidth(60);   // Size
        requestsTable.getColumnModel().getColumn(4).setMaxWidth(80);
        requestsTable.getColumnModel().getColumn(5).setPreferredWidth(60);   // Time
        requestsTable.getColumnModel().getColumn(5).setMaxWidth(80);
        requestsTable.getColumnModel().getColumn(6).setPreferredWidth(70);   // Secrets
        requestsTable.getColumnModel().getColumn(6).setMaxWidth(100);
    }

    /**
     * Get the filter panel for external updates.
     */
    public RequestsFilterPanel getFilterPanel() {
        return filterPanel;
    }

    /**
     * Custom cell renderer for the Secrets column with color coding.
     */
    private class SecretsCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            int secretCount = value != null ? (Integer) value : 0;
            setHorizontalAlignment(JLabel.CENTER);

            if (secretCount > 0) {
                RequestsTableModel.SecretInfo info = tableModel.getSecretInfoAt(row);
                if (!isSelected && info != null && info.primaryCategory() != null) {
                    c.setBackground(info.primaryCategory().getLightColor());
                }
                setText(String.valueOf(secretCount));
            } else {
                if (!isSelected) {
                    c.setBackground(table.getBackground());
                }
                setText("-");
            }

            return c;
        }
    }

    private JPanel createEditorPanel(String title, Component editor) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(editor, BorderLayout.CENTER);
        return panel;
    }

    private void onSelectionChanged(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) {
            return;
        }

        int selectedRow = requestsTable.getSelectedRow();
        if (selectedRow >= 0) {
            ScanJob job = tableModel.getJobAt(selectedRow);
            if (job != null) {
                requestEditor.setRequest(job.request());
                responseEditor.setResponse(job.response());
            }
        }
    }

    /**
     * Update the status label with current count.
     */
    public void updateStatus() {
        int count = tableModel.getEntryCount();
        statusLabel.setText(count + " request" + (count != 1 ? "s" : ""));
    }

    /**
     * Get the underlying table component.
     */
    public JTable getTable() {
        return requestsTable;
    }

    /**
     * Get the table model.
     */
    public RequestsTableModel getTableModel() {
        return tableModel;
    }

    /**
     * Clear all entries and viewers.
     */
    public void clear() {
        tableModel.clear();
        // Clear editors by setting null (creates blank display)
        requestEditor.setRequest(null);
        responseEditor.setResponse(null);
        updateStatus();
    }
}
