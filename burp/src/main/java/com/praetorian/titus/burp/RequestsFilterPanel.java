package com.praetorian.titus.burp;

import javax.swing.*;
import java.awt.*;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

/**
 * Filter panel for the Requests table.
 */
public class RequestsFilterPanel extends JPanel {

    private final JComboBox<String> hostFilter;
    private final JComboBox<String> secretTypeFilter;
    private final JComboBox<String> hasSecretsFilter;
    private final JComboBox<String> methodFilter;
    private final JComboBox<String> statusFilter;
    private final JTextField searchField;
    private final JButton clearButton;

    private Consumer<FilterCriteria> filterChangeListener;

    // Known hosts and secret types (dynamically populated)
    private final Set<String> knownHosts = new TreeSet<>();
    private final Set<String> knownSecretTypes = new TreeSet<>();

    public RequestsFilterPanel() {
        setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Host filter
        add(new JLabel("Host:"));
        hostFilter = new JComboBox<>(new String[]{"All"});
        hostFilter.setPreferredSize(new Dimension(120, 25));
        hostFilter.addActionListener(e -> notifyFilterChange());
        add(hostFilter);

        // Secret type filter
        add(new JLabel("Secret Type:"));
        secretTypeFilter = new JComboBox<>(new String[]{"All"});
        secretTypeFilter.setPreferredSize(new Dimension(120, 25));
        secretTypeFilter.addActionListener(e -> notifyFilterChange());
        add(secretTypeFilter);

        // Has secrets filter
        add(new JLabel("Has Secrets:"));
        hasSecretsFilter = new JComboBox<>(new String[]{"All", "With Secrets", "No Secrets"});
        hasSecretsFilter.setPreferredSize(new Dimension(100, 25));
        hasSecretsFilter.addActionListener(e -> notifyFilterChange());
        add(hasSecretsFilter);

        // Method filter
        add(new JLabel("Method:"));
        methodFilter = new JComboBox<>(new String[]{"All", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"});
        methodFilter.setPreferredSize(new Dimension(80, 25));
        methodFilter.addActionListener(e -> notifyFilterChange());
        add(methodFilter);

        // Status filter
        add(new JLabel("Status:"));
        statusFilter = new JComboBox<>(new String[]{"All", "2xx", "3xx", "4xx", "5xx"});
        statusFilter.setPreferredSize(new Dimension(70, 25));
        statusFilter.addActionListener(e -> notifyFilterChange());
        add(statusFilter);

        // URL search
        add(new JLabel("Search:"));
        searchField = new JTextField(15);
        searchField.addActionListener(e -> notifyFilterChange());
        // Also listen for text changes with a delay
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private javax.swing.Timer timer;
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { scheduleUpdate(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { scheduleUpdate(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { scheduleUpdate(); }
            private void scheduleUpdate() {
                if (timer != null) timer.stop();
                timer = new javax.swing.Timer(300, evt -> notifyFilterChange());
                timer.setRepeats(false);
                timer.start();
            }
        });
        add(searchField);

        // Clear button
        clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> clearFilters());
        add(clearButton);
    }

    /**
     * Set the filter change listener.
     */
    public void setFilterChangeListener(Consumer<FilterCriteria> listener) {
        this.filterChangeListener = listener;
    }

    /**
     * Add a host to the filter dropdown.
     */
    public void addHost(String host) {
        if (host != null && !host.isEmpty() && !knownHosts.contains(host)) {
            knownHosts.add(host);
            updateHostComboBox();
        }
    }

    /**
     * Add a secret type to the filter dropdown.
     */
    public void addSecretType(String type) {
        if (type != null && !type.isEmpty() && !knownSecretTypes.contains(type)) {
            knownSecretTypes.add(type);
            updateSecretTypeComboBox();
        }
    }

    private void updateHostComboBox() {
        String selected = (String) hostFilter.getSelectedItem();
        hostFilter.removeAllItems();
        hostFilter.addItem("All");
        for (String host : knownHosts) {
            hostFilter.addItem(host);
        }
        if (selected != null && knownHosts.contains(selected)) {
            hostFilter.setSelectedItem(selected);
        }
    }

    private void updateSecretTypeComboBox() {
        String selected = (String) secretTypeFilter.getSelectedItem();
        secretTypeFilter.removeAllItems();
        secretTypeFilter.addItem("All");
        for (String type : knownSecretTypes) {
            secretTypeFilter.addItem(type);
        }
        if (selected != null && knownSecretTypes.contains(selected)) {
            secretTypeFilter.setSelectedItem(selected);
        }
    }

    /**
     * Clear all filters.
     */
    public void clearFilters() {
        hostFilter.setSelectedIndex(0);
        secretTypeFilter.setSelectedIndex(0);
        hasSecretsFilter.setSelectedIndex(0);
        methodFilter.setSelectedIndex(0);
        statusFilter.setSelectedIndex(0);
        searchField.setText("");
        notifyFilterChange();
    }

    /**
     * Get current filter criteria.
     */
    public FilterCriteria getFilterCriteria() {
        return new FilterCriteria(
            getSelectedString(hostFilter),
            getSelectedString(secretTypeFilter),
            getSelectedString(hasSecretsFilter),
            getSelectedString(methodFilter),
            getSelectedString(statusFilter),
            searchField.getText().trim()
        );
    }

    private String getSelectedString(JComboBox<String> combo) {
        String selected = (String) combo.getSelectedItem();
        return "All".equals(selected) ? null : selected;
    }

    private void notifyFilterChange() {
        if (filterChangeListener != null) {
            filterChangeListener.accept(getFilterCriteria());
        }
    }

    /**
     * Filter criteria record.
     */
    public record FilterCriteria(
        String host,
        String secretType,
        String hasSecrets,
        String method,
        String status,
        String searchText
    ) {
        public boolean matches(String entryHost, String entryMethod, int entryStatus,
                              String entryUrl, int secretCount, String entrySecretType) {

            // Host filter
            if (host != null && !host.equalsIgnoreCase(entryHost)) {
                return false;
            }

            // Method filter
            if (method != null && !method.equalsIgnoreCase(entryMethod)) {
                return false;
            }

            // Status filter
            if (status != null) {
                int statusClass = entryStatus / 100;
                String statusPrefix = statusClass + "xx";
                if (!status.equals(statusPrefix)) {
                    return false;
                }
            }

            // Has secrets filter
            if (hasSecrets != null) {
                if ("With Secrets".equals(hasSecrets) && secretCount == 0) {
                    return false;
                }
                if ("No Secrets".equals(hasSecrets) && secretCount > 0) {
                    return false;
                }
            }

            // Secret type filter
            if (secretType != null && (entrySecretType == null || !entrySecretType.contains(secretType))) {
                return false;
            }

            // URL search
            if (searchText != null && !searchText.isEmpty()) {
                if (entryUrl == null || !entryUrl.toLowerCase().contains(searchText.toLowerCase())) {
                    return false;
                }
            }

            return true;
        }
    }
}
