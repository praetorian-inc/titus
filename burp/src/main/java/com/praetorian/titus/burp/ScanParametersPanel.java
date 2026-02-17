package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * UI panel for configurable scan parameters.
 */
public class ScanParametersPanel extends JPanel {

    private static final String KEY_WORKERS = "titus.workers";
    private static final String KEY_MAX_FILE_SIZE = "titus.max_file_size_mb";
    private static final String KEY_SNIPPET_LENGTH = "titus.snippet_length";

    private static final int DEFAULT_WORKERS = 4;
    private static final int DEFAULT_MAX_FILE_SIZE_MB = 10;
    private static final int DEFAULT_SNIPPET_LENGTH = 256;

    private final MontoyaApi api;
    private final JSpinner workersSpinner;
    private final JSpinner maxFileSizeSpinner;
    private final JSpinner snippetLengthSpinner;

    private ParameterChangeListener changeListener;

    /**
     * Listener for parameter changes.
     */
    public interface ParameterChangeListener {
        void onParametersChanged(int workers, int maxFileSizeMB, int snippetLength);
    }

    public ScanParametersPanel(MontoyaApi api) {
        this.api = api;

        setBorder(new TitledBorder("Scan Parameters"));
        setLayout(new GridBagLayout());
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 150));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Workers
        gbc.gridx = 0; gbc.gridy = 0;
        add(new JLabel("Worker threads:"), gbc);
        gbc.gridx = 1;
        workersSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_WORKERS, 1, 16, 1));
        workersSpinner.setPreferredSize(new Dimension(60, 25));
        add(workersSpinner, gbc);
        gbc.gridx = 2;
        JLabel workersHint = new JLabel("(1-16)");
        workersHint.setForeground(Color.GRAY);
        add(workersHint, gbc);

        // Max file size
        gbc.gridx = 0; gbc.gridy = 1;
        add(new JLabel("Max file size:"), gbc);
        gbc.gridx = 1;
        maxFileSizeSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_MAX_FILE_SIZE_MB, 1, 100, 1));
        maxFileSizeSpinner.setPreferredSize(new Dimension(60, 25));
        add(maxFileSizeSpinner, gbc);
        gbc.gridx = 2;
        JLabel sizeHint = new JLabel("MB");
        sizeHint.setForeground(Color.GRAY);
        add(sizeHint, gbc);

        // Snippet length
        gbc.gridx = 0; gbc.gridy = 2;
        add(new JLabel("Snippet length:"), gbc);
        gbc.gridx = 1;
        snippetLengthSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_SNIPPET_LENGTH, 64, 1024, 64));
        snippetLengthSpinner.setPreferredSize(new Dimension(60, 25));
        add(snippetLengthSpinner, gbc);
        gbc.gridx = 2;
        JLabel snippetHint = new JLabel("chars");
        snippetHint.setForeground(Color.GRAY);
        add(snippetHint, gbc);

        // Note about restart
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        JLabel noteLabel = new JLabel("Note: Changes take effect on next scan batch");
        noteLabel.setForeground(Color.GRAY);
        noteLabel.setFont(noteLabel.getFont().deriveFont(Font.ITALIC, 11f));
        add(noteLabel, gbc);

        // Add change listeners to persist settings
        workersSpinner.addChangeListener(e -> saveSettings());
        maxFileSizeSpinner.addChangeListener(e -> saveSettings());
        snippetLengthSpinner.addChangeListener(e -> saveSettings());

        // Load saved values
        loadSettings();
    }

    public void setChangeListener(ParameterChangeListener listener) {
        this.changeListener = listener;
    }

    public int getWorkers() {
        return (Integer) workersSpinner.getValue();
    }

    public int getMaxFileSizeMB() {
        return (Integer) maxFileSizeSpinner.getValue();
    }

    public int getSnippetLength() {
        return (Integer) snippetLengthSpinner.getValue();
    }

    /**
     * Get max file size in bytes.
     */
    public int getMaxFileSizeBytes() {
        return getMaxFileSizeMB() * 1024 * 1024;
    }

    private void loadSettings() {
        try {
            String workersStr = api.persistence().extensionData().getString(KEY_WORKERS);
            if (workersStr != null && !workersStr.isEmpty()) {
                workersSpinner.setValue(Integer.parseInt(workersStr));
            }

            String maxSizeStr = api.persistence().extensionData().getString(KEY_MAX_FILE_SIZE);
            if (maxSizeStr != null && !maxSizeStr.isEmpty()) {
                maxFileSizeSpinner.setValue(Integer.parseInt(maxSizeStr));
            }

            String snippetStr = api.persistence().extensionData().getString(KEY_SNIPPET_LENGTH);
            if (snippetStr != null && !snippetStr.isEmpty()) {
                snippetLengthSpinner.setValue(Integer.parseInt(snippetStr));
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load scan parameters: " + e.getMessage());
        }
    }

    private void saveSettings() {
        try {
            api.persistence().extensionData().setString(KEY_WORKERS, String.valueOf(getWorkers()));
            api.persistence().extensionData().setString(KEY_MAX_FILE_SIZE, String.valueOf(getMaxFileSizeMB()));
            api.persistence().extensionData().setString(KEY_SNIPPET_LENGTH, String.valueOf(getSnippetLength()));

            if (changeListener != null) {
                changeListener.onParametersChanged(getWorkers(), getMaxFileSizeMB(), getSnippetLength());
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to save scan parameters: " + e.getMessage());
        }
    }
}
