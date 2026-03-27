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
import java.util.function.BiConsumer;
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
    private SecretsTableModel secretsTableModel;

    private Timer statsTimer;

    // Callback for annotating scanned items (URL, secretsFound) -> annotation
    private BiConsumer<String, Integer> annotationCallback;

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

        // Keep reference for severity table
        secretsTableModel = secretsView.getTableModel();

        // Statistics tab (second)
        statisticsView = new StatisticsView(api, secretsTableModel, severityConfig);
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

            @Override
            public void onScanComplete(int jobCount, int secretsFound, ScanJob.Source source) {
                SwingUtilities.invokeLater(() -> {
                    // Always refresh secrets view on scan complete (to update counts for existing secrets)
                    secretsView.refresh();

                    // Show feedback for active (right-click) scans
                    if (source == ScanJob.Source.ACTIVE) {
                        String msg;
                        if (secretsFound > 0) {
                            msg = "Titus: Found " + secretsFound + " new secret" + (secretsFound > 1 ? "s" : "") +
                                  " in " + jobCount + " request" + (jobCount > 1 ? "s" : "");
                        } else {
                            msg = "Titus: No new secrets found in " + jobCount + " request" + (jobCount > 1 ? "s" : "");
                        }
                        secretsView.showTemporaryStatus(msg);
                    }
                });
            }

            @Override
            public void onUrlScanned(String url, int secretsFound, ScanJob.Source source) {
                // Forward to annotation callback (for Proxy history annotations)
                BiConsumer<String, Integer> cb = annotationCallback;
                if (cb != null) {
                    cb.accept(url, secretsFound);
                }
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
                        api.userInterface().swingUtils().suiteFrame(),
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
     * Set the callback for annotating actively-scanned items.
     * Called with (url, secretsFound) after each URL is scanned.
     */
    public void setAnnotationCallback(BiConsumer<String, Integer> callback) {
        this.annotationCallback = callback;
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

        // Create table model: Type | Severity | Description (read-only)
        String[] columns = {"Type", "Severity", "Description"};
        severityTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Read-only table
            }
        };

        severityTable = new JTable(severityTableModel);

        // Add row sorter for sorting columns
        severityRowSorter = new TableRowSorter<>(severityTableModel);
        severityTable.setRowSorter(severityRowSorter);

        // Custom comparator for severity column to sort by severity order
        severityRowSorter.setComparator(1, (o1, o2) -> {
            String s1 = o1.toString();
            String s2 = o2.toString();
            return severityOrdinal(s1) - severityOrdinal(s2);
        });

        // Set preferred column widths
        severityTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        severityTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        severityTable.getColumnModel().getColumn(2).setPreferredWidth(300);

        // Populate table
        populateSeverityTable();

        // Table in scroll pane
        JScrollPane tableScroll = new JScrollPane(severityTable);

        JPanel tablePanel = new JPanel(new BorderLayout(5, 5));

        // Top: search bar
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        searchPanel.add(new JLabel("Search:"));
        severitySearchField = new JTextField(15);
        severitySearchField.setToolTipText("Filter types");
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

        panel.add(tablePanel, BorderLayout.CENTER);

        return panel;
    }

    private static int severityOrdinal(String display) {
        return switch (display) {
            case "High" -> 0;
            case "Medium" -> 1;
            case "Low" -> 2;
            case "Info" -> 3;
            default -> 4;
        };
    }

    private static String severityToDisplay(AuditIssueSeverity severity) {
        return switch (severity) {
            case HIGH -> "High";
            case MEDIUM -> "Medium";
            case LOW -> "Low";
            case INFORMATION -> "Info";
            case FALSE_POSITIVE -> "FP";
        };
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

    private JPanel createActionsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(new TitledBorder("Actions"));
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));

        JButton clearCacheButton = new JButton("Clear Findings");
        clearCacheButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(
                api.userInterface().swingUtils().suiteFrame(),
                "This will permanently delete all findings, stored requests, and statistics.\nThe extension will start fresh as if no secrets were ever found.",
                "Clear All Findings",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            if (result == JOptionPane.YES_OPTION) {
                dedupCache.clear();
                requestsView.clear();
                messagePersistence.clear();
                if (secretsTableModel != null) {
                    secretsTableModel.refresh();
                }
                api.logging().logToOutput("Findings and requests cleared");
                updateStats();
            }
        });

        JButton exportButton = new JButton("Export Findings to JSON");
        exportButton.addActionListener(e -> findingsExporter.exportFindings(dedupCache, this));

        panel.add(clearCacheButton);
        panel.add(exportButton);

        return panel;
    }

    private void populateSeverityTable() {
        severityTableModel.setRowCount(0);

        if (secretsTableModel == null || secretsTableModel.getRowCount() == 0) {
            return;
        }

        // Collect unique types with their severity and ruleId
        Map<String, String[]> typeInfo = new java.util.LinkedHashMap<>();
        for (int i = 0; i < secretsTableModel.getRowCount(); i++) {
            DedupCache.FindingRecord record = secretsTableModel.getRecordAt(i);
            if (record == null) continue;

            String type = record.ruleName != null ? record.ruleName
                : SecretCategoryMapper.getDisplayName(record.ruleId, null);

            if (!typeInfo.containsKey(type)) {
                AuditIssueSeverity severity = secretsTableModel.getSeverityAt(i);
                String description = getTypeDescription(record.ruleId, type);
                typeInfo.put(type, new String[]{severityToDisplay(severity), description});
            }
        }

        // Add rows sorted by type name
        typeInfo.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(entry -> {
                String type = entry.getKey();
                String severity = entry.getValue()[0];
                String description = entry.getValue()[1];
                severityTableModel.addRow(new Object[]{type, severity, description});
            });
    }

    /**
     * Generate a human-readable description for a secret type based on its rule ID.
     */
    private String getTypeDescription(String ruleId, String typeName) {
        if (ruleId == null) return "Secret pattern detected in traffic";

        String lower = ruleId.toLowerCase();

        // Cloud providers
        if (lower.contains("aws")) return "Amazon Web Services credentials (access keys, secret keys, session tokens)";
        if (lower.contains("azure")) return "Microsoft Azure credentials (subscription keys, storage keys, AD tokens)";
        if (lower.contains("gcp") || lower.contains("gcs")) return "Google Cloud Platform service account keys and credentials";
        if (lower.contains("google")) return "Google API keys and OAuth credentials";
        if (lower.contains("firebase")) return "Firebase API keys and service credentials";
        if (lower.contains("digitalocean")) return "DigitalOcean API tokens and access keys";
        if (lower.contains("heroku")) return "Heroku API keys and deployment credentials";
        if (lower.contains("cloudflare")) return "Cloudflare API tokens and zone keys";
        if (lower.contains("vercel")) return "Vercel deployment tokens and API keys";
        if (lower.contains("netlify")) return "Netlify access tokens and site credentials";
        if (lower.contains("flyio")) return "Fly.io deploy tokens and API keys";

        // Databases
        if (lower.contains("postgres")) return "PostgreSQL connection strings and passwords";
        if (lower.contains("mysql")) return "MySQL connection strings and passwords";
        if (lower.contains("mongodb")) return "MongoDB connection URIs and credentials";
        if (lower.contains("redis")) return "Redis connection strings and auth tokens";
        if (lower.contains("jdbc")) return "JDBC database connection strings with embedded credentials";

        // Private keys
        if (lower.contains("pem") || lower.contains("privkey")) return "Private key files (PEM, PKCS format)";
        if (lower.contains("ssh")) return "SSH private keys and passphrases";
        if (lower.contains("age")) return "Age encryption private keys";
        if (lower.contains("wireguard")) return "WireGuard VPN private keys";

        // Auth & Identity
        if (lower.contains("jwt")) return "JSON Web Tokens (may contain session data or signing secrets)";
        if (lower.contains("oauth")) return "OAuth client secrets and refresh tokens";
        if (lower.contains("auth0")) return "Auth0 management API tokens and client secrets";
        if (lower.contains("okta")) return "Okta API tokens and SSO credentials";
        if (lower.contains("kubernetes") || lower.contains("k8s")) return "Kubernetes service account tokens and kubeconfig secrets";

        // AI & ML
        if (lower.contains("openai")) return "OpenAI API keys for GPT and other AI models";
        if (lower.contains("anthropic")) return "Anthropic API keys for Claude models";
        if (lower.contains("huggingface")) return "Hugging Face access tokens for model repositories";
        if (lower.contains("cohere")) return "Cohere API keys for language models";
        if (lower.contains("replicate")) return "Replicate API tokens for ML model hosting";
        if (lower.contains("deepseek")) return "DeepSeek API keys for AI models";
        if (lower.contains("mistral")) return "Mistral AI API keys";
        if (lower.contains("groq")) return "Groq API keys for fast AI inference";

        // Communication & Email
        if (lower.contains("slack")) return "Slack bot tokens, webhooks, and OAuth tokens";
        if (lower.contains("discord")) return "Discord bot tokens and webhook URLs";
        if (lower.contains("telegram")) return "Telegram bot tokens and API credentials";
        if (lower.contains("twilio")) return "Twilio API keys for SMS and voice services";
        if (lower.contains("sendgrid")) return "SendGrid API keys for email delivery";
        if (lower.contains("mailgun")) return "Mailgun API keys for email services";
        if (lower.contains("mailchimp")) return "Mailchimp API keys for email marketing";
        if (lower.contains("msteams")) return "Microsoft Teams webhook URLs and connector tokens";

        // Payment
        if (lower.contains("stripe")) return "Stripe API keys for payment processing";
        if (lower.contains("square")) return "Square API keys for payment services";
        if (lower.contains("paypal")) return "PayPal API credentials and client secrets";

        // CI/CD & DevOps
        if (lower.contains("github")) return "GitHub personal access tokens and OAuth tokens";
        if (lower.contains("gitlab")) return "GitLab personal and project access tokens";
        if (lower.contains("bitbucket")) return "Bitbucket app passwords and OAuth credentials";
        if (lower.contains("jenkins")) return "Jenkins API tokens and build credentials";
        if (lower.contains("circleci")) return "CircleCI API tokens for CI/CD pipelines";
        if (lower.contains("docker")) return "Docker registry credentials and hub tokens";
        if (lower.contains("npm")) return "NPM registry authentication tokens";
        if (lower.contains("pypi")) return "PyPI upload tokens for package publishing";

        // Monitoring & Analytics
        if (lower.contains("datadog")) return "Datadog API and application keys for monitoring";
        if (lower.contains("sentry")) return "Sentry DSN and auth tokens for error tracking";
        if (lower.contains("newrelic")) return "New Relic API keys for application monitoring";
        if (lower.contains("grafana")) return "Grafana API keys and service account tokens";
        if (lower.contains("pagerduty")) return "PagerDuty API keys for incident management";

        // Social & Marketing
        if (lower.contains("linkedin")) return "LinkedIn API keys and OAuth tokens";
        if (lower.contains("facebook") || lower.contains("instagram")) return "Meta (Facebook/Instagram) API tokens and app secrets";
        if (lower.contains("twitter")) return "Twitter/X API keys and bearer tokens";
        if (lower.contains("spotify")) return "Spotify API client credentials and tokens";
        if (lower.contains("youtube")) return "YouTube Data API keys";

        // Generic patterns
        if (lower.contains("generic")) return "Generic secret patterns (passwords, keys, tokens found via broad rules)";
        if (lower.contains("password") || lower.contains("pwhash")) return "Hardcoded passwords or password hashes in source or config";
        if (lower.contains("http")) return "Credentials embedded in HTTP URLs or headers";
        if (lower.contains("credentials") || lower.contains("netrc")) return "Stored credentials in configuration files";
        if (lower.contains("uri")) return "Connection URIs with embedded authentication";

        // Fallback: use category
        SecretCategoryMapper.Category category = SecretCategoryMapper.getCategory(ruleId);
        return category.getDisplayName() + " — detected by rule " + ruleId;
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

    /**
     * Clean up resources on extension unload.
     */
    public void close() {
        if (statsTimer != null) {
            statsTimer.cancel();
        }
    }

    private int lastSeverityTableSize = 0;

    private void updateStats() {
        // Stats are now shown in the Statistics tab, refresh it periodically
        if (statisticsView != null) {
            statisticsView.refresh();
        }

        // Refresh severity table when new types appear
        if (secretsTableModel != null) {
            int currentTypes = secretsTableModel.getUniqueTypes().size();
            if (currentTypes != lastSeverityTableSize) {
                lastSeverityTableSize = currentTypes;
                populateSeverityTable();
            }
        }
    }
}
