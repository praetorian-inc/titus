package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

/**
 * Provides a custom "Titus" tab in Burp's response editor when secrets are detected.
 * The tab only appears if secrets are found in the response, reducing UI noise.
 */
public class SecretEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final ProcessManager processManager;
    private final DedupCache dedupCache;

    public SecretEditorProvider(MontoyaApi api, ProcessManager processManager, DedupCache dedupCache) {
        this.api = api;
        this.processManager = processManager;
        this.dedupCache = dedupCache;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new SecretResponseEditor(creationContext);
    }

    private class SecretResponseEditor implements ExtensionProvidedHttpResponseEditor {

        private final JPanel panel;
        private final JTextArea secretsArea;
        private final JLabel statusLabel;
        private HttpResponse currentResponse;
        private HttpRequest currentRequest;
        private List<TitusProcessScanner.Match> currentMatches;
        private List<DedupCache.FindingRecord> cachedFindings;
        private boolean hasSecrets = false;

        // Cache for isEnabledFor to avoid double-scanning
        private HttpRequestResponse lastCheckedRequestResponse;
        private boolean lastCheckHadSecrets = false;

        SecretResponseEditor(EditorCreationContext creationContext) {
            panel = new JPanel(new BorderLayout());
            panel.setBorder(new EmptyBorder(10, 10, 10, 10));

            // Header panel
            JPanel headerPanel = new JPanel(new BorderLayout());
            JLabel titleLabel = new JLabel("Titus Secret Scanner");
            titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
            statusLabel = new JLabel("");
            statusLabel.setForeground(Color.GRAY);
            headerPanel.add(titleLabel, BorderLayout.WEST);
            headerPanel.add(statusLabel, BorderLayout.EAST);
            panel.add(headerPanel, BorderLayout.NORTH);

            // Secrets display area
            secretsArea = new JTextArea();
            secretsArea.setEditable(false);
            secretsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            secretsArea.setLineWrap(true);
            secretsArea.setWrapStyleWord(true);
            JScrollPane scrollPane = new JScrollPane(secretsArea);
            panel.add(scrollPane, BorderLayout.CENTER);
        }

        @Override
        public HttpResponse getResponse() {
            return currentResponse;
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.currentRequest = requestResponse.request();
            this.currentResponse = requestResponse.response();

            if (currentResponse == null) {
                secretsArea.setText("No response available");
                statusLabel.setText("");
                this.hasSecrets = false;
                return;
            }

            // Check if we already have cached matches from isEnabledFor
            if (requestResponse == lastCheckedRequestResponse && currentMatches != null && !currentMatches.isEmpty()) {
                this.hasSecrets = true;
                displaySecrets(currentMatches);
                statusLabel.setText(currentMatches.size() + " secret(s) found");
                statusLabel.setForeground(new Color(200, 50, 50));
            } else {
                // Scan for secrets (fallback if cache miss)
                this.hasSecrets = false;
                this.currentMatches = null;
                scanForSecrets();
            }
        }

        private void scanForSecrets() {
            String url = currentRequest != null ? currentRequest.url() : "unknown";

            // First check if we have cached findings from the DedupCache
            List<DedupCache.FindingRecord> findings = dedupCache.getFindingsForUrl(url);
            if (!findings.isEmpty()) {
                this.cachedFindings = findings;
                this.hasSecrets = true;
                displayCachedFindings(findings);
                statusLabel.setText(findings.size() + " secret(s) found (cached)");
                statusLabel.setForeground(new Color(200, 50, 50));
                return;
            }

            // No cached findings - scan the response
            try {
                TitusProcessScanner scanner = processManager.getScanner();
                String content = currentResponse.toString();

                List<TitusProcessScanner.Match> matches = scanner.scan(content, url);
                this.currentMatches = matches;
                this.hasSecrets = !matches.isEmpty();

                if (hasSecrets) {
                    displaySecrets(matches);
                    statusLabel.setText(matches.size() + " secret(s) found");
                    statusLabel.setForeground(new Color(200, 50, 50));
                } else {
                    secretsArea.setText("No secrets detected in this response.");
                    statusLabel.setText("Clean");
                    statusLabel.setForeground(new Color(50, 150, 50));
                }
            } catch (Exception e) {
                secretsArea.setText("Error scanning for secrets: " + e.getMessage());
                statusLabel.setText("Error");
                statusLabel.setForeground(Color.RED);
            }
        }

        private void displayCachedFindings(List<DedupCache.FindingRecord> findings) {
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < findings.size(); i++) {
                DedupCache.FindingRecord record = findings.get(i);

                sb.append("=== Secret #").append(i + 1).append(" ===\n\n");
                sb.append("Type: ").append(record.ruleName).append("\n");
                sb.append("Rule ID: ").append(record.ruleId).append("\n");
                sb.append("Category: ").append(SecretCategoryMapper.getCategory(record.ruleId).getDisplayName()).append("\n\n");

                sb.append("Secret: ").append(record.secretContent).append("\n\n");

                sb.append("--- Validation ---\n");
                sb.append("Checked: ").append(record.validatedAt != null ? "Yes" : "No").append("\n");
                if (record.validatedAt != null) {
                    sb.append("Result: ").append(getValidationResultDisplay(record.validationStatus)).append("\n");
                    if (record.validationMessage != null && !record.validationMessage.isEmpty()) {
                        sb.append("Message: ").append(record.validationMessage).append("\n");
                    }
                }
                sb.append("False Positive: ").append(
                    record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE ? "Yes" : "No"
                ).append("\n");

                if (i < findings.size() - 1) {
                    sb.append("\n");
                    sb.append("─".repeat(50)).append("\n\n");
                }
            }

            secretsArea.setText(sb.toString());
            secretsArea.setCaretPosition(0);
        }

        private void displaySecrets(List<TitusProcessScanner.Match> matches) {
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < matches.size(); i++) {
                TitusProcessScanner.Match match = matches.get(i);

                sb.append("=== Secret #").append(i + 1).append(" ===\n\n");
                sb.append("Type: ").append(match.ruleName()).append("\n");
                sb.append("Rule ID: ").append(match.ruleId()).append("\n");
                sb.append("Category: ").append(SecretCategoryMapper.getCategory(match.ruleId()).getDisplayName()).append("\n\n");

                sb.append("Secret: ").append(match.matchedContent()).append("\n\n");

                if (match.line() > 0) {
                    sb.append("Location: Line ").append(match.line());
                    if (match.column() > 0) {
                        sb.append(", Column ").append(match.column());
                    }
                    sb.append("\n\n");
                }

                // Check validation status from cache
                String url = currentRequest != null ? currentRequest.url() : "unknown";
                DedupCache.FindingRecord record = dedupCache.getFinding(url, match.matchedContent());
                if (record != null) {
                    sb.append("--- Validation ---\n");
                    sb.append("Checked: ").append(record.validatedAt != null ? "Yes" : "No").append("\n");
                    if (record.validatedAt != null) {
                        sb.append("Result: ").append(getValidationResultDisplay(record.validationStatus)).append("\n");
                        if (record.validationMessage != null && !record.validationMessage.isEmpty()) {
                            sb.append("Message: ").append(record.validationMessage).append("\n");
                        }
                    }
                    sb.append("False Positive: ").append(
                        record.validationStatus == DedupCache.ValidationStatus.FALSE_POSITIVE ? "Yes" : "No"
                    ).append("\n");
                } else {
                    sb.append("--- Validation ---\n");
                    sb.append("Not yet recorded in Titus cache.\n");
                }

                if (i < matches.size() - 1) {
                    sb.append("\n");
                    sb.append("─".repeat(50)).append("\n\n");
                }
            }

            secretsArea.setText(sb.toString());
            secretsArea.setCaretPosition(0);
        }

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

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            // Only show tab if secrets are found
            if (requestResponse == null || requestResponse.response() == null) {
                return false;
            }

            // Check instance cache to avoid re-scanning
            if (requestResponse == lastCheckedRequestResponse) {
                return lastCheckHadSecrets;
            }

            String url = requestResponse.request() != null ? requestResponse.request().url() : "unknown";

            // First check if we have cached findings in DedupCache
            List<DedupCache.FindingRecord> findings = dedupCache.getFindingsForUrl(url);
            if (!findings.isEmpty()) {
                lastCheckedRequestResponse = requestResponse;
                lastCheckHadSecrets = true;
                this.cachedFindings = findings;
                return true;
            }

            // No cached findings - scan the response
            try {
                TitusProcessScanner scanner = processManager.getScanner();
                String content = requestResponse.response().toString();

                List<TitusProcessScanner.Match> matches = scanner.scan(content, url);

                // Cache result
                lastCheckedRequestResponse = requestResponse;
                lastCheckHadSecrets = !matches.isEmpty();

                // Also cache matches for setRequestResponse to reuse
                if (lastCheckHadSecrets) {
                    this.currentMatches = matches;
                }

                return lastCheckHadSecrets;
            } catch (Exception e) {
                api.logging().logToError("Error checking for secrets: " + e.getMessage());
                return false;
            }
        }

        @Override
        public String caption() {
            return "Titus";
        }

        @Override
        public Component uiComponent() {
            return panel;
        }

        @Override
        public Selection selectedData() {
            return null;
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }
}
