package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Reports secret findings as Burp Scanner issues.
 */
public class IssueReporter {

    private final MontoyaApi api;
    private final SeverityConfig severityConfig;

    public IssueReporter(MontoyaApi api, SeverityConfig severityConfig) {
        this.api = api;
        this.severityConfig = severityConfig;
    }

    /**
     * Report a finding as a Burp Scanner issue.
     *
     * @param job   The scan job that found the issue
     * @param match The match details
     */
    public void reportIssue(ScanJob job, TitusProcessScanner.Match match) {
        try {
            // Create the audit issue
            AuditIssue issue = AuditIssue.auditIssue(
                "Secret Detected: " + match.ruleName(),
                buildIssueDetail(match),
                buildRemediation(match),
                job.url(),
                mapSeverity(match.ruleId()),
                AuditIssueConfidence.CERTAIN,
                buildBackground(match),
                buildRemediationBackground(),
                mapSeverity(match.ruleId()),
                HttpRequestResponse.httpRequestResponse(job.request(), job.response())
            );

            // Add to site map
            api.siteMap().add(issue);

            api.logging().logToOutput("Reported issue: " + match.ruleName() + " at " + job.url());

        } catch (Exception e) {
            api.logging().logToError("Failed to report issue: " + e.getMessage());
        }
    }

    private String buildIssueDetail(TitusProcessScanner.Match match) {
        StringBuilder sb = new StringBuilder();

        sb.append("<p><b>Rule:</b> ").append(escapeHtml(match.ruleId())).append("</p>\n");
        sb.append("<p><b>Rule Name:</b> ").append(escapeHtml(match.ruleName())).append("</p>\n");
        sb.append("<p><b>Secret Preview:</b> <code>").append(escapeHtml(match.preview())).append("</code></p>\n");

        if (match.line() > 0) {
            sb.append("<p><b>Location:</b> Line ").append(match.line());
            if (match.column() > 0) {
                sb.append(", Column ").append(match.column());
            }
            sb.append("</p>\n");
        }

        if (match.snippet() != null && !match.snippet().isEmpty()) {
            sb.append("<p><b>Context:</b></p>\n");
            sb.append("<pre>").append(escapeHtml(match.snippet())).append("</pre>\n");
        }

        return sb.toString();
    }

    private String buildBackground(TitusProcessScanner.Match match) {
        return "<p>The application response contains what appears to be a secret or credential. " +
               "Exposing secrets in HTTP responses can lead to unauthorized access if the secret " +
               "is captured by an attacker through various means such as browser history, proxy logs, " +
               "or man-in-the-middle attacks.</p>\n" +
               "<p>Rule: <b>" + escapeHtml(match.ruleName()) + "</b></p>";
    }

    private String buildRemediation(TitusProcessScanner.Match match) {
        return "<ul>\n" +
               "<li>Remove the secret from the HTTP response</li>\n" +
               "<li>If the secret is a credential, rotate it immediately</li>\n" +
               "<li>Review application logic to prevent secrets from being included in responses</li>\n" +
               "<li>Consider using environment variables or secrets management for sensitive configuration</li>\n" +
               "</ul>";
    }

    private String buildRemediationBackground() {
        return "<p>Secrets and credentials should never be exposed in HTTP responses. " +
               "Even if the response is only visible to authenticated users, it may be logged, " +
               "cached, or intercepted. Use secure secrets management practices and ensure " +
               "sensitive data is only transmitted when absolutely necessary, using secure channels.</p>";
    }

    private AuditIssueSeverity mapSeverity(String ruleId) {
        return severityConfig.getSeverity(ruleId);
    }

    private String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }
}
