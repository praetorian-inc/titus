package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Exports findings to JSON format.
 */
public class FindingsExporter {

    private final MontoyaApi api;
    private final Gson gson;

    public FindingsExporter(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();
    }

    /**
     * Export report structure.
     */
    public record ExportReport(
        String export_time,
        String extension_version,
        int total_findings,
        List<ExportedFinding> findings
    ) {}

    /**
     * Individual finding in export.
     */
    public record ExportedFinding(
        String rule_id,
        String secret_preview,
        List<String> urls,
        int occurrence_count,
        String first_seen
    ) {}

    /**
     * Export findings to JSON file.
     * Shows a file chooser dialog and exports on user confirmation.
     *
     * @param dedupCache The dedup cache containing findings
     * @param parent     Parent component for dialogs
     */
    public void exportFindings(DedupCache dedupCache, Component parent) {
        Collection<DedupCache.FindingRecord> findings = dedupCache.getAllFindings();

        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(
                parent,
                "No findings to export.",
                "Export Findings",
                JOptionPane.INFORMATION_MESSAGE
            );
            return;
        }

        // Show file chooser
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Findings to JSON");
        fileChooser.setSelectedFile(new File("titus-findings.json"));

        int result = fileChooser.showSaveDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();

        // Ensure .json extension
        if (!file.getName().toLowerCase().endsWith(".json")) {
            file = new File(file.getPath() + ".json");
        }

        // Check if file exists
        if (file.exists()) {
            int overwrite = JOptionPane.showConfirmDialog(
                parent,
                "File already exists. Overwrite?",
                "Confirm Overwrite",
                JOptionPane.YES_NO_OPTION
            );
            if (overwrite != JOptionPane.YES_OPTION) {
                return;
            }
        }

        try {
            List<ExportedFinding> exportedFindings = new ArrayList<>();

            for (DedupCache.FindingRecord finding : findings) {
                exportedFindings.add(new ExportedFinding(
                    finding.ruleId,
                    maskSecret(finding.secretPreview),
                    new ArrayList<>(finding.urls),
                    finding.occurrenceCount,
                    finding.firstSeen != null ? finding.firstSeen.toString() : "unknown"
                ));
            }

            ExportReport report = new ExportReport(
                Instant.now().toString(),
                "1.0.0",
                exportedFindings.size(),
                exportedFindings
            );

            try (FileWriter writer = new FileWriter(file)) {
                gson.toJson(report, writer);
            }

            api.logging().logToOutput("Exported " + exportedFindings.size() + " findings to " + file.getPath());

            JOptionPane.showMessageDialog(
                parent,
                "Exported " + exportedFindings.size() + " findings to:\n" + file.getPath(),
                "Export Complete",
                JOptionPane.INFORMATION_MESSAGE
            );

        } catch (Exception e) {
            api.logging().logToError("Export failed: " + e.getMessage());
            JOptionPane.showMessageDialog(
                parent,
                "Export failed: " + e.getMessage(),
                "Export Error",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }

    /**
     * Mask a secret for export (shows first and last 4 chars).
     */
    private String maskSecret(String secret) {
        if (secret == null || secret.length() < 12) {
            return secret;
        }
        return secret.substring(0, 4) + "..." + secret.substring(secret.length() - 4);
    }
}
