package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import javax.swing.*;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Manages secret validation requests to the Titus CLI.
 */
public class ValidationManager {

    private static final String SETTINGS_KEY = "titus.validation_enabled";
    private static final Gson GSON = new Gson();

    private final MontoyaApi api;
    private final ProcessManager processManager;
    private final DedupCache dedupCache;

    private volatile boolean validationEnabled = false;
    private final Map<String, DedupCache.ValidationStatus> validationCache = new ConcurrentHashMap<>();

    public ValidationManager(MontoyaApi api, ProcessManager processManager, DedupCache dedupCache) {
        this.api = api;
        this.processManager = processManager;
        this.dedupCache = dedupCache;
        loadSettings();
    }

    /**
     * Check if validation is enabled.
     */
    public boolean isValidationEnabled() {
        return validationEnabled;
    }

    /**
     * Set validation enabled state.
     */
    public void setValidationEnabled(boolean enabled) {
        this.validationEnabled = enabled;
        saveSettings();
    }

    /**
     * Validate a secret asynchronously.
     *
     * @param record   The finding record to validate
     * @param callback Called when validation completes (on EDT)
     */
    public void validateAsync(DedupCache.FindingRecord record, Consumer<DedupCache.FindingRecord> callback) {
        if (!validationEnabled) {
            api.logging().logToError("Validation not enabled");
            return;
        }

        if (record.secretContent == null || record.secretContent.isEmpty()) {
            record.setValidation(DedupCache.ValidationStatus.UNDETERMINED, "No secret content available");
            SwingUtilities.invokeLater(() -> callback.accept(record));
            return;
        }

        // Check cache
        String cacheKey = record.ruleId + ":" + record.secretContent;
        DedupCache.ValidationStatus cached = validationCache.get(cacheKey);
        if (cached != null && cached != DedupCache.ValidationStatus.NOT_CHECKED) {
            record.validationStatus = cached;
            SwingUtilities.invokeLater(() -> callback.accept(record));
            return;
        }

        // Mark as validating
        record.validationStatus = DedupCache.ValidationStatus.VALIDATING;
        SwingUtilities.invokeLater(() -> callback.accept(record));

        // Perform validation in background
        new Thread(() -> {
            try {
                ValidationResult result = validate(record.ruleId, record.secretContent);

                DedupCache.ValidationStatus status = switch (result.status()) {
                    case "valid" -> DedupCache.ValidationStatus.VALID;
                    case "invalid" -> DedupCache.ValidationStatus.INVALID;
                    default -> DedupCache.ValidationStatus.UNDETERMINED;
                };

                record.setValidation(status, result.message());
                record.setValidationDetails(result.details());
                validationCache.put(cacheKey, status);
                dedupCache.saveToSettings(); // Persist

                SwingUtilities.invokeLater(() -> callback.accept(record));

            } catch (Exception e) {
                api.logging().logToError("Validation failed: " + e.getMessage());
                record.setValidation(DedupCache.ValidationStatus.UNDETERMINED, "Error: " + e.getMessage());
                SwingUtilities.invokeLater(() -> callback.accept(record));
            }
        }, "titus-validator").start();
    }

    /**
     * Perform synchronous validation.
     */
    private ValidationResult validate(String ruleId, String secret) throws IOException {
        TitusProcessScanner scanner = processManager.getScanner();

        // Build validation request
        JsonObject payload = new JsonObject();
        payload.addProperty("rule_id", ruleId);
        payload.addProperty("secret", secret);

        JsonObject namedGroups = new JsonObject();
        namedGroups.addProperty("secret", secret);
        payload.add("named_groups", namedGroups);

        JsonObject request = new JsonObject();
        request.addProperty("type", "validate");
        request.add("payload", payload);

        // Send request and get response
        JsonObject response = scanner.sendValidateRequest(request);

        if (!response.get("success").getAsBoolean()) {
            String error = response.has("error") ? response.get("error").getAsString() : "Unknown error";
            return new ValidationResult("undetermined", 0, error, new HashMap<>());
        }

        JsonObject data = response.getAsJsonObject("data");
        
        // Extract details
        Map<String, String> details = new HashMap<>();
        if (data.has("details") && !data.get("details").isJsonNull()) {
            JsonObject detailsObj = data.getAsJsonObject("details");
            for (String key : detailsObj.keySet()) {
                details.put(key, detailsObj.get(key).getAsString());
            }
        }
        
        return new ValidationResult(
            data.has("status") ? data.get("status").getAsString() : "undetermined",
            data.has("confidence") ? data.get("confidence").getAsDouble() : 0,
            data.has("message") ? data.get("message").getAsString() : "",
            details
        );
    }

    private void loadSettings() {
        try {
            String enabled = api.persistence().extensionData().getString(SETTINGS_KEY);
            if (enabled != null) {
                validationEnabled = Boolean.parseBoolean(enabled);
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load validation settings: " + e.getMessage());
        }
    }

    private void saveSettings() {
        try {
            api.persistence().extensionData().setString(SETTINGS_KEY, String.valueOf(validationEnabled));
        } catch (Exception e) {
            api.logging().logToError("Failed to save validation settings: " + e.getMessage());
        }
    }

    /**
     * Clear the validation cache.
     */
    public void clearCache() {
        validationCache.clear();
    }

    /**
     * Validation result record.
     */
    public record ValidationResult(String status, double confidence, String message, Map<String, String> details) {}
}
