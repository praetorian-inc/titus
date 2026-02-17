package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

/**
 * Configurable severity mapping for Titus rules.
 *
 * Maps rule IDs or categories to Burp severity levels.
 * Persisted to Burp project settings.
 */
public class SeverityConfig {

    private static final String SETTINGS_KEY = "titus.severity_config";
    private static final Gson GSON = new Gson();

    private final MontoyaApi api;
    private final Map<String, AuditIssueSeverity> ruleOverrides = new HashMap<>();
    private final Map<String, AuditIssueSeverity> categoryDefaults = new HashMap<>();

    public SeverityConfig(MontoyaApi api) {
        this.api = api;
        initializeDefaults();
        loadFromSettings();
    }

    /**
     * Get severity for a rule ID.
     */
    public AuditIssueSeverity getSeverity(String ruleId) {
        // Check rule-specific override first
        if (ruleOverrides.containsKey(ruleId)) {
            return ruleOverrides.get(ruleId);
        }

        // Check category defaults
        String category = extractCategory(ruleId);
        if (category != null && categoryDefaults.containsKey(category)) {
            return categoryDefaults.get(category);
        }

        // Default to Medium
        return AuditIssueSeverity.MEDIUM;
    }

    /**
     * Set severity override for a specific rule.
     */
    public void setRuleSeverity(String ruleId, AuditIssueSeverity severity) {
        ruleOverrides.put(ruleId, severity);
        saveToSettings();
    }

    /**
     * Set default severity for a category.
     */
    public void setCategorySeverity(String category, AuditIssueSeverity severity) {
        categoryDefaults.put(category.toLowerCase(), severity);
        saveToSettings();
    }

    /**
     * Get all category defaults.
     */
    public Map<String, AuditIssueSeverity> getCategoryDefaults() {
        return new HashMap<>(categoryDefaults);
    }

    /**
     * Get all rule overrides.
     */
    public Map<String, AuditIssueSeverity> getRuleOverrides() {
        return new HashMap<>(ruleOverrides);
    }

    /**
     * Reset to defaults.
     */
    public void resetToDefaults() {
        ruleOverrides.clear();
        initializeDefaults();
        saveToSettings();
    }

    private void initializeDefaults() {
        // Cloud credentials - High severity
        categoryDefaults.put("aws", AuditIssueSeverity.HIGH);
        categoryDefaults.put("azure", AuditIssueSeverity.HIGH);
        categoryDefaults.put("gcp", AuditIssueSeverity.HIGH);
        categoryDefaults.put("cloud", AuditIssueSeverity.HIGH);

        // Authentication/API keys - High severity
        categoryDefaults.put("auth", AuditIssueSeverity.HIGH);
        categoryDefaults.put("api", AuditIssueSeverity.HIGH);
        categoryDefaults.put("oauth", AuditIssueSeverity.HIGH);
        categoryDefaults.put("jwt", AuditIssueSeverity.HIGH);

        // Database/Infrastructure - High severity
        categoryDefaults.put("database", AuditIssueSeverity.HIGH);
        categoryDefaults.put("db", AuditIssueSeverity.HIGH);
        categoryDefaults.put("postgres", AuditIssueSeverity.HIGH);
        categoryDefaults.put("mysql", AuditIssueSeverity.HIGH);
        categoryDefaults.put("mongodb", AuditIssueSeverity.HIGH);

        // Private keys - High severity
        categoryDefaults.put("private", AuditIssueSeverity.HIGH);
        categoryDefaults.put("ssh", AuditIssueSeverity.HIGH);
        categoryDefaults.put("rsa", AuditIssueSeverity.HIGH);

        // Third-party services - Medium severity
        categoryDefaults.put("slack", AuditIssueSeverity.MEDIUM);
        categoryDefaults.put("github", AuditIssueSeverity.MEDIUM);
        categoryDefaults.put("gitlab", AuditIssueSeverity.MEDIUM);
        categoryDefaults.put("npm", AuditIssueSeverity.MEDIUM);
        categoryDefaults.put("pypi", AuditIssueSeverity.MEDIUM);

        // Generic patterns - Low severity (more likely false positives)
        categoryDefaults.put("generic", AuditIssueSeverity.LOW);
        categoryDefaults.put("password", AuditIssueSeverity.MEDIUM);
        categoryDefaults.put("secret", AuditIssueSeverity.MEDIUM);
    }

    private String extractCategory(String ruleId) {
        if (ruleId == null || ruleId.isEmpty()) {
            return null;
        }

        // Rule IDs typically follow pattern: "np.category.number" or "category_name"
        String lower = ruleId.toLowerCase();

        // Check for np.category.number pattern
        if (lower.startsWith("np.")) {
            String[] parts = lower.split("\\.");
            if (parts.length >= 2) {
                return parts[1];
            }
        }

        // Check for category_name pattern
        if (lower.contains("_")) {
            return lower.split("_")[0];
        }

        // Check if any category keyword is in the rule ID
        for (String category : categoryDefaults.keySet()) {
            if (lower.contains(category)) {
                return category;
            }
        }

        return null;
    }

    private void saveToSettings() {
        try {
            Map<String, Object> config = new HashMap<>();
            config.put("ruleOverrides", convertToStringMap(ruleOverrides));
            config.put("categoryDefaults", convertToStringMap(categoryDefaults));

            String json = GSON.toJson(config);
            api.persistence().extensionData().setString(SETTINGS_KEY, json);
        } catch (Exception e) {
            api.logging().logToError("Failed to save severity config: " + e.getMessage());
        }
    }

    private void loadFromSettings() {
        try {
            String json = api.persistence().extensionData().getString(SETTINGS_KEY);
            if (json != null && !json.isEmpty()) {
                Type mapType = new TypeToken<Map<String, Object>>(){}.getType();
                Map<String, Object> config = GSON.fromJson(json, mapType);

                if (config.containsKey("ruleOverrides")) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> overrides = (Map<String, String>) config.get("ruleOverrides");
                    for (Map.Entry<String, String> entry : overrides.entrySet()) {
                        ruleOverrides.put(entry.getKey(), AuditIssueSeverity.valueOf(entry.getValue()));
                    }
                }

                if (config.containsKey("categoryDefaults")) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> defaults = (Map<String, String>) config.get("categoryDefaults");
                    for (Map.Entry<String, String> entry : defaults.entrySet()) {
                        categoryDefaults.put(entry.getKey(), AuditIssueSeverity.valueOf(entry.getValue()));
                    }
                }

                api.logging().logToOutput("Loaded severity config");
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load severity config: " + e.getMessage());
        }
    }

    private Map<String, String> convertToStringMap(Map<String, AuditIssueSeverity> map) {
        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, AuditIssueSeverity> entry : map.entrySet()) {
            result.put(entry.getKey(), entry.getValue().name());
        }
        return result;
    }
}
