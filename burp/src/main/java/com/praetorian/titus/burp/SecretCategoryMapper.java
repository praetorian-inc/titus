package com.praetorian.titus.burp;

import java.awt.Color;

/**
 * Maps secret rule IDs to categories and colors for UI display.
 */
public class SecretCategoryMapper {

    /**
     * Secret categories for grouping and color-coding.
     */
    public enum Category {
        CLOUD("Cloud Credentials", new Color(220, 53, 69)),      // Red
        DATABASE("Database Credentials", new Color(255, 152, 0)), // Orange
        API_KEY("API Keys", new Color(255, 193, 7)),              // Yellow
        PRIVATE_KEY("Private Keys", new Color(156, 39, 176)),     // Purple
        GENERIC("Generic Secrets", new Color(158, 158, 158));     // Gray

        private final String displayName;
        private final Color color;

        Category(String displayName, Color color) {
            this.displayName = displayName;
            this.color = color;
        }

        public String getDisplayName() {
            return displayName;
        }

        public Color getColor() {
            return color;
        }

        public Color getLightColor() {
            // Lighter version for backgrounds
            return new Color(
                Math.min(255, color.getRed() + 60),
                Math.min(255, color.getGreen() + 60),
                Math.min(255, color.getBlue() + 60),
                100
            );
        }
    }

    /**
     * Get category for a rule ID.
     */
    public static Category getCategory(String ruleId) {
        if (ruleId == null || ruleId.isEmpty()) {
            return Category.GENERIC;
        }

        String lower = ruleId.toLowerCase();

        // Cloud providers
        if (containsAny(lower, "aws", "amazon", "gcp", "google_cloud", "azure", "digitalocean", "heroku", "cloudflare")) {
            return Category.CLOUD;
        }

        // Database credentials
        if (containsAny(lower, "postgres", "mysql", "mongodb", "redis", "database", "db_", "connection_string", "jdbc")) {
            return Category.DATABASE;
        }

        // Private keys and certificates
        if (containsAny(lower, "private_key", "ssh_", "rsa", "pem", "pkcs", "certificate", "x509")) {
            return Category.PRIVATE_KEY;
        }

        // API keys (third-party services)
        if (containsAny(lower, "slack", "stripe", "twilio", "sendgrid", "mailgun", "github", "gitlab",
                        "npm", "pypi", "algolia", "firebase", "mapbox", "openai", "api_key", "apikey",
                        "oauth", "jwt", "bearer", "token", "secret_key")) {
            return Category.API_KEY;
        }

        return Category.GENERIC;
    }

    /**
     * Get display name for a rule ID (human-readable secret type).
     */
    public static String getDisplayName(String ruleId, String ruleName) {
        // Prefer ruleName if available and meaningful
        if (ruleName != null && !ruleName.isEmpty() && !ruleName.equals(ruleId)) {
            return ruleName;
        }

        // Generate from rule ID
        if (ruleId == null || ruleId.isEmpty()) {
            return "Unknown Secret";
        }

        // Handle np.xxx.n format
        if (ruleId.startsWith("np.")) {
            String[] parts = ruleId.split("\\.");
            if (parts.length >= 2) {
                return formatName(parts[1]);
            }
        }

        return formatName(ruleId);
    }

    /**
     * Extract host from URL.
     */
    public static String extractHost(String url) {
        if (url == null || url.isEmpty()) {
            return "unknown";
        }

        try {
            // Remove protocol
            String host = url;
            if (host.contains("://")) {
                host = host.substring(host.indexOf("://") + 3);
            }

            // Remove path
            int slashIndex = host.indexOf('/');
            if (slashIndex > 0) {
                host = host.substring(0, slashIndex);
            }

            // Remove port
            int colonIndex = host.lastIndexOf(':');
            if (colonIndex > 0) {
                host = host.substring(0, colonIndex);
            }

            return host.toLowerCase();
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static boolean containsAny(String text, String... keywords) {
        for (String keyword : keywords) {
            if (text.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private static String formatName(String name) {
        // Convert snake_case or camelCase to Title Case
        StringBuilder result = new StringBuilder();
        boolean capitalizeNext = true;

        for (char c : name.toCharArray()) {
            if (c == '_' || c == '-' || c == '.') {
                result.append(' ');
                capitalizeNext = true;
            } else if (Character.isUpperCase(c)) {
                if (result.length() > 0 && !capitalizeNext) {
                    result.append(' ');
                }
                result.append(c);
                capitalizeNext = false;
            } else {
                result.append(capitalizeNext ? Character.toUpperCase(c) : c);
                capitalizeNext = false;
            }
        }

        return result.toString().trim();
    }
}
