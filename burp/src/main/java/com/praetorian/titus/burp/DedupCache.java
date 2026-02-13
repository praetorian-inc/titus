package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Deduplication cache for secret findings.
 *
 * Deduplicates by URL + secret content, tracking occurrence counts across URLs.
 * State is persisted to the Burp project file.
 */
public class DedupCache {

    private static final String SETTINGS_KEY = "titus.dedup_cache";
    private static final Gson GSON = new GsonBuilder()
        .registerTypeAdapter(Instant.class, new InstantTypeAdapter())
        .create();
    private static final int MAX_CACHE_SIZE = 50000; // Prevent unbounded memory growth

    /**
     * TypeAdapter for java.time.Instant serialization.
     */
    private static class InstantTypeAdapter extends TypeAdapter<Instant> {
        @Override
        public void write(JsonWriter out, Instant value) throws IOException {
            if (value == null) {
                out.nullValue();
            } else {
                out.value(value.toString());
            }
        }

        @Override
        public Instant read(JsonReader in) throws IOException {
            if (in.peek() == JsonToken.NULL) {
                in.nextNull();
                return null;
            }
            return Instant.parse(in.nextString());
        }
    }

    private final MontoyaApi api;
    private final Map<String, FindingRecord> cache = new ConcurrentHashMap<>();
    // Track processed URL+contentHash for bulk scan deduplication
    private final Set<String> processedUrls = ConcurrentHashMap.newKeySet();

    public DedupCache(MontoyaApi api) {
        this.api = api;
        loadFromSettings();
    }

    /**
     * Check if a URL with specific content hash has been processed (for bulk scan).
     *
     * @param url         The URL
     * @param contentHash Hash of the response content
     * @return true if already processed
     */
    public boolean hasProcessedUrl(String url, String contentHash) {
        return processedUrls.contains(url + ":" + contentHash);
    }

    /**
     * Mark a URL with specific content hash as processed (for bulk scan).
     *
     * @param url         The URL
     * @param contentHash Hash of the response content
     */
    public void markUrlProcessed(String url, String contentHash) {
        processedUrls.add(url + ":" + contentHash);
    }

    /**
     * Clear the processed URLs set (e.g., when clearing cache).
     */
    public void clearProcessedUrls() {
        processedUrls.clear();
    }

    /**
     * Check if this is a new finding (not seen before).
     *
     * @param url           The URL where the secret was found
     * @param secretContent The secret content
     * @param ruleId        The rule that matched
     * @return true if this is a new finding
     */
    public boolean isNewFinding(String url, String secretContent, String ruleId) {
        String key = computeKey(normalizeUrl(url), secretContent);
        return !cache.containsKey(key);
    }

    /**
     * Record an occurrence of a finding.
     *
     * @param url           The URL where the secret was found
     * @param secretContent The secret content
     * @param ruleId        The rule that matched
     * @return The updated finding record
     */
    public FindingRecord recordOccurrence(String url, String secretContent, String ruleId) {
        return recordOccurrence(url, secretContent, ruleId, null);
    }

    /**
     * Record an occurrence of a finding with rule name.
     *
     * @param url           The URL where the secret was found
     * @param secretContent The secret content
     * @param ruleId        The rule that matched
     * @param ruleName      The human-readable rule name
     * @return The updated finding record
     */
    public FindingRecord recordOccurrence(String url, String secretContent, String ruleId, String ruleName) {
        return recordOccurrence(url, secretContent, ruleId, ruleName, null, null);
    }

    /**
     * Record an occurrence of a finding with rule name and HTTP content.
     *
     * @param url             The URL where the secret was found
     * @param secretContent   The secret content
     * @param ruleId          The rule that matched
     * @param ruleName        The human-readable rule name
     * @param requestContent  The full HTTP request content
     * @param responseContent The full HTTP response content
     * @return The updated finding record
     */
    public FindingRecord recordOccurrence(String url, String secretContent, String ruleId, String ruleName,
                                          String requestContent, String responseContent) {
        String normalizedUrl = normalizeUrl(url);
        String host = SecretCategoryMapper.extractHost(url);
        String key = computeKey(normalizedUrl, secretContent);

        // Evict oldest entries if at max capacity before adding new
        if (!cache.containsKey(key) && cache.size() >= MAX_CACHE_SIZE) {
            evictOldest();
        }

        FindingRecord record = cache.compute(key, (k, existing) -> {
            if (existing == null) {
                FindingRecord newRecord = new FindingRecord(
                    ruleId,
                    ruleName != null ? ruleName : SecretCategoryMapper.getDisplayName(ruleId, null),
                    createPreview(secretContent),
                    secretContent,
                    host,
                    new HashSet<>(Set.of(normalizedUrl)),
                    1,
                    Instant.now()
                );
                // Store HTTP content for first occurrence only
                if (requestContent != null || responseContent != null) {
                    newRecord.setHttpContent(requestContent, responseContent);
                }
                return newRecord;
            } else {
                existing.urls.add(normalizedUrl);
                existing.hosts.add(host);
                existing.occurrenceCount++;
                return existing;
            }
        });

        // Persist to settings periodically (every 10 findings)
        if (cache.size() % 10 == 0) {
            saveToSettings();
        }

        return record;
    }

    /**
     * Evict oldest 10% of entries when cache is full.
     */
    private void evictOldest() {
        int toEvict = MAX_CACHE_SIZE / 10;
        cache.entrySet().stream()
            .sorted(Comparator.comparing(e -> e.getValue().firstSeen))
            .limit(toEvict)
            .map(Map.Entry::getKey)
            .toList()
            .forEach(cache::remove);
        api.logging().logToOutput("Evicted " + toEvict + " oldest findings from cache");
    }

    /**
     * Get a finding record by URL and secret.
     */
    public FindingRecord getFinding(String url, String secretContent) {
        String key = computeKey(normalizeUrl(url), secretContent);
        return cache.get(key);
    }

    /**
     * Get all finding records.
     */
    public Collection<FindingRecord> getAllFindings() {
        return Collections.unmodifiableCollection(cache.values());
    }

    /**
     * Get total number of unique findings.
     */
    public int uniqueFindingsCount() {
        return cache.size();
    }

    /**
     * Clear the cache.
     */
    public void clear() {
        cache.clear();
        saveToSettings();
    }

    /**
     * Save cache to Burp settings.
     */
    public void saveToSettings() {
        try {
            String json = GSON.toJson(new ArrayList<>(cache.values()));
            api.persistence().extensionData().setString(SETTINGS_KEY, json);
        } catch (Exception e) {
            api.logging().logToError("Failed to save dedup cache: " + e.getMessage());
        }
    }

    /**
     * Load cache from Burp settings.
     */
    private void loadFromSettings() {
        try {
            String json = api.persistence().extensionData().getString(SETTINGS_KEY);
            if (json != null && !json.isEmpty()) {
                Type listType = new TypeToken<List<FindingRecord>>(){}.getType();
                List<FindingRecord> records = GSON.fromJson(json, listType);
                if (records != null) {
                    for (FindingRecord record : records) {
                        // Reconstruct keys (we need at least one URL)
                        if (!record.urls.isEmpty()) {
                            String url = record.urls.iterator().next();
                            // We don't have the original secret, so use preview as approximation
                            String key = computeKey(url, record.secretPreview);

                            // Fix missing host data from older cache versions
                            if (record.primaryHost == null || record.primaryHost.isEmpty()) {
                                record.primaryHost = SecretCategoryMapper.extractHost(url);
                            }
                            if (record.hosts == null) {
                                record.hosts = new HashSet<>();
                            }
                            if (record.hosts.isEmpty()) {
                                for (String u : record.urls) {
                                    record.hosts.add(SecretCategoryMapper.extractHost(u));
                                }
                            }
                            if (record.validationStatus == null) {
                                record.validationStatus = ValidationStatus.NOT_CHECKED;
                            }

                            cache.put(key, record);
                        }
                    }
                }
                api.logging().logToOutput("Loaded " + cache.size() + " findings from cache");
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load dedup cache: " + e.getMessage());
        }
    }

    private String computeKey(String normalizedUrl, String secretContent) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String combined = normalizedUrl + ":" + secretContent;
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // Fallback to simple hash
            return String.valueOf((normalizedUrl + ":" + secretContent).hashCode());
        }
    }

    private String normalizeUrl(String url) {
        if (url == null) {
            return "";
        }
        // Remove query parameters for dedup purposes
        // Same secret on /api/v1/users and /api/v1/users?page=2 should be one finding
        int queryIndex = url.indexOf('?');
        if (queryIndex > 0) {
            return url.substring(0, queryIndex);
        }
        return url;
    }

    private String createPreview(String secretContent) {
        if (secretContent == null || secretContent.isEmpty()) {
            return "[empty]";
        }
        if (secretContent.length() <= 20) {
            return secretContent;
        }
        return secretContent.substring(0, 20) + "...";
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Validation status for secrets.
     */
    public enum ValidationStatus {
        NOT_CHECKED("-"),
        VALIDATING("..."),
        VALID("Active"),
        INVALID("Inactive"),
        UNDETERMINED("Unknown"),
        FALSE_POSITIVE("False Positive");

        private final String displayText;

        ValidationStatus(String displayText) {
            this.displayText = displayText;
        }

        public String getDisplayText() {
            return displayText;
        }
    }

    /**
     * Record of a deduplicated finding.
     */
    public static class FindingRecord {
        public String ruleId;
        public String ruleName;
        public String secretPreview;
        public String secretContent;  // Full content for validation
        public String primaryHost;    // Host where first seen
        public Set<String> urls;
        public Set<String> hosts;     // All hosts where seen
        public int occurrenceCount;
        public Instant firstSeen;
        public ValidationStatus validationStatus;
        public String validationMessage;
        public Instant validatedAt;
        public String responseSnippet; // Snippet of response around the secret
        public String requestContent;  // Full request content for display
        public String responseContent; // Full response content for display

        public FindingRecord() {
            this.urls = new HashSet<>();
            this.hosts = new HashSet<>();
            this.validationStatus = ValidationStatus.NOT_CHECKED;
        }

        public FindingRecord(String ruleId, String ruleName, String secretPreview,
                           String secretContent, String primaryHost, Set<String> urls,
                           int occurrenceCount, Instant firstSeen) {
            this.ruleId = ruleId;
            this.ruleName = ruleName;
            this.secretPreview = secretPreview;
            this.secretContent = secretContent;
            this.primaryHost = primaryHost;
            this.urls = urls;
            this.hosts = new HashSet<>();
            if (primaryHost != null && !primaryHost.isEmpty()) {
                this.hosts.add(primaryHost);
            }
            this.occurrenceCount = occurrenceCount;
            this.firstSeen = firstSeen;
            this.validationStatus = ValidationStatus.NOT_CHECKED;
        }

        /**
         * Update validation status.
         */
        public void setValidation(ValidationStatus status, String message) {
            this.validationStatus = status;
            this.validationMessage = message;
            this.validatedAt = Instant.now();
        }

        /**
         * Set response snippet.
         */
        public void setResponseSnippet(String snippet) {
            this.responseSnippet = snippet;
        }

        /**
         * Set request and response content for display.
         */
        public void setHttpContent(String requestContent, String responseContent) {
            this.requestContent = requestContent;
            this.responseContent = responseContent;
        }
    }
}
