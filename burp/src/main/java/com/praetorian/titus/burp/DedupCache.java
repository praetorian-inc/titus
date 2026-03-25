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
    // Track all URLs that have been scanned (for Titus editor tab visibility)
    private final Set<String> scannedUrls = ConcurrentHashMap.newKeySet();

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
     * Mark a URL as having been scanned by the scan queue.
     */
    public void markUrlScanned(String url) {
        scannedUrls.add(normalizeUrl(url));
    }

    /**
     * Check if a URL has been scanned (regardless of whether secrets were found).
     */
    public boolean hasUrlBeenScanned(String url) {
        return scannedUrls.contains(normalizeUrl(url));
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
        String key = computeKey(secretContent, ruleId);
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
        return recordOccurrence(url, secretContent, ruleId, ruleName, requestContent, responseContent, null);
    }

    /**
     * Record an occurrence of a finding with rule name, HTTP content, and named groups.
     *
     * @param url             The URL where the secret was found
     * @param secretContent   The secret content
     * @param ruleId          The rule that matched
     * @param ruleName        The human-readable rule name
     * @param requestContent  The full HTTP request content
     * @param responseContent The full HTTP response content
     * @param namedGroups     Named capture groups from regex match (for validation)
     * @return The updated finding record
     */
    public FindingRecord recordOccurrence(String url, String secretContent, String ruleId, String ruleName,
                                          String requestContent, String responseContent,
                                          Map<String, String> namedGroups) {
        String normalizedUrl = normalizeUrl(url);
        String host = SecretCategoryMapper.extractHost(url);
        String key = computeKey(secretContent, ruleId);

        // Evict oldest entries if at max capacity before adding new
        if (!cache.containsKey(key) && cache.size() >= MAX_CACHE_SIZE) {
            evictOldest();
        }

        FindingRecord record = cache.compute(key, (k, existing) -> {
            if (existing == null) {
                FindingRecord newRecord = new FindingRecord(
                    ruleId,
                    ruleName != null ? ruleName : SecretCategoryMapper.getDisplayName(ruleId, null),
                    createPreview(secretContent, namedGroups),
                    secretContent,
                    host,
                    new HashSet<>(Set.of(normalizedUrl)),
                    1,
                    Instant.now(),
                    namedGroups
                );
                // Store HTTP content for first occurrence only
                if (requestContent != null || responseContent != null) {
                    newRecord.setHttpContent(requestContent, responseContent);
                }
                return newRecord;
            } else {
                boolean isNewUrl = existing.urls.add(normalizedUrl);
                existing.hosts.add(host);
                existing.occurrenceCount++;
                // Update named groups if not set (keep first occurrence's groups)
                if ((existing.namedGroups == null || existing.namedGroups.isEmpty()) && namedGroups != null) {
                    existing.namedGroups = namedGroups;
                }
                // Keep first occurrence's HTTP content (user can check other URLs in Proxy history)
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
     * Get a finding record by URL, secret, and rule ID.
     */
    public FindingRecord getFinding(String url, String secretContent, String ruleId) {
        String key = computeKey(secretContent, ruleId);
        return cache.get(key);
    }

    /**
     * Get all finding records.
     */
    public Collection<FindingRecord> getAllFindings() {
        return Collections.unmodifiableCollection(cache.values());
    }

    /**
     * Get all findings for a specific URL.
     *
     * @param url The URL to get findings for
     * @return List of findings for this URL (may be empty)
     */
    public List<FindingRecord> getFindingsForUrl(String url) {
        String normalizedUrl = normalizeUrl(url);
        List<FindingRecord> results = new ArrayList<>();
        for (FindingRecord record : cache.values()) {
            if (record.urls.contains(normalizedUrl)) {
                results.add(record);
            }
        }
        return results;
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
    /**
     * Remove a specific finding from the cache.
     *
     * @param record The finding record to remove
     * @return true if the finding was removed
     */
    public boolean removeFinding(FindingRecord record) {
        String key = computeKey(record.secretContent, record.ruleId);
        boolean removed = cache.remove(key) != null;
        if (removed) {
            saveToSettings();
        }
        return removed;
    }

    public void clear() {
        cache.clear();
        scannedUrls.clear();
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
                        String secretForKey = record.secretContent != null ? record.secretContent : record.secretPreview;
                        String key = computeKey(secretForKey, record.ruleId);
                        String url = !record.urls.isEmpty() ? record.urls.iterator().next() : null;

                        // Fix missing host data from older cache versions
                        if (record.primaryHost == null || record.primaryHost.isEmpty()) {
                            record.primaryHost = url != null ? SecretCategoryMapper.extractHost(url) : "unknown";
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
                        if (record.namedGroups == null) {
                            record.namedGroups = new HashMap<>();
                        }

                        // Merge with existing entry if same key (migrating old per-URL entries)
                        FindingRecord existing = cache.get(key);
                        if (existing != null) {
                            existing.urls.addAll(record.urls);
                            existing.hosts.addAll(record.hosts);
                            existing.occurrenceCount += record.occurrenceCount;
                        } else {
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

    private String computeKey(String secretContent, String ruleId) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // Key by ruleId + secretContent only — same secret at different URLs = one finding
            String combined = ruleId + ":" + secretContent;
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // Fallback to simple hash
            return String.valueOf((ruleId + ":" + secretContent).hashCode());
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

    private String createPreview(String secretContent, Map<String, String> namedGroups) {
        // For findings with multiple named groups (e.g., AWS key_id + secret_key),
        // show a paired preview with values joined by ":"
        if (namedGroups != null && namedGroups.size() > 1) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> entry : namedGroups.entrySet()) {
                if (sb.length() > 0) sb.append(":");
                String val = entry.getValue();
                if (val.length() > 12) {
                    sb.append(val, 0, 12).append("...");
                } else {
                    sb.append(val);
                }
            }
            String paired = sb.toString();
            if (paired.length() > 40) {
                return paired.substring(0, 40) + "...";
            }
            return paired;
        }

        // Single value preview
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
        NOT_CHECKED("No"),
        VALIDATING("..."),
        VALID("Active"),
        INVALID("Inactive"),
        UNDETERMINED("Unknown"),
        FALSE_POSITIVE("FP");

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
        public Map<String, String> validationDetails;
        public Map<String, String> namedGroups;  // Named capture groups from regex match
        public boolean hidden;  // User can hide secrets they don't want to see
        public ValidationStatus preMarkFPStatus;  // Validation status before FP marking
        public String severityOverride;  // Per-finding severity override (HIGH/MEDIUM/LOW/INFORMATION), null = use config default

        public FindingRecord() {
            this.urls = new HashSet<>();
            this.hosts = new HashSet<>();
            this.validationStatus = ValidationStatus.NOT_CHECKED;
            this.validationDetails = new HashMap<>();
            this.namedGroups = new HashMap<>();
        }

        public FindingRecord(String ruleId, String ruleName, String secretPreview,
                           String secretContent, String primaryHost, Set<String> urls,
                           int occurrenceCount, Instant firstSeen) {
            this(ruleId, ruleName, secretPreview, secretContent, primaryHost, urls,
                 occurrenceCount, firstSeen, new HashMap<>());
        }

        public FindingRecord(String ruleId, String ruleName, String secretPreview,
                           String secretContent, String primaryHost, Set<String> urls,
                           int occurrenceCount, Instant firstSeen, Map<String, String> namedGroups) {
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
            this.validationDetails = new HashMap<>();
            this.namedGroups = namedGroups != null ? namedGroups : new HashMap<>();
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

        /**
         * Set validation details.
         */
        public void setValidationDetails(Map<String, String> details) {
            this.validationDetails = details;
        }

        /**
         * Set named groups from regex match.
         */
        public void setNamedGroups(Map<String, String> namedGroups) {
            this.namedGroups = namedGroups != null ? namedGroups : new HashMap<>();
        }

        /**
         * Get named groups for validation.
         */
        public Map<String, String> getNamedGroups() {
            return this.namedGroups != null ? this.namedGroups : new HashMap<>();
        }
    }
}
