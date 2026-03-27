package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Persists and restores HTTP messages across extension reloads.
 * Uses Burp's persistence API to store serialized messages.
 *
 * Note: ScanJob now stores extracted primitive data (not Burp API objects),
 * so serialization is straightforward.
 */
public class MessagePersistence {

    private static final String KEY_MESSAGES = "titus.persisted_messages";
    private static final String KEY_SCHEMA_VERSION = "titus.messages_schema_version";
    private static final int CURRENT_SCHEMA_VERSION = 2; // v2: ScanJob stores extracted data
    private static final int MAX_MESSAGES = 1000;

    private final MontoyaApi api;
    private final Gson gson;

    public MessagePersistence(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().create();
    }

    /**
     * Serializable message format.
     * Stores extracted data from ScanJob (not Burp API objects).
     */
    public record PersistedMessage(
        String url,
        String method,
        int statusCode,
        int responseSize,
        String requestBase64,
        String responseBase64,
        long timestamp,
        boolean scanRequest
    ) {}

    /**
     * Persist messages from the table model.
     *
     * @param entries List of request entries to persist
     */
    public void persistMessages(List<RequestsTableModel.RequestEntry> entries) {
        List<PersistedMessage> messages = new ArrayList<>();

        // Take last MAX_MESSAGES entries
        int start = Math.max(0, entries.size() - MAX_MESSAGES);
        for (int i = start; i < entries.size(); i++) {
            RequestsTableModel.RequestEntry entry = entries.get(i);
            ScanJob job = entry.scanJob();

            if (job == null) {
                continue;
            }

            try {
                String requestBase64 = Base64.getEncoder().encodeToString(
                    job.requestBytes() != null ? job.requestBytes() : new byte[0]
                );
                String responseBase64 = Base64.getEncoder().encodeToString(
                    job.responseBytes() != null ? job.responseBytes() : new byte[0]
                );

                messages.add(new PersistedMessage(
                    job.url(),
                    job.method(),
                    job.statusCode(),
                    job.responseSize(),
                    requestBase64,
                    responseBase64,
                    job.queuedAt(),
                    job.scanRequest()
                ));
            } catch (Exception e) {
                api.logging().logToError("Failed to serialize message: " + e.getMessage());
            }
        }

        try {
            String json = gson.toJson(messages);
            api.persistence().extensionData().setString(KEY_MESSAGES, json);
            api.persistence().extensionData().setString(KEY_SCHEMA_VERSION, String.valueOf(CURRENT_SCHEMA_VERSION));
            api.logging().logToOutput("Persisted " + messages.size() + " messages");
        } catch (Exception e) {
            api.logging().logToError("Failed to persist messages: " + e.getMessage());
        }
    }

    /**
     * Restore messages from persistence.
     *
     * @return List of restored scan jobs
     */
    public List<ScanJob> restoreMessages() {
        List<ScanJob> jobs = new ArrayList<>();

        try {
            // Check schema version - clear stale data from older format
            String versionStr = api.persistence().extensionData().getString(KEY_SCHEMA_VERSION);
            int storedVersion = 0;
            if (versionStr != null) {
                try { storedVersion = Integer.parseInt(versionStr); } catch (NumberFormatException ignored) {}
            }
            if (storedVersion < CURRENT_SCHEMA_VERSION) {
                api.logging().logToOutput("Message persistence schema upgraded (v" + storedVersion + " -> v" + CURRENT_SCHEMA_VERSION + "), clearing old entries");
                api.persistence().extensionData().setString(KEY_MESSAGES, "");
                api.persistence().extensionData().setString(KEY_SCHEMA_VERSION, String.valueOf(CURRENT_SCHEMA_VERSION));
                return jobs;
            }

            String json = api.persistence().extensionData().getString(KEY_MESSAGES);
            if (json == null || json.isEmpty()) {
                return jobs;
            }

            Type listType = new TypeToken<List<PersistedMessage>>(){}.getType();
            List<PersistedMessage> messages = gson.fromJson(json, listType);

            if (messages == null) {
                return jobs;
            }

            for (PersistedMessage msg : messages) {
                try {
                    byte[] requestBytes = Base64.getDecoder().decode(msg.requestBase64());
                    byte[] responseBytes = Base64.getDecoder().decode(msg.responseBase64());

                    jobs.add(ScanJob.fromRawData(
                        msg.url(),
                        msg.method(),
                        msg.statusCode(),
                        msg.responseSize(),
                        requestBytes,
                        responseBytes,
                        ScanJob.Source.PASSIVE,
                        msg.timestamp(),
                        msg.scanRequest()
                    ));
                } catch (Exception e) {
                    api.logging().logToError("Failed to deserialize message: " + e.getMessage());
                }
            }

            api.logging().logToOutput("Restored " + jobs.size() + " messages from persistence");

        } catch (Exception e) {
            api.logging().logToError("Failed to restore messages: " + e.getMessage());
        }

        return jobs;
    }

    /**
     * Clear persisted messages.
     */
    public void clear() {
        try {
            api.persistence().extensionData().setString(KEY_MESSAGES, "");
            api.logging().logToOutput("Cleared persisted messages");
        } catch (Exception e) {
            api.logging().logToError("Failed to clear persisted messages: " + e.getMessage());
        }
    }

    /**
     * Check if there are persisted messages.
     */
    public boolean hasPersistedMessages() {
        try {
            String json = api.persistence().extensionData().getString(KEY_MESSAGES);
            return json != null && !json.isEmpty() && !json.equals("[]");
        } catch (Exception e) {
            return false;
        }
    }
}
