package com.praetorian.titus.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
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
 */
public class MessagePersistence {

    private static final String KEY_MESSAGES = "titus.persisted_messages";
    private static final int MAX_MESSAGES = 1000;

    private final MontoyaApi api;
    private final Gson gson;

    public MessagePersistence(MontoyaApi api) {
        this.api = api;
        this.gson = new GsonBuilder().create();
    }

    /**
     * Serializable message format.
     * Burp HTTP objects cannot be serialized directly, so we store raw bytes.
     */
    public record PersistedMessage(
        String url,
        String method,
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

            if (job == null || job.request() == null || job.response() == null) {
                continue;
            }

            try {
                String requestBase64 = Base64.getEncoder().encodeToString(
                    job.request().toByteArray().getBytes()
                );
                String responseBase64 = Base64.getEncoder().encodeToString(
                    job.response().toByteArray().getBytes()
                );

                messages.add(new PersistedMessage(
                    job.url(),
                    job.request().method(),
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

                    HttpRequest request = HttpRequest.httpRequest(
                        ByteArray.byteArray(requestBytes)
                    );
                    HttpResponse response = HttpResponse.httpResponse(
                        ByteArray.byteArray(responseBytes)
                    );

                    jobs.add(new ScanJob(
                        request,
                        response,
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
