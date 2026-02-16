package com.praetorian.titus.burp;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Native process-based Titus scanner.
 *
 * Spawns a titus serve subprocess and communicates via NDJSON over stdin/stdout.
 * Process is spawned once and reused for all scans.
 */
public class TitusProcessScanner implements AutoCloseable {

    private static final Gson GSON = new Gson();
    private static final long READY_TIMEOUT_MS = 30000; // 30 seconds for rule loading

    private Process process;
    private BufferedWriter stdin;
    private BufferedReader stdout;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private volatile String version = "unknown";

    /**
     * Create a new process-based scanner.
     *
     * @param titusPath Path to the titus binary
     * @throws IOException If process fails to start or initialize
     */
    public TitusProcessScanner(String titusPath) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(titusPath, "serve")
            .redirectErrorStream(false);

        this.process = pb.start();
        this.stdin = new BufferedWriter(
            new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
        this.stdout = new BufferedReader(
            new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));

        // Wait for ready signal with timeout
        long deadline = System.currentTimeMillis() + READY_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            if (!process.isAlive()) {
                throw new IOException("Process terminated unexpectedly");
            }

            if (stdout.ready()) {
                String line = stdout.readLine();
                if (line == null) {
                    throw new IOException("Unexpected end of output");
                }

                JsonObject ready = GSON.fromJson(line, JsonObject.class);
                if (ready.get("success").getAsBoolean() &&
                    "ready".equals(ready.get("type").getAsString())) {

                    if (ready.has("data")) {
                        JsonObject data = ready.getAsJsonObject("data");
                        if (data.has("version")) {
                            version = data.get("version").getAsString();
                        }
                    }

                    initialized.set(true);
                    return;
                }
            }

            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted waiting for ready signal");
            }
        }

        process.destroy();
        throw new IOException("Timeout waiting for ready signal");
    }

    /**
     * Scan content for secrets.
     *
     * @param content The content to scan
     * @param source  The source identifier (e.g., URL)
     * @return List of matches found
     * @throws IOException If communication fails
     */
    public synchronized List<Match> scan(String content, String source) throws IOException {
        ensureAlive();

        JsonObject payload = new JsonObject();
        payload.addProperty("content", content);
        payload.addProperty("source", source);

        JsonObject request = new JsonObject();
        request.addProperty("type", "scan");
        request.add("payload", payload);

        JsonObject response = sendRequest(request);
        return parseMatches(response.getAsJsonObject("data"));
    }

    /**
     * Batch scan multiple content items.
     *
     * @param items List of content items to scan
     * @return Map of source -> matches
     * @throws IOException If communication fails
     */
    public synchronized Map<String, List<Match>> scanBatch(List<ContentItem> items) throws IOException {
        ensureAlive();

        JsonArray itemsArray = new JsonArray();
        for (ContentItem item : items) {
            JsonObject itemObj = new JsonObject();
            itemObj.addProperty("source", item.source());
            itemObj.addProperty("content", item.content());
            itemsArray.add(itemObj);
        }

        JsonObject payload = new JsonObject();
        payload.add("items", itemsArray);

        JsonObject request = new JsonObject();
        request.addProperty("type", "scan_batch");
        request.add("payload", payload);

        JsonObject response = sendRequest(request);
        return parseBatchMatches(response.getAsJsonObject("data"));
    }

    public String getVersion() {
        return version;
    }

    public boolean isAlive() {
        return process != null && process.isAlive() && initialized.get() && !closed.get();
    }

    /**
     * Send a validation request and return the response.
     *
     * @param request The validation request JSON object
     * @return The response JSON object
     * @throws IOException If communication fails
     */
    public synchronized JsonObject sendValidateRequest(JsonObject request) throws IOException {
        ensureAlive();
        return sendRequest(request);
    }

    @Override
    public synchronized void close() {
        if (closed.getAndSet(true)) {
            return;
        }

        try {
            JsonObject request = new JsonObject();
            request.addProperty("type", "close");
            request.add("payload", new JsonObject());
            stdin.write(GSON.toJson(request));
            stdin.newLine();
            stdin.flush();
        } catch (Exception ignored) {
        }

        try {
            stdin.close();
        } catch (Exception ignored) {
        }

        try {
            stdout.close();
        } catch (Exception ignored) {
        }

        if (process != null) {
            process.destroy();
            try {
                process.waitFor(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                process.destroyForcibly();
            }
        }
    }

    private void ensureAlive() throws IOException {
        if (!isAlive()) {
            throw new IOException("Scanner process is not alive");
        }
    }

    private JsonObject sendRequest(JsonObject request) throws IOException {
        stdin.write(GSON.toJson(request));
        stdin.newLine();
        stdin.flush();

        String responseLine = stdout.readLine();
        if (responseLine == null) {
            throw new IOException("Process terminated unexpectedly");
        }

        JsonObject response = GSON.fromJson(responseLine, JsonObject.class);
        if (!response.get("success").getAsBoolean()) {
            String error = response.has("error") ? response.get("error").getAsString() : "Unknown error";
            throw new IOException("Request failed: " + error);
        }

        return response;
    }

    private List<Match> parseMatches(JsonObject data) {
        List<Match> matches = new ArrayList<>();
        if (data.has("matches") && !data.get("matches").isJsonNull()) {
            JsonArray matchesArray = data.getAsJsonArray("matches");
            for (int i = 0; i < matchesArray.size(); i++) {
                matches.add(parseMatch(matchesArray.get(i).getAsJsonObject()));
            }
        }
        return matches;
    }

    private Map<String, List<Match>> parseBatchMatches(JsonObject data) {
        Map<String, List<Match>> matchesBySource = new HashMap<>();
        if (data.has("results") && !data.get("results").isJsonNull()) {
            JsonArray results = data.getAsJsonArray("results");
            for (int i = 0; i < results.size(); i++) {
                JsonObject result = results.get(i).getAsJsonObject();
                String source = result.has("source") ? result.get("source").getAsString() : "";
                List<Match> matches = new ArrayList<>();
                if (result.has("matches") && !result.get("matches").isJsonNull()) {
                    JsonArray matchesArray = result.getAsJsonArray("matches");
                    for (int j = 0; j < matchesArray.size(); j++) {
                        matches.add(parseMatch(matchesArray.get(j).getAsJsonObject()));
                    }
                }
                if (!matches.isEmpty()) {
                    matchesBySource.put(source, matches);
                }
            }
        }
        return matchesBySource;
    }

    private Match parseMatch(JsonObject m) {
        String ruleId = m.has("RuleID") ? m.get("RuleID").getAsString() : "";
        String ruleName = m.has("RuleName") ? m.get("RuleName").getAsString() : ruleId;
        String structuralId = m.has("StructuralID") ? m.get("StructuralID").getAsString() : "";

        String matchedContent = "";

        // Try to get content from Groups first (array of captured groups)
        if (m.has("Groups") && !m.get("Groups").isJsonNull()) {
            JsonArray groups = m.getAsJsonArray("Groups");
            if (groups.size() > 0) {
                try {
                    String base64 = groups.get(0).getAsString();
                    byte[] decoded = java.util.Base64.getDecoder().decode(base64);
                    matchedContent = new String(decoded, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    try {
                        matchedContent = groups.get(0).getAsString();
                    } catch (Exception e2) {
                        // Fall through to try Snippet
                    }
                }
            }
        }

        String snippet = "";
        if (m.has("Snippet") && !m.get("Snippet").isJsonNull()) {
            JsonObject snippetObj = m.getAsJsonObject("Snippet");
            if (snippetObj.has("Matching") && !snippetObj.get("Matching").isJsonNull()) {
                String snippetMatchingRaw = snippetObj.get("Matching").getAsString();
                // Snippet.Matching is base64 encoded - decode it
                try {
                    byte[] decoded = java.util.Base64.getDecoder().decode(snippetMatchingRaw);
                    snippet = new String(decoded, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    // If not valid base64, use as-is
                    snippet = snippetMatchingRaw;
                }
            }
        }

        // If Groups was null/empty, fall back to Snippet.Matching for the secret content
        if (matchedContent.isEmpty() && !snippet.isEmpty()) {
            matchedContent = snippet;
        }

        int startOffset = 0, endOffset = 0, line = 0, column = 0;
        if (m.has("Location") && !m.get("Location").isJsonNull()) {
            JsonObject loc = m.getAsJsonObject("Location");
            if (loc.has("Offset") && !loc.get("Offset").isJsonNull()) {
                JsonObject offset = loc.getAsJsonObject("Offset");
                startOffset = offset.has("Start") ? offset.get("Start").getAsInt() : 0;
                endOffset = offset.has("End") ? offset.get("End").getAsInt() : 0;
            }
            if (loc.has("Source") && !loc.get("Source").isJsonNull()) {
                JsonObject source = loc.getAsJsonObject("Source");
                if (source.has("Start") && !source.get("Start").isJsonNull()) {
                    JsonObject start = source.getAsJsonObject("Start");
                    line = start.has("Line") ? start.get("Line").getAsInt() : 0;
                    column = start.has("Column") ? start.get("Column").getAsInt() : 0;
                }
            }
        }

        return new Match(ruleId, ruleName, structuralId, matchedContent, snippet,
                         startOffset, endOffset, line, column);
    }

    public record ContentItem(String source, String content) {}

    public record Match(
        String ruleId, String ruleName, String structuralId,
        String matchedContent, String snippet,
        int startOffset, int endOffset, int line, int column
    ) {
        /**
         * Returns the full secret content.
         */
        public String preview() {
            if (matchedContent == null || matchedContent.isEmpty()) return "[no content]";
            return matchedContent;
        }
    }
}
