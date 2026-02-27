package com.praetorian.titus.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

/**
 * Titus Secret Scanner - Burp Suite Extension
 *
 * Scans HTTP response content for secrets using Titus (Go NoseyParker port).
 * Supports both passive (proxy listener) and active (context menu) scanning modes.
 */
public class TitusExtension implements BurpExtension {

    private MontoyaApi api;
    private ProcessManager processManager;
    private ScanQueue scanQueue;
    private DedupCache dedupCache;
    private IssueReporter issueReporter;
    private FastPathFilter fastPathFilter;
    private SeverityConfig severityConfig;
    private SettingsTab settingsTab;
    private BulkScanHandler bulkScanHandler;
    private ValidationManager validationManager;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("Titus Secret Scanner");
        api.logging().logToOutput("Titus Secret Scanner initializing...");

        try {
            String titusPath = findTitusBinary();
            api.logging().logToOutput("Found titus binary at: " + titusPath);

            this.processManager = new ProcessManager(api, titusPath);
            this.processManager.initialize();

            this.severityConfig = new SeverityConfig(api);
            this.dedupCache = new DedupCache(api);
            this.issueReporter = new IssueReporter(api, severityConfig);
            this.fastPathFilter = new FastPathFilter();

            // Use 4 workers - shared process across all workers
            this.scanQueue = new ScanQueue(api, dedupCache, issueReporter, processManager, 4);

            // Register HTTP handler for passive scanning
            api.http().registerHttpHandler(new TitusHttpHandler());

            // Register context menu for active scanning
            api.userInterface().registerContextMenuItemsProvider(new TitusContextMenuProvider());

            // Register settings tab
            this.settingsTab = new SettingsTab(api, severityConfig, scanQueue, dedupCache);
            api.userInterface().registerSuiteTab("Titus", settingsTab);

            // Initialize validation manager and wire up to settings tab
            this.validationManager = new ValidationManager(api, processManager, dedupCache);
            this.settingsTab.setValidationManager(validationManager);

            // Initialize bulk scan handler
            this.bulkScanHandler = new BulkScanHandler(api, scanQueue, fastPathFilter, dedupCache, settingsTab);

            // Register custom response editor for secrets tab
            api.userInterface().registerHttpResponseEditorProvider(
                new SecretEditorProvider(api, processManager, dedupCache)
            );

            api.logging().logToOutput("Titus Secret Scanner initialized successfully");
            api.logging().logToOutput("  - Titus version: " + processManager.getScanner().getVersion());
            api.logging().logToOutput("  - Passive scanning: ENABLED");
            api.logging().logToOutput("  - Active scanning: Right-click context menu");

        } catch (Exception e) {
            api.logging().logToError("Failed to initialize Titus: " + e.getMessage());
            e.printStackTrace();
        }

        // Register unload handler
        api.extension().registerUnloadingHandler(() -> {
            // Save messages before unload
            if (settingsTab != null) {
                settingsTab.saveMessages();
            }
            if (scanQueue != null) scanQueue.close();
            if (processManager != null) processManager.close();
        });
    }

    private String findTitusBinary() throws java.io.IOException {
        boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
        String exe = isWindows ? ".exe" : "";
        String home = System.getProperty("user.home");

        // Check common locations (platform-aware)
        String[] paths;
        if (isWindows) {
            paths = new String[] {
                home + "\\.titus\\titus" + exe,
                home + "\\bin\\titus" + exe,
                "titus" + exe // PATH lookup
            };
        } else {
            paths = new String[] {
                home + "/.titus/titus",
                home + "/bin/titus",
                "/usr/local/bin/titus",
                "titus" // PATH lookup
            };
        }

        for (String path : paths) {
            if (java.nio.file.Files.exists(java.nio.file.Path.of(path))) {
                return path;
            }
        }

        // Try to extract bundled binary
        return extractBundledBinary();
    }

    private String extractBundledBinary() throws java.io.IOException {
        boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
        String binaryName = isWindows ? "titus.exe" : "titus";
        String installPath = isWindows ? "%USERPROFILE%\\.titus\\titus.exe" : "~/.titus/titus";

        // Extract from JAR resources
        try (java.io.InputStream is = getClass().getResourceAsStream("/" + binaryName)) {
            if (is == null) {
                throw new java.io.IOException(
                    "Titus binary not found. Install it to " + installPath);
            }

            var tempDir = java.nio.file.Files.createTempDirectory("titus");
            var binaryPath = tempDir.resolve(binaryName);
            java.nio.file.Files.copy(is, binaryPath);
            binaryPath.toFile().setExecutable(true);

            return binaryPath.toString();
        }
    }

    /**
     * HTTP handler for passive scanning of proxy traffic.
     */
    private class TitusHttpHandler implements HttpHandler {

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            // Pass through - we don't modify requests
            return RequestToBeSentAction.continueWith(request);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            // Check if passive scanning is enabled
            if (settingsTab == null || !settingsTab.isPassiveScanEnabled()) {
                return ResponseReceivedAction.continueWith(response);
            }

            // Fast-path filter: skip non-scannable content
            if (!fastPathFilter.shouldScan(response)) {
                return ResponseReceivedAction.continueWith(response);
            }

            // Queue for scanning
            try {
                boolean scanRequest = settingsTab.isRequestScanEnabled();
                scanQueue.enqueue(new ScanJob(
                    response.initiatingRequest(),
                    response,
                    ScanJob.Source.PASSIVE,
                    scanRequest
                ));
            } catch (Exception e) {
                api.logging().logToError("Failed to queue response for scanning: " + e.getMessage());
            }

            return ResponseReceivedAction.continueWith(response);
        }
    }

    /**
     * Context menu provider for active scanning of selected items.
     */
    private class TitusContextMenuProvider implements ContextMenuItemsProvider {

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> menuItems = new ArrayList<>();

            // Get selected request/response pairs
            List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();

            if (!selectedItems.isEmpty()) {
                // Scan selected items
                JMenuItem scanItem = new JMenuItem("Scan with Titus (" + selectedItems.size() + " items)");
                scanItem.addActionListener(e -> scanSelectedItems(selectedItems));
                menuItems.add(scanItem);
            }

            // Always show bulk scan option
            JMenuItem bulkScanItem = new JMenuItem("Scan All In-Scope Responses");
            bulkScanItem.addActionListener(e -> bulkScanHandler.scanAllInScope());
            menuItems.add(bulkScanItem);

            return menuItems;
        }

        private void scanSelectedItems(List<HttpRequestResponse> items) {
            int queued = 0;
            boolean scanRequest = settingsTab != null && settingsTab.isRequestScanEnabled();

            for (HttpRequestResponse item : items) {
                if (item.response() == null) {
                    continue;
                }

                if (!fastPathFilter.shouldScan(item.response())) {
                    continue;
                }

                try {
                    scanQueue.enqueue(new ScanJob(
                        item.request(),
                        item.response(),
                        ScanJob.Source.ACTIVE,
                        scanRequest
                    ));
                    queued++;
                } catch (Exception e) {
                    api.logging().logToError("Failed to queue item for scanning: " + e.getMessage());
                }
            }

            api.logging().logToOutput("Queued " + queued + " items for Titus scanning");
        }
    }
}
