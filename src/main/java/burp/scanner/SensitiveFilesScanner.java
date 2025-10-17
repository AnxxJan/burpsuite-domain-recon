package burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Sensitive Files and Directories Scanner
 * Quick discovery of exposed sensitive files and directories
 */
public class SensitiveFilesScanner {
    
    private MontoyaApi api;
    
    // Custom paths loaded from dictionary file
    private List<String> customPaths = new ArrayList<>();
    private AtomicBoolean shouldStop = new AtomicBoolean(false);
    
    public SensitiveFilesScanner(MontoyaApi api) {
        this.api = api;
    }
    
    public void setShouldStop(AtomicBoolean shouldStop) {
        this.shouldStop = shouldStop;
    }
    
    // Wordlist of sensitive files and directories (compact for fast scanning)
    private static final String[] SENSITIVE_PATHS = {
        // Version control
        "/.git/",
        "/.git/config",
        "/.git/HEAD",
        "/.svn/",
        "/.hg/",
        
        // Configuration files
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config.php",
        "/configuration.php",
        "/wp-config.php",
        "/web.config",
        "/app.config",
        "/.htaccess",
        "/.htpasswd",
        
        // Database files
        "/backup.sql",
        "/dump.sql",
        "/database.sql",
        "/db.sql",
        "/mysql.sql",
        "/backup.zip",
        "/backup.tar.gz",
        
        // Admin interfaces
        "/admin/",
        "/administrator/",
        "/admin.php",
        "/admin/login.php",
        "/wp-admin/",
        "/phpmyadmin/",
        "/phpMyAdmin/",
        "/adminer.php",
        
        // Development files
        "/dev/",
        "/test/",
        "/debug/",
        "/.vscode/",
        "/.idea/",
        "/composer.json",
        "/package.json",
        "/composer.lock",
        "/package-lock.json",
        "/node_modules/",
        
        // Log files
        "/error.log",
        "/access.log",
        "/debug.log",
        "/app.log",
        
        // Info disclosure
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/.DS_Store",
        "/robots.txt",
        "/sitemap.xml",
        "/README.md",
        "/license.txt",
        
        // Backup files
        "/backup/",
        "/backups/",
        "/old/",
        "/.bak",
        "/index.php.bak"
    };
    
    /**
     * Load custom dictionary from a file
     * @param dictionaryPath Path to the dictionary file (one path per line)
     */
    public void loadCustomDictionary(String dictionaryPath) {
        customPaths.clear();
        
        if (dictionaryPath == null || dictionaryPath.trim().isEmpty()) {
            return;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(dictionaryPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                // Skip empty lines and comments
                if (!line.isEmpty() && !line.startsWith("#")) {
                    // Ensure path starts with /
                    StringBuilder pathBuilder = new StringBuilder();
                    if (!line.startsWith("/")) {
                        pathBuilder.append("/");
                    }
                    pathBuilder.append(line);
                    customPaths.add(pathBuilder.toString());
                }
            }
        } catch (IOException e) {
            api.logging().logToError("Error loading custom dictionary: " + e.getMessage());
        }
    }
    
    /**
     * Clear custom dictionary
     */
    public void clearCustomDictionary() {
        customPaths.clear();
    }
    
    public SensitiveFilesInfo scanSensitiveFiles(String domain) {
        SensitiveFilesInfo info = new SensitiveFilesInfo(domain);
        
        if (shouldStop.get()) {
            return info;
        }
        
        try {
            // First, get baseline response from domain root to detect false positives
            FileCheckResult baselineResult = checkFile("https://" + domain + "/nonexistent-baseline-test-" + System.currentTimeMillis());
            
            // Combine default and custom paths
            List<String> allPaths = new ArrayList<>();
            allPaths.addAll(Arrays.asList(SENSITIVE_PATHS));
            
            // Track if we're using custom dictionary
            boolean usingCustomDict = !customPaths.isEmpty();
            if (usingCustomDict) {
                info.setUsingCustomDictionary(true);
            }
            allPaths.addAll(customPaths);
            
            for (String path : allPaths) {
                if (shouldStop.get()) {
                    break;
                }
                
                String urlString = "https://" + domain + path;
                
                // Use Burp's proxy to make the request
                FileCheckResult result = checkFile(urlString);
                
                if (result.isExists() && !isFalsePositive(result, baselineResult)) {
                    info.addExposedFile(path, result);
                }
            }
            
        } catch (Exception e) {
            info.addFinding("Sensitive Files Check Failed",
                "Could not complete sensitive files check: " + e.getMessage(),
                "Low");
        }
        
        return info;
    }
    
    private FileCheckResult checkFile(String urlString) {
        try {
            // Build HEAD request using Montoya API
            HttpRequest request = HttpRequest.httpRequestFromUrl(urlString)
                .withMethod("HEAD")
                .withAddedHeader("User-Agent", "Mozilla/5.0");
            
            // Make request through Burp's proxy
            HttpResponse response = api.http().sendRequest(request).response();
            
            if (response == null) {
                return new FileCheckResult(0, false, 0, null);
            }
            
            // Get status code
            int statusCode = response.statusCode();
            
            // Get content length from headers
            long contentLength = parseContentLength(response);
            
            // Only accept 200 OK (file directly accessible)
            // Exclude redirects (301, 302, 303, 307, 308) as they don't indicate exposed files
            boolean exists = (statusCode == 200);
            
            // No size filtering - we'll use size comparison with baseline for false positive detection
            
            return new FileCheckResult(statusCode, exists, contentLength, exists ? response : null);
            
        } catch (Exception e) {
            api.logging().logToError("Error checking file: " + e.getMessage());
            return new FileCheckResult(0, false, 0, null);
        }
    }
    
    /**
     * Parse content length from response header
     */
    private long parseContentLength(HttpResponse response) {
        String contentLengthHeader = response.headerValue("Content-Length");
        if (contentLengthHeader != null) {
            try {
                return Long.parseLong(contentLengthHeader);
            } catch (NumberFormatException e) {
                return 0;
            }
        }
        return 0;
    }
    
    /**
     * Detect false positives by comparing with baseline response
     * If the status code and content length match the baseline (404 page or default error),
     * it's likely a false positive
     */
    private boolean isFalsePositive(FileCheckResult result, FileCheckResult baseline) {
        // If baseline check failed, can't determine false positive
        if (baseline == null || baseline.getStatusCode() == 0) {
            return false;
        }
        
        // If both have the same status code AND similar content length, likely false positive
        if (result.getStatusCode() == baseline.getStatusCode()) {
            long resultSize = result.getContentLength();
            long baselineSize = baseline.getContentLength();
            
            // If both are exactly the same size, definitely a false positive
            if (resultSize == baselineSize && resultSize > 0) {
                return true;
            }
            
            // If sizes are within 5% of each other, likely the same page
            if (baselineSize > 0 && resultSize > 0) {
                double difference = Math.abs(resultSize - baselineSize);
                double percentDiff = (difference / baselineSize) * 100;
                if (percentDiff < 5.0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Sensitive files information container
     */
    public static class SensitiveFilesInfo {
        private String domain;
        private Map<String, FileCheckResult> exposedFiles;
        private List<SecurityFinding> findings;
        private boolean usingCustomDictionary = false;
        
        public SensitiveFilesInfo(String domain) {
            this.domain = domain;
            this.exposedFiles = new HashMap<>();
            this.findings = new ArrayList<>();
        }
        
        public String getDomain() { return domain; }
        public Map<String, FileCheckResult> getExposedFiles() { return exposedFiles; }
        public List<SecurityFinding> getFindings() { return findings; }
        public boolean isUsingCustomDictionary() { return usingCustomDictionary; }
        
        public void setUsingCustomDictionary(boolean usingCustomDictionary) {
            this.usingCustomDictionary = usingCustomDictionary;
        }
        
        public void addExposedFile(String path, FileCheckResult result) {
            exposedFiles.put(path, result);
        }
        
        public void addFinding(String title, String description, String severity) {
            findings.add(new SecurityFinding(title, description, severity));
        }
    }
    
    /**
     * File check result
     */
    public static class FileCheckResult {
        private int statusCode;
        private boolean exists;
        private long contentLength;
        private HttpResponse response;
        
        public FileCheckResult(int statusCode, boolean exists, long contentLength, HttpResponse response) {
            this.statusCode = statusCode;
            this.exists = exists;
            this.contentLength = contentLength;
            this.response = response;
        }
        
        public int getStatusCode() { return statusCode; }
        public boolean isExists() { return exists; }
        public long getContentLength() { return contentLength; }
        public HttpResponse getResponse() { return response; }
    }
    
    /**
     * Security finding class
     */
    public static class SecurityFinding {
        private String title;
        private String description;
        private String severity;
        
        public SecurityFinding(String title, String description, String severity) {
            this.title = title;
            this.description = description;
            this.severity = severity;
        }
        
        public String getTitle() { return title; }
        public String getDescription() { return description; }
        public String getSeverity() { return severity; }
    }
}
