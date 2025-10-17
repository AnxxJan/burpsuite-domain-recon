package burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WordPress Scanner - Detects WordPress installations and performs security analysis
 * All checks are performed locally without external API dependencies (100% FREE)
 */
public class WordPressScanner {
    
    private MontoyaApi api;
    
    // Protocol constants
    private static final String HTTPS_PREFIX = "https://";
    
    // Header constants
    private static final String USER_AGENT_HEADER = "User-Agent";
    private static final String USER_AGENT_MOZILLA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    
    // Version constants
    private static final String VERSION_UNKNOWN = "Unknown";
    
    // Severity constants
    private static final String SEVERITY_MEDIUM = "Medium";
    
    public WordPressScanner(MontoyaApi api) {
        this.api = api;
    }
    
    /**
     * Check if a domain is running WordPress
     */
    public boolean isWordPressSite(String domain) {
        try {
            String url = HTTPS_PREFIX + domain;
            HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_MOZILLA);
            
            HttpResponse response = api.http().sendRequest(request).response();
            String html = response.bodyToString();
            
            // Check for WordPress indicators
            return html.contains("wp-content") || 
                   html.contains("wp-includes") || 
                   html.contains("/wp-json/") ||
                   html.contains("wordpress");
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Perform WordPress scan with selected modules
     */
    public WordPressInfo scanWordPress(String domain, Set<ScanModule> enabledModules) {
        WordPressInfo info = new WordPressInfo(domain);
        
        if (!isWordPressSite(domain)) {
            info.setWordPress(false);
            return info;
        }
        
        info.setWordPress(true);
        
        // Execute enabled scan modules
        if (enabledModules.contains(ScanModule.VERSION_DETECTION)) {
            detectWordPressVersion(domain, info);
        }
        
        if (enabledModules.contains(ScanModule.THEME_DETECTION)) {
            detectTheme(domain, info);
        }
        
        if (enabledModules.contains(ScanModule.PLUGIN_ENUMERATION)) {
            enumeratePlugins(domain, info);
        }
        
        if (enabledModules.contains(ScanModule.USER_ENUMERATION)) {
            enumerateUsers(domain, info);
        }
        
        if (enabledModules.contains(ScanModule.SECURITY_ISSUES)) {
            checkSecurityIssues(domain, info);
        }
        
        if (enabledModules.contains(ScanModule.CONFIG_BACKUP_CHECK)) {
            checkConfigBackups(domain, info);
        }
        
        return info;
    }
    
    /**
     * Detect WordPress version
     */
    private void detectWordPressVersion(String domain, WordPressInfo info) {
        try {
            String url = HTTPS_PREFIX + domain;
            HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                    .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_MOZILLA);
            
            HttpResponse response = api.http().sendRequest(request).response();
            String html = response.bodyToString();
            Document doc = Jsoup.parse(html);
            
            // Check meta generator tag
            Elements metaTags = doc.select("meta[name=generator]");
            for (Element meta : metaTags) {
                String content = meta.attr("content");
                if (content.contains("WordPress")) {
                    Pattern versionPattern = Pattern.compile("WordPress\\s+([\\d.]+)");
                    Matcher matcher = versionPattern.matcher(content);
                    if (matcher.find()) {
                        info.setVersion(matcher.group(1));
                        return;
                    }
                }
            }
            
            // Try readme.html
            String readmeUrl = HTTPS_PREFIX + domain + "/readme.html";
            HttpRequest readmeRequest = HttpRequest.httpRequestFromUrl(readmeUrl);
            try {
                HttpResponse readmeResponse = api.http().sendRequest(readmeRequest).response();
                String readmeHtml = readmeResponse.bodyToString();
                Pattern versionPattern = Pattern.compile("Version\\s+([\\d.]+)");
                Matcher matcher = versionPattern.matcher(readmeHtml);
                if (matcher.find()) {
                    info.setVersion(matcher.group(1));
                    info.addFinding("readme.html", "Exposed readme.html file reveals WordPress version", "Low");
                }
            } catch (Exception e) {
                // readme.html not accessible - this is expected
                api.logging().logToOutput("readme.html not accessible: " + e.getMessage());
            }
        } catch (Exception e) {
            // Version detection failed - this is expected
            api.logging().logToOutput("WordPress version detection failed: " + e.getMessage());
        }
    }
    
    /**
     * Detect active theme
     */
    private void detectTheme(String domain, WordPressInfo info) {
        try {
            String url = HTTPS_PREFIX + domain;
            HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                    .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_MOZILLA);
            
            HttpResponse response = api.http().sendRequest(request).response();
            String html = response.bodyToString();
            Document doc = Jsoup.parse(html);
            
            // Look for theme references in HTML
            Elements links = doc.select("link[href*=/wp-content/themes/]");
            Set<String> themes = new HashSet<>();
            
            for (Element link : links) {
                String href = link.attr("href");
                Pattern themePattern = Pattern.compile("/wp-content/themes/([^/]+)");
                Matcher matcher = themePattern.matcher(href);
                if (matcher.find()) {
                    themes.add(matcher.group(1));
                }
            }
            
            // Detect version for each theme
            for (String theme : themes) {
                String version = detectThemeVersion(domain, theme);
                info.addTheme(theme, version);
            }
        } catch (Exception e) {
            // Theme detection failed - this is expected
            api.logging().logToOutput("WordPress theme detection failed: " + e.getMessage());
        }
    }
    
    /**
     * Detect theme version from style.css
     */
    private String detectThemeVersion(String domain, String themeName) {
        try {
            String styleUrl = HTTPS_PREFIX + domain + "/wp-content/themes/" + themeName + "/style.css";
            HttpRequest request = HttpRequest.httpRequestFromUrl(styleUrl);
            
            HttpResponse response = api.http().sendRequest(request).response();
            if (response.statusCode() == 200) {
                String css = response.bodyToString();
                Pattern versionPattern = Pattern.compile("Version:\\s*([\\d.]+)");
                Matcher matcher = versionPattern.matcher(css);
                if (matcher.find()) {
                    return matcher.group(1);
                }
            }
        } catch (Exception e) {
            // Version detection failed - this is expected
            api.logging().logToOutput("Theme version detection failed for " + themeName + ": " + e.getMessage());
        }
        return VERSION_UNKNOWN;
    }
    
    /**
     * Enumerate installed plugins
     */
    private void enumeratePlugins(String domain, WordPressInfo info) {
        try {
            String url = HTTPS_PREFIX + domain;
            HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                    .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_MOZILLA);
            
            HttpResponse response = api.http().sendRequest(request).response();
            String html = response.bodyToString();
            Document doc = Jsoup.parse(html);
            
            // Look for plugin references in HTML
            Elements links = doc.select("link[href*=/wp-content/plugins/], script[src*=/wp-content/plugins/]");
            Set<String> plugins = new HashSet<>();
            
            for (Element element : links) {
                String attr = element.hasAttr("href") ? element.attr("href") : element.attr("src");
                Pattern pluginPattern = Pattern.compile("/wp-content/plugins/([^/]+)");
                Matcher matcher = pluginPattern.matcher(attr);
                if (matcher.find()) {
                    plugins.add(matcher.group(1));
                }
            }
            
            // Detect version for each plugin
            for (String plugin : plugins) {
                String version = detectPluginVersion(domain, plugin);
                info.addPlugin(plugin, version);
            }
        } catch (Exception e) {
            // Plugin enumeration failed - this is expected
            api.logging().logToOutput("WordPress plugin enumeration failed: " + e.getMessage());
        }
    }
    
    /**
     * Detect plugin version from readme.txt
     */
    private String detectPluginVersion(String domain, String pluginName) {
        try {
            String readmeUrl = HTTPS_PREFIX + domain + "/wp-content/plugins/" + pluginName + "/readme.txt";
            HttpRequest request = HttpRequest.httpRequestFromUrl(readmeUrl);
            
            HttpResponse response = api.http().sendRequest(request).response();
            if (response.statusCode() == 200) {
                String readme = response.bodyToString();
                Pattern versionPattern = Pattern.compile("Stable tag:\\s*([\\d.]+)");
                Matcher matcher = versionPattern.matcher(readme);
                if (matcher.find()) {
                    return matcher.group(1);
                }
            }
        } catch (Exception e) {
            // Version detection failed - this is expected
            api.logging().logToOutput("Plugin version detection failed for " + pluginName + ": " + e.getMessage());
        }
        return VERSION_UNKNOWN;
    }
    
    /**
     * Enumerate WordPress users via REST API
     */
    private void enumerateUsers(String domain, WordPressInfo info) {
        try {
            String apiUrl = HTTPS_PREFIX + domain + "/wp-json/wp/v2/users";
            HttpRequest request = HttpRequest.httpRequestFromUrl(apiUrl)
                    .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_MOZILLA);
            
            HttpResponse response = api.http().sendRequest(request).response();
            if (response.statusCode() == 200) {
                String json = response.bodyToString();
                
                // Parse user information
                Pattern namePattern = Pattern.compile("\"name\":\"([^\"]+)\"");
                Pattern slugPattern = Pattern.compile("\"slug\":\"([^\"]+)\"");
                
                Matcher nameMatcher = namePattern.matcher(json);
                Matcher slugMatcher = slugPattern.matcher(json);
                
                Set<String> users = new HashSet<>();
                while (nameMatcher.find() && slugMatcher.find()) {
                    String name = nameMatcher.group(1);
                    String slug = slugMatcher.group(1);
                    users.add(slug + " (" + name + ")");
                }
                
                for (String user : users) {
                    info.addUser(user);
                }
                
                if (!users.isEmpty()) {
                    info.addFinding("User Enumeration", 
                        "WordPress REST API exposes " + users.size() + " user(s)", 
                        SEVERITY_MEDIUM);
                }
            }
        } catch (Exception e) {
            // User enumeration failed - this is expected
            api.logging().logToOutput("WordPress user enumeration failed: " + e.getMessage());
        }
    }
    
    /**
     * Check for common security issues and misconfigurations
     */
    private void checkSecurityIssues(String domain, WordPressInfo info) {
        try {
            
            // Check for outdated WordPress version
            if (info.getVersion() != null) {
                checkOutdatedVersion(info);
            }
            
            // Check for directory listing
            checkDirectoryListing(domain, info);
            
            // Check for xmlrpc.php
            checkXmlRpc(domain, info);
            
            // Check for debug mode
            checkDebugMode(domain, info);
            
            // Check for default admin username
            checkDefaultUsers(info);
            
            // Check for version disclosure
            checkVersionDisclosure(domain, info);
            
            // Check for wp-cron.php accessibility
            checkWpCron(domain, info);
            
        } catch (Exception e) {
            // Security checks failed - this is expected
            api.logging().logToOutput("WordPress security checks failed: " + e.getMessage());
        }
    }
    
    private void checkOutdatedVersion(WordPressInfo info) {
        try {
            String version = info.getVersion();
            String[] parts = version.split("\\.");
            if (parts.length >= 2) {
                int major = Integer.parseInt(parts[0]);
                int minor = Integer.parseInt(parts[1]);
                
                // WordPress 6.7 is the latest as of October 2025
                if (major < 6 || (major == 6 && minor < 6)) {
                    info.addFinding("Outdated WordPress Version",
                        "WordPress version " + version + " is outdated. Latest stable version is 6.7.x",
                        "High");
                } else if (major == 6 && minor < 7) {
                    info.addFinding("WordPress Version Behind",
                        "WordPress version " + version + " is not the latest. Consider updating to 6.7.x",
                        SEVERITY_MEDIUM);
                }
            }
        } catch (Exception e) {
            // Version checking failed - this is expected
            api.logging().logToOutput("WordPress version checking failed: " + e.getMessage());
        }
    }
    
    private void checkDirectoryListing(String domain, WordPressInfo info) {
        String[] paths = {
            "/wp-content/uploads/",
            "/wp-content/plugins/",
            "/wp-content/themes/"
        };
        
        for (String path : paths) {
            try {
                HttpRequest request = HttpRequest.httpRequestFromUrl(HTTPS_PREFIX + domain + path);
                HttpResponse response = api.http().sendRequest(request).response();
                String body = response.bodyToString();
                
                if (body.contains("Index of") || body.contains("Parent Directory")) {
                    info.addFinding("Directory Listing Enabled",
                        "Directory listing is enabled at " + path,
                        SEVERITY_MEDIUM);
                }
            } catch (Exception e) {
                // Continue checking other paths - this is expected
                api.logging().logToOutput("Directory listing check failed for " + path + ": " + e.getMessage());
            }
        }
    }
    
    private void checkXmlRpc(String domain, WordPressInfo info) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(HTTPS_PREFIX + domain + "/xmlrpc.php")
                    .withMethod("POST")
                    .withBody("<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>")
                    .withAddedHeader("Content-Type", "text/xml");
            
            HttpResponse response = api.http().sendRequest(request).response();
            String body = response.bodyToString();
            
            if (response.statusCode() == 200 && body.contains("methodResponse")) {
                info.addFinding("XML-RPC Enabled",
                    "XML-RPC is enabled and accessible at /xmlrpc.php",
                    SEVERITY_MEDIUM);
            }
        } catch (Exception e) {
            // XML-RPC check failed - this is expected
            api.logging().logToOutput("XML-RPC check failed: " + e.getMessage());
        }
    }
    
    private void checkDebugMode(String domain, WordPressInfo info) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(HTTPS_PREFIX + domain);
            HttpResponse response = api.http().sendRequest(request).response();
            String body = response.bodyToString();
            
            if (body.contains("WP_DEBUG") || body.contains("WordPress database error") || 
                body.contains("Fatal error in") || body.contains("Warning: ") ||
                body.contains("Notice: ") || body.contains("Deprecated: ")) {
                info.addFinding("Debug Mode Enabled",
                    "WordPress debug mode appears to be enabled, exposing sensitive information",
                    "High");
            }
        } catch (Exception e) {
            // Debug check failed - this is expected
            api.logging().logToOutput("Debug mode check failed: " + e.getMessage());
        }
    }
    
    private void checkDefaultUsers(WordPressInfo info) {
        String[] defaultUsernames = {"admin", "administrator", "root", "test", "demo", "wordpress"};
        
        for (String user : info.getUsers()) {
            String username = user.toLowerCase(Locale.ROOT).split("\\(")[0].trim();
            for (String defaultUser : defaultUsernames) {
                if (username.equals(defaultUser)) {
                    info.addFinding("Default Username Detected",
                        "Default username '" + username + "' is in use",
                        SEVERITY_MEDIUM);
                    break;
                }
            }
        }
    }
    
    private void checkVersionDisclosure(String domain, WordPressInfo info) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(HTTPS_PREFIX + domain);
            HttpResponse response = api.http().sendRequest(request).response();
            String body = response.bodyToString();
            
            if (body.contains("<meta name=\"generator\" content=\"WordPress")) {
                info.addFinding("WordPress Version Disclosure",
                    "WordPress version is exposed in HTML meta tag",
                    "Low");
            }
        } catch (Exception e) {
            // Version disclosure check failed - this is expected
            api.logging().logToOutput("Version disclosure check failed: " + e.getMessage());
        }
    }
    
    private void checkWpCron(String domain, WordPressInfo info) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(HTTPS_PREFIX + domain + "/wp-cron.php");
            HttpResponse response = api.http().sendRequest(request).response();
            if (response.statusCode() == 200) {
                info.addFinding("wp-cron.php Accessible",
                    "wp-cron.php is publicly accessible and could be abused for DoS",
                    "Low");
            }
        } catch (Exception e) {
            // wp-cron check failed - this is expected
            api.logging().logToOutput("wp-cron.php check failed: " + e.getMessage());
        }
    }
    
    /**
     * Check for exposed configuration and backup files
     */
    private void checkConfigBackups(String domain, WordPressInfo info) {
        try {
            String[] sensitiveFiles = {
                "/wp-config.php.bak",
                "/wp-config.php.old",
                "/wp-config.php.save",
                "/wp-config.php~",
                "/wp-config.bak",
                "/wp-config.old",
                "/.wp-config.php.swp",
                "/wp-config.php.txt",
                "/readme.html",
                "/license.txt",
                "/.htaccess"
            };
            
            for (String file : sensitiveFiles) {
                try {
                    String url = HTTPS_PREFIX + domain + file;
                    HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                            .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_MOZILLA);
                    
                    HttpResponse response = api.http().sendRequest(request).response();
                    if (response.statusCode() == 200) {
                        String severity = file.contains("wp-config") ? "High" : "Low";
                        info.addFinding("Sensitive File Exposed",
                            "Sensitive file accessible: " + file,
                            severity);
                    }
                } catch (Exception e) {
                    // File not accessible - this is expected, continue checking other files
                    api.logging().logToOutput("File check failed for " + file + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            // Config backup check failed - this is expected
            api.logging().logToOutput("Config backup check failed: " + e.getMessage());
        }
    }
    
    /**
     * Scan modules enum
     */
    public enum ScanModule {
        VERSION_DETECTION("Version Detection", "Detect WordPress core version"),
        THEME_DETECTION("Theme Detection", "Detect active theme and version"),
        PLUGIN_ENUMERATION("Plugin Enumeration", "Enumerate installed plugins"),
        USER_ENUMERATION("User Enumeration", "Enumerate WordPress users"),
        SECURITY_ISSUES("Security Issues", "Check for common security misconfigurations"),
        CONFIG_BACKUP_CHECK("Config & Backup Check", "Check for exposed configuration and backup files");
        
        private final String name;
        private final String description;
        
        ScanModule(String name, String description) {
            this.name = name;
            this.description = description;
        }
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * WordPress information container
     */
    public static class WordPressInfo {
        private String domain;
        private boolean isWordPress;
        private String version;
        private Map<String, String> themes;
        private Map<String, String> plugins;
        private List<String> users;
        private List<SecurityFinding> findings;
        
        public WordPressInfo(String domain) {
            this.domain = domain;
            this.isWordPress = false;
            this.themes = new HashMap<>();
            this.plugins = new HashMap<>();
            this.users = new ArrayList<>();
            this.findings = new ArrayList<>();
        }
        
        // Getters
        public String getDomain() { return domain; }
        public boolean isWordPress() { return isWordPress; }
        public String getVersion() { return version; }
        public Map<String, String> getThemes() { return themes; }
        public Map<String, String> getPlugins() { return plugins; }
        public List<String> getUsers() { return users; }
        public List<SecurityFinding> getFindings() { return findings; }
        
        // Setters
        public void setWordPress(boolean isWordPress) { this.isWordPress = isWordPress; }
        public void setVersion(String version) { this.version = version; }
        
        public void addTheme(String name, String version) {
            themes.put(name, version);
        }
        
        public void addPlugin(String name, String version) {
            plugins.put(name, version);
        }
        
        public void addUser(String user) {
            users.add(user);
        }
        
        public void addFinding(String title, String description, String severity) {
            findings.add(new SecurityFinding(title, description, severity));
        }
        
        public String getThemeVersion(String themeName) {
            return themes.getOrDefault(themeName, VERSION_UNKNOWN);
        }
        
        public String getPluginVersion(String pluginName) {
            return plugins.getOrDefault(pluginName, VERSION_UNKNOWN);
        }
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
