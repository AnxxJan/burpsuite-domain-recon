package burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.*;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TechnologyDetector {
    private MontoyaApi api;
    
    public TechnologyDetector(MontoyaApi api) {
        this.api = api;
        initializeSignatures();
    }
    
    // Technology signatures with version detection
    private Map<String, TechnologySignature> signatures = new HashMap<>();
    
    // Technology name constants
    private static final String TECH_APACHE = "Apache";
    private static final String TECH_LITESPEED = "LiteSpeed";
    private static final String TECH_WORDPRESS = "WordPress";
    private static final String TECH_DRUPAL = "Drupal";
    private static final String TECH_JOOMLA = "Joomla";
    private static final String TECH_PRESTASHOP = "PrestaShop";
    private static final String TECH_ASP_NET = "ASP.NET";
    private static final String TECH_PYTHON = "Python";
    private static final String TECH_EXPRESS = "Express";
    
    // Header name constants
    private static final String HEADER_SERVER = "Server";
    private static final String HEADER_X_POWERED_BY = "X-Powered-By";
    
    // Meta tag constants
    private static final String META_GENERATOR = "generator";
    
    // Category constants
    private static final String CAT_WEB_SERVER = "Web Server";
    private static final String CAT_JS_FRAMEWORK = "JavaScript Framework";
    private static final String CAT_PROGRAMMING_LANG = "Programming Language";
    private static final String CAT_WEB_FRAMEWORK = "Web Framework";
    
    /**
     * Initialize technology signatures with version patterns (Wappalyzer-style)
     */
    private void initializeSignatures() {
        // Web Servers with version detection
        signatures.put(TECH_APACHE, new TechnologySignature(TECH_APACHE)
            .addHeaderWithVersion(HEADER_SERVER, TECH_APACHE, "Apache/([\\d.]+)")
            .setCategory(CAT_WEB_SERVER));
        
        signatures.put("Nginx", new TechnologySignature("Nginx")
            .addHeaderWithVersion(HEADER_SERVER, "nginx", "nginx/([\\d.]+)")
            .setCategory(CAT_WEB_SERVER));
        
        signatures.put("IIS", new TechnologySignature("IIS")
            .addHeaderWithVersion(HEADER_SERVER, "Microsoft-IIS", "Microsoft-IIS/([\\d.]+)")
            .setCategory(CAT_WEB_SERVER));
        
        signatures.put(TECH_LITESPEED, new TechnologySignature(TECH_LITESPEED)
            .addHeaderWithVersion(HEADER_SERVER, TECH_LITESPEED, "LiteSpeed/([\\d.]+)")
            .setCategory(CAT_WEB_SERVER));
        
        signatures.put("OpenResty", new TechnologySignature("OpenResty")
            .addHeaderWithVersion(HEADER_SERVER, "openresty", "openresty/([\\d.]+)")
            .setCategory(CAT_WEB_SERVER));
        
        // JavaScript Libraries with version detection
        signatures.put("jQuery", new TechnologySignature("jQuery")
            .addScriptWithVersion("jquery", "jquery[.-]([\\d.]+\\.?(min|slim)?)\\.js")
            .addHtmlPatternWithVersion("jQuery JavaScript Library", "jQuery JavaScript Library v([\\d.]+)")
            .addHtmlPatternWithVersion("jQuery v", "jQuery v([\\d.]+)")
            .setCategory("JavaScript Library"));
        
        signatures.put("Bootstrap", new TechnologySignature("Bootstrap")
            .addScriptWithVersion("bootstrap", "bootstrap[.-]([\\d.]+.*?)\\.js")
            .addHtmlPatternWithVersion("Bootstrap v", "Bootstrap v([\\d.]+)")
            .setCategory("CSS Framework"));
        
        signatures.put("React", new TechnologySignature("React")
            .addScriptWithVersion("react", "react[.-]([\\d.]+.*?)\\.js")
            .addHtmlPattern("data-reactroot")
            .addHtmlPattern("_reactRootContainer")
            .setCategory(CAT_JS_FRAMEWORK));
        
        signatures.put("Vue.js", new TechnologySignature("Vue.js")
            .addScriptWithVersion("vue", "vue[.-]([\\d.]+.*?)\\.js")
            .addHtmlPattern("data-v-")
            .setCategory(CAT_JS_FRAMEWORK));
        
        signatures.put("Angular", new TechnologySignature("Angular")
            .addScriptWithVersion("angular", "angular[.-]([\\d.]+.*?)\\.js")
            .addHtmlPatternWithVersion("ng-version", "ng-version=\"([\\d.]+)\"")
            .setCategory(CAT_JS_FRAMEWORK));
        
        // CMS with version detection
        signatures.put(TECH_WORDPRESS, new TechnologySignature(TECH_WORDPRESS)
            .addMetaWithVersion(META_GENERATOR, TECH_WORDPRESS, "WordPress ([\\d.]+)")
            .addScript("wp-content")
            .addHtmlPattern("/wp-content/")
            .addHtmlPatternWithVersion("wp-includes/js", "ver=([\\d.]+)")
            .setCategory("CMS"));
        
        signatures.put(TECH_DRUPAL, new TechnologySignature(TECH_DRUPAL)
            .addMetaWithVersion(META_GENERATOR, TECH_DRUPAL, "Drupal ([\\d.]+)")
            .addHtmlPattern("Drupal.settings")
            .setCategory("CMS"));
        
        signatures.put(TECH_JOOMLA, new TechnologySignature(TECH_JOOMLA)
            .addMetaWithVersion(META_GENERATOR, TECH_JOOMLA, "Joomla! ([\\d.]+)")
            .addScript("joomla")
            .setCategory("CMS"));
        
        signatures.put("Magento", new TechnologySignature("Magento")
            .addScript("mage/")
            .addScript("skin/frontend")
            .addCookie("frontend")
            .setCategory("CMS/E-commerce"));
        
        signatures.put(TECH_PRESTASHOP, new TechnologySignature(TECH_PRESTASHOP)
            .addMetaWithVersion(META_GENERATOR, TECH_PRESTASHOP, "PrestaShop ([\\d.]+)")
            .addScript("prestashop")
            .setCategory("CMS/E-commerce"));
        
        // Programming Languages with version
        signatures.put("PHP", new TechnologySignature("PHP")
            .addHeaderWithVersion(HEADER_X_POWERED_BY, "PHP", "PHP/([\\d.]+)")
            .addCookie("PHPSESSID")
            .setCategory(CAT_PROGRAMMING_LANG));
        
        signatures.put(TECH_ASP_NET, new TechnologySignature(TECH_ASP_NET)
            .addHeaderWithVersion("X-AspNet-Version", "", "([\\d.]+)")
            .addHeader(HEADER_X_POWERED_BY, TECH_ASP_NET)
            .addCookie("ASP.NET_SessionId")
            .setCategory(CAT_PROGRAMMING_LANG));
        
        signatures.put(TECH_PYTHON, new TechnologySignature(TECH_PYTHON)
            .addHeaderWithVersion(HEADER_SERVER, TECH_PYTHON, "Python/([\\d.]+)")
            .setCategory(CAT_PROGRAMMING_LANG));
        
        signatures.put("Node.js", new TechnologySignature("Node.js")
            .addHeader(HEADER_X_POWERED_BY, TECH_EXPRESS)
            .setCategory(CAT_PROGRAMMING_LANG));
        
        // Web Frameworks with version
        signatures.put("Laravel", new TechnologySignature("Laravel")
            .addCookie("laravel_session")
            .addCookie("XSRF-TOKEN")
            .setCategory(CAT_WEB_FRAMEWORK));
        
        signatures.put("Django", new TechnologySignature("Django")
            .addCookie("csrftoken")
            .addCookie("sessionid")
            .setCategory(CAT_WEB_FRAMEWORK));
        
        signatures.put(TECH_EXPRESS, new TechnologySignature(TECH_EXPRESS)
            .addHeader(HEADER_X_POWERED_BY, TECH_EXPRESS)
            .setCategory(CAT_WEB_FRAMEWORK));
        
        signatures.put("Spring Framework", new TechnologySignature("Spring")
            .addCookie("JSESSIONID")
            .addHeader("X-Application-Context")
            .setCategory(CAT_WEB_FRAMEWORK));
        
        signatures.put("Ruby on Rails", new TechnologySignature("Rails")
            .addCookie("_rails_session")
            .addHeader(HEADER_X_POWERED_BY, "Phusion Passenger")
            .setCategory(CAT_WEB_FRAMEWORK));
        
        // Analytics & Marketing
        signatures.put("Google Analytics", new TechnologySignature("Google Analytics")
            .addScriptWithVersion("google-analytics.com", "analytics\\.js")
            .addScriptWithVersion("googletagmanager.com/gtag", "gtag/js\\?id=")
            .setCategory("Analytics"));
        
        signatures.put("Google Tag Manager", new TechnologySignature("Google Tag Manager")
            .addScript("googletagmanager.com")
            .setCategory("Tag Manager"));
        
        signatures.put("Facebook Pixel", new TechnologySignature("Facebook Pixel")
            .addScript("connect.facebook.net")
            .addHtmlPattern("fbq(")
            .setCategory("Analytics"));
        
        // CDN
        signatures.put("Cloudflare", new TechnologySignature("Cloudflare")
            .addHeader(HEADER_SERVER, "cloudflare")
            .addHeader("CF-Ray")
            .setCategory("CDN"));
        
        signatures.put("Akamai", new TechnologySignature("Akamai")
            .addHeader("X-Akamai")
            .setCategory("CDN"));
        
        signatures.put("Amazon CloudFront", new TechnologySignature("CloudFront")
            .addHeader("X-Amz-Cf-Id")
            .addHeader("Via", "CloudFront")
            .setCategory("CDN"));
        
        // Security
        signatures.put("reCAPTCHA", new TechnologySignature("reCAPTCHA")
            .addScript("recaptcha")
            .addScript("google.com/recaptcha")
            .setCategory("Security"));
        
        signatures.put("Wordfence", new TechnologySignature("Wordfence")
            .addScript("wordfence")
            .setCategory("Security"));
        
        // E-commerce
        signatures.put("Shopify", new TechnologySignature("Shopify")
            .addScript("cdn.shopify.com")
            .addHtmlPattern("Shopify.shop")
            .setCategory("E-commerce"));
        
        signatures.put("WooCommerce", new TechnologySignature("WooCommerce")
            .addScriptWithVersion("woocommerce", "woocommerce.*?ver=([\\d.]+)")
            .addHtmlPattern("woocommerce")
            .setCategory("E-commerce"));
        
        // Frontend Build Tools
        signatures.put("Webpack", new TechnologySignature("Webpack")
            .addHtmlPattern("webpackJsonp")
            .addScript("webpack")
            .setCategory("Build Tool"));
        
        signatures.put("Next.js", new TechnologySignature("Next.js")
            .addScript("_next/")
            .addHtmlPattern("__NEXT_DATA__")
            .setCategory("Framework"));
        
        signatures.put("Nuxt.js", new TechnologySignature("Nuxt.js")
            .addScript("_nuxt/")
            .addHtmlPattern("__NUXT__")
            .setCategory("Framework"));
    }
    
    
    /**
     * Detect technologies used by a domain
     */
    public TechnologyDetectionResult detectTechnologies(String domain) {
        api.logging().logToOutput("[*] Detecting technologies for: " + domain);
        
        TechnologyDetectionResult result = new TechnologyDetectionResult(domain);
        
        try {
            tryHttpsDetection(domain, result);
            
            if (!result.isSuccess()) {
                tryHttpDetection(domain, result);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error detecting technologies: " + e.getMessage());
            result.setSuccess(false);
            result.setError(e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Try technology detection using HTTPS
     */
    private TechnologyDetectionResult tryHttpsDetection(String domain, TechnologyDetectionResult result) {
        String url = "https://" + domain;
        return performDetection(url, result);
    }
    
    /**
     * Try technology detection using HTTP
     */
    private TechnologyDetectionResult tryHttpDetection(String domain, TechnologyDetectionResult result) {
        String url = "http://" + domain;
        return performDetection(url, result);
    }
    
    /**
     * Perform technology detection for given URL using Montoya API
     */
    private TechnologyDetectionResult performDetection(String url, TechnologyDetectionResult result) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                .withHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            
            HttpResponse response = api.http().sendRequest(request).response();
            String htmlContent = response.bodyToString();
            Document doc = Jsoup.parse(htmlContent);
            
            checkAllSignatures(result, response, doc, htmlContent);
            result.setSuccess(true);
                
        } catch (Exception e) {
            result.setSuccess(false);
            result.setError(e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Check all technology signatures
     */
    private void checkAllSignatures(TechnologyDetectionResult result, HttpResponse response, 
                                    Document doc, String htmlContent) {
        for (Map.Entry<String, TechnologySignature> entry : signatures.entrySet()) {
            String techName = entry.getKey();
            TechnologySignature signature = entry.getValue();
            
            String version = checkSignatureWithVersion(signature, response, doc, htmlContent);
            if (version != null) {
                String fullName = version.isEmpty() ? techName : techName + " " + version;
                result.addTechnology(fullName, signature.getCategory());
                api.logging().logToOutput("[+] Detected: " + fullName + " (" + signature.getCategory() + ")");
            }
        }
    }
    
    /**
     * Check if a technology signature matches and extract version if available
     * Returns version string if found, empty string if matched without version, null if not matched
     */
    private String checkSignatureWithVersion(TechnologySignature signature, HttpResponse response, 
                                             Document doc, String htmlContent) {
        StringBuilder detectedVersion = new StringBuilder();
        boolean matched = false;
        
        matched |= checkHeaderVersions(signature, response, detectedVersion);
        matched |= checkCookies(signature, response);
        matched |= checkMetaVersions(signature, doc, detectedVersion);
        matched |= checkScriptVersions(signature, doc, detectedVersion);
        matched |= checkHtmlVersions(signature, htmlContent, detectedVersion);
        
        return matched ? detectedVersion.toString() : null;
    }
    
    /**
     * Check headers with version patterns
     */
    private boolean checkHeaderVersions(TechnologySignature signature, HttpResponse response, 
                                       StringBuilder versionBuilder) {
        boolean matched = false;
        for (VersionPattern versionPattern : signature.getHeaderVersionPatterns()) {
            if (response.hasHeader(versionPattern.getHeaderName())) {
                String headerValue = response.headerValue(versionPattern.getHeaderName());
                if (versionPattern.getMatchPattern() == null || versionPattern.getMatchPattern().isEmpty() || 
                    headerValue.toLowerCase(Locale.ROOT).contains(versionPattern.getMatchPattern().toLowerCase(Locale.ROOT))) {
                    matched = true;
                    extractVersion(versionPattern, headerValue, versionBuilder);
                }
            }
        }
        return matched;
    }
    
    /**
     * Check cookies
     */
    private boolean checkCookies(TechnologySignature signature, HttpResponse response) {
        for (String cookieName : signature.getCookies()) {
            if (response.hasHeader("Set-Cookie")) {
                String cookieHeader = response.headerValue("Set-Cookie");
                if (cookieHeader.toLowerCase(Locale.ROOT).contains(cookieName.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Check meta tags with version
     */
    private boolean checkMetaVersions(TechnologySignature signature, Document doc, 
                                     StringBuilder versionBuilder) {
        boolean matched = false;
        for (VersionPattern versionPattern : signature.getMetaVersionPatterns()) {
            for (Element element : doc.select("meta[name=" + versionPattern.getHeaderName() + "]")) {
                String content = element.attr("content");
                if (versionPattern.getMatchPattern() == null || versionPattern.getMatchPattern().isEmpty() ||
                    content.toLowerCase(Locale.ROOT).contains(versionPattern.getMatchPattern().toLowerCase(Locale.ROOT))) {
                    matched = true;
                    extractVersion(versionPattern, content, versionBuilder);
                }
            }
        }
        return matched;
    }
    
    /**
     * Check scripts with version
     */
    private boolean checkScriptVersions(TechnologySignature signature, Document doc, 
                                       StringBuilder versionBuilder) {
        boolean matched = false;
        for (VersionPattern versionPattern : signature.getScriptVersionPatterns()) {
            for (Element script : doc.select("script[src]")) {
                String src = script.attr("src");
                if (src.toLowerCase(Locale.ROOT).contains(versionPattern.getMatchPattern().toLowerCase(Locale.ROOT))) {
                    matched = true;
                    extractVersion(versionPattern, src, versionBuilder);
                }
            }
        }
        return matched;
    }
    
    /**
     * Check HTML patterns with version
     */
    private boolean checkHtmlVersions(TechnologySignature signature, String htmlContent, 
                                     StringBuilder versionBuilder) {
        boolean matched = false;
        for (VersionPattern versionPattern : signature.getHtmlVersionPatterns()) {
            if (htmlContent.contains(versionPattern.getMatchPattern())) {
                matched = true;
                extractVersion(versionPattern, htmlContent, versionBuilder);
            }
        }
        return matched;
    }
    
    /**
     * Helper method to extract version from content using regex pattern
     */
    private void extractVersion(VersionPattern versionPattern, String content, StringBuilder versionBuilder) {
        if (versionPattern.getVersionRegex() != null && versionBuilder.isEmpty()) {
            Pattern pattern = Pattern.compile(versionPattern.getVersionRegex());
            Matcher matcher = pattern.matcher(content);
            if (matcher.find() && matcher.groupCount() > 0) {
                versionBuilder.append(matcher.group(1));
            }
        }
    }
    
    /**
     * Version pattern holder
     */
    private static class VersionPattern {
        private String headerName;  // For headers/metas
        private String matchPattern;  // Pattern to match
        private String versionRegex;  // Regex to extract version (with capture group)
        
        public VersionPattern(String matchPattern, String versionRegex) {
            this.matchPattern = matchPattern;
            this.versionRegex = versionRegex;
        }
        
        public VersionPattern(String headerName, String matchPattern, String versionRegex) {
            this.headerName = headerName;
            this.matchPattern = matchPattern;
            this.versionRegex = versionRegex;
        }
        
        public String getHeaderName() { return headerName; }
        public String getMatchPattern() { return matchPattern; }
        public String getVersionRegex() { return versionRegex; }
    }
    
    /**
     * Technology signature class with version detection support
     */
    private static class TechnologySignature {
        private String category;
        private List<VersionPattern> headerVersionPatterns = new ArrayList<>();
        private List<String> cookies = new ArrayList<>();
        private List<VersionPattern> metaVersionPatterns = new ArrayList<>();
        private List<VersionPattern> scriptVersionPatterns = new ArrayList<>();
        private List<VersionPattern> htmlVersionPatterns = new ArrayList<>();
        
        public TechnologySignature(String name) {
            // Name is only used for identification in the map, not stored
        }
        
        public TechnologySignature setCategory(String category) {
            this.category = category;
            return this;
        }
        
        public TechnologySignature addHeaderWithVersion(String headerName, String matchPattern, String versionRegex) {
            headerVersionPatterns.add(new VersionPattern(headerName, matchPattern, versionRegex));
            return this;
        }
        
        public TechnologySignature addHeader(String headerName, String matchPattern) {
            headerVersionPatterns.add(new VersionPattern(headerName, matchPattern, null));
            return this;
        }
        
        public TechnologySignature addHeader(String headerName) {
            headerVersionPatterns.add(new VersionPattern(headerName, "", null));
            return this;
        }
        
        public TechnologySignature addCookie(String name) {
            cookies.add(name);
            return this;
        }
        
        public TechnologySignature addMetaWithVersion(String metaName, String matchPattern, String versionRegex) {
            metaVersionPatterns.add(new VersionPattern(metaName, matchPattern, versionRegex));
            return this;
        }
        
        public TechnologySignature addScriptWithVersion(String matchPattern, String versionRegex) {
            scriptVersionPatterns.add(new VersionPattern(matchPattern, versionRegex));
            return this;
        }
        
        public TechnologySignature addScript(String matchPattern) {
            scriptVersionPatterns.add(new VersionPattern(matchPattern, null));
            return this;
        }
        
        public TechnologySignature addHtmlPatternWithVersion(String matchPattern, String versionRegex) {
            htmlVersionPatterns.add(new VersionPattern(matchPattern, versionRegex));
            return this;
        }
        
        public TechnologySignature addHtmlPattern(String matchPattern) {
            htmlVersionPatterns.add(new VersionPattern(matchPattern, null));
            return this;
        }
        
        public String getCategory() { return category; }
        public List<VersionPattern> getHeaderVersionPatterns() { return headerVersionPatterns; }
        public List<String> getCookies() { return cookies; }
        public List<VersionPattern> getMetaVersionPatterns() { return metaVersionPatterns; }
        public List<VersionPattern> getScriptVersionPatterns() { return scriptVersionPatterns; }
        public List<VersionPattern> getHtmlVersionPatterns() { return htmlVersionPatterns; }
    }
    
    /**
     * Technology detection result class
     */
    public static class TechnologyDetectionResult {
        private String domain;
        private boolean success;
        private String error;
        private Map<String, String> technologies = new HashMap<>(); // name -> category
        
        public TechnologyDetectionResult(String domain) {
            this.domain = domain;
        }
        
        public void addTechnology(String name, String category) {
            technologies.put(name, category);
        }
        
        public String getDomain() { return domain; }
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        public Map<String, String> getTechnologies() { return technologies; }
        
        public String getSummary() {
            if (!success) {
                return "Error: " + error;
            }
            return technologies.size() + " technologies detected";
        }
        
        public Map<String, List<String>> getTechnologiesByCategory() {
            Map<String, List<String>> byCategory = new HashMap<>();
            
            for (Map.Entry<String, String> entry : technologies.entrySet()) {
                String tech = entry.getKey();
                String category = entry.getValue();
                
                byCategory.computeIfAbsent(category, k -> new ArrayList<>()).add(tech);
            }
            
            return byCategory;
        }
    }
}
