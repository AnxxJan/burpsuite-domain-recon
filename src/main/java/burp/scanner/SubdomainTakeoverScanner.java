package burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.Locale;

/**
 * Scanner to detect Subdomain Takeover vulnerabilities
 * 
 * This scanner identifies subdomains that may be vulnerable to takeover attacks
 * by checking for:
 * - CNAME records pointing to non-existent or unclaimed external services
 * - DNS records pointing to expired or available domains
 * - Common fingerprints of vulnerable services (GitHub Pages, AWS S3, Azure, etc.)
 */
public class SubdomainTakeoverScanner {
    
    private static final String HTTPS_PREFIX = "https://";
    private static final String HTTP_PREFIX = "http://";
    private static final String USER_AGENT_HEADER = "User-Agent";
    private static final String USER_AGENT_MOZILLA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    
    private final MontoyaApi api;
    
    // Vulnerable service fingerprints based on can-i-take-over-xyz
    private static final Map<String, ServiceFingerprint> VULNERABLE_SERVICES = new HashMap<>();
    
    static {
        // GitHub Pages
        VULNERABLE_SERVICES.put("github.io", new ServiceFingerprint(
            "GitHub Pages",
            Arrays.asList("There isn't a GitHub Pages site here", "404 - File not found"),
            Arrays.asList("github.io", "github.com"),
            "High"
        ));
        
        // AWS S3
        VULNERABLE_SERVICES.put("s3.amazonaws.com", new ServiceFingerprint(
            "AWS S3",
            Arrays.asList("NoSuchBucket", "The specified bucket does not exist"),
            Arrays.asList("s3.amazonaws.com", "s3-website"),
            "High"
        ));
        
        // Azure
        VULNERABLE_SERVICES.put("azurewebsites.net", new ServiceFingerprint(
            "Azure Web App",
            Arrays.asList("404 Web Site not found", "Error 404 - Web app not found"),
            Arrays.asList("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com"),
            "High"
        ));
        
        // Heroku
        VULNERABLE_SERVICES.put("herokuapp.com", new ServiceFingerprint(
            "Heroku",
            Arrays.asList("No such app", "There's nothing here, yet"),
            Arrays.asList("herokuapp.com", "herokussl.com"),
            "High"
        ));
        
        // AWS Elastic Beanstalk
        VULNERABLE_SERVICES.put("elasticbeanstalk.com", new ServiceFingerprint(
            "AWS Elastic Beanstalk",
            Arrays.asList("404 Not Found", "nginx"),
            Arrays.asList("elasticbeanstalk.com"),
            "Medium"
        ));
        
        // Shopify
        VULNERABLE_SERVICES.put("myshopify.com", new ServiceFingerprint(
            "Shopify",
            Arrays.asList("Sorry, this shop is currently unavailable", "Only one step left!"),
            Arrays.asList("myshopify.com"),
            "High"
        ));
        
        // Tumblr
        VULNERABLE_SERVICES.put("tumblr.com", new ServiceFingerprint(
            "Tumblr",
            Arrays.asList("There's nothing here", "Whatever you were looking for doesn't currently exist"),
            Arrays.asList("tumblr.com"),
            "Medium"
        ));
        
        // WordPress.com
        VULNERABLE_SERVICES.put("wordpress.com", new ServiceFingerprint(
            "WordPress.com",
            Arrays.asList("Do you want to register", "doesn't exist"),
            Arrays.asList("wordpress.com"),
            "Medium"
        ));
        
        // Bitbucket
        VULNERABLE_SERVICES.put("bitbucket.io", new ServiceFingerprint(
            "Bitbucket",
            Arrays.asList("Repository not found", "The page you have requested does not exist"),
            Arrays.asList("bitbucket.io"),
            "High"
        ));
        
        // Ghost
        VULNERABLE_SERVICES.put("ghost.io", new ServiceFingerprint(
            "Ghost",
            Arrays.asList("The thing you were looking for is no longer here"),
            Arrays.asList("ghost.io"),
            "Medium"
        ));
        
        // Fastly
        VULNERABLE_SERVICES.put("fastly.net", new ServiceFingerprint(
            "Fastly",
            Arrays.asList("Fastly error: unknown domain"),
            Arrays.asList("fastly.net"),
            "High"
        ));
        
        // Pantheon
        VULNERABLE_SERVICES.put("pantheonsite.io", new ServiceFingerprint(
            "Pantheon",
            Arrays.asList("404 error unknown site!"),
            Arrays.asList("pantheonsite.io"),
            "High"
        ));
        
        // Zendesk
        VULNERABLE_SERVICES.put("zendesk.com", new ServiceFingerprint(
            "Zendesk",
            Arrays.asList("Help Center Closed", "This help center no longer exists"),
            Arrays.asList("zendesk.com"),
            "Medium"
        ));
        
        // Desk
        VULNERABLE_SERVICES.put("desk.com", new ServiceFingerprint(
            "Desk.com",
            Arrays.asList("Please try again or try Desk.com free for 14 days"),
            Arrays.asList("desk.com"),
            "Medium"
        ));
    }
    
    public SubdomainTakeoverScanner(MontoyaApi api) {
        this.api = api;
    }
    
    /**
     * Scan a subdomain for potential takeover vulnerabilities
     */
    public TakeoverInfo scanSubdomain(String subdomain) {
        TakeoverInfo info = new TakeoverInfo(subdomain);
        
        try {
            // Check DNS resolution
            info.isDnsResolvable = checkDnsResolution(subdomain);
            
            // Check for CNAME records pointing to external services
            String cnameTarget = getCnameTarget(subdomain);
            if (cnameTarget != null && !cnameTarget.isEmpty()) {
                info.cnameTarget = cnameTarget;
                checkCnameVulnerability(subdomain, cnameTarget, info);
            }
            
            // Check HTTP/HTTPS responses for fingerprints
            checkHttpFingerprints(subdomain, info);
            
        } catch (Exception e) {
            api.logging().logToError("Error scanning subdomain for takeover: " + subdomain + " - " + e.getMessage());
        }
        
        return info;
    }
    
    /**
     * Check if DNS resolves for the subdomain
     */
    private boolean checkDnsResolution(String subdomain) {
        try {
            InetAddress.getByName(subdomain);
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }
    
    /**
     * Get CNAME target using DNS lookup
     */
    private String getCnameTarget(String subdomain) {
        try {
            // Try to resolve CNAME using InetAddress canonical hostname
            InetAddress addr = InetAddress.getByName(subdomain);
            String canonical = addr.getCanonicalHostName();
            
            // If canonical hostname is different and not just an IP, it's likely a CNAME
            if (!canonical.equals(subdomain) && !canonical.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                return canonical;
            }
        } catch (Exception e) {
            // DNS lookup failed
        }
        return null;
    }
    
    /**
     * Check if CNAME points to a vulnerable service
     */
    private void checkCnameVulnerability(String subdomain, String cnameTarget, TakeoverInfo info) {
        String lowerCname = cnameTarget.toLowerCase(Locale.ROOT);
        
        for (Map.Entry<String, ServiceFingerprint> entry : VULNERABLE_SERVICES.entrySet()) {
            ServiceFingerprint fingerprint = entry.getValue();
            
            // Check if CNAME matches any known vulnerable service pattern
            for (String pattern : fingerprint.cnamePatterns) {
                if (lowerCname.contains(pattern.toLowerCase(Locale.ROOT))) {
                    info.potentialService = fingerprint.serviceName;
                    info.cnameMatchesVulnerableService = true;
                    
                    // Add initial finding
                    info.addFinding(
                        "Potential Subdomain Takeover - CNAME to " + fingerprint.serviceName,
                        "Subdomain '" + subdomain + "' has a CNAME record pointing to '" + cnameTarget + 
                        "' which is a known vulnerable service provider. This could potentially be claimed by an attacker.",
                        "Medium"
                    );
                    break;
                }
            }
        }
    }
    
    /**
     * Check HTTP/HTTPS responses for takeover fingerprints
     */
    private void checkHttpFingerprints(String subdomain, TakeoverInfo info) {
        // Try HTTPS first, then HTTP
        String[] protocols = {HTTPS_PREFIX, HTTP_PREFIX};
        
        for (String protocol : protocols) {
            try {
                String url = protocol + subdomain;
                HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                        .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_MOZILLA);
                
                HttpResponse response = api.http().sendRequest(request).response();
                
                if (response != null) {
                    info.httpStatusCode = response.statusCode();
                    String body = response.bodyToString();
                    
                    // Check response against known fingerprints
                    checkResponseForFingerprints(subdomain, body, response.statusCode(), info);
                    
                    break; // Successfully got a response, no need to try other protocol
                }
            } catch (Exception e) {
                // Connection failed, continue to next protocol
                api.logging().logToOutput("Failed to check " + protocol + subdomain + ": " + e.getMessage());
            }
        }
    }
    
    /**
     * Check HTTP response body for known vulnerable service fingerprints
     */
    private void checkResponseForFingerprints(String subdomain, String body, int statusCode, TakeoverInfo info) {
        for (Map.Entry<String, ServiceFingerprint> entry : VULNERABLE_SERVICES.entrySet()) {
            ServiceFingerprint fingerprint = entry.getValue();
            
            // Check if response contains any of the vulnerability fingerprints
            for (String pattern : fingerprint.responsePatterns) {
                if (body.contains(pattern)) {
                    info.isVulnerable = true;
                    info.detectedService = fingerprint.serviceName;
                    
                    info.addFinding(
                        "Subdomain Takeover Vulnerability Detected - " + fingerprint.serviceName,
                        "Subdomain '" + subdomain + "' appears to be vulnerable to takeover attack. " +
                        "The service returned HTTP " + statusCode + " with fingerprint: '" + pattern + "'. " +
                        "This subdomain may be claimable by an attacker on " + fingerprint.serviceName + ".",
                        fingerprint.severity
                    );
                    
                    api.logging().logToOutput("⚠️ SUBDOMAIN TAKEOVER DETECTED: " + subdomain + 
                                            " -> " + fingerprint.serviceName);
                    return;
                }
            }
        }
        
        // Check for NXDOMAIN-like responses
        if (statusCode == 404 && info.cnameMatchesVulnerableService) {
            info.isVulnerable = true;
            info.addFinding(
                "Potential Subdomain Takeover - 404 Response",
                "Subdomain '" + subdomain + "' returns 404 and has a CNAME pointing to a vulnerable service (" + 
                info.potentialService + "). This may indicate the service is not claimed and could be vulnerable to takeover.",
                "Medium"
            );
        }
    }
    
    /**
     * Information about subdomain takeover vulnerability
     */
    public static class TakeoverInfo {
        private final String subdomain;
        private boolean isDnsResolvable = false;
        private String cnameTarget = null;
        private boolean cnameMatchesVulnerableService = false;
        private String potentialService = null;
        private String detectedService = null;
        private boolean isVulnerable = false;
        private int httpStatusCode = 0;
        private final List<Finding> findings = new ArrayList<>();
        
        public TakeoverInfo(String subdomain) {
            this.subdomain = subdomain;
        }
        
        public void addFinding(String title, String description, String severity) {
            findings.add(new Finding(title, description, severity));
        }
        
        public String getSubdomain() {
            return subdomain;
        }
        
        public boolean isDnsResolvable() {
            return isDnsResolvable;
        }
        
        public String getCnameTarget() {
            return cnameTarget;
        }
        
        public boolean isCnameMatchesVulnerableService() {
            return cnameMatchesVulnerableService;
        }
        
        public String getPotentialService() {
            return potentialService;
        }
        
        public String getDetectedService() {
            return detectedService;
        }
        
        public boolean isVulnerable() {
            return isVulnerable;
        }
        
        public int getHttpStatusCode() {
            return httpStatusCode;
        }
        
        public List<Finding> getFindings() {
            return findings;
        }
        
        public boolean hasFindings() {
            return !findings.isEmpty();
        }
    }
    
    /**
     * Security finding for subdomain takeover
     */
    public static class Finding {
        private final String title;
        private final String description;
        private final String severity;
        
        public Finding(String title, String description, String severity) {
            this.title = title;
            this.description = description;
            this.severity = severity;
        }
        
        public String getTitle() {
            return title;
        }
        
        public String getDescription() {
            return description;
        }
        
        public String getSeverity() {
            return severity;
        }
    }
    
    /**
     * Fingerprint for a vulnerable service
     */
    private static class ServiceFingerprint {
        private final String serviceName;
        private final List<String> responsePatterns;
        private final List<String> cnamePatterns;
        private final String severity;
        
        public ServiceFingerprint(String serviceName, List<String> responsePatterns, 
                                 List<String> cnamePatterns, String severity) {
            this.serviceName = serviceName;
            this.responsePatterns = responsePatterns;
            this.cnamePatterns = cnamePatterns;
            this.severity = severity;
        }
    }
}
