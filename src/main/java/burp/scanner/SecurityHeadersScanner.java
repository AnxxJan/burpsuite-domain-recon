package burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;
import java.util.Locale;

public class SecurityHeadersScanner {
    // Issue constants for missing headers
    public static final String ISSUE_NAME = "Missing Security Headers";
    public static final String ISSUE_DETAIL = "The following recommended security headers are missing: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Missing these headers may expose the application to moderate risks such as clickjacking, MIME sniffing, or information leakage. It is recommended to implement these headers to improve the security posture.";
    public static final String SEVERITY = "Medium";
    private MontoyaApi api;
    
    // Security headers to check
    private static final String[] SECURITY_HEADERS = {
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    };
    
    public SecurityHeadersScanner(MontoyaApi api) {
        this.api = api;
    }
    
    /**
     * Scan a domain for security headers using Montoya API
     */
    public SecurityHeadersResult scanSecurityHeaders(String domain) {
        SecurityHeadersResult result = new SecurityHeadersResult(domain);
        
        api.logging().logToOutput("[*] Scanning security headers for: " + domain);
        
        try {
            HttpResponse response = attemptHttpRequest(domain, result);
            
            if (response != null) {
                processSecurityHeaders(response, result);
                result.setSuccess(true);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error scanning headers for " + domain + ": " + e.getMessage());
            result.setSuccess(false);
            result.setError(e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Attempt HTTP request, trying HTTPS first, then HTTP as fallback
     */
    private HttpResponse attemptHttpRequest(String domain, SecurityHeadersResult result) {
        // Try HTTPS first
        HttpResponse response = tryHttpsRequest(domain, result);
        if (response != null) {
            return response;
        }
        
        // If HTTPS fails, try HTTP
        return tryHttpRequest(domain, result);
    }
    
    /**
     * Try HTTPS request
     */
    private HttpResponse tryHttpsRequest(String domain, SecurityHeadersResult result) {
        try {
            String urlString = "https://" + domain;
            HttpRequest request = HttpRequest.httpRequestFromUrl(urlString)
                .withMethod("GET")
                .withAddedHeader("User-Agent", "Mozilla/5.0");
            
            HttpResponse response = api.http().sendRequest(request).response();
            result.setProtocol("HTTPS");
            return response;
        } catch (Exception e) {
            api.logging().logToOutput("[!] HTTPS failed, trying HTTP for: " + domain);
            return null;
        }
    }
    
    /**
     * Try HTTP request as fallback
     */
    private HttpResponse tryHttpRequest(String domain, SecurityHeadersResult result) {
        try {
            String urlString = "http://" + domain;
            HttpRequest request = HttpRequest.httpRequestFromUrl(urlString)
                .withMethod("GET")
                .withAddedHeader("User-Agent", "Mozilla/5.0");
            
            HttpResponse response = api.http().sendRequest(request).response();
            result.setProtocol("HTTP");
            return response;
        } catch (Exception ex) {
            api.logging().logToError("Error scanning " + domain + ": " + ex.getMessage());
            result.setSuccess(false);
            result.setError(ex.getMessage());
            return null;
        }
    }
    
    /**
     * Process response headers and check for security headers
     */
    private void processSecurityHeaders(HttpResponse response, SecurityHeadersResult result) {
        result.setStatusCode(response.statusCode());
        
        // Parse headers into map
        Map<String, String> headerMap = new HashMap<>();
        for (String headerName : response.headers().stream()
                .map(HttpHeader::name)
                .distinct()
                .toArray(String[]::new)) {
            String value = response.headerValue(headerName);
            if (value != null) {
                headerMap.put(headerName.toLowerCase(Locale.ROOT), value);
            }
        }
        
        // Check each security header
        for (String headerName : SECURITY_HEADERS) {
            String lowerHeaderName = headerName.toLowerCase(Locale.ROOT);
            if (headerMap.containsKey(lowerHeaderName)) {
                result.addHeader(headerName, headerMap.get(lowerHeaderName), true);
            } else {
                result.addHeader(headerName, null, false);
            }
        }
    }
    
    /**
     * Result class for security headers scan
     */
    public static class SecurityHeadersResult {
        private String domain;
        private boolean success;
        private String protocol;
        private int statusCode;
        private String error;
        private Map<String, HeaderInfo> headers;
        
        public SecurityHeadersResult(String domain) {
            this.domain = domain;
            this.headers = new HashMap<>();
        }
        
        public void addHeader(String name, String value, boolean present) {
            headers.put(name, new HeaderInfo(name, value, present));
        }
        
        public String getDomain() { return domain; }
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }
        public int getStatusCode() { return statusCode; }
        public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        public Map<String, HeaderInfo> getHeaders() { return headers; }
        
        public List<String> getMissingHeaders() {
            List<String> missing = new ArrayList<>();
            for (HeaderInfo header : headers.values()) {
                if (!header.isPresent()) {
                    missing.add(header.getName());
                }
            }
            return missing;
        }
        
        public int getMissingHeadersCount() {
            return getMissingHeaders().size();
        }
        
        public String getSummary() {
            int present = 0;
            int missing = 0;
            
            for (HeaderInfo header : headers.values()) {
                if (header.isPresent()) {
                    present++;
                } else {
                    missing++;
                }
            }
            
            return String.format("%d present, %d missing", present, missing);
        }
    }
    
    /**
     * Header information class
     */
    public static class HeaderInfo {
        private String name;
        private String value;
        private boolean present;
        
        public HeaderInfo(String name, String value, boolean present) {
            this.name = name;
            this.value = value;
            this.present = present;
        }
        
        public String getName() { return name; }
        public String getValue() { return value; }
        public boolean isPresent() { return present; }
        
        public String getRecommendation() {
            switch (name) {
                case "Strict-Transport-Security":
                    return "Recommended: max-age=31536000; includeSubDomains";
                case "Content-Security-Policy":
                    return "Recommended: default-src 'self'; script-src 'self'";
                case "X-Frame-Options":
                    return "Recommended: DENY or SAMEORIGIN";
                case "X-Content-Type-Options":
                    return "Recommended: nosniff";
                case "Referrer-Policy":
                    return "Recommended: strict-origin-when-cross-origin";
                case "Permissions-Policy":
                    return "Recommended: geolocation=(), microphone=(), camera=()";
                default:
                    return "";
            }
        }
        
        public String getSeverity() {
            if (present) {
                return "Info";
            }
            
            return SEVERITY;
        }
    }
}
