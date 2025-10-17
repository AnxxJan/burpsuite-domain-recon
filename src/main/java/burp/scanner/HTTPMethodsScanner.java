package burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;

/**
 * HTTP Methods Scanner
 * Tests for dangerous HTTP methods (OPTIONS, TRACE, PUT, DELETE)
 */
public class HTTPMethodsScanner {
    
    // HTTP Method constants
    private static final String METHOD_OPTIONS = "OPTIONS";
    private static final String METHOD_TRACE = "TRACE";
    private static final String METHOD_PUT = "PUT";
    private static final String METHOD_DELETE = "DELETE";
    private static final String METHOD_HEAD = "HEAD";
    private static final String METHOD_PATCH = "PATCH";
    
    // Message constants
    private static final String METHOD_ENABLED_SUFFIX = " Method Enabled";
    
    private MontoyaApi api;
    
    public HTTPMethodsScanner(MontoyaApi api) {
        this.api = api;
    }
    
    public HTTPMethodsInfo scanHTTPMethods(String domain) {
        HTTPMethodsInfo info = new HTTPMethodsInfo(domain);
        
        try {
            String url = "https://" + domain;
            
            // Test OPTIONS
            info.addResult(METHOD_OPTIONS, testMethod(url, METHOD_OPTIONS));
            
            // Test TRACE
            info.addResult(METHOD_TRACE, testMethod(url, METHOD_TRACE));
            
            // Test PUT
            info.addResult(METHOD_PUT, testMethod(url, METHOD_PUT));
            
            // Test DELETE
            info.addResult(METHOD_DELETE, testMethod(url, METHOD_DELETE));
            
            // Test HEAD
            info.addResult(METHOD_HEAD, testMethod(url, METHOD_HEAD));
            
            // Test PATCH
            info.addResult(METHOD_PATCH, testMethod(url, METHOD_PATCH));
            
            // Analyze results for security issues
            analyzeResults(info);
            
        } catch (Exception e) {
            info.addFinding("HTTP Methods Check Failed",
                "Could not test HTTP methods: " + e.getMessage(),
                "Low");
        }
        
        return info;
    }
    
    private MethodResult testMethod(String url, String method) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                .withMethod(method)
                .withAddedHeader("User-Agent", "Mozilla/5.0");
            
            HttpResponse response = api.http().sendRequest(request).response();
            int statusCode = response.statusCode();
            
            // Method is allowed if status is not 405 (Method Not Allowed) or 501 (Not Implemented)
            boolean allowed = (statusCode != 405 && statusCode != 501);
            
            return new MethodResult(statusCode, "HTTP " + statusCode, allowed);
        } catch (Exception e) {
            return new MethodResult(0, "Error: " + e.getMessage(), false);
        }
    }
    
    private void analyzeResults(HTTPMethodsInfo info) {
        // Check for dangerous methods
        if (info.isMethodAllowed(METHOD_TRACE)) {
            info.addFinding(METHOD_TRACE + METHOD_ENABLED_SUFFIX,
                METHOD_TRACE + " method is enabled. This can be used for Cross-Site Tracing (XST) attacks",
                "Medium");
        }
        
        if (info.isMethodAllowed(METHOD_PUT)) {
            info.addFinding(METHOD_PUT + METHOD_ENABLED_SUFFIX,
                "PUT method is enabled. This could allow file uploads if not properly restricted",
                "High");
        }
        
        if (info.isMethodAllowed(METHOD_DELETE)) {
            info.addFinding(METHOD_DELETE + METHOD_ENABLED_SUFFIX,
                METHOD_DELETE + " method is enabled. This could allow resource deletion if not properly restricted",
                "High");
        }
        
        if (info.isMethodAllowed(METHOD_PATCH)) {
            info.addFinding(METHOD_PATCH + METHOD_ENABLED_SUFFIX,
                METHOD_PATCH + " method is enabled. Ensure proper authentication and authorization",
                "Medium");
        }
        
        // Check OPTIONS response
        MethodResult optionsResult = info.getMethodResult(METHOD_OPTIONS);
        if (optionsResult != null && optionsResult.isAllowed()) {
            int dangerousCount = 0;
            if (info.isMethodAllowed(METHOD_PUT)) {
                dangerousCount++;
            }
            if (info.isMethodAllowed(METHOD_DELETE)) {
                dangerousCount++;
            }
            if (info.isMethodAllowed(METHOD_TRACE)) {
                dangerousCount++;
            }
            
            if (dangerousCount > 0) {
                info.addFinding("Multiple Dangerous Methods",
                    dangerousCount + " dangerous HTTP methods are enabled",
                    "High");
            }
        }
    }
    
    /**
     * HTTP Methods information container
     */
    public static class HTTPMethodsInfo {
        private String domain;
        private Map<String, MethodResult> methodResults;
        private List<SecurityFinding> findings;
        
        public HTTPMethodsInfo(String domain) {
            this.domain = domain;
            this.methodResults = new HashMap<>();
            this.findings = new ArrayList<>();
        }
        
        public String getDomain() { return domain; }
        public Map<String, MethodResult> getMethodResults() { return methodResults; }
        public List<SecurityFinding> getFindings() { return findings; }
        
        public void addResult(String method, MethodResult result) {
            methodResults.put(method, result);
        }
        
        public MethodResult getMethodResult(String method) {
            return methodResults.get(method);
        }
        
        public boolean isMethodAllowed(String method) {
            MethodResult result = methodResults.get(method);
            return result != null && result.isAllowed();
        }
        
        public void addFinding(String title, String description, String severity) {
            findings.add(new SecurityFinding(title, description, severity));
        }
    }
    
    /**
     * Method test result
     */
    public static class MethodResult {
        private int statusCode;
        private String statusMessage;
        private boolean allowed;
        
        public MethodResult(int statusCode, String statusMessage, boolean allowed) {
            this.statusCode = statusCode;
            this.statusMessage = statusMessage;
            this.allowed = allowed;
        }
        
        public int getStatusCode() { return statusCode; }
        public String getStatusMessage() { return statusMessage; }
        public boolean isAllowed() { return allowed; }
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
