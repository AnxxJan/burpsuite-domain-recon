package burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

public class SubdomainEnumerator {
    private static final String USER_AGENT_HEADER = "User-Agent";
    private static final String USER_AGENT_VALUE = "BurpSuite-DomainRecon/1.0";
    
    private MontoyaApi api;
    private AtomicBoolean shouldStop = new AtomicBoolean(false);
    
    public SubdomainEnumerator(MontoyaApi api) {
        this.api = api;
    }
    
    public void setShouldStop(AtomicBoolean shouldStop) {
        this.shouldStop = shouldStop;
    }
    
    /**
     * Enumerate subdomains from multiple sources
     */
    public Set<String> enumerateSubdomains(String domain) {
        Set<String> subdomains = new HashSet<>();
        
        if (shouldStop.get()) {
            return subdomains;
        }
        
        api.logging().logToOutput("[*] Starting subdomain enumeration for: " + domain);
        
        // Enumerate from crt.sh
        if (!shouldStop.get()) {
            Set<String> crtSubdomains = enumerateFromCrtSh(domain);
            subdomains.addAll(crtSubdomains);
            api.logging().logToOutput("[+] Found " + crtSubdomains.size() + " subdomains from crt.sh");
        }
        
        // Enumerate using Sublist3r API (using public API endpoint)
        if (!shouldStop.get()) {
            Set<String> sublist3rSubdomains = enumerateFromSublist3r(domain);
            subdomains.addAll(sublist3rSubdomains);
            api.logging().logToOutput("[+] Found " + sublist3rSubdomains.size() + " subdomains from Sublist3r sources");
        }
        
        api.logging().logToOutput("[+] Total unique subdomains found: " + subdomains.size());
        
        // Remove www duplicates (if www.domain.com and domain.com point to same site)
        subdomains = removeDuplicateWwwSubdomains(subdomains);
        api.logging().logToOutput("[+] After removing www duplicates: " + subdomains.size());
        
        return subdomains;
    }
    
    /**
     * Remove www subdomain if it points to the same site as the apex domain
     * This prevents scanning the same website twice and improves speed
     */
    private Set<String> removeDuplicateWwwSubdomains(Set<String> subdomains) {
        Set<String> filtered = new HashSet<>(subdomains);
        Set<String> toRemove = new HashSet<>();
        
        // Create a map to group domains by their apex domain
        Map<String, List<String>> domainGroups = new HashMap<>();
        
        for (String subdomain : subdomains) {
            String apexDomain = getApexDomain(subdomain);
            if (apexDomain != null) {
                domainGroups.computeIfAbsent(apexDomain, k -> new ArrayList<>()).add(subdomain);
            }
        }
        
        // For each group, check if www and apex both exist
        for (Map.Entry<String, List<String>> entry : domainGroups.entrySet()) {
            String apex = entry.getKey();
            List<String> variants = entry.getValue();
            
            String wwwDomain = "www." + apex;
            
            // If both www.domain.com and domain.com exist, check if they're the same
            if (variants.contains(apex) && variants.contains(wwwDomain)) {
                api.logging().logToOutput("[*] Checking if " + wwwDomain + " and " + apex + " are the same site...");
                
                if (areSameSite(wwwDomain, apex)) {
                    // Remove www version, keep apex domain
                    toRemove.add(wwwDomain);
                    api.logging().logToOutput("[+] Removing " + wwwDomain + " (same as " + apex + ")");
                } else {
                    api.logging().logToOutput("[+] Keeping both " + wwwDomain + " and " + apex + " (different sites)");
                }
            }
        }
        
        filtered.removeAll(toRemove);
        return filtered;
    }
    
    /**
     * Extract apex domain from subdomain
     * Example: www.example.com -> example.com
     *          api.example.com -> example.com
     */
    private String getApexDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return null;
        }
        
        String[] parts = domain.split("\\.");
        
        // Need at least domain.tld (2 parts)
        if (parts.length < 2) {
            return null;
        }
        
        // For domains like example.com, return as is
        if (parts.length == 2) {
            return domain;
        }
        
        // For subdomains like www.example.com, return example.com
        // Handle special TLDs like co.uk, com.br, etc.
        if (parts.length >= 3) {
            String tld = parts[parts.length - 1];
            String sld = parts[parts.length - 2];
            
            // Check for two-part TLDs (co.uk, com.br, etc.)
            if (((tld.length() == 2 && sld.matches("^(co|com|org|net|gov|edu|ac)$")) ||
                ("uk".equals(tld) && sld.matches("^(co|org|ac|gov|nhs|police|sch)$"))) &&
                parts.length >= 3) {
                // Three-part apex: example.co.uk
                return parts[parts.length - 3] + "." + sld + "." + tld;
            }
            
            // Standard two-part apex: example.com
            return sld + "." + tld;
        }
        
        return domain;
    }
    
    /**
     * Check if two domains point to the same website
     * Compares HTTP response headers and content fingerprint
     */
    private boolean areSameSite(String domain1, String domain2) {
        try {
            // Get fingerprint for both domains
            SiteFingerprint fp1 = getSiteFingerprint(domain1);
            SiteFingerprint fp2 = getSiteFingerprint(domain2);
            
            if (fp1 == null || fp2 == null) {
                // If either fails, consider them different (conservative approach)
                return false;
            }
            
            // Compare fingerprints
            return fp1.isSimilar(fp2);
            
        } catch (Exception e) {
            api.logging().logToError("Error comparing sites: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Get a fingerprint of a website for comparison
     */
    private SiteFingerprint getSiteFingerprint(String domain) {
        String[] protocols = {"https://", "http://"};
        
        for (String protocol : protocols) {
            SiteFingerprint fingerprint = tryGetFingerprint(protocol, domain);
            if (fingerprint != null) {
                return fingerprint;
            }
        }
        
        return null;
    }
    
    private SiteFingerprint tryGetFingerprint(String protocol, String domain) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(protocol + domain)
                    .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_VALUE);
            
            HttpResponse response = api.http().sendRequest(request).response();
            int statusCode = response.statusCode();
            
            if (statusCode >= 200 && statusCode < 400) {
                return createFingerprint(response, statusCode);
            }
        } catch (Exception e) {
            // Try next protocol - connection failed or timeout
            api.logging().logToOutput("Failed to get fingerprint with " + protocol + ": " + e.getMessage());
        }
        return null;
    }
    
    private SiteFingerprint createFingerprint(HttpResponse response, int statusCode) {
        String server = getHeaderValueOrEmpty(response, "Server");
        String contentType = getHeaderValueOrEmpty(response, "Content-Type");
        String location = getHeaderValueOrEmpty(response, "Location");
        
        String fullContent = response.bodyToString();
        String content = fullContent.length() > 1000 ? fullContent.substring(0, 1000) : fullContent;
        int contentHash = content.replaceAll("\\s+", "").hashCode();
        
        return new SiteFingerprint(statusCode, server, contentType, location, contentHash);
    }
    
    private String getHeaderValueOrEmpty(HttpResponse response, String headerName) {
        String value = response.headerValue(headerName);
        return value != null ? value : "";
    }
    
    /**
     * Site fingerprint for comparison
     */
    private static class SiteFingerprint {
        final int statusCode;
        final String server;
        final String contentType;
        final String location;
        final int contentHash;
        
        SiteFingerprint(int statusCode, String server, String contentType, String location, int contentHash) {
            this.statusCode = statusCode;
            this.server = server.toLowerCase(Locale.ROOT);
            this.contentType = contentType.toLowerCase(Locale.ROOT);
            this.location = location.toLowerCase(Locale.ROOT);
            this.contentHash = contentHash;
        }
        
        /**
         * Check if two fingerprints are similar enough to consider same site
         */
        boolean isSimilar(SiteFingerprint other) {
            // Status code should match (or both redirects)
            boolean statusMatch = (this.statusCode == other.statusCode) ||
                                 (isRedirect(this.statusCode) && isRedirect(other.statusCode));
            
            // If both redirect, check if they redirect to similar locations
            if (isRedirect(this.statusCode) && isRedirect(other.statusCode)) {
                // Normalize locations (remove protocol and www)
                String loc1 = normalizeLocation(this.location);
                String loc2 = normalizeLocation(other.location);
                return loc1.equals(loc2);
            }
            
            // Server header should match (if present)
            boolean serverMatch = this.server.isEmpty() || other.server.isEmpty() || 
                                 this.server.equals(other.server);
            
            // Content type should match
            boolean contentTypeMatch = this.contentType.equals(other.contentType);
            
            // Content hash should match (same page content)
            boolean contentMatch = this.contentHash == other.contentHash;
            
            // Consider same if status, server, content type, and content all match
            return statusMatch && serverMatch && contentTypeMatch && contentMatch;
        }
        
        private boolean isRedirect(int status) {
            return status >= 300 && status < 400;
        }
        
        private String normalizeLocation(String location) {
            if (location == null || location.isEmpty()) {
                return "";
            }
            // Remove protocol
            String normalized = location.replaceFirst("^https?://", "");
            // Remove www prefix
            normalized = normalized.replaceFirst("^www\\.", "");
            // Remove trailing slash
            normalized = normalized.replaceFirst("/$", "");
            return normalized;
        }
    }
    
    
    /**
     * Enumerate subdomains from crt.sh
     */
    private Set<String> enumerateFromCrtSh(String domain) {
        Set<String> subdomains = new HashSet<>();
        
        try {
            String url = "https://crt.sh/?q=%25." + URLEncoder.encode(domain, StandardCharsets.UTF_8) + "&output=json";
            HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                    .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_VALUE);
            
            HttpResponse response = api.http().sendRequest(request).response();
            
            if (response.statusCode() == 200) {
                parseCrtShResponse(response.bodyToString(), domain, subdomains);
            }
        } catch (Exception e) {
            api.logging().logToError("Error querying crt.sh: " + e.getMessage());
        }
        
        return subdomains;
    }
    
    private void parseCrtShResponse(String responseBody, String domain, Set<String> subdomains) {
        JsonArray jsonArray = JsonParser.parseString(responseBody).getAsJsonArray();
        
        for (JsonElement element : jsonArray) {
            if (element.isJsonObject()) {
                String nameValue = element.getAsJsonObject().get("name_value").getAsString();
                processCrtShDomains(nameValue, domain, subdomains);
            }
        }
    }
    
    private void processCrtShDomains(String nameValue, String domain, Set<String> subdomains) {
        String[] domains = nameValue.split("\n");
        for (String d : domains) {
            d = d.trim().toLowerCase(Locale.ROOT);
            
            if (d.startsWith("*.")) {
                d = d.substring(2);
            }
            
            if (isValidDomain(d) && d.endsWith(domain)) {
                subdomains.add(d);
            }
        }
    }
    
    /**
     * Enumerate subdomains using various public APIs (similar to Sublist3r approach)
     */
    private Set<String> enumerateFromSublist3r(String domain) {
        Set<String> subdomains = new HashSet<>();
        
        // Query multiple sources
        subdomains.addAll(queryHackerTarget(domain));
        subdomains.addAll(queryThreatCrowd(domain));
        subdomains.addAll(queryVirusTotal());
        subdomains.addAll(queryDNSDumpster());
        
        return subdomains;
    }
    
    /**
     * Query HackerTarget API
     */
    private Set<String> queryHackerTarget(String domain) {
        Set<String> subdomains = new HashSet<>();
        
        try {
            String url = "https://api.hackertarget.com/hostsearch/?q=" + domain;
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            
            HttpResponse response = api.http().sendRequest(request).response();
            if (response.statusCode() == 200) {
                String responseBody = response.bodyToString();
                String[] lines = responseBody.split("\n");
                
                for (String line : lines) {
                    if (line.contains(",")) {
                        String subdomain = line.split(",")[0].trim().toLowerCase(Locale.ROOT);
                        if (isValidDomain(subdomain)) {
                            subdomains.add(subdomain);
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error querying HackerTarget: " + e.getMessage());
        }
        
        return subdomains;
    }
    
    /**
     * Query ThreatCrowd API
     */
    private Set<String> queryThreatCrowd(String domain) {
        Set<String> subdomains = new HashSet<>();
        
        try {
            String url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + domain;
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            
            HttpResponse response = api.http().sendRequest(request).response();
            if (response.statusCode() == 200) {
                String responseBody = response.bodyToString();
                JsonElement jsonElement = JsonParser.parseString(responseBody);
                
                if (jsonElement.isJsonObject() && jsonElement.getAsJsonObject().has("subdomains")) {
                    JsonArray subdomainsArray = jsonElement.getAsJsonObject().get("subdomains").getAsJsonArray();
                    for (JsonElement element : subdomainsArray) {
                        String subdomain = element.getAsString().trim().toLowerCase(Locale.ROOT);
                        if (isValidDomain(subdomain)) {
                            subdomains.add(subdomain);
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error querying ThreatCrowd: " + e.getMessage());
        }
        
        return subdomains;
    }
    
    /**
     * Query VirusTotal API (limited without API key)
     */
    private Set<String> queryVirusTotal() {
        Set<String> subdomains = new HashSet<>();
        
        // Note: This would require an API key for full functionality
        // Keeping the structure for future implementation
        api.logging().logToOutput("[!] VirusTotal requires API key - skipping");
        
        return subdomains;
    }
    
    /**
     * Query DNSDumpster (through web scraping)
     */
    private Set<String> queryDNSDumpster() {
        Set<String> subdomains = new HashSet<>();
        
        // Note: DNSDumpster requires CSRF token and POST request
        // This is a simplified version
        api.logging().logToOutput("[!] DNSDumpster requires special handling - using other sources");
        
        return subdomains;
    }
    
    /**
     * Validate domain format
     */
    private boolean isValidDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false;
        }
        
        // Basic validation
        String domainPattern = "^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]\\.[a-zA-Z]{2,}$";
        return domain.matches(domainPattern);
    }
    
    /**
     * Verify if subdomain is alive by making HTTP request
     * Checks standard ports (80/443) first, then tries common alternate ports
     */
    public boolean isSubdomainAlive(String subdomain) {
        try {
            // Try standard ports (HTTPS then HTTP)
            return tryHttpsRequest(subdomain) || tryHttpRequest(subdomain);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Try HTTPS request to subdomain on standard port
     */
    private boolean tryHttpsRequest(String subdomain) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl("https://" + subdomain)
                    .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_VALUE);
            HttpResponse response = api.http().sendRequest(request).response();
            return response.statusCode() < 500;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Try HTTP request to subdomain on standard port
     */
    private boolean tryHttpRequest(String subdomain) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl("http://" + subdomain)
                    .withAddedHeader(USER_AGENT_HEADER, USER_AGENT_VALUE);
            HttpResponse response = api.http().sendRequest(request).response();
            return response.statusCode() < 500;
        } catch (Exception ex) {
            return false;
        }
    }
    
    // Port-specific helpers removed: the enumerator only checks standard HTTP/HTTPS ports now
}
