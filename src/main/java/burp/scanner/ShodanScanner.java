package burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonArray;

import java.net.InetAddress;
import java.util.*;

public class ShodanScanner {
    private MontoyaApi api;
    private String apiKey;
    
    public ShodanScanner(MontoyaApi api) {
        this.api = api;
    }
    
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }
    
    public String getApiKey() {
        return apiKey;
    }
    
    public boolean hasApiKey() {
        return apiKey != null && !apiKey.trim().isEmpty();
    }
    
    /**
     * Get server information including IP and Shodan data
     */
    public ServerInfo getServerInfo(String domain) {
        api.logging().logToOutput("[*] Getting server information for: " + domain);
        
        ServerInfo info = new ServerInfo(domain);
        
        try {
            // Resolve IP address
            InetAddress address = InetAddress.getByName(domain);
            String ip = address.getHostAddress();
            info.setIpAddress(ip);
            api.logging().logToOutput("[+] Resolved IP: " + ip);
            
            // Get Shodan information using API
            ShodanInfo shodanInfo = getShodanInfoFromAPI(ip);
            info.setShodanInfo(shodanInfo);
            
            info.setSuccess(true);
            
        } catch (Exception e) {
            api.logging().logToError("Error getting server info for " + domain + ": " + e.getMessage());
            info.setSuccess(false);
            info.setError(e.getMessage());
        }
        
        return info;
    }
    
    /**
     * Get Shodan information using official API
     */
    private ShodanInfo getShodanInfoFromAPI(String ip) {
        ShodanInfo info = new ShodanInfo();
        info.setIpAddress(ip);
        info.setShodanUrl("https://www.shodan.io/host/" + ip);
        
        if (!validateApiKey(info)) {
            return info;
        }
        
        try {
            api.logging().logToOutput("[*] Querying Shodan API for: " + ip);
            HttpResponse response = queryShodanApi(ip);
            
            if (!processApiResponse(response, info)) {
                return info;
            }
            
            JsonObject json = JsonParser.parseString(response.bodyToString()).getAsJsonObject();
            extractGeneralInfo(json, info);
            extractHostnamesAndPorts(json, info);
            extractVulnerabilities(json, info);
            extractServices(json, info);
            
            api.logging().logToOutput("[+] Shodan data retrieved successfully");
            info.setSuccess(true);
            
        } catch (Exception e) {
            api.logging().logToOutput("[!] Error querying Shodan API: " + e.getMessage());
            info.setSuccess(false);
            info.setError("Failed to query Shodan API: " + e.getMessage());
        }
        
        return info;
    }
    
    private boolean validateApiKey(ShodanInfo info) {
        if (!hasApiKey()) {
            api.logging().logToOutput("[!] No Shodan API key configured");
            info.setSuccess(false);
            info.setError("No API key configured. Please add your Shodan API key in the settings.");
            return false;
        }
        return true;
    }
    
    private HttpResponse queryShodanApi(String ip) {
        String apiUrl = "https://api.shodan.io/shodan/host/" + ip + "?key=" + apiKey.trim();
        HttpRequest request = HttpRequest.httpRequestFromUrl(apiUrl)
                .withAddedHeader("User-Agent", "BurpSuite-DomainRecon/1.0");
        return api.http().sendRequest(request).response();
    }
    
    private boolean processApiResponse(HttpResponse response, ShodanInfo info) {
        int statusCode = response.statusCode();
        
        if (statusCode == 401) {
            api.logging().logToError("[!] Invalid Shodan API key");
            info.setSuccess(false);
            info.setError("Invalid API key. Please check your Shodan API key.");
            return false;
        }
        
        if (statusCode == 404) {
            api.logging().logToOutput("[!] No Shodan data available for this IP");
            info.setSuccess(false);
            info.setError("No information available for this IP in Shodan database.");
            return false;
        }
        
        if (statusCode != 200) {
            api.logging().logToError("[!] Shodan API error: " + statusCode);
            info.setSuccess(false);
            info.setError("API error (HTTP " + statusCode + "). Please try again later.");
            return false;
        }
        
        return true;
    }
    
    private void extractGeneralInfo(JsonObject json, ShodanInfo info) {
        if (json.has("country_name")) {
            info.setCountry(json.get("country_name").getAsString());
        }
        if (json.has("city")) {
            info.setCity(json.get("city").getAsString());
        }
        if (json.has("org")) {
            info.setOrganization(json.get("org").getAsString());
        }
        if (json.has("isp")) {
            info.setIsp(json.get("isp").getAsString());
        }
    }
    
    private void extractHostnamesAndPorts(JsonObject json, ShodanInfo info) {
        if (json.has("hostnames")) {
            JsonArray hostnames = json.getAsJsonArray("hostnames");
            for (JsonElement hostname : hostnames) {
                info.addHostname(hostname.getAsString());
            }
        }
        
        if (json.has("ports")) {
            JsonArray ports = json.getAsJsonArray("ports");
            for (JsonElement port : ports) {
                info.addOpenPort(port.getAsInt());
            }
        }
    }
    
    private void extractVulnerabilities(JsonObject json, ShodanInfo info) {
        if (json.has("vulns")) {
            JsonArray vulns = json.getAsJsonArray("vulns");
            info.setVulnerabilitiesCount(vulns.size());
            
            for (JsonElement vuln : vulns) {
                info.addVulnerability(vuln.getAsString());
            }
        }
    }
    
    private void extractServices(JsonObject json, ShodanInfo info) {
        if (!json.has("data")) {
            return;
        }
        
        JsonArray data = json.getAsJsonArray("data");
        for (JsonElement item : data) {
            JsonObject service = item.getAsJsonObject();
            String serviceInfo = buildServiceInfo(service);
            
            if (!serviceInfo.isEmpty()) {
                info.addService(serviceInfo);
            }
        }
    }
    
    private String buildServiceInfo(JsonObject service) {
        StringBuilder serviceInfo = new StringBuilder();
        
        if (service.has("port")) {
            serviceInfo.append("Port ").append(service.get("port").getAsInt());
        }
        
        if (service.has("transport")) {
            serviceInfo.append("/").append(service.get("transport").getAsString());
        }
        
        if (service.has("product")) {
            serviceInfo.append(" - ").append(service.get("product").getAsString());
        }
        
        if (service.has("version")) {
            serviceInfo.append(" ").append(service.get("version").getAsString());
        }
        
        return serviceInfo.toString();
    }
    
    /**
     * Server information class
     */
    public static class ServerInfo {
        private String domain;
        private String ipAddress;
        private boolean success;
        private String error;
        private ShodanInfo shodanInfo;
        
        public ServerInfo(String domain) {
            this.domain = domain;
        }
        
        public String getDomain() { return domain; }
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        public ShodanInfo getShodanInfo() { return shodanInfo; }
        public void setShodanInfo(ShodanInfo shodanInfo) { this.shodanInfo = shodanInfo; }
    }
    
    /**
     * Shodan information class
     */
    public static class ShodanInfo {
        private String ipAddress;
        private String shodanUrl;
        private String city;
        private String country;
        private String organization;
        private String isp;
        private List<String> hostnames = new ArrayList<>();
        private List<Integer> openPorts = new ArrayList<>();
        private List<String> services = new ArrayList<>();
        private List<String> vulnerabilities = new ArrayList<>();
        private int vulnerabilitiesCount = 0;
        private boolean success;
        private String error;
        
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        public String getShodanUrl() { return shodanUrl; }
        public void setShodanUrl(String shodanUrl) { this.shodanUrl = shodanUrl; }
        public String getCity() { return city; }
        public void setCity(String city) { this.city = city; }
        public String getCountry() { return country; }
        public void setCountry(String country) { this.country = country; }
        public String getOrganization() { return organization; }
        public void setOrganization(String organization) { this.organization = organization; }
        public String getIsp() { return isp; }
        public void setIsp(String isp) { this.isp = isp; }
        public List<String> getHostnames() { return hostnames; }
        public void addHostname(String hostname) { this.hostnames.add(hostname); }
        public List<Integer> getOpenPorts() { return openPorts; }
        public void addOpenPort(int port) { this.openPorts.add(port); }
        public List<String> getServices() { return services; }
        public void addService(String service) { this.services.add(service); }
        public List<String> getVulnerabilities() { return vulnerabilities; }
        public void addVulnerability(String vuln) { this.vulnerabilities.add(vuln); }
        public int getVulnerabilitiesCount() { return vulnerabilitiesCount; }
        public void setVulnerabilitiesCount(int count) { this.vulnerabilitiesCount = count; }
        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        
        public String getSummary() {
            if (!success) {
                return "Shodan data unavailable";
            }
            
            StringBuilder summary = new StringBuilder();
            if (organization != null && !organization.isEmpty()) {
                summary.append(organization);
            }
            if (country != null && !country.isEmpty()) {
                if (!summary.isEmpty()) {
                    summary.append(" - ");
                }
                summary.append(country);
            }
            if (!openPorts.isEmpty()) {
                if (!summary.isEmpty()) {
                    summary.append(" | ");
                }
                summary.append(openPorts.size()).append(" ports");
            }
            
            if (summary.isEmpty()) {
                summary.append("Limited info available");
            }
            
            return summary.toString();
        }
        
        public String getDetailedInfo() {
            StringBuilder detail = new StringBuilder();
            
            detail.append("Shodan Information for ").append(ipAddress).append("\n\n");
            
            if (!success) {
                appendErrorInfo(detail);
                return detail.toString();
            }
            
            appendBasicInfo(detail);
            appendHostnamesInfo(detail);
            appendPortsInfo(detail);
            appendServicesInfo(detail);
            appendVulnerabilitiesInfo(detail);
            appendLimitedInfoWarning(detail);
            
            return detail.toString();
        }
        
        private void appendErrorInfo(StringBuilder detail) {
            detail.append("Could not retrieve Shodan data.\n");
            if (error != null) {
                detail.append("Error: ").append(error).append("\n");
            }
            detail.append("\nView manually at: ").append(shodanUrl).append("\n");
        }
        
        private void appendBasicInfo(StringBuilder detail) {
            detail.append("URL: ").append(shodanUrl).append("\n\n");
            
            if (organization != null && !organization.isEmpty()) {
                detail.append("Organization: ").append(organization).append("\n");
            }
            if (isp != null && !isp.isEmpty()) {
                detail.append("ISP: ").append(isp).append("\n");
            }
            if (country != null && !country.isEmpty()) {
                detail.append("Country: ").append(country).append("\n");
            }
            if (city != null && !city.isEmpty()) {
                detail.append("City: ").append(city).append("\n");
            }
        }
        
        private void appendHostnamesInfo(StringBuilder detail) {
            if (!hostnames.isEmpty()) {
                detail.append("\nHostnames:\n");
                for (String hostname : hostnames) {
                    detail.append("  - ").append(hostname).append("\n");
                }
            }
        }
        
        private void appendPortsInfo(StringBuilder detail) {
            if (!openPorts.isEmpty()) {
                detail.append("\nOpen Ports (").append(openPorts.size()).append("):\n");
                Collections.sort(openPorts);
                for (int port : openPorts) {
                    detail.append("  - ").append(port).append("\n");
                }
            }
        }
        
        private void appendServicesInfo(StringBuilder detail) {
            if (!services.isEmpty()) {
                detail.append("\nServices:\n");
                for (String service : services) {
                    detail.append("  - ").append(service).append("\n");
                }
            }
        }
        
        private void appendVulnerabilitiesInfo(StringBuilder detail) {
            if (vulnerabilitiesCount > 0) {
                detail.append("\nVulnerabilities Found: ").append(vulnerabilitiesCount).append("\n");
                if (!vulnerabilities.isEmpty()) {
                    detail.append("CVE IDs:\n");
                    for (String vuln : vulnerabilities) {
                        detail.append("  - ").append(vuln).append("\n");
                    }
                }
            }
        }
        
        private void appendLimitedInfoWarning(StringBuilder detail) {
            if (organization == null && isp == null && openPorts.isEmpty()) {
                detail.append("\nLimited information available.\n");
                detail.append("Visit Shodan directly for more details: ").append(shodanUrl).append("\n");
            }
        }
    }
}
