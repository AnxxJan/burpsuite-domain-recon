package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.ui.ReconTab;
import burp.scanner.SecurityHeadersScanner;
import burp.scanner.SubdomainEnumerator;
import burp.scanner.TechnologyDetector;
import burp.scanner.ShodanScanner;
import burp.scanner.WordPressScanner;
import burp.scanner.SSLScanner;
import burp.scanner.HTTPMethodsScanner;
import burp.scanner.SensitiveFilesScanner;
import burp.scanner.SubdomainTakeoverScanner;

import javax.swing.*;

public class BurpExtender implements BurpExtension {
    private static final String BANNER_SEPARATOR = "========================================";
    
    private MontoyaApi api;
    private ReconTab reconTab;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        
        // Set extension name
        api.extension().setName("Domain Reconnaissance Suite");
        
        // Print banner
        printBanner();
        
        // Initialize scanners with Montoya API
        SubdomainEnumerator subdomainEnumerator = new SubdomainEnumerator(api);
        SecurityHeadersScanner headersScanner = new SecurityHeadersScanner(api);
        TechnologyDetector techDetector = new TechnologyDetector(api);
        ShodanScanner shodanScanner = new ShodanScanner(api);
        WordPressScanner wordPressScanner = new WordPressScanner(api);
        SSLScanner sslScanner = new SSLScanner();
        HTTPMethodsScanner httpMethodsScanner = new HTTPMethodsScanner(api);
        SensitiveFilesScanner sensitiveFilesScanner = new SensitiveFilesScanner(api);
        SubdomainTakeoverScanner takeoverScanner = new SubdomainTakeoverScanner(api);
        
        // Create UI
        SwingUtilities.invokeLater(() -> {
            reconTab = new ReconTab(api, subdomainEnumerator, headersScanner, 
                                   techDetector, shodanScanner, wordPressScanner,
                                   sslScanner, httpMethodsScanner, sensitiveFilesScanner,
                                   takeoverScanner);
            
            // Register custom tab
            api.userInterface().registerSuiteTab("Domain Recon", reconTab);
        });
        
        // Register unloading handler to clean up resources
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("Extension unloading - stopping all active scans...");
            if (reconTab != null) {
                reconTab.cleanup();
            }
            api.logging().logToOutput("Extension unloaded successfully");
        });
        
        api.logging().logToOutput("Extension loaded successfully!");
    }
    
    private void printBanner() {
        api.logging().logToOutput(BANNER_SEPARATOR);
        api.logging().logToOutput("  Domain Reconnaissance Suite v1.1");
        api.logging().logToOutput(BANNER_SEPARATOR);
        api.logging().logToOutput("Features:");
        api.logging().logToOutput("  - Subdomain Enumeration (crt.sh)");
        api.logging().logToOutput("  - Security Headers Verification");
        api.logging().logToOutput("  - Technology Detection");
        api.logging().logToOutput("  - Shodan Server Information");
        api.logging().logToOutput("  - BurpSuite Issues Integration");
        api.logging().logToOutput(BANNER_SEPARATOR);
    }
}
