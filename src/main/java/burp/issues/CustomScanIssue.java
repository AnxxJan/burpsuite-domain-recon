package burp.issues;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import java.util.Locale;

/**
 * Custom implementation to create custom audit issues in Burp Suite using Montoya API
 * Note: Montoya API uses builder pattern instead of implementing IScanIssue interface
 */
public final class CustomScanIssue {
    
    // Private constructor to prevent instantiation of this utility class
    private CustomScanIssue() {
        throw new IllegalStateException("Utility class - do not instantiate");
    }
    
    /**
     * Convert severity string to AuditIssueSeverity enum
     */
    private static AuditIssueSeverity parseSeverity(String severity) {
        switch (severity.toLowerCase(Locale.ROOT)) {
            case "high":
                return AuditIssueSeverity.HIGH;
            case "medium":
                return AuditIssueSeverity.MEDIUM;
            case "low":
                return AuditIssueSeverity.LOW;
            case "information":
            default:
                return AuditIssueSeverity.INFORMATION;
        }
    }
    
    /**
     * Convert confidence string to AuditIssueConfidence enum
     */
    private static AuditIssueConfidence parseConfidence(String confidence) {
        switch (confidence.toLowerCase(Locale.ROOT)) {
            case "certain":
                return AuditIssueConfidence.CERTAIN;
            case "firm":
                return AuditIssueConfidence.FIRM;
            case "tentative":
            default:
                return AuditIssueConfidence.TENTATIVE;
        }
    }
    
    /**
     * Create a custom audit issue using Montoya API builder pattern
     * 
     * @param name Issue name
     * @param detail Issue detail/description
     * @param remediation Remediation information (can be null)
     * @param baseRequestResponse The HTTP message that triggered the issue (can be null)
     * @param severity Severity level: "High", "Medium", "Low", or "Information"
     * @param confidence Confidence level: "Certain", "Firm", or "Tentative"
     * @return AuditIssue instance ready to be added to Burp
     */
    public static AuditIssue create(
            String name,
            String detail,
            String remediation,
            HttpRequestResponse baseRequestResponse,
            String severity,
            String confidence) {
        
        // Convert severity and confidence strings to enums
        AuditIssueSeverity auditSeverity = parseSeverity(severity);
        AuditIssueConfidence auditConfidence = parseConfidence(confidence);
        
        // Build the audit issue using Montoya API builder pattern
        // Extract URL from request if available
        String url = null;
        if (baseRequestResponse != null && baseRequestResponse.request() != null) {
            url = baseRequestResponse.request().url();
        }
        
        return AuditIssue.auditIssue(
            name,                              // Issue name
            detail,                            // Issue detail
            remediation,                       // Remediation (can be null)
            url,                               // URL as string
            auditSeverity,                     // Severity
            auditConfidence,                   // Confidence
            null,                              // Background (not used)
            null,                              // Remediation background (not used)
            auditSeverity,                     // Also used as impact
            baseRequestResponse                // Base request-response (single vararg)
        );
    }
    
    /**
     * Create a custom audit issue without HTTP message
     */
    public static AuditIssue create(
            String name,
            String detail,
            String remediation,
            String url,
            String severity,
            String confidence) {
        
        // Convert severity and confidence strings to enums
        AuditIssueSeverity auditSeverity = parseSeverity(severity);
        AuditIssueConfidence auditConfidence = parseConfidence(confidence);
        
        // Build the audit issue using Montoya API builder pattern
        return AuditIssue.auditIssue(
            name,                              // Issue name
            detail,                            // Issue detail
            remediation,                       // Remediation (can be null)
            url,                               // URL as string
            auditSeverity,                     // Severity
            auditConfidence,                   // Confidence
            null,                              // Background (not used)
            null,                              // Remediation background (not used)
            auditSeverity,                     // Also used as impact
            (HttpRequestResponse) null         // No base request-response (typed null)
        );
    }
}
