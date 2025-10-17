package burp.scanner;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * SSL/TLS Security Scanner
 * Checks certificate validity, hostname matching, expiration, and protocol versions
 */
public class SSLScanner {
    
    // Severity level constants
    private static final String SEVERITY_HIGH = "High";
    private static final String SEVERITY_MEDIUM = "Medium";
    private static final String SEVERITY_LOW = "Low";
    
    public SSLInfo scanSSL(String domain) {
        SSLInfo info = new SSLInfo(domain);
        
        try {
            @SuppressWarnings("deprecation")
            URL url = new URL("https://" + domain);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            
            // Connect to get SSL session
            conn.connect();
            
            // Get SSL session info
            SSLSession session = conn.getSSLSession().orElse(null);
            if (session == null) {
                info.addFinding("SSL Session Error", "Could not establish SSL session", SEVERITY_LOW);
                return info;
            }
            
            // Check protocol and cipher suite
            checkProtocolVersion(session, info);
            checkCipherSuite(session, info);
            
            // Check certificates
            Certificate[] certs = session.getPeerCertificates();
            if (certs != null && certs.length > 0) {
                checkCertificate((X509Certificate) certs[0], domain, info);
            }
            
            conn.disconnect();
            
        } catch (IOException e) {
            info.addFinding("SSL Connection Failed",
                "Could not establish SSL connection: " + e.getMessage(),
                SEVERITY_LOW);
        } catch (Exception e) {
            info.addFinding("SSL Check Error",
                "Error checking SSL: " + e.getMessage(),
                SEVERITY_LOW);
        }
        
        return info;
    }
    
    /**
     * Check SSL/TLS protocol version for security issues
     */
    private void checkProtocolVersion(SSLSession session, SSLInfo info) {
        String protocol = session.getProtocol();
        info.setProtocol(protocol);
        
        if ("TLSv1".equals(protocol) || "TLSv1.0".equals(protocol) || "SSLv3".equals(protocol)) {
            info.addFinding("Weak TLS Version",
                "Server supports " + protocol + " which is deprecated and insecure",
                SEVERITY_HIGH);
        } else if ("TLSv1.1".equals(protocol)) {
            info.addFinding("Old TLS Version",
                "Server uses TLS 1.1. Consider upgrading to TLS 1.2 or 1.3",
                SEVERITY_MEDIUM);
        }
    }
    
    /**
     * Check cipher suite for weak algorithms
     */
    private void checkCipherSuite(SSLSession session, SSLInfo info) {
        String cipherSuite = session.getCipherSuite();
        info.setCipherSuite(cipherSuite);
        
        if (cipherSuite.contains("NULL") || cipherSuite.contains("EXPORT") || 
            cipherSuite.contains("DES") || cipherSuite.contains("MD5") ||
            cipherSuite.contains("RC4")) {
            info.addFinding("Weak Cipher Suite",
                "Server uses weak cipher: " + cipherSuite,
                SEVERITY_HIGH);
        }
    }
    
    /**
     * Check certificate validity, hostname matching, and other certificate properties
     */
    private void checkCertificate(X509Certificate cert, String domain, SSLInfo info) {
        // Certificate issuer and subject
        info.setIssuer(cert.getIssuerX500Principal().getName());
        info.setSubject(cert.getSubjectX500Principal().getName());
        
        // Validity dates
        Date notBefore = cert.getNotBefore();
        Date notAfter = cert.getNotAfter();
        info.setValidFrom(notBefore.toString());
        info.setValidUntil(notAfter.toString());
        
        // Check validity and expiration
        checkCertificateValidity(cert, notBefore, notAfter, info);
        
        // Check hostname matching
        checkHostnameMatch(cert, domain, info);
        
        // Check for self-signed certificate
        if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
            info.setSelfSigned(true);
            info.addFinding("Self-Signed Certificate",
                "Server uses a self-signed certificate",
                SEVERITY_MEDIUM);
        }
    }
    
    /**
     * Check certificate validity and expiration dates
     */
    private void checkCertificateValidity(X509Certificate cert, Date notBefore, Date notAfter, SSLInfo info) {
        try {
            cert.checkValidity();
            info.setValid(true);
        } catch (CertificateExpiredException e) {
            info.setValid(false);
            info.addFinding("Certificate Expired",
                "SSL certificate expired on " + notAfter,
                SEVERITY_HIGH);
        } catch (CertificateNotYetValidException e) {
            info.setValid(false);
            info.addFinding("Certificate Not Yet Valid",
                "SSL certificate not valid until " + notBefore,
                SEVERITY_HIGH);
        }
        
        // Check expiration warning (within 30 days)
        long daysUntilExpiry = (notAfter.getTime() - System.currentTimeMillis()) / (1000 * 60 * 60 * 24);
        if (daysUntilExpiry > 0 && daysUntilExpiry < 30) {
            info.addFinding("Certificate Expiring Soon",
                "SSL certificate expires in " + daysUntilExpiry + " days",
                SEVERITY_MEDIUM);
        }
    }
    
    /**
     * Check if certificate hostname matches the domain
     */
    private void checkHostnameMatch(X509Certificate cert, String domain, SSLInfo info) {
        Collection<List<?>> altNames = getSubjectAlternativeNames(cert);
        boolean hostnameMatches = false;
        String cn = getCommonName(cert.getSubjectX500Principal().getName());
        
        // Check common name
        if (cn != null && matchesHostname(cn, domain)) {
            hostnameMatches = true;
        }
        
        // Check alternative names
        if (!hostnameMatches && !altNames.isEmpty()) {
            hostnameMatches = checkAlternativeNames(altNames, domain);
        }
        
        info.setHostnameMatch(hostnameMatches);
        if (!hostnameMatches) {
            info.addFinding("Hostname Mismatch",
                "Certificate hostname does not match domain. CN: " + cn,
                SEVERITY_HIGH);
        }
    }
    
    /**
     * Get subject alternative names from certificate
     */
    private Collection<List<?>> getSubjectAlternativeNames(X509Certificate cert) {
        try {
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            return altNames != null ? altNames : Collections.emptyList();
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }
    
    /**
     * Check if any alternative name matches the domain
     */
    private boolean checkAlternativeNames(Collection<List<?>> altNames, String domain) {
        for (List<?> altName : altNames) {
            if (altName.size() >= 2) {
                String name = (String) altName.get(1);
                if (matchesHostname(name, domain)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Check if a hostname pattern matches the domain
     */
    private boolean matchesHostname(String hostname, String domain) {
        return hostname.equals(domain) || 
               hostname.equals("*." + domain) || 
               (hostname.startsWith("*.") && domain.endsWith(hostname.substring(1)));
    }
    
    private String getCommonName(String dn) {
        String[] parts = dn.split(",");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return null;
    }
    
    /**
     * SSL/TLS information container
     */
    public static class SSLInfo {
        private String domain;
        private String protocol;
        private String cipherSuite;
        private String issuer;
        private String subject;
        private String validFrom;
        private String validUntil;
        private boolean isValid;
        private boolean hostnameMatch;
        private boolean selfSigned;
        private List<SecurityFinding> findings;
        
        public SSLInfo(String domain) {
            this.domain = domain;
            this.findings = new ArrayList<>();
        }
        
        // Getters
        public String getDomain() { return domain; }
        public String getProtocol() { return protocol; }
        public String getCipherSuite() { return cipherSuite; }
        public String getIssuer() { return issuer; }
        public String getSubject() { return subject; }
        public String getValidFrom() { return validFrom; }
        public String getValidUntil() { return validUntil; }
        public boolean isValid() { return isValid; }
        public boolean isHostnameMatch() { return hostnameMatch; }
        public boolean isSelfSigned() { return selfSigned; }
        public List<SecurityFinding> getFindings() { return findings; }
        
        // Setters
        public void setProtocol(String protocol) { this.protocol = protocol; }
        public void setCipherSuite(String cipherSuite) { this.cipherSuite = cipherSuite; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public void setSubject(String subject) { this.subject = subject; }
        public void setValidFrom(String validFrom) { this.validFrom = validFrom; }
        public void setValidUntil(String validUntil) { this.validUntil = validUntil; }
        public void setValid(boolean valid) { isValid = valid; }
        public void setHostnameMatch(boolean hostnameMatch) { this.hostnameMatch = hostnameMatch; }
        public void setSelfSigned(boolean selfSigned) { this.selfSigned = selfSigned; }
        
        public void addFinding(String title, String description, String severity) {
            findings.add(new SecurityFinding(title, description, severity));
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
