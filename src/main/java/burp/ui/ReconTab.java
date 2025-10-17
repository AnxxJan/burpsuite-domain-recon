package burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.scanner.*;
import burp.issues.CustomScanIssue;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.net.URI;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main UI tab for Domain Reconnaissance Suite
 * 
 * Note on memory management for large projects:
 * - This extension does NOT keep references to HttpRequestResponse objects
 * - Only processed data (strings, scan results) are stored in memory
 * - Maximum results limit prevents OOM in large scans
 * - Use "Clear Results" button to free memory if needed
 */
public class ReconTab extends JPanel {
    // Memory management: Limit stored results to prevent OOM in very large scans
    private static final int MAX_STORED_DOMAINS = 10000;
    private static final int WARN_THRESHOLD = 8000;
    
    private transient MontoyaApi api;
    
    private transient SubdomainEnumerator subdomainEnumerator;
    private transient SecurityHeadersScanner headersScanner;
    private transient TechnologyDetector techDetector;
    private transient ShodanScanner shodanScanner;
    private transient WordPressScanner wpScanScanner;
    private transient SSLScanner sslScanner;
    private transient HTTPMethodsScanner httpMethodsScanner;
    private transient SensitiveFilesScanner sensitiveFilesScanner;
    private transient SubdomainTakeoverScanner takeoverScanner;
    
    private JTextField domainField;
    private JTextField shodanApiKeyField;
    private JButton scanButton;
    private JButton stopButton;
    private JButton skipDomainButton;
    private JProgressBar progressBar;
    private JTextArea logArea;
    
    // Configuration fields
    private JTextField customDictionaryField;
    
    // Main scan module checkboxes
    private JCheckBox enableSubdomainEnumeration;
    private JCheckBox scanDiscoveredSubdomains;
    private JCheckBox enableSecurityHeaders;
    private JCheckBox enableTechnologyDetection;
    private JCheckBox enableShodan;
    private JCheckBox enableWordPress;
    private JCheckBox enableSSL;
    private JCheckBox enableHTTPMethods;
    private JCheckBox enableSensitiveFiles;
    private JCheckBox enableSubdomainTakeover;
    
    // WPScan module checkboxes
    private Map<WordPressScanner.ScanModule, JCheckBox> wpScanModules = new EnumMap<>(WordPressScanner.ScanModule.class);
    
    private DefaultTableModel mainTableModel;
    private transient TableRowSorter<DefaultTableModel> tableSorter;
    
    private JTextArea technologiesDetailArea;
    private JTextArea headersDetailArea;
    private JTextArea summaryDetailArea;
    private JTextArea shodanDetailArea;
    private JTextArea wpScanDetailArea;
    private JTextArea sslDetailArea;
    private JTextArea httpMethodsDetailArea;
    private JTextArea sensitiveFilesDetailArea;
    private JTextArea subdomainTakeoverDetailArea;
    
    private Set<String> discoveredSubdomains = new HashSet<>();
    private transient Map<String, DomainInfo> domainData = new HashMap<>();
    
    private AtomicBoolean scanRunning = new AtomicBoolean(false);
    private AtomicBoolean shouldStop = new AtomicBoolean(false);
    private AtomicBoolean skipCurrentDomain = new AtomicBoolean(false);
    private volatile String currentScanningDomain = null;
    
    // UI String Constants - Used for display formatting
    private static final String SEPARATOR_LINE = "═══════════════════════════════════════════════════════";
    private static final String SEPARATOR_LINE_NEWLINE = SEPARATOR_LINE + "\n";
    private static final String SEPARATOR_LINE_DOUBLE_NEWLINE = SEPARATOR_LINE + "\n\n";
    private static final String STATUS_ACTIVE = "✓ Active";
    private static final String STATUS_INACTIVE = "✗ Inactive";
    private static final String STATUS_YES = "✓ Yes";
    private static final String SECURITY_FINDINGS_PREFIX = "▼ SECURITY FINDINGS (";
    
    // Severity constants
    private static final String SEVERITY_HIGH = "High";
    private static final String SEVERITY_MEDIUM = "Medium";
    private static final String SEVERITY_LOW = "Low";
    private static final String SEVERITY_INFORMATION = "Information";
    private static final String SEVERITY_CERTAIN = "Certain";
    private static final String MEDIUM_LOWERCASE = "medium";
    private static final String MEDIUM_CAPITALIZED = "Medium";
    
    // HTML/Report constants
    private static final String HTML_TABLE_HEADER_ROW = "                <tr><th>Severity</th><th>Issue</th><th>Details</th></tr>";
    private static final String HTML_TABLE_ROW_START = "                <tr><td><span class='badge ";
    private static final String HTML_BADGE_INFO = "badge-info";
    private static final String HTML_BADGE_HIGH = "badge-high";
    private static final String HTML_BADGE_MEDIUM = "badge-medium";
    private static final String HTML_BADGE_LOW = "badge-low";
    private static final String HTML_SPAN_END_TD = "</span></td><td>";
    
    private static final String SKIPPED_BY_USER = "  └─ ⏭️  Skipped by user";
    private static final String SUMMARY_PREFIX = "Summary: ";
    private static final String ERROR_TITLE = "Error";
    private static final String UNKNOWN = "Unknown";
    private static final String HTTPS_PREFIX = "https://";
    private static final String BACKUP_KEYWORD = "backup";
    
    public ReconTab(MontoyaApi api, SubdomainEnumerator subdomainEnumerator,
                   SecurityHeadersScanner headersScanner,
                   TechnologyDetector techDetector,
                   ShodanScanner shodanScanner,
                   WordPressScanner wpScanScanner,
                   SSLScanner sslScanner,
                   HTTPMethodsScanner httpMethodsScanner,
                   SensitiveFilesScanner sensitiveFilesScanner,
                   SubdomainTakeoverScanner takeoverScanner) {
        this.api = api;
        this.subdomainEnumerator = subdomainEnumerator;
        this.headersScanner = headersScanner;
        this.techDetector = techDetector;
        this.shodanScanner = shodanScanner;
        this.wpScanScanner = wpScanScanner;
        this.sslScanner = sslScanner;
        this.httpMethodsScanner = httpMethodsScanner;
        this.sensitiveFilesScanner = sensitiveFilesScanner;
        this.takeoverScanner = takeoverScanner;
        
        initUI();
        loadSettings();
    }
    
    private void loadSettings() {
        // Load Shodan API key from extension settings
        String savedApiKey = api.persistence().extensionData().getString("shodan_api_key");
        if (savedApiKey != null && !savedApiKey.isEmpty()) {
            shodanApiKeyField.setText(savedApiKey);
            shodanScanner.setApiKey(savedApiKey);
        }
    }
    
    private void saveSettings() {
        // Save Shodan API key to extension settings
        String apiKey = shodanApiKeyField.getText().trim();
        api.persistence().extensionData().setString("shodan_api_key", apiKey);
    }
    
    private void initUI() {
        setLayout(new BorderLayout());
        
        // Top panel - Input
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Input panel - First row
        JPanel inputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        
        inputPanel.add(new JLabel("Target Domains:"));
        domainField = new JTextField(40);
        domainField.setToolTipText("Enter one or more domains separated by commas (e.g., example.com, test.com)");
        inputPanel.add(domainField);
        
        JButton loadDomainsButton = new JButton("📁 Load from file");
        loadDomainsButton.setToolTipText("Load domains from a text file (one domain per line)");
        loadDomainsButton.addActionListener(e -> loadDomainsFromFile());
        inputPanel.add(loadDomainsButton);
        
        scanButton = new JButton("Start Reconnaissance");
        scanButton.addActionListener(e -> startRecon());
        inputPanel.add(scanButton);
        
        stopButton = new JButton("Stop Scan");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopScan());
        inputPanel.add(stopButton);
        
        skipDomainButton = new JButton("Skip Current Domain");
        skipDomainButton.setEnabled(false);
        skipDomainButton.setToolTipText("Skip the current domain being scanned and move to the next one");
        skipDomainButton.addActionListener(e -> skipCurrentDomain());
        inputPanel.add(skipDomainButton);
        
        JButton clearButton = new JButton("Clear Results");
        clearButton.setToolTipText("Clear all scan results");
        clearButton.addActionListener(e -> clearResults());
        inputPanel.add(clearButton);
        
        // Options panel - Second row
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 20, 5));
        optionsPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        
        enableSubdomainEnumeration = new JCheckBox("🔍 Enable Subdomain Discovery");
        enableSubdomainEnumeration.setSelected(true);
        enableSubdomainEnumeration.setToolTipText("Enumerate subdomains using crt.sh, HackerTarget, and ThreatCrowd");
        optionsPanel.add(enableSubdomainEnumeration);
        
        JCheckBox scanDiscoveredSubdomains = new JCheckBox("📊 Scan Discovered Subdomains");
        scanDiscoveredSubdomains.setSelected(true);
        scanDiscoveredSubdomains.setToolTipText("If enabled, will scan all discovered subdomains. If disabled, only performs discovery without scanning");
        optionsPanel.add(scanDiscoveredSubdomains);
        
        // Store reference for later use
        this.scanDiscoveredSubdomains = scanDiscoveredSubdomains;
        
        // Add dependency: scanning requires enumeration to be enabled
        enableSubdomainEnumeration.addActionListener(e -> {
            if (!enableSubdomainEnumeration.isSelected()) {
                scanDiscoveredSubdomains.setSelected(false);
                scanDiscoveredSubdomains.setEnabled(false);
            } else {
                scanDiscoveredSubdomains.setEnabled(true);
            }
        });
        
        JPanel topContainer = new JPanel(new BorderLayout());
        topContainer.add(inputPanel, BorderLayout.NORTH);
        topContainer.add(optionsPanel, BorderLayout.CENTER);
        
        topPanel.add(topContainer, BorderLayout.NORTH);
        
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        topPanel.add(progressBar, BorderLayout.SOUTH);
        
        add(topPanel, BorderLayout.NORTH);
        
        // Center panel - Horizontal split pane (left: results tabs, right: details tabs)
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplitPane.setResizeWeight(0.5);
        
        // Left side: Results table with tabs
        JTabbedPane resultsTabbedPane = new JTabbedPane();
        
        // Main table with subdomains
        JPanel mainPanel = new JPanel(new BorderLayout());
        String[] columns = {"Domain/Subdomain", "Status", "Technologies", "Security Headers", 
                           "Subdomain Takeover", "Sensitive Files", "WordPress"};
        mainTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        final JTable mainTable = new JTable(mainTableModel);
        mainTable.setAutoCreateRowSorter(true);
        mainTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        mainTable.setRowHeight(30);
        
        // Enable sorting and filtering
        tableSorter = new TableRowSorter<>(mainTableModel);
        mainTable.setRowSorter(tableSorter);
        
        // Add selection listener to update details panel
        mainTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = mainTable.getSelectedRow();
                if (selectedRow >= 0) {
                    int modelRow = mainTable.convertRowIndexToModel(selectedRow);
                    String domain = (String) mainTableModel.getValueAt(modelRow, 0);
                    updateDetailsPanel(domain);
                }
            }
        });
        
        // Add context menu (right-click)
        JPopupMenu contextMenu = new JPopupMenu();
        
        JMenuItem rescanItem = new JMenuItem("🔄 Rescan Domain");
        rescanItem.addActionListener(e -> {
            int selectedRow = mainTable.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = mainTable.convertRowIndexToModel(selectedRow);
                String domain = (String) mainTableModel.getValueAt(modelRow, 0);
                rescanDomain(domain);
            }
        });
        contextMenu.add(rescanItem);
        
        JMenuItem deleteItem = new JMenuItem("🗑️ Delete Result");
        deleteItem.addActionListener(e -> {
            int selectedRow = mainTable.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = mainTable.convertRowIndexToModel(selectedRow);
                String domain = (String) mainTableModel.getValueAt(modelRow, 0);
                deleteResult(domain);
            }
        });
        contextMenu.add(deleteItem);
        
        mainTable.setComponentPopupMenu(contextMenu);
        
        JScrollPane mainScrollPane = new JScrollPane(mainTable);
        mainPanel.add(mainScrollPane, BorderLayout.CENTER);
        
        // Add filter panel
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterPanel.add(new JLabel("Filter:"));
        JTextField filterField = new JTextField(20);
        filterField.addActionListener(e -> applyFilter(filterField.getText()));
        filterPanel.add(filterField);
        
        JButton filterButton = new JButton("Apply");
        filterButton.addActionListener(e -> applyFilter(filterField.getText()));
        filterPanel.add(filterButton);
        
        JButton clearFilterButton = new JButton("Clear");
        clearFilterButton.addActionListener(e -> {
            filterField.setText("");
            applyFilter("");
        });
        filterPanel.add(clearFilterButton);
        
        mainPanel.add(filterPanel, BorderLayout.NORTH);
        
        resultsTabbedPane.addTab("Results", mainPanel);
        
        // Log tab
        resultsTabbedPane.addTab("Log", createLogPanel());
        
        // Settings tab
        resultsTabbedPane.addTab("Settings", createSettingsPanel());
        
        mainSplitPane.setLeftComponent(resultsTabbedPane);
        
        // Right side: Details tabbed pane
        JTabbedPane detailsTabbedPane = new JTabbedPane();
        
        // Summary tab
        summaryDetailArea = new JTextArea();
        summaryDetailArea.setEditable(false);
        summaryDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        summaryDetailArea.setText("Select a domain to see details");
        JScrollPane summaryScrollPane = new JScrollPane(summaryDetailArea);
        detailsTabbedPane.addTab("Summary", summaryScrollPane);
        
        // Technologies tab
        technologiesDetailArea = new JTextArea();
        technologiesDetailArea.setEditable(false);
        technologiesDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane techScrollPane = new JScrollPane(technologiesDetailArea);
        detailsTabbedPane.addTab("Technologies", techScrollPane);
        
        // Security Headers tab
        headersDetailArea = new JTextArea();
        headersDetailArea.setEditable(false);
        headersDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane headersScrollPane = new JScrollPane(headersDetailArea);
        detailsTabbedPane.addTab("Security Headers", headersScrollPane);
        
        // Shodan tab
        shodanDetailArea = new JTextArea();
        shodanDetailArea.setEditable(false);
        shodanDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane shodanScrollPane = new JScrollPane(shodanDetailArea);
        detailsTabbedPane.addTab("Shodan Info", shodanScrollPane);
        
        // WordPress tab
        wpScanDetailArea = new JTextArea();
        wpScanDetailArea.setEditable(false);
        wpScanDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane wpScanScrollPane = new JScrollPane(wpScanDetailArea);
        detailsTabbedPane.addTab("WordPress", wpScanScrollPane);
        
        // SSL/TLS tab
        sslDetailArea = new JTextArea();
        sslDetailArea.setEditable(false);
        sslDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane sslScrollPane = new JScrollPane(sslDetailArea);
        detailsTabbedPane.addTab("SSL/TLS", sslScrollPane);
        
        // HTTP Methods tab
        httpMethodsDetailArea = new JTextArea();
        httpMethodsDetailArea.setEditable(false);
        httpMethodsDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane httpMethodsScrollPane = new JScrollPane(httpMethodsDetailArea);
        detailsTabbedPane.addTab("HTTP Methods", httpMethodsScrollPane);
        
        // Sensitive Files tab
        sensitiveFilesDetailArea = new JTextArea();
        sensitiveFilesDetailArea.setEditable(false);
        sensitiveFilesDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane sensitiveFilesScrollPane = new JScrollPane(sensitiveFilesDetailArea);
        detailsTabbedPane.addTab("Sensitive Files", sensitiveFilesScrollPane);
        
        // Subdomain Takeover tab
        subdomainTakeoverDetailArea = new JTextArea();
        subdomainTakeoverDetailArea.setEditable(false);
        subdomainTakeoverDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane subdomainTakeoverScrollPane = new JScrollPane(subdomainTakeoverDetailArea);
        detailsTabbedPane.addTab("Subdomain Takeover", subdomainTakeoverScrollPane);
        
        mainSplitPane.setRightComponent(detailsTabbedPane);
        
        add(mainSplitPane, BorderLayout.CENTER);
    }
    
    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        JPanel logControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearLogButton = new JButton("Clear Log");
        clearLogButton.addActionListener(e -> logArea.setText(""));
        logControlPanel.add(clearLogButton);
        
        panel.add(logControlPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Main container with vertical layout
        JPanel mainContainer = new JPanel();
        mainContainer.setLayout(new BoxLayout(mainContainer, BoxLayout.Y_AXIS));
        
        // ===== SCAN MODULES SECTION =====
        JPanel modulesSection = new JPanel(new BorderLayout());
        modulesSection.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(76, 175, 80), 2),
                "Scan Modules Configuration",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 14),
                new Color(76, 175, 80)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        // Panel for modules with two columns
        JPanel modulesGridPanel = new JPanel(new GridLayout(0, 2, 20, 5));
        
        // Column 1: Main Modules
        JPanel col1Panel = new JPanel();
        col1Panel.setLayout(new BoxLayout(col1Panel, BoxLayout.Y_AXIS));
        col1Panel.setBorder(BorderFactory.createTitledBorder("Main Scan Modules"));
        
        enableSecurityHeaders = new JCheckBox("Security Headers Analysis");
        enableSecurityHeaders.setToolTipText("Analyze HTTP security headers");
        enableSecurityHeaders.setSelected(true);
        col1Panel.add(enableSecurityHeaders);
        col1Panel.add(Box.createVerticalStrut(5));
        
        enableTechnologyDetection = new JCheckBox("Technology Detection");
        enableTechnologyDetection.setToolTipText("Detect web technologies and frameworks");
        enableTechnologyDetection.setSelected(true);
        col1Panel.add(enableTechnologyDetection);
        col1Panel.add(Box.createVerticalStrut(5));
        
        enableShodan = new JCheckBox("Shodan Intelligence");
        enableShodan.setToolTipText("Gather server information from Shodan");
        enableShodan.setSelected(true);
        col1Panel.add(enableShodan);
        col1Panel.add(Box.createVerticalStrut(5));
        
        enableWordPress = new JCheckBox("WordPress Security Scan");
        enableWordPress.setToolTipText("Detect and scan WordPress installations");
        enableWordPress.setSelected(true);
        col1Panel.add(enableWordPress);
        col1Panel.add(Box.createVerticalStrut(5));
        
        enableSSL = new JCheckBox("SSL/TLS Analysis");
        enableSSL.setToolTipText("Check SSL/TLS certificate and protocol security");
        enableSSL.setSelected(true);
        col1Panel.add(enableSSL);
        col1Panel.add(Box.createVerticalStrut(5));
        
        enableHTTPMethods = new JCheckBox("HTTP Methods Check");
        enableHTTPMethods.setToolTipText("Test for dangerous HTTP methods (PUT, DELETE, TRACE)");
        enableHTTPMethods.setSelected(true);
        col1Panel.add(enableHTTPMethods);
        col1Panel.add(Box.createVerticalStrut(5));
        
        enableSensitiveFiles = new JCheckBox("Sensitive Files Discovery");
        enableSensitiveFiles.setToolTipText("Check for exposed sensitive files and directories");
        enableSensitiveFiles.setSelected(true);
        col1Panel.add(enableSensitiveFiles);
        col1Panel.add(Box.createVerticalStrut(5));
        
        enableSubdomainTakeover = new JCheckBox("Subdomain Takeover Detection");
        enableSubdomainTakeover.setToolTipText("Detect subdomain takeover vulnerabilities (unclaimed services, expired domains)");
        enableSubdomainTakeover.setSelected(true);
        col1Panel.add(enableSubdomainTakeover);
        
        // Column 2: WordPress Modules
        JPanel col2Panel = new JPanel();
        col2Panel.setLayout(new BoxLayout(col2Panel, BoxLayout.Y_AXIS));
        col2Panel.setBorder(BorderFactory.createTitledBorder("WordPress Scan Modules"));
        
        for (WordPressScanner.ScanModule module : WordPressScanner.ScanModule.values()) {
            JCheckBox moduleCheckbox = new JCheckBox(module.getName());
            moduleCheckbox.setToolTipText(module.getDescription());
            moduleCheckbox.setSelected(true);
            wpScanModules.put(module, moduleCheckbox);
            col2Panel.add(moduleCheckbox);
            col2Panel.add(Box.createVerticalStrut(5));
        }
        
        modulesGridPanel.add(col1Panel);
        modulesGridPanel.add(col2Panel);
        
        // Wrap in scroll pane
        JScrollPane modulesScrollPane = new JScrollPane(modulesGridPanel);
        modulesScrollPane.setPreferredSize(new Dimension(0, 280));
        modulesScrollPane.setBorder(null);
        modulesScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        
        modulesSection.add(modulesScrollPane, BorderLayout.CENTER);
        mainContainer.add(modulesSection);
        mainContainer.add(Box.createVerticalStrut(15));
        
        // ===== NETWORK CONFIGURATION SECTION =====
        JPanel networkSection = new JPanel(new BorderLayout());
        networkSection.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(255, 87, 34), 2),
                "Network & Performance Configuration (All traffic routes through Burp)",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 14),
                new Color(255, 87, 34)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        JPanel networkOptionsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints netGbc = new GridBagConstraints();
        netGbc.insets = new Insets(5, 5, 5, 5);
        netGbc.anchor = GridBagConstraints.WEST;
        netGbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Timeout configuration
        netGbc.gridx = 0;
        netGbc.gridy = 0;
        netGbc.weightx = 0.0;
        JLabel timeoutLabel = new JLabel("⏱️ Request Timeout (seconds):");
        timeoutLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        networkOptionsPanel.add(timeoutLabel, netGbc);
        
        netGbc.gridx = 1;
        netGbc.weightx = 1.0;
    // Default timeout reduced to 5 seconds for more cautious behavior
    JSpinner timeoutSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 120, 1));
    timeoutSpinner.setToolTipText("Time to wait for server response (1-120 seconds). Default: 5s");
        ((JSpinner.DefaultEditor) timeoutSpinner.getEditor()).getTextField().setColumns(5);
        networkOptionsPanel.add(timeoutSpinner, netGbc);
        
        // Retry configuration
        netGbc.gridx = 0;
        netGbc.gridy = 1;
        netGbc.weightx = 0.0;
        JLabel retryLabel = new JLabel("🔄 Max Retries:");
        retryLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        networkOptionsPanel.add(retryLabel, netGbc);
        
        netGbc.gridx = 1;
        netGbc.weightx = 1.0;
    // Default max retries reduced to 1 to be more cautious
    JSpinner retrySpinner = new JSpinner(new SpinnerNumberModel(1, 0, 10, 1));
    retrySpinner.setToolTipText("Number of retry attempts on failure (0-10). Default: 1");
        ((JSpinner.DefaultEditor) retrySpinner.getEditor()).getTextField().setColumns(5);
        networkOptionsPanel.add(retrySpinner, netGbc);
        
        networkSection.add(networkOptionsPanel, BorderLayout.CENTER);
        mainContainer.add(networkSection);
        mainContainer.add(Box.createVerticalStrut(15));
        
        // ===== SENSITIVE FILES DICTIONARY SECTION =====
        JPanel dictSection = new JPanel(new BorderLayout());
        dictSection.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(205, 220, 57), 2),
                "Sensitive Files Scanner - Custom Dictionary",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 14),
                new Color(139, 195, 74)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        JPanel dictPanel = new JPanel(new BorderLayout(10, 5));
        
        JPanel dictInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JLabel dictLabel = new JLabel("📁 Custom Dictionary File:");
        dictLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        dictInputPanel.add(dictLabel);
        
        customDictionaryField = new JTextField(40);
        customDictionaryField.setToolTipText("<html>Path to a text file with additional paths to check (one per line)<br><b>⚠️ Note: Issues will NOT be created for custom dictionary results</b></html>");
        dictInputPanel.add(customDictionaryField);
        
        JButton browseDictButton = new JButton("Browse...");
        browseDictButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Select Custom Dictionary File");
            fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
                @Override
                public boolean accept(java.io.File f) {
                    return f.isDirectory() || f.getName().toLowerCase(Locale.ROOT).endsWith(".txt");
                }
                @Override
                public String getDescription() {
                    return "Text files (*.txt)";
                }
            });
            
            if (fileChooser.showOpenDialog(getBurpFrame()) == JFileChooser.APPROVE_OPTION) {
                customDictionaryField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        dictInputPanel.add(browseDictButton);
        
        dictPanel.add(dictInputPanel, BorderLayout.CENTER);
        
        dictSection.add(dictPanel, BorderLayout.CENTER);
        mainContainer.add(dictSection);
        mainContainer.add(Box.createVerticalStrut(15));
        
        // ===== EXPORT SECTION =====
        JPanel exportSection = new JPanel(new BorderLayout());
        exportSection.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(33, 150, 243), 2),
                "Export Results",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 14),
                new Color(33, 150, 243)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        JPanel exportButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        
        JButton exportCsvButton = new JButton("📊 Export to CSV");
        exportCsvButton.setToolTipText("Export scan results to CSV file");
        exportCsvButton.addActionListener(e -> exportToCSV());
        exportButtonPanel.add(exportCsvButton);
        
        JButton exportReportButton = new JButton("📄 Generate HTML Report");
        exportReportButton.setToolTipText("Generate detailed HTML report");
        exportReportButton.addActionListener(e -> exportToHTML());
        exportButtonPanel.add(exportReportButton);
        
        exportSection.add(exportButtonPanel, BorderLayout.CENTER);
        mainContainer.add(exportSection);
        mainContainer.add(Box.createVerticalStrut(15));
        
        // ===== API KEYS SECTION =====
        JPanel apiSection = new JPanel(new GridBagLayout());
        apiSection.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(255, 152, 0), 2),
                "API Keys Configuration",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 14),
                new Color(255, 152, 0)
            ),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Shodan API Key
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0.0;
        JLabel shodanLabel = new JLabel("🔍 Shodan:");
        shodanLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        apiSection.add(shodanLabel, gbc);
        
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        shodanApiKeyField = new JPasswordField(30);
        shodanApiKeyField.setToolTipText("Get your free API key at: https://account.shodan.io/register");
        shodanApiKeyField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { saveSettings(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { saveSettings(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { saveSettings(); }
        });
        apiSection.add(shodanApiKeyField, gbc);
        
        mainContainer.add(apiSection);
        
        // Wrap main container in scroll pane
        JScrollPane mainScrollPane = new JScrollPane(mainContainer);
        mainScrollPane.setBorder(null);
        mainScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        
        panel.add(mainScrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void applyFilter(String filterText) {
        if (filterText.trim().isEmpty()) {
            tableSorter.setRowFilter(null);
        } else {
            tableSorter.setRowFilter(RowFilter.regexFilter("(?i)" + filterText));
        }
    }
    
    /**
     * Updates the summary text area with domain information
     */
    private void updateSummarySection(String domain, DomainInfo info) {
        StringBuilder summary = new StringBuilder();
        summary.append(SEPARATOR_LINE).append("\n");
        summary.append("  DOMAIN: ").append(domain).append("\n");
        summary.append(SEPARATOR_LINE).append("\n\n");
        
        summary.append("Status: ").append(info.isAlive ? STATUS_ACTIVE : STATUS_INACTIVE);
        if (info.activePort > 0) {
            summary.append(" (Port: ").append(info.activePort).append(")");
        }
        summary.append("\n\n");
        
        // Technologies
        summary.append("Technologies Detected: ").append(info.technologies.size()).append("\n");
        
        // Security Headers
        summary.append("Security Headers Analyzed: ").append(info.headers.size()).append("\n");
        if (!info.headers.isEmpty()) {
            int present = 0;
            int missing = 0;
            for (SecurityHeadersScanner.HeaderInfo header : info.headers.values()) {
                if (header.isPresent()) {
                    present++;
                } else {
                    missing++;
                }
            }
            summary.append("  - Present: ").append(present).append("\n");
            summary.append("  - Missing: ").append(missing).append("\n");
        }
        
        // WordPress Detection
        summary.append("\nWordPress: ");
        if (info.isWordPress()) {
            summary.append("✅ YES");
            if (info.wpInfo.getVersion() != null) {
                summary.append(" (v").append(info.wpInfo.getVersion()).append(")");
            }
            summary.append("\n");
            if (!info.wpInfo.getFindings().isEmpty()) {
                summary.append("  - Security Findings: ").append(info.wpInfo.getFindings().size()).append("\n");
            }
        } else {
            summary.append("NO\n");
        }
        
        // Sensitive Files
        if (info.sensitiveFilesInfo != null) {
            int filesCount = info.sensitiveFilesInfo.getExposedFiles().size();
            summary.append("Sensitive Files Exposed: ");
            if (filesCount == 0) {
                summary.append("✅ 0");
            } else if (filesCount <= 5) {
                summary.append("⚠️ ").append(filesCount);
            } else {
                summary.append("🔴 ").append(filesCount);
            }
            summary.append("\n");
        }
        
        // Subdomain Takeover
        if (info.takeoverInfo != null) {
            summary.append("Subdomain Takeover: ");
            if (info.takeoverInfo.isVulnerable()) {
                summary.append("🔴 VULNERABLE\n");
                if (info.takeoverInfo.getDetectedService() != null) {
                    summary.append("  - Service: ").append(info.takeoverInfo.getDetectedService()).append("\n");
                }
            } else if (info.takeoverInfo.isCnameMatchesVulnerableService()) {
                summary.append("⚠️ POTENTIAL\n");
            } else {
                summary.append("✅ NO\n");
            }
        }
        
        summaryDetailArea.setText(summary.toString());
    }
    
    /**
     * Updates the technologies text area with detected technologies
     */
    private void updateTechnologiesSection(DomainInfo info) {
        StringBuilder tech = new StringBuilder();
        tech.append(SEPARATOR_LINE).append("\n");
        tech.append("  TECHNOLOGIES DETECTED\n");
        tech.append(SEPARATOR_LINE).append("\n\n");
        
        if (info.technologies.isEmpty()) {
            tech.append("No technologies detected\n");
        } else {
            // Group by category
            Map<String, List<String>> byCategory = new TreeMap<>();
            for (Map.Entry<String, String> entry : info.technologies.entrySet()) {
                String category = entry.getValue();
                String techName = entry.getKey();
                
                byCategory.computeIfAbsent(category, k -> new ArrayList<>()).add(techName);
            }
            
            for (Map.Entry<String, List<String>> entry : byCategory.entrySet()) {
                tech.append("▼ ").append(entry.getKey()).append("\n");
                for (String techName : entry.getValue()) {
                    tech.append("  • ").append(techName).append("\n");
                }
                tech.append("\n");
            }
        }
        
        technologiesDetailArea.setText(tech.toString());
        technologiesDetailArea.setCaretPosition(0);
    }
    
    /**
     * Updates the security headers text area
     */
    private void updateHeadersSection(DomainInfo info) {
        StringBuilder headers = new StringBuilder();
        headers.append(SEPARATOR_LINE).append("\n");
        headers.append("  SECURITY HEADERS ANALYSIS\n");
        headers.append(SEPARATOR_LINE).append("\n\n");
        
        if (info.headers.isEmpty()) {
            headers.append("No header information available\n");
        } else {
            for (SecurityHeadersScanner.HeaderInfo header : info.headers.values()) {
                if (header.isPresent()) {
                    headers.append("✓ ").append(header.getName()).append("\n");
                    headers.append("  Status: PRESENT\n");
                    if (header.getValue() != null && !header.getValue().isEmpty()) {
                        headers.append("  Value: ").append(header.getValue()).append("\n");
                    }
                } else {
                    headers.append("✗ ").append(header.getName()).append("\n");
                    headers.append("  Status: MISSING\n");
                    headers.append("  Recommendation: ").append(header.getRecommendation()).append("\n");
                }
                headers.append("\n");
            }
        }
        
        headersDetailArea.setText(headers.toString());
        headersDetailArea.setCaretPosition(0);
    }
    
    /**
     * Updates the Shodan information text area
     */
    private void updateShodanSection(DomainInfo info) {
        StringBuilder shodan = new StringBuilder();
        shodan.append(SEPARATOR_LINE).append("\n");
        shodan.append("  SHODAN SERVER INFORMATION\n");
        shodan.append(SEPARATOR_LINE).append("\n\n");
        
        if (info.serverInfo != null && info.serverInfo.isSuccess()) {
            shodan.append("IP Address: ").append(info.serverInfo.getIpAddress()).append("\n\n");
            
            if (info.serverInfo.getShodanInfo() != null) {
                ShodanScanner.ShodanInfo shodanInfo = info.serverInfo.getShodanInfo();
                shodan.append(shodanInfo.getDetailedInfo());
            }
        } else {
            shodan.append("Server information not available\n");
            if (info.serverInfo != null && info.serverInfo.getError() != null) {
                shodan.append("Error: ").append(info.serverInfo.getError()).append("\n");
            }
        }
        
        shodanDetailArea.setText(shodan.toString());
        shodanDetailArea.setCaretPosition(0);
    }
    
    private void updateDetailsPanel(String domain) {
        DomainInfo info = domainData.get(domain);
        
        if (info == null) {
            summaryDetailArea.setText("No details available for: " + domain);
            technologiesDetailArea.setText("");
            headersDetailArea.setText("");
            return;
        }
        
        // Update each section using helper methods
        updateSummarySection(domain, info);
        updateTechnologiesSection(info);
        updateHeadersSection(info);
        updateShodanSection(info);
        updateWordPressSection(info);
        updateSSLSection(info);
        updateHTTPMethodsSection(info);
        updateSensitiveFilesSection(info);
    }
    
    /**
     * Updates the WordPress scan results text area
     */
    private void updateWordPressSection(DomainInfo info) {
        StringBuilder wp = new StringBuilder();
        wp.append(SEPARATOR_LINE).append("\n");
        wp.append("  WORDPRESS SCAN RESULTS\n");
        wp.append(SEPARATOR_LINE).append("\n\n");
        
        if (info.wpInfo != null && info.wpInfo.isWordPress()) {
            appendWordPressDetails(wp, info.wpInfo);
        } else {
            wp.append("Not a WordPress site\n");
        }
        
        wpScanDetailArea.setText(wp.toString());
        wpScanDetailArea.setCaretPosition(0);
    }
    
    /**
     * Appends WordPress details to the string builder
     */
    private void appendWordPressDetails(StringBuilder wp, WordPressScanner.WordPressInfo wpInfo) {
        wp.append("Status: ✓ WordPress Detected\n");
        if (wpInfo.getVersion() != null) {
            wp.append("Version: ").append(wpInfo.getVersion()).append("\n");
        }
        wp.append("\n");
        
        appendWordPressThemes(wp, wpInfo);
        appendWordPressPlugins(wp, wpInfo);
        appendWordPressUsers(wp, wpInfo);
        appendWordPressFindings(wp, wpInfo);
    }
    
    /**
     * Appends WordPress themes section
     */
    private void appendWordPressThemes(StringBuilder wp, WordPressScanner.WordPressInfo wpInfo) {
        if (wpInfo.getThemes().isEmpty()) {
            return;
        }
        
        wp.append("▼ THEMES (").append(wpInfo.getThemes().size()).append(")\n");
        for (Map.Entry<String, String> theme : wpInfo.getThemes().entrySet()) {
            wp.append("  • ").append(theme.getKey());
            if (theme.getValue() != null) {
                wp.append(" (v").append(theme.getValue()).append(")");
            }
            wp.append("\n");
        }
        wp.append("\n");
    }
    
    /**
     * Appends WordPress plugins section
     */
    private void appendWordPressPlugins(StringBuilder wp, WordPressScanner.WordPressInfo wpInfo) {
        if (wpInfo.getPlugins().isEmpty()) {
            return;
        }
        
        wp.append("▼ PLUGINS (").append(wpInfo.getPlugins().size()).append(")\n");
        for (Map.Entry<String, String> plugin : wpInfo.getPlugins().entrySet()) {
            wp.append("  • ").append(plugin.getKey());
            if (plugin.getValue() != null) {
                wp.append(" (v").append(plugin.getValue()).append(")");
            }
            wp.append("\n");
        }
        wp.append("\n");
    }
    
    /**
     * Appends WordPress users section
     */
    private void appendWordPressUsers(StringBuilder wp, WordPressScanner.WordPressInfo wpInfo) {
        if (wpInfo.getUsers().isEmpty()) {
            return;
        }
        
        wp.append("▼ USERS (").append(wpInfo.getUsers().size()).append(")\n");
        for (String user : wpInfo.getUsers()) {
            wp.append("  • ").append(user).append("\n");
        }
        wp.append("\n");
    }
    
    /**
     * Appends WordPress security findings section
     */
    private void appendWordPressFindings(StringBuilder wp, WordPressScanner.WordPressInfo wpInfo) {
        if (wpInfo.getFindings().isEmpty()) {
            return;
        }
        
        wp.append(SECURITY_FINDINGS_PREFIX).append(wpInfo.getFindings().size()).append(")\n");
        for (WordPressScanner.SecurityFinding finding : wpInfo.getFindings()) {
            wp.append("  [").append(finding.getSeverity()).append("] ").append(finding.getTitle()).append("\n");
            wp.append("    ").append(finding.getDescription()).append("\n\n");
        }
    }
    
    /**
     * Updates the SSL/TLS security analysis text area
     */
    private void updateSSLSection(DomainInfo info) {
        // Update SSL/TLS Info
        StringBuilder ssl = new StringBuilder();
        ssl.append(SEPARATOR_LINE).append("\n");
        ssl.append("  SSL/TLS SECURITY ANALYSIS\n");
        ssl.append(SEPARATOR_LINE).append("\n\n");
        
        if (info.sslInfo != null) {
            appendSSLDetails(ssl, info.sslInfo);
        } else {
            ssl.append("SSL/TLS analysis not performed\n");
        }
        
        sslDetailArea.setText(ssl.toString());
        sslDetailArea.setCaretPosition(0);
    }
    
    /**
     * Appends SSL/TLS details to the string builder
     */
    private void appendSSLDetails(StringBuilder ssl, SSLScanner.SSLInfo sslInfo) {
        ssl.append("▼ CERTIFICATE INFORMATION\n\n");
        
        appendSSLBasicInfo(ssl, sslInfo);
        appendSSLValidityInfo(ssl, sslInfo);
        appendSSLStatusInfo(ssl, sslInfo);
        appendSSLFindings(ssl, sslInfo);
    }
    
    /**
     * Appends basic SSL information
     */
    private void appendSSLBasicInfo(StringBuilder ssl, SSLScanner.SSLInfo sslInfo) {
        if (sslInfo.getProtocol() != null) {
            ssl.append("Protocol: ").append(sslInfo.getProtocol()).append("\n");
        }
        
        if (sslInfo.getCipherSuite() != null) {
            ssl.append("Cipher Suite: ").append(sslInfo.getCipherSuite()).append("\n");
        }
        
        if (sslInfo.getIssuer() != null) {
            ssl.append("\nIssuer:\n  ").append(sslInfo.getIssuer()).append("\n");
        }
        
        if (sslInfo.getSubject() != null) {
            ssl.append("\nSubject:\n  ").append(sslInfo.getSubject()).append("\n");
        }
    }
    
    /**
     * Appends SSL validity information
     */
    private void appendSSLValidityInfo(StringBuilder ssl, SSLScanner.SSLInfo sslInfo) {
        if (sslInfo.getValidFrom() != null && sslInfo.getValidUntil() != null) {
            ssl.append("\nValidity Period:\n");
            ssl.append("  From: ").append(sslInfo.getValidFrom()).append("\n");
            ssl.append("  To:   ").append(sslInfo.getValidUntil()).append("\n");
        }
    }
    
    /**
     * Appends SSL status information
     */
    private void appendSSLStatusInfo(StringBuilder ssl, SSLScanner.SSLInfo sslInfo) {
        ssl.append("\nStatus:\n");
        ssl.append("  Valid: ").append(sslInfo.isValid() ? STATUS_YES : "✗ No").append("\n");
        ssl.append("  Hostname Match: ").append(sslInfo.isHostnameMatch() ? STATUS_YES : "✗ No").append("\n");
        
        if (sslInfo.isSelfSigned()) {
            ssl.append("  Self-Signed: ⚠️ Yes\n");
        }
    }
    
    /**
     * Appends SSL security findings
     */
    private void appendSSLFindings(StringBuilder ssl, SSLScanner.SSLInfo sslInfo) {
        if (sslInfo.getFindings().isEmpty()) {
            ssl.append("\n✅ No security issues detected\n");
            return;
        }
        
        ssl.append("\n");
        ssl.append(SEPARATOR_LINE).append("\n");
        ssl.append(SECURITY_FINDINGS_PREFIX).append(sslInfo.getFindings().size()).append(")\n");
        ssl.append(SEPARATOR_LINE).append("\n\n");
        
        for (SSLScanner.SecurityFinding finding : sslInfo.getFindings()) {
            String severityIcon = getSeverityIcon(finding.getSeverity());
            ssl.append(severityIcon).append(" [").append(finding.getSeverity().toUpperCase(Locale.ROOT)).append("] ")
               .append(finding.getTitle()).append("\n");
            ssl.append("   ").append(finding.getDescription()).append("\n\n");
        }
        
        appendSSLFindingsSummary(ssl, sslInfo);
    }
    
    /**
     * Appends SSL findings summary
     */
    private void appendSSLFindingsSummary(StringBuilder ssl, SSLScanner.SSLInfo sslInfo) {
        long highCount = sslInfo.getFindings().stream()
            .filter(f -> "High".equalsIgnoreCase(f.getSeverity())).count();
        long mediumCount = sslInfo.getFindings().stream()
            .filter(f -> MEDIUM_CAPITALIZED.equalsIgnoreCase(f.getSeverity())).count();
        long lowCount = sslInfo.getFindings().stream()
            .filter(f -> "Low".equalsIgnoreCase(f.getSeverity())).count();
        
        ssl.append(SUMMARY_PREFIX);
        if (highCount > 0) {
            ssl.append(highCount).append(" High, ");
        }
        if (mediumCount > 0) {
            ssl.append(mediumCount).append(" ").append(MEDIUM_CAPITALIZED).append(", ");
        }
        if (lowCount > 0) {
            ssl.append(lowCount).append(" Low");
        }
        ssl.append("\n");
    }
    
    /**
     * Returns the appropriate severity icon
     */
    private String getSeverityIcon(String severity) {
        switch (severity.toLowerCase(Locale.ROOT)) {
            case "high": return "🔴";
            case MEDIUM_LOWERCASE: return "🟡";
            case "low": return "🔵";
            default: return "ℹ️";
        }
    }
    
    /**
     * Updates the HTTP Methods security analysis text area
     */
    private void updateHTTPMethodsSection(DomainInfo info) {
        // Update HTTP Methods Info
        StringBuilder httpMethods = new StringBuilder();
        httpMethods.append(SEPARATOR_LINE).append("\n");
        httpMethods.append("  HTTP METHODS SECURITY ANALYSIS\n");
        httpMethods.append(SEPARATOR_LINE).append("\n\n");
        
        if (info.httpMethodsInfo != null) {
            appendHTTPMethodsDetails(httpMethods, info.httpMethodsInfo);
        } else {
            httpMethods.append("HTTP Methods analysis not performed\n");
        }
        
        httpMethodsDetailArea.setText(httpMethods.toString());
        httpMethodsDetailArea.setCaretPosition(0);
    }
    
    /**
     * Appends HTTP methods details to the string builder
     */
    private void appendHTTPMethodsDetails(StringBuilder httpMethods, HTTPMethodsScanner.HTTPMethodsInfo methodsInfo) {
        httpMethods.append("▼ METHODS TEST RESULTS\n\n");
        
        appendHTTPMethodsTable(httpMethods, methodsInfo);
        appendHTTPMethodsFindings(httpMethods, methodsInfo);
    }
    
    /**
     * Appends HTTP methods results table
     */
    private void appendHTTPMethodsTable(StringBuilder httpMethods, HTTPMethodsScanner.HTTPMethodsInfo methodsInfo) {
        httpMethods.append(String.format("%-10s %-15s %-35s %-10s\n", 
            "Method", "Status Code", "Status Message", "Allowed"));
        httpMethods.append("─".repeat(75)).append("\n");
        
        String[] methodOrder = {"OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "PATCH"};
        
        for (String method : methodOrder) {
            HTTPMethodsScanner.MethodResult result = methodsInfo.getMethodResults().get(method);
            if (result != null) {
                appendMethodResult(httpMethods, method, result);
            }
        }
    }
    
    /**
     * Appends a single HTTP method result
     */
    private void appendMethodResult(StringBuilder httpMethods, String method, HTTPMethodsScanner.MethodResult result) {
        String allowedIcon = result.isAllowed() ? "⚠️ YES" : "✓ NO";
        String statusMsg = result.getStatusMessage();
        if (statusMsg.length() > 33) {
            statusMsg = statusMsg.substring(0, 30) + "...";
        }
        
        httpMethods.append(String.format("%-10s %-15d %-35s %-10s\n",
            method,
            result.getStatusCode(),
            statusMsg,
            allowedIcon));
    }
    
    /**
     * Appends HTTP methods security findings
     */
    private void appendHTTPMethodsFindings(StringBuilder httpMethods, HTTPMethodsScanner.HTTPMethodsInfo methodsInfo) {
        if (methodsInfo.getFindings().isEmpty()) {
            httpMethods.append("\n✅ No dangerous methods detected\n");
            return;
        }
        
        httpMethods.append("\n");
        httpMethods.append(SEPARATOR_LINE).append("\n");
        httpMethods.append(SECURITY_FINDINGS_PREFIX).append(methodsInfo.getFindings().size()).append(")\n");
        httpMethods.append(SEPARATOR_LINE).append("\n\n");
        
        for (HTTPMethodsScanner.SecurityFinding finding : methodsInfo.getFindings()) {
            String severityIcon = getSeverityIcon(finding.getSeverity());
            httpMethods.append(severityIcon).append(" [").append(finding.getSeverity().toUpperCase(Locale.ROOT)).append("] ")
                       .append(finding.getTitle()).append("\n");
            httpMethods.append("   ").append(finding.getDescription()).append("\n\n");
        }
        
        appendHTTPMethodsFindingsSummary(httpMethods, methodsInfo);
    }
    
    /**
     * Appends HTTP methods findings summary
     */
    private void appendHTTPMethodsFindingsSummary(StringBuilder httpMethods, HTTPMethodsScanner.HTTPMethodsInfo methodsInfo) {
        long highCount = methodsInfo.getFindings().stream()
            .filter(f -> "High".equalsIgnoreCase(f.getSeverity())).count();
        long mediumCount = methodsInfo.getFindings().stream()
            .filter(f -> MEDIUM_CAPITALIZED.equalsIgnoreCase(f.getSeverity())).count();
        
        httpMethods.append(SUMMARY_PREFIX);
        if (highCount > 0) {
            httpMethods.append("⚠️ ").append(highCount).append(" dangerous method(s) enabled");
        } else if (mediumCount > 0) {
            httpMethods.append("⚠️ ").append(mediumCount).append(" potentially risky method(s)");
        } else {
            httpMethods.append("✅ No critical issues");
        }
        httpMethods.append("\n");
    }
    
    /**
     * Updates the Sensitive Files & Directories discovery text area
     */
    private void updateSensitiveFilesSection(DomainInfo info) {
        // Update Sensitive Files Info
        StringBuilder sensitiveFiles = new StringBuilder();
        sensitiveFiles.append(SEPARATOR_LINE).append("\n");
        sensitiveFiles.append("  SENSITIVE FILES & DIRECTORIES DISCOVERY\n");
        sensitiveFiles.append(SEPARATOR_LINE).append("\n\n");
        
        if (info.sensitiveFilesInfo != null) {
            appendSensitiveFilesDetails(sensitiveFiles, info.sensitiveFilesInfo);
        } else {
            sensitiveFiles.append("Sensitive files scan not performed\n");
        }
        
        sensitiveFilesDetailArea.setText(sensitiveFiles.toString());
        sensitiveFilesDetailArea.setCaretPosition(0);
        
        // Update Subdomain Takeover tab
        StringBuilder takeoverDetails = new StringBuilder();
        takeoverDetails.append(SEPARATOR_LINE).append("\n");
        takeoverDetails.append("  SUBDOMAIN TAKEOVER DETECTION\n");
        takeoverDetails.append(SEPARATOR_LINE).append("\n\n");
        
        if (info.takeoverInfo != null) {
            appendSubdomainTakeoverDetails(takeoverDetails, info.takeoverInfo);
        } else {
            takeoverDetails.append("Subdomain takeover scan not performed\n");
        }
        
        subdomainTakeoverDetailArea.setText(takeoverDetails.toString());
        subdomainTakeoverDetailArea.setCaretPosition(0);
    }
    
    /**
     * Appends subdomain takeover details to the string builder
     */
    private void appendSubdomainTakeoverDetails(StringBuilder details, SubdomainTakeoverScanner.TakeoverInfo takeoverInfo) {
        details.append("Subdomain: ").append(takeoverInfo.getSubdomain()).append("\n");
        details.append("DNS Resolvable: ").append(takeoverInfo.isDnsResolvable() ? "Yes" : "No").append("\n");
        
        if (takeoverInfo.getCnameTarget() != null) {
            details.append("CNAME Target: ").append(takeoverInfo.getCnameTarget()).append("\n");
        }
        
        if (takeoverInfo.getPotentialService() != null) {
            details.append("Potential Service: ").append(takeoverInfo.getPotentialService()).append("\n");
        }
        
        if (takeoverInfo.getDetectedService() != null) {
            details.append("Detected Service: ").append(takeoverInfo.getDetectedService()).append("\n");
        }
        
        if (takeoverInfo.getHttpStatusCode() > 0) {
            details.append("HTTP Status Code: ").append(takeoverInfo.getHttpStatusCode()).append("\n");
        }
        
        details.append("\nVulnerability Status: ");
        if (takeoverInfo.isVulnerable()) {
            details.append("⚠️  VULNERABLE - Subdomain takeover possible!\n");
        } else if (takeoverInfo.isCnameMatchesVulnerableService()) {
            details.append("⚠️  POTENTIAL - CNAME points to vulnerable service\n");
        } else {
            details.append("✓ No vulnerability detected\n");
        }
        
        if (takeoverInfo.hasFindings()) {
            details.append("\n───────────────────────────────────────────────────────\n");
            details.append("Findings (").append(takeoverInfo.getFindings().size()).append("):\n");
            details.append("───────────────────────────────────────────────────────\n\n");
            
            for (SubdomainTakeoverScanner.Finding finding : takeoverInfo.getFindings()) {
                details.append("[").append(finding.getSeverity()).append("] ").append(finding.getTitle()).append("\n");
                details.append("  ").append(finding.getDescription()).append("\n\n");
            }
        } else {
            details.append("\nNo findings to report.\n");
        }
        
        // Recommendations
        details.append("\n───────────────────────────────────────────────────────\n");
        details.append("Recommendations:\n");
        details.append("───────────────────────────────────────────────────────\n\n");
        details.append("1. Remove DNS records for unused subdomains\n");
        details.append("2. Reclaim or reactivate services before removing DNS records\n");
        details.append("3. Maintain an inventory of all subdomains and their services\n");
        details.append("4. Implement automated monitoring for subdomain status\n");
        details.append("5. Regularly audit DNS records for dangling entries\n");
        details.append("6. Use DNS CAA records to restrict certificate issuance\n");
    }
    
    /**
     * Appends sensitive files details to the string builder
     */
    private void appendSensitiveFilesDetails(StringBuilder sensitiveFiles, SensitiveFilesScanner.SensitiveFilesInfo filesInfo) {
        sensitiveFiles.append("Scan Summary:\n");
        sensitiveFiles.append("  Total Paths Scanned: 57\n");
        sensitiveFiles.append("  Files Exposed: ").append(filesInfo.getExposedFiles().size()).append("\n\n");
        
        if (filesInfo.getExposedFiles().isEmpty()) {
            sensitiveFiles.append("✅ No sensitive files exposed\n");
            return;
        }
        
        Map<String, List<Map.Entry<String, SensitiveFilesScanner.FileCheckResult>>> bySeverity = groupFilesBySeverity(filesInfo);
        appendFilesBySeverity(sensitiveFiles, bySeverity);
        appendSensitiveFilesSummary(sensitiveFiles, bySeverity);
        appendSecurityImplications(sensitiveFiles, filesInfo);
    }
    
    /**
     * Groups exposed files by severity
     */
    private Map<String, List<Map.Entry<String, SensitiveFilesScanner.FileCheckResult>>> groupFilesBySeverity(
            SensitiveFilesScanner.SensitiveFilesInfo filesInfo) {
        Map<String, List<Map.Entry<String, SensitiveFilesScanner.FileCheckResult>>> bySeverity = new LinkedHashMap<>();
        bySeverity.put(SEVERITY_HIGH, new ArrayList<>());
        bySeverity.put(SEVERITY_MEDIUM, new ArrayList<>());
        bySeverity.put(SEVERITY_LOW, new ArrayList<>());
        
        for (Map.Entry<String, SensitiveFilesScanner.FileCheckResult> entry : filesInfo.getExposedFiles().entrySet()) {
            String severity = determineFileSeverity(entry.getKey());
            bySeverity.get(severity).add(entry);
        }
        
        return bySeverity;
    }
    
    /**
     * Determines the severity of a file based on its path
     */
    private String determineFileSeverity(String path) {
        if (path.contains(".git") || path.contains(".env") || path.contains("wp-config") || 
            path.contains(".sql") || path.contains(BACKUP_KEYWORD)) {
            return SEVERITY_HIGH;
        } else if (path.contains("robots.txt") || path.contains("sitemap") || 
                   path.contains("package.json") || path.contains(".DS_Store")) {
            return SEVERITY_LOW;
        }
        return SEVERITY_MEDIUM;
    }
    
    /**
     * Appends files grouped by severity
     */
    private void appendFilesBySeverity(StringBuilder sensitiveFiles, 
            Map<String, List<Map.Entry<String, SensitiveFilesScanner.FileCheckResult>>> bySeverity) {
        for (String severity : new String[]{SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW}) {
            List<Map.Entry<String, SensitiveFilesScanner.FileCheckResult>> files = bySeverity.get(severity);
            
            if (!files.isEmpty()) {
                appendSeveritySection(sensitiveFiles, severity, files);
            }
        }
    }
    
    /**
     * Appends a single severity section with its files
     */
    private void appendSeveritySection(StringBuilder sensitiveFiles, String severity, 
            List<Map.Entry<String, SensitiveFilesScanner.FileCheckResult>> files) {
        String severityIcon = getSeverityIcon(severity);
        
        sensitiveFiles.append(SEPARATOR_LINE_NEWLINE);
        sensitiveFiles.append(severityIcon).append(" [").append(severity.toUpperCase(Locale.ROOT))
                     .append(" SEVERITY] - ").append(files.size()).append(" file(s)\n");
        sensitiveFiles.append(SEPARATOR_LINE_DOUBLE_NEWLINE);
        
        for (Map.Entry<String, SensitiveFilesScanner.FileCheckResult> entry : files) {
            appendFileResult(sensitiveFiles, entry);
        }
    }
    
    /**
     * Appends a single file result
     */
    private void appendFileResult(StringBuilder sensitiveFiles, 
            Map.Entry<String, SensitiveFilesScanner.FileCheckResult> entry) {
        SensitiveFilesScanner.FileCheckResult result = entry.getValue();
        sensitiveFiles.append("  ").append(entry.getKey()).append("\n");
        sensitiveFiles.append("    Status: ").append(result.getStatusCode());
        
        if (result.getContentLength() > 0) {
            sensitiveFiles.append(" | Size: ").append(formatFileSize(result.getContentLength()));
        }
        sensitiveFiles.append("\n\n");
    }
    
    /**
     * Appends sensitive files summary
     */
    private void appendSensitiveFilesSummary(StringBuilder sensitiveFiles, 
            Map<String, List<Map.Entry<String, SensitiveFilesScanner.FileCheckResult>>> bySeverity) {
        int highCount = bySeverity.get(SEVERITY_HIGH).size();
        int mediumCount = bySeverity.get(SEVERITY_MEDIUM).size();
        int lowCount = bySeverity.get(SEVERITY_LOW).size();
        
        sensitiveFiles.append(SEPARATOR_LINE_NEWLINE);
        sensitiveFiles.append(SUMMARY_PREFIX);
        if (highCount > 0) {
            sensitiveFiles.append("🔴 ").append(highCount).append(" critical, ");
        }
        if (mediumCount > 0) {
            sensitiveFiles.append("🟡 ").append(mediumCount).append(" ").append(MEDIUM_LOWERCASE).append(", ");
        }
        if (lowCount > 0) {
            sensitiveFiles.append("🔵 ").append(lowCount).append(" low");
        }
        sensitiveFiles.append("\n");
    }
    
    /**
     * Appends security implications section
     */
    private void appendSecurityImplications(StringBuilder sensitiveFiles, SensitiveFilesScanner.SensitiveFilesInfo filesInfo) {
        if (filesInfo.getFindings().isEmpty()) {
            return;
        }
        
        sensitiveFiles.append("\n▼ SECURITY IMPLICATIONS\n\n");
        for (SensitiveFilesScanner.SecurityFinding finding : filesInfo.getFindings()) {
            sensitiveFiles.append("  • ").append(finding.getTitle()).append("\n");
            sensitiveFiles.append("    ").append(finding.getDescription()).append("\n\n");
        }
    }
    
    private void stopScan() {
        shouldStop.set(true);
        log("==> User requested scan stop");
    }
    
    private void skipCurrentDomain() {
        skipCurrentDomain.set(true);
        if (currentScanningDomain != null) {
            log("==> User requested to skip current domain: " + currentScanningDomain);
        } else {
            log("==> User requested to skip current domain");
        }
    }
    
    private void loadDomainsFromFile() {
        JFileChooser fileChooser = createDomainFileChooser();
        
        if (fileChooser.showOpenDialog(getBurpFrame()) == JFileChooser.APPROVE_OPTION) {
            java.io.File file = fileChooser.getSelectedFile();
            processSelectedDomainFile(file);
        }
    }
    
    /**
     * Creates and configures the file chooser for domain files
     */
    private JFileChooser createDomainFileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Domain List File");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            @Override
            public boolean accept(java.io.File f) {
                return f.isDirectory() || f.getName().toLowerCase(Locale.ROOT).endsWith(".txt");
            }
            @Override
            public String getDescription() {
                return "Text files (*.txt)";
            }
        });
        return fileChooser;
    }
    
    /**
     * Processes the selected domain file and loads domains
     */
    private void processSelectedDomainFile(java.io.File file) {
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(file))) {
            DomainLoadResult result = readDomainsFromFile(reader);
            handleDomainLoadResult(result, file);
        } catch (java.io.IOException e) {
            handleFileLoadError(e);
        }
    }
    
    /**
     * Reads domains from the file reader
     */
    private DomainLoadResult readDomainsFromFile(java.io.BufferedReader reader) throws java.io.IOException {
        StringBuilder domains = new StringBuilder();
        String line;
        int count = 0;
        
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (isValidDomainLine(line)) {
                if (count > 0) {
                    domains.append(", ");
                }
                domains.append(line);
                count++;
            }
        }
        
        return new DomainLoadResult(domains.toString(), count);
    }
    
    /**
     * Checks if a line is a valid domain entry
     */
    private boolean isValidDomainLine(String line) {
        return !line.isEmpty() && !line.startsWith("#");
    }
    
    /**
     * Handles the result of loading domains from file
     */
    private void handleDomainLoadResult(DomainLoadResult result, java.io.File file) {
        if (result.count > 0) {
            domainField.setText(result.domains);
            log("[+] Loaded " + result.count + " domain(s) from file: " + file.getName());
            JOptionPane.showMessageDialog(getBurpFrame(),
                "Successfully loaded " + result.count + " domain(s) from file.",
                "Domains Loaded",
                JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(getBurpFrame(),
                "No valid domains found in the file.",
                "No Domains Found",
                JOptionPane.WARNING_MESSAGE);
        }
    }
    
    /**
     * Handles file loading errors
     */
    private void handleFileLoadError(java.io.IOException e) {
        log("[!] Error loading domains from file: " + e.getMessage());
        api.logging().logToError("File loading error: " + e.getMessage());
        JOptionPane.showMessageDialog(getBurpFrame(),
            "Error loading file: " + e.getMessage(),
            ERROR_TITLE,
            JOptionPane.ERROR_MESSAGE);
    }
    
    /**
     * Simple container for domain loading results
     */
    private static class DomainLoadResult {
        final String domains;
        final int count;
        
        DomainLoadResult(String domains, int count) {
            this.domains = domains;
            this.count = count;
        }
    }
    
    /**
     * Clear all scan results and free memory
     * Important for large projects to prevent memory buildup
     */
    private void clearResults() {
        int currentSize = domainData.size();
        int response = JOptionPane.showConfirmDialog(getBurpFrame(),
            "Clear all " + currentSize + " scan results?\n\n" +
            "This will free memory and reset all data.",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        
        if (response == JOptionPane.YES_OPTION) {
            mainTableModel.setRowCount(0);
            domainData.clear();
            discoveredSubdomains.clear(); // Also clear subdomain cache
            summaryDetailArea.setText("No data available");
            technologiesDetailArea.setText("");
            headersDetailArea.setText("");
            shodanDetailArea.setText("");
            wpScanDetailArea.setText("");
            sslDetailArea.setText("");
            httpMethodsDetailArea.setText("");
            sensitiveFilesDetailArea.setText("");
            log("[+] All results cleared (" + currentSize + " domains freed from memory)");
            
            // Memory will be reclaimed automatically by JVM when needed
            if (currentSize > 1000) {
                log("[*] " + currentSize + " domains cleared from memory");
            }
        }
    }
    
    private void deleteResult(String domain) {
        int response = JOptionPane.showConfirmDialog(getBurpFrame(),
            "Are you sure you want to delete the result for: " + domain + "?",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        
        if (response == JOptionPane.YES_OPTION) {
            // Remove from table
            for (int i = 0; i < mainTableModel.getRowCount(); i++) {
                String tableDomain = (String) mainTableModel.getValueAt(i, 0);
                if (tableDomain.equals(domain)) {
                    mainTableModel.removeRow(i);
                    break;
                }
            }
            
            // Remove from data map
            domainData.remove(domain);
            
            // Clear details if this domain was selected
            summaryDetailArea.setText("Select a domain to see details");
            technologiesDetailArea.setText("");
            headersDetailArea.setText("");
            shodanDetailArea.setText("");
            wpScanDetailArea.setText("");
            sslDetailArea.setText("");
            httpMethodsDetailArea.setText("");
            sensitiveFilesDetailArea.setText("");
            
            log("[+] Deleted result for: " + domain);
        }
    }
    
    private void rescanDomain(String domain) {
        if (scanRunning.get()) {
            JOptionPane.showMessageDialog(getBurpFrame(),
                "A scan is already in progress. Please wait for it to complete.",
                "Scan in Progress",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int response = JOptionPane.showConfirmDialog(getBurpFrame(),
            "Rescan domain: " + domain + "?",
            "Confirm Rescan",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.QUESTION_MESSAGE);
        
        if (response == JOptionPane.YES_OPTION) {
            // Set the domain in the input field and start scan
            domainField.setText(domain);
            // Disable subdomain enumeration for rescan (just rescan the specific domain)
            boolean wasEnumerationEnabled = enableSubdomainEnumeration.isSelected();
            enableSubdomainEnumeration.setSelected(false);
            
            log("[*] Rescanning domain: " + domain);
            startRecon();
            
            // Restore enumeration setting after scan starts
            enableSubdomainEnumeration.setSelected(wasEnumerationEnabled);
        }
    }
    
    /**
     * Scans a single subdomain and returns true if the loop should continue, false if it should break.
     * 
     * @param subdomain The subdomain to scan
     * @param currentCount Current scan count
     * @param total Total number of domains
     * @param customDictPath Custom dictionary path for sensitive files
     * @return true to continue loop, false to break
     */
    private boolean scanSingleDomain(String subdomain, int currentCount, int total, String customDictPath) {
        // Reset skip flag for new domain
        skipCurrentDomain.set(false);
        currentScanningDomain = subdomain;
        
        updateScanProgress(currentCount, total);
        log("[" + currentCount + "/" + total + "] Scanning: " + subdomain);
        
        // Check if subdomain is alive
        log("  └─ Checking if domain is alive...");
        boolean isAlive = subdomainEnumerator.isSubdomainAlive(subdomain);
        
        if (skipCurrentDomain.get()) {
            log(SKIPPED_BY_USER);
            return true;
        }
        
        DomainInfo info = new DomainInfo(subdomain);
        info.isAlive = isAlive;
        
        // Note: only standard HTTP/HTTPS ports are used to determine if a subdomain is alive
        
        log("  └─ Status: " + (isAlive ? STATUS_ACTIVE : STATUS_INACTIVE) + 
            (info.activePort > 0 ? " (port " + info.activePort + ")" : ""));
        
        String status = isAlive ? STATUS_ACTIVE : STATUS_INACTIVE;
        String techSummary = "N/A";
        String headersSummary = "N/A";
        
        if (isAlive) {
            // Perform all scans
            if (!performAllScans(subdomain, info, customDictPath)) {
                return true; // User skipped
            }
            
            // Process and log scan results
            String[] summaries = processScanResults(subdomain, info);
            techSummary = summaries[0];
            headersSummary = summaries[1];
        }
        
        // Check memory limits and add to results
        return addScanResultToTable(subdomain, info, status, techSummary, headersSummary);
    }
    
    /**
     * Updates the progress bar with current scan progress
     */
    private void updateScanProgress(int currentCount, int total) {
        final int progress = (currentCount * 100) / total;
        
        SwingUtilities.invokeLater(() -> {
            progressBar.setIndeterminate(false);
            progressBar.setValue(progress);
            progressBar.setString("Scanning " + currentCount + "/" + total + " domains...");
        });
    }
    
    /**
     * Performs all enabled scans on a domain
     * @return false if user skipped, true otherwise
     */
    private boolean performAllScans(String subdomain, DomainInfo info, String customDictPath) {
        return executeShodanScan(subdomain, info)
                && executeSecurityHeadersScan()
                && executeTechnologyDetectionScan()
                && executeWordPressScan(subdomain, info)
                && executeSSLScan(subdomain, info)
                && executeHTTPMethodsScan(subdomain, info)
                && executeSensitiveFilesScan(subdomain, info, customDictPath)
                && executeSubdomainTakeoverScan(subdomain, info);
    }
    
    /**
     * Executes Shodan scan if enabled
     * @return false if user skipped, true otherwise
     */
    private boolean executeShodanScan(String subdomain, DomainInfo info) {
        return !enableShodan.isSelected() || (!checkSkipAndLog() && performShodanScan(subdomain, info));
    }
    
    /**
     * Executes security headers scan if enabled
     * @return false if user skipped, true otherwise
     */
    private boolean executeSecurityHeadersScan() {
        if (!enableSecurityHeaders.isSelected()) {
            return true;
        }
        if (checkSkipAndLog()) {
            return false;
        }
        log("  └─ Scanning security headers...");
        return true;
    }
    
    /**
     * Executes technology detection scan if enabled
     * @return false if user skipped, true otherwise
     */
    private boolean executeTechnologyDetectionScan() {
        if (!enableTechnologyDetection.isSelected()) {
            return true;
        }
        if (checkSkipAndLog()) {
            return false;
        }
        log("  └─ Detecting technologies...");
        return true;
    }
    
    /**
     * Executes WordPress scan if enabled
     * @return false if user skipped, true otherwise
     */
    private boolean executeWordPressScan(String subdomain, DomainInfo info) {
        return !enableWordPress.isSelected() || (!checkSkipAndLog() && performWordPressScan(subdomain, info));
    }
    
    /**
     * Executes SSL/TLS scan if enabled
     * @return false if user skipped, true otherwise
     */
    private boolean executeSSLScan(String subdomain, DomainInfo info) {
        return !enableSSL.isSelected() || (!checkSkipAndLog() && performSSLScan(subdomain, info));
    }
    
    /**
     * Executes HTTP methods scan if enabled
     * @return false if user skipped, true otherwise
     */
    private boolean executeHTTPMethodsScan(String subdomain, DomainInfo info) {
        return !enableHTTPMethods.isSelected() || (!checkSkipAndLog() && performHTTPMethodsScan(subdomain, info));
    }
    
    /**
     * Executes sensitive files scan if enabled
     * @return false if user skipped, true otherwise
     */
    private boolean executeSensitiveFilesScan(String subdomain, DomainInfo info, String customDictPath) {
        return !enableSensitiveFiles.isSelected() || (!checkSkipAndLog() && performSensitiveFilesScan(subdomain, info, customDictPath));
    }
    
    /**
     * Executes subdomain takeover scan if enabled
     * @return false if user skipped, true otherwise
     */
    private boolean executeSubdomainTakeoverScan(String subdomain, DomainInfo info) {
        return !enableSubdomainTakeover.isSelected() || (!checkSkipAndLog() && performSubdomainTakeoverScan(subdomain, info));
    }
    
    /**
     * Checks if user requested to skip current domain and logs if so
     * @return true if skip was requested, false otherwise
     */
    private boolean checkSkipAndLog() {
        if (skipCurrentDomain.get()) {
            log(SKIPPED_BY_USER);
            return true;
        }
        return false;
    }
    
    /**
     * Performs Shodan scan on a domain
     * @return false if user skipped, true otherwise
     */
    private boolean performShodanScan(String subdomain, DomainInfo info) {
        if (shouldStop.get()) {
            return false;
        }
        
        log("  └─ Getting server information...");
        ShodanScanner.ServerInfo serverInfo = shodanScanner.getServerInfo(subdomain);
        info.serverInfo = serverInfo;
        
        if (shouldStop.get() || skipCurrentDomain.get()) {
            log(SKIPPED_BY_USER);
            return false;
        }
        
        if (serverInfo.isSuccess() && serverInfo.getShodanInfo() != null) {
            log("  └─ Shodan: " + serverInfo.getShodanInfo().getSummary());
            
            if (serverInfo.getShodanInfo().isSuccess()) {
                createShodanIssue(subdomain, serverInfo);
            }
        }
        
        return true;
    }
    
    /**
     * Performs WordPress scan on a domain
     * @return false if user skipped, true otherwise
     */
    private boolean performWordPressScan(String subdomain, DomainInfo info) {
        if (shouldStop.get()) {
            return false;
        }
        
        log("  └─ Checking for WordPress...");
        Set<WordPressScanner.ScanModule> enabledModules = getEnabledWPScanModules();
        WordPressScanner.WordPressInfo wpInfo = wpScanScanner.scanWordPress(subdomain, enabledModules);
        info.wpInfo = wpInfo;
        
        if (shouldStop.get() || skipCurrentDomain.get()) {
            log(SKIPPED_BY_USER);
            return false;
        }
        
        if (wpInfo.isWordPress()) {
            log("  └─ WordPress detected - Version: " + (wpInfo.getVersion() != null ? wpInfo.getVersion() : UNKNOWN));
            createWordPressIssue(subdomain, wpInfo);
        } else {
            log("  └─ Not a WordPress site");
        }
        
        return true;
    }
    
    /**
     * Performs SSL/TLS scan on a domain
     * @return false if user skipped, true otherwise
     */
    private boolean performSSLScan(String subdomain, DomainInfo info) {
        if (shouldStop.get()) {
            return false;
        }
        
        log("  └─ Analyzing SSL/TLS security...");
        SSLScanner.SSLInfo sslInfo = sslScanner.scanSSL(subdomain);
        info.sslInfo = sslInfo;
        
        if (shouldStop.get() || skipCurrentDomain.get()) {
            log(SKIPPED_BY_USER);
            return false;
        }
        
        if (sslInfo != null && !sslInfo.getFindings().isEmpty()) {
            log("  └─ SSL/TLS: " + sslInfo.getFindings().size() + " security finding(s)");
            createSSLIssue(subdomain, sslInfo);
        } else {
            log("  └─ SSL/TLS: No issues detected");
        }
        
        return true;
    }
    
    /**
     * Performs HTTP methods scan on a domain
     * @return false if user skipped, true otherwise
     */
    private boolean performHTTPMethodsScan(String subdomain, DomainInfo info) {
        if (shouldStop.get()) {
            return false;
        }
        
        log("  └─ Testing HTTP methods...");
        HTTPMethodsScanner.HTTPMethodsInfo httpMethodsInfo = httpMethodsScanner.scanHTTPMethods(subdomain);
        info.httpMethodsInfo = httpMethodsInfo;
        
        if (shouldStop.get() || skipCurrentDomain.get()) {
            log(SKIPPED_BY_USER);
            return false;
        }
        
        if (httpMethodsInfo != null && !httpMethodsInfo.getFindings().isEmpty()) {
            log("  └─ HTTP Methods: " + httpMethodsInfo.getFindings().size() + " security finding(s)");
            createHTTPMethodsIssue(subdomain, httpMethodsInfo);
        } else {
            log("  └─ HTTP Methods: No dangerous methods detected");
        }
        
        return true;
    }
    
    /**
     * Performs sensitive files scan on a domain
     * @return false if user skipped, true otherwise
     */
    private boolean performSensitiveFilesScan(String subdomain, DomainInfo info, String customDictPath) {
        if (shouldStop.get()) {
            return false;
        }
        
        log("  └─ Scanning for sensitive files...");
        
        if (!customDictPath.isEmpty()) {
            sensitiveFilesScanner.loadCustomDictionary(customDictPath);
            log("  └─ Loaded custom dictionary: " + customDictPath);
        }
        
        SensitiveFilesScanner.SensitiveFilesInfo sensitiveFilesInfo = sensitiveFilesScanner.scanSensitiveFiles(subdomain);
        info.sensitiveFilesInfo = sensitiveFilesInfo;
        
        if (shouldStop.get() || skipCurrentDomain.get()) {
            log(SKIPPED_BY_USER);
            return false;
        }
        
        if (sensitiveFilesInfo != null && !sensitiveFilesInfo.getExposedFiles().isEmpty()) {
            log("  └─ Sensitive Files: " + sensitiveFilesInfo.getExposedFiles().size() + " file(s) exposed");
            createSensitiveFilesIssue(subdomain, sensitiveFilesInfo);
        } else {
            log("  └─ Sensitive Files: No exposed files detected");
        }
        
        return true;
    }
    
    /**
     * Performs subdomain takeover scan on a domain
     * @return false if user skipped, true otherwise
     */
    private boolean performSubdomainTakeoverScan(String subdomain, DomainInfo info) {
        if (shouldStop.get()) {
            return false;
        }
        
        log("  └─ Checking for subdomain takeover vulnerabilities...");
        
        SubdomainTakeoverScanner.TakeoverInfo takeoverInfo = takeoverScanner.scanSubdomain(subdomain);
        info.takeoverInfo = takeoverInfo;
        
        if (shouldStop.get() || skipCurrentDomain.get()) {
            log(SKIPPED_BY_USER);
            return false;
        }
        
        if (takeoverInfo != null && takeoverInfo.hasFindings()) {
            String severity = takeoverInfo.isVulnerable() ? "VULNERABLE" : "Potential";
            log("  └─ Subdomain Takeover: " + severity + " - " + takeoverInfo.getFindings().size() + " finding(s)");
            if (takeoverInfo.isVulnerable()) {
                createSubdomainTakeoverIssue(subdomain, takeoverInfo);
            }
        } else {
            log("  └─ Subdomain Takeover: No vulnerabilities detected");
        }
        
        return true;
    }
    
    /**
     * Processes scan results and returns summaries
     * @return Array with [techSummary, headersSummary]
     */
    private String[] processScanResults(String subdomain, DomainInfo info) {
        String techSummary = "N/A";
        String headersSummary = "N/A";
        
        // Process security headers scan
        if (enableSecurityHeaders.isSelected()) {
            SecurityHeadersScanner.SecurityHeadersResult headersResult = headersScanner.scanSecurityHeaders(subdomain);
            if (headersResult != null && headersResult.isSuccess()) {
                info.headers = headersResult.getHeaders();
                headersSummary = headersResult.getSummary();
                log("  └─ Security headers: " + headersSummary);
                createUnifiedSecurityHeadersIssue(subdomain, headersResult);
            }
        }
        
        // Process technology detection scan
        if (enableTechnologyDetection.isSelected()) {
            TechnologyDetector.TechnologyDetectionResult techResult = techDetector.detectTechnologies(subdomain);
            if (techResult != null && techResult.isSuccess()) {
                info.technologies = techResult.getTechnologies();
                techSummary = buildTechnologySummary(info.technologies);
                log("  └─ Technologies: " + techSummary);
                createTechnologyIssue(subdomain, techResult);
            }
        }
        
        return new String[]{techSummary, headersSummary};
    }
    
    /**
     * Builds a summary string from detected technologies
     */
    private String buildTechnologySummary(Map<String, String> technologies) {
        StringBuilder techBuilder = new StringBuilder();
        int count = 0;
        
        for (Map.Entry<String, String> tech : technologies.entrySet()) {
            if (count > 0) {
                techBuilder.append(", ");
            }
            techBuilder.append(tech.getKey());
            count++;
            
            if (count >= 3) {
                techBuilder.append("... (+").append(technologies.size() - 3).append(" more)");
                break;
            }
        }
        
        String summary = techBuilder.toString();
        return summary.isEmpty() ? "None detected" : summary;
    }
    
    /**
     * Adds scan result to table and checks memory limits
     * @return true to continue scanning, false to stop
     */
    private boolean addScanResultToTable(String subdomain, DomainInfo info, String status, 
                                         String techSummary, String headersSummary) {
        // Memory management: Check if we're approaching the limit
        if (domainData.size() >= MAX_STORED_DOMAINS) {
            log("[!] WARNING: Maximum domain limit (" + MAX_STORED_DOMAINS + ") reached.");
            log("[!] Skipping remaining domains to prevent memory issues.");
            log("[!] Use 'Clear Results' to free memory and continue scanning.");
            return false;
        }
        
        // Warn user when approaching limit (80% threshold)
        if (domainData.size() == WARN_THRESHOLD) {
            showMemoryWarning();
        }
        
        domainData.put(subdomain, info);
        updateTableRow(subdomain, status, techSummary, headersSummary);
        
        log("");
        return true;
    }
    
    /**
     * Shows memory warning dialog to user
     */
    private void showMemoryWarning() {
        log("[!] WARNING: Approaching maximum domain limit (" + domainData.size() + "/" + MAX_STORED_DOMAINS + ")");
        log("[!] Consider clearing old results to free memory.");
        
        SwingUtilities.invokeLater(() ->
            JOptionPane.showMessageDialog(getBurpFrame(),
                "Approaching maximum results limit (" + domainData.size() + "/" + MAX_STORED_DOMAINS + ").\n" +
                "Consider using 'Clear Results' to free memory for continued scanning.",
                "Memory Warning",
                JOptionPane.WARNING_MESSAGE)
        );
    }
    
    /**
     * Updates or adds a row in the results table
     */
    private void updateTableRow(String subdomain, String status, String techSummary, String headersSummary) {
        SwingUtilities.invokeLater(() -> {
            DomainInfo info = domainData.get(subdomain);
            
            // Calculate new column values
            String takeoverStatus = getTakeoverStatus(info);
            String sensitiveFilesCount = getSensitiveFilesCount(info);
            String wordpressStatus = getWordPressStatus(info);
            
            boolean found = false;
            
            // Check if domain already exists in table
            for (int i = 0; i < mainTableModel.getRowCount(); i++) {
                String existingDomain = (String) mainTableModel.getValueAt(i, 0);
                if (existingDomain.equals(subdomain)) {
                    // Update existing row with all columns
                    mainTableModel.setValueAt(status, i, 1);
                    mainTableModel.setValueAt(techSummary, i, 2);
                    mainTableModel.setValueAt(headersSummary, i, 3);
                    mainTableModel.setValueAt(takeoverStatus, i, 4);
                    mainTableModel.setValueAt(sensitiveFilesCount, i, 5);
                    mainTableModel.setValueAt(wordpressStatus, i, 6);
                    found = true;
                    break;
                }
            }
            
            // Add new row if domain doesn't exist
            if (!found) {
                mainTableModel.addRow(new Object[]{
                    subdomain, 
                    status, 
                    techSummary, 
                    headersSummary,
                    takeoverStatus,
                    sensitiveFilesCount,
                    wordpressStatus
                });
            }
        });
    }
    
    /**
     * Get subdomain takeover status for table display
     */
    private String getTakeoverStatus(DomainInfo info) {
        if (info == null || info.takeoverInfo == null) {
            return "N/A";
        }
        return info.takeoverInfo.isVulnerable() ? "🔴 YES" : "✅ NO";
    }
    
    /**
     * Get sensitive files count for table display with color coding
     */
    private String getSensitiveFilesCount(DomainInfo info) {
        if (info == null || info.sensitiveFilesInfo == null) {
            return "N/A";
        }
        int count = info.sensitiveFilesInfo.getExposedFiles().size();
        if (count == 0) {
            return "✅ 0";
        } else if (count <= 5) {
            return "⚠️ " + count;
        } else {
            return "🔴 " + count;
        }
    }
    
    /**
     * Get WordPress status for table display
     */
    private String getWordPressStatus(DomainInfo info) {
        if (info == null) {
            return "N/A";
        }
        return info.isWordPress() ? "✅ YES" : "NO";
    }
    
    private void startRecon() {
        String domainsInput = domainField.getText().trim();
        
        if (domainsInput.isEmpty()) {
            JOptionPane.showMessageDialog(getBurpFrame(), "Please enter one or more domains", ERROR_TITLE, JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        configureShodanApiKey();
        
        List<String> targetDomains = parseTargetDomains(domainsInput);
        if (targetDomains.isEmpty()) {
            JOptionPane.showMessageDialog(getBurpFrame(), "Please enter valid domain(s)", ERROR_TITLE, JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        prepareForScan();
        
        // Get custom dictionary path
        final String customDictPath = customDictionaryField.getText().trim();
        
        // Run scan in background thread
        new Thread(() -> executeScan(targetDomains, customDictPath)).start();
    }
    
    /**
     * Configures the Shodan API key for scanning
     */
    private void configureShodanApiKey() {
        String apiKey = shodanApiKeyField.getText().trim();
        if (!apiKey.isEmpty()) {
            shodanScanner.setApiKey(apiKey);
            log("[+] Shodan API key configured");
        } else {
            shodanScanner.setApiKey(null);
            log("[!] No Shodan API key provided - Shodan features will be limited");
        }
    }
    
    /**
     * Parses and validates the target domains from input
     */
    private List<String> parseTargetDomains(String domainsInput) {
        String[] domains = domainsInput.split(",");
        List<String> targetDomains = new ArrayList<>();
        for (String domain : domains) {
            String trimmed = domain.trim();
            if (!trimmed.isEmpty()) {
                targetDomains.add(trimmed);
            }
        }
        return targetDomains;
    }
    
    /**
     * Prepares the UI and state for a new scan
     */
    private void prepareForScan() {
        discoveredSubdomains.clear();
        scanButton.setEnabled(false);
        stopButton.setEnabled(true);
        skipDomainButton.setEnabled(true);
        scanRunning.set(true);
        shouldStop.set(false);
        skipCurrentDomain.set(false);
        progressBar.setIndeterminate(true);
        progressBar.setString("Starting scan...");
        
        subdomainEnumerator.setShouldStop(shouldStop);
        sensitiveFilesScanner.setShouldStop(shouldStop);
    }
    
    /**
     * Executes the main scan workflow
     */
    private void executeScan(List<String> targetDomains, String customDictPath) {
        try {
            logScanStart(targetDomains);
            
            processTargetDomains(targetDomains);
            
            if (shouldStop.get()) {
                logScanAborted();
                showScanAbortedUI();
                return;
            }
            
            scanDiscoveredDomains(customDictPath);
            
            if (shouldStop.get()) {
                logScanAborted();
                showScanAbortedUI();
            } else {
                logScanCompletion();
                showScanCompletedUI();
            }
            
        } catch (Exception e) {
            handleScanError(e);
        }
    }
    
    /**
     * Logs the start of the scan
     */
    private void logScanStart(List<String> targetDomains) {
        log(SEPARATOR_LINE);
        log("  STARTING RECONNAISSANCE");
        log(SEPARATOR_LINE);
        log("Target domains: " + String.join(", ", targetDomains));
        log("Timestamp: " + new Date());
        log("");
    }
    
    /**
     * Processes each target domain for subdomain enumeration
     */
    private void processTargetDomains(List<String> targetDomains) {
        for (String domain : targetDomains) {
            if (shouldStop.get()) {
                log("\n[!] Scan stopped by user");
                break;
            }
            
            log("───────────────────────────────────────────────────────");
            log("Processing domain: " + domain);
            log("───────────────────────────────────────────────────────");
            
            processSubdomainEnumeration(domain);
            
            // Always add the main domain to the scan list
            discoveredSubdomains.add(domain);
            log("[*] Main domain added to scan list: " + domain);
        }
    }
    
    /**
     * Handles subdomain enumeration for a single domain
     */
    private void processSubdomainEnumeration(String domain) {
        if (enableSubdomainEnumeration.isSelected()) {
            SwingUtilities.invokeLater(() -> progressBar.setString("Enumerating subdomains for " + domain + "..."));
            log("[*] Enumerating subdomains...");
            Set<String> subdomains = subdomainEnumerator.enumerateSubdomains(domain);
            
            log("[+] Found " + subdomains.size() + " subdomains for " + domain);
            
            if (scanDiscoveredSubdomains.isSelected()) {
                discoveredSubdomains.addAll(subdomains);
                log("[*] Subdomains will be scanned");
            } else {
                log("[*] Discovery only mode - subdomains will NOT be scanned");
            }
            log("");
        } else {
            log("[*] Subdomain enumeration disabled");
            log("");
        }
    }
    
    /**
     * Scans all discovered domains
     */
    private void scanDiscoveredDomains(String customDictPath) {
        log("[*] Total unique subdomains/domains to scan: " + discoveredSubdomains.size());
        log("");
        
        final int[] current = {0};
        int total = discoveredSubdomains.size();
        
        for (String subdomain : discoveredSubdomains) {
            if (shouldStop.get()) {
                log("\n[!] Scan stopped by user");
                break;
            }
            
            current[0]++;
            boolean shouldContinue = scanSingleDomain(subdomain, current[0], total, customDictPath);
            if (!shouldContinue) {
                break;
            }
        }
    }
    
    /**
     * Logs scan completion statistics
     */
    private void logScanCompletion() {
        log(SEPARATOR_LINE);
        log("  RECONNAISSANCE COMPLETED");
        log(SEPARATOR_LINE);
        log("Total domains analyzed: " + discoveredSubdomains.size());
        log("Active domains found: " + domainData.values().stream().filter(d -> d.isAlive).count());
        log("Timestamp: " + new Date());
        log("");
    }
    
    /**
     * Logs scan aborted message
     */
    private void logScanAborted() {
        log(SEPARATOR_LINE);
        log("  RECONNAISSANCE ABORTED");
        log(SEPARATOR_LINE);
        log("Scan stopped by user");
        log("Partial results: " + domainData.size() + " domains analyzed");
        log("Timestamp: " + new Date());
        log("");
    }
    
    /**
     * Updates UI to show scan completed
     */
    private void showScanCompletedUI() {
        SwingUtilities.invokeLater(() -> {
            progressBar.setIndeterminate(false);
            progressBar.setValue(100);
            int totalResults = domainData.size();
            int memoryUsage = (totalResults * 100) / MAX_STORED_DOMAINS;
            progressBar.setString("Scan completed! (" + totalResults + " results, " + memoryUsage + "% capacity)");
            scanButton.setEnabled(true);
            stopButton.setEnabled(false);
            skipDomainButton.setEnabled(false);
            scanRunning.set(false);
            currentScanningDomain = null;
            
            JOptionPane.showMessageDialog(getBurpFrame(),
                "Scan completed!\n" +
                "Domains analyzed: " + discoveredSubdomains.size() + "\n" +
                "Check the Target > Issues tab for findings.\n\n" +
                "Select any row to see detailed information in the tabs below.",
                "Scan Complete", JOptionPane.INFORMATION_MESSAGE);
        });
    }
    
    /**
     * Updates UI to show scan was aborted
     */
    private void showScanAbortedUI() {
        SwingUtilities.invokeLater(() -> {
            progressBar.setIndeterminate(false);
            int totalResults = domainData.size();
            progressBar.setString("Scan aborted - " + totalResults + " partial results");
            scanButton.setEnabled(true);
            stopButton.setEnabled(false);
            skipDomainButton.setEnabled(false);
            scanRunning.set(false);
            currentScanningDomain = null;
            
            JOptionPane.showMessageDialog(getBurpFrame(),
                "Scan aborted by user!\n" +
                "Partial results: " + domainData.size() + " domains analyzed\n\n" +
                "You can view the partial results in the table below.",
                "Scan Aborted", JOptionPane.WARNING_MESSAGE);
        });
    }
    
    /**
     * Handles scan errors
     */
    private void handleScanError(Exception e) {
        log("ERROR: " + e.getMessage());
        api.logging().logToError("Scan error: " + e.getMessage());
        api.logging().logToError(e.toString());
        
        SwingUtilities.invokeLater(() -> {
            progressBar.setIndeterminate(false);
            progressBar.setString("Error occurred");
            scanButton.setEnabled(true);
            stopButton.setEnabled(false);
            scanRunning.set(false);
            
            JOptionPane.showMessageDialog(getBurpFrame(),
                "Error during scan: " + e.getMessage(),
                ERROR_TITLE, JOptionPane.ERROR_MESSAGE);
        });
    }
    
    private void createUnifiedSecurityHeadersIssue(String domain, SecurityHeadersScanner.SecurityHeadersResult result) {
        try {
            URL url = URI.create(HTTPS_PREFIX + domain).toURL();
            
            StringBuilder detail = new StringBuilder();
            
            int missingCount = 0;
            int presentCount = 0;
            
            Map<String, SecurityHeadersScanner.HeaderInfo> headers = result.getHeaders();
            
            // Count
            for (SecurityHeadersScanner.HeaderInfo header : headers.values()) {
                if (header.isPresent()) {
                    presentCount++;
                } else {
                    missingCount++;
                }
            }

            detail.append("<b>Security Headers Analysis</b><br>");
            detail.append("<b>Domain:</b> ").append(domain).append("<br>");
            detail.append("<b>Summary:</b> ")
                .append(presentCount).append(" present, ")
                .append(missingCount).append(" missing<br><br>");

            // Present headers
            if (presentCount > 0) {
                detail.append("<b>Present Headers:</b><br><ul>");
                for (SecurityHeadersScanner.HeaderInfo header : headers.values()) {
                    if (header.isPresent()) {
                        detail.append("<li><b>")
                            .append(header.getName())
                            .append("</b>");
                        if (header.getValue() != null && !header.getValue().isEmpty()) {
                            detail.append("<br>&nbsp;&nbsp;Current: ")
                                .append(header.getValue());
                        }
                        detail.append("</li>");
                    }
                }
                detail.append("</ul><br>");
            }

            // Missing headers
            if (missingCount > 0) {
                detail.append("<b>Missing Headers:</b><br><ul>");
                for (SecurityHeadersScanner.HeaderInfo header : headers.values()) {
                    if (!header.isPresent()) {
                        detail.append("<li><b>")
                            .append(header.getName()).append(" - MISSING")
                            .append("</b><br>")
                            .append("&nbsp;&nbsp; ") //Recommended:
                            .append(header.getRecommendation())
                            .append("</li>");
                    }
                }
                detail.append("</ul><br>");

                detail.append("<b>Security Impact:</b><br>");
                detail.append("<ul>");
                detail.append("<li>Clickjacking attacks (without X-Frame-Options)</li>");
                detail.append("<li>MIME-sniffing vulnerabilities (without X-Content-Type-Options)</li>");
                detail.append("<li>Information leakage (without Referrer-Policy)</li>");
                detail.append("<li>Man-in-the-Middle attacks (without Strict-Transport-Security)</li>");
                detail.append("<li>Cross-Site Scripting (without Content-Security-Policy)</li>");
                detail.append("<li>Unauthorized feature access (without Permissions-Policy)</li>");
                detail.append("</ul>");
            } else {
                detail.append("<b>All recommended security headers are properly configured.</b>");
            }
            
            // Determine severity
            String severity = missingCount == 0 ? SEVERITY_INFORMATION : SEVERITY_MEDIUM;
            String issueName = "Security Headers Analysis - " + missingCount + " Missing at " + domain;
            
            api.siteMap().add(CustomScanIssue.create(issueName, detail.toString(), null, url.toString(), severity, SEVERITY_CERTAIN));
            
        } catch (Exception e) {
            api.logging().logToError("Error creating unified security headers issue: " + e.getMessage());
        }
    }
    
    private void createTechnologyIssue(String domain, TechnologyDetector.TechnologyDetectionResult result) {
        try {
            URL url = URI.create(HTTPS_PREFIX + domain).toURL();
            
            StringBuilder detail = new StringBuilder();
            
            Map<String, List<String>> techsByCategory = result.getTechnologiesByCategory();
            
            detail.append("<b>Technology Stack Detection</b><br>");
            detail.append("<b>Domain:</b> ").append(domain).append("<br><br>");
            
            if (techsByCategory.isEmpty()) {
                detail.append("<i>No technologies detected</i><br>");
            } else {
                int totalCount = 0;
                for (List<String> techs : techsByCategory.values()) {
                    totalCount += techs.size();
                }
                
                detail.append("<b>Summary:</b> ")
                    .append(totalCount).append(" technologies detected in ")
                    .append(techsByCategory.size()).append(" categories<br><br>");
                
                // List by category
                detail.append("<b>Detected Technologies:</b><br>");
                for (Map.Entry<String, List<String>> entry : techsByCategory.entrySet()) {
                    detail.append("<br><b>").append(entry.getKey()).append(":</b><br>");
                    detail.append("<ul>");
                    for (String tech : entry.getValue()) {
                        detail.append("<li>").append(tech).append("</li>");
                    }
                    detail.append("</ul>");
                }
                
                detail.append("<br><b>Security Note:</b><br>");
                detail.append("<ul>");
                detail.append("<li>Technology information helps identify potential attack vectors</li>");
                detail.append("<li>Outdated versions may contain known vulnerabilities</li>");
                detail.append("<li>Review each technology for security updates and patches</li>");
                detail.append("</ul>");
            }
            
            api.siteMap().add(CustomScanIssue.create("Technology Stack Detected", detail.toString(), null, url.toString(), SEVERITY_INFORMATION, SEVERITY_CERTAIN));
            
        } catch (Exception e) {
            api.logging().logToError("Error creating technology issue: " + e.getMessage());
        }
    }
    
    private void createShodanIssue(String domain, ShodanScanner.ServerInfo serverInfo) {
        try {
            URL url = URI.create(HTTPS_PREFIX + domain).toURL();
            
            ShodanScanner.ShodanInfo shodanInfo = serverInfo.getShodanInfo();
            
            StringBuilder detail = new StringBuilder();
            
            detail.append("<b>Server Intelligence Report (Shodan)</b><br>");
            detail.append("<b>Domain:</b> ").append(domain).append("<br>");
            detail.append("<b>IP Address:</b> ").append(serverInfo.getIpAddress()).append("<br>");
            detail.append("<b>Shodan URL:</b> <a href='").append(shodanInfo.getShodanUrl())
                .append("'>").append(shodanInfo.getShodanUrl()).append("</a><br><br>");
            
            // Location and Organization
            boolean hasLocationInfo = false;
            if (shodanInfo.getOrganization() != null && !shodanInfo.getOrganization().isEmpty()) {
                if (!hasLocationInfo) {
                    detail.append("<b>Location & Organization:</b><br><ul>");
                    hasLocationInfo = true;
                }
                detail.append("<li><b>Organization:</b> ").append(shodanInfo.getOrganization()).append("</li>");
            }
            if (shodanInfo.getIsp() != null && !shodanInfo.getIsp().isEmpty()) {
                if (!hasLocationInfo) {
                    detail.append("<b>Location & Organization:</b><br><ul>");
                    hasLocationInfo = true;
                }
                detail.append("<li><b>ISP:</b> ").append(shodanInfo.getIsp()).append("</li>");
            }
            if (shodanInfo.getCountry() != null && !shodanInfo.getCountry().isEmpty()) {
                if (!hasLocationInfo) {
                    detail.append("<b>Location & Organization:</b><br><ul>");
                    hasLocationInfo = true;
                }
                detail.append("<li><b>Country:</b> ").append(shodanInfo.getCountry()).append("</li>");
            }
            if (shodanInfo.getCity() != null && !shodanInfo.getCity().isEmpty()) {
                if (!hasLocationInfo) {
                    detail.append("<b>Location & Organization:</b><br><ul>");
                    hasLocationInfo = true;
                }
                detail.append("<li><b>City:</b> ").append(shodanInfo.getCity()).append("</li>");
            }
            if (hasLocationInfo) {
                detail.append("</ul><br>");
            }
            
            // Open Ports
            if (!shodanInfo.getOpenPorts().isEmpty()) {
                detail.append("<b>Open Ports (").append(shodanInfo.getOpenPorts().size()).append(" total):</b><br>");
                detail.append("<ul>");
                Collections.sort(shodanInfo.getOpenPorts());
                for (int port : shodanInfo.getOpenPorts()) {
                    detail.append("<li>Port <b>").append(port).append("</b></li>");
                }
                detail.append("</ul><br>");
            }
            
            // Services
            if (!shodanInfo.getServices().isEmpty()) {
                detail.append("<b>Services Detected:</b><br>");
                detail.append("<ul>");
                for (String service : shodanInfo.getServices()) {
                    detail.append("<li>").append(service).append("</li>");
                }
                detail.append("</ul><br>");
            }
            
            // Vulnerabilities
            if (shodanInfo.getVulnerabilitiesCount() > 0) {
                detail.append("<b>⚠️ Vulnerabilities Found:</b><br>");
                detail.append("<div style='background-color: #fff3e0; padding: 10px; border-left: 4px solid #ff9800; margin: 10px 0;'>");
                detail.append("<b style='color: #e65100;'>")
                    .append(shodanInfo.getVulnerabilitiesCount())
                    .append(" vulnerabilities detected</b><br>");
                detail.append("Check detailed CVE information at: <a href='")
                    .append(shodanInfo.getShodanUrl()).append("'>")
                    .append(shodanInfo.getShodanUrl()).append("</a>");
                detail.append("</div><br>");
            }
            
            // Additional info
            detail.append("<b>Additional Information:</b><br>");
            detail.append("<ul>");
            detail.append("<li>Complete server details available at Shodan</li>");
            detail.append("<li>Historical data and scan records may be available</li>");
            detail.append("<li>SSL/TLS certificate information may be included</li>");
            detail.append("</ul>");
            
            detail.append("<br><i>Visit <a href='").append(shodanInfo.getShodanUrl())
                .append("'>Shodan</a> for complete information</i>");
            
            // Determine severity based on vulnerabilities
            String severity = shodanInfo.getVulnerabilitiesCount() > 0 ? SEVERITY_HIGH : SEVERITY_INFORMATION;
            String issueName = shodanInfo.getVulnerabilitiesCount() > 0 ?
                "Server Exposed - " + shodanInfo.getVulnerabilitiesCount() + " Vulnerabilities Found" :
                "Server Information (Shodan)";
            
            api.siteMap().add(CustomScanIssue.create(issueName, detail.toString(), null, url.toString(), severity, SEVERITY_CERTAIN));
            
        } catch (Exception e) {
            api.logging().logToError("Error creating Shodan issue: " + e.getMessage());
        }
    }
    
    /**
     * Create WordPress security issue
     */
    private void createWordPressIssue(String domain, WordPressScanner.WordPressInfo wpInfo) {
        try {
            URL url = URI.create(HTTPS_PREFIX + domain).toURL();
            
            StringBuilder detail = new StringBuilder();
            
            detail.append("<b>WordPress Installation Detected</b><br>");
            detail.append("<b>Domain:</b> ").append(domain).append("<br>");
            if (wpInfo.getVersion() != null) {
                detail.append("<b>Version:</b> ").append(wpInfo.getVersion()).append("<br>");
            }
            detail.append("<br>");
            
            // Summary
            int totalFindings = wpInfo.getFindings().size();
            
            detail.append("<b>Summary:</b><br>");
            detail.append("<ul>");
            detail.append("<li>Themes: ").append(wpInfo.getThemes().size()).append("</li>");
            detail.append("<li>Plugins: ").append(wpInfo.getPlugins().size()).append("</li>");
            detail.append("<li>Users: ").append(wpInfo.getUsers().size()).append("</li>");
            detail.append("<li>Security Findings: ").append(totalFindings).append("</li>");
            detail.append("</ul><br>");
            
            // Themes
            if (!wpInfo.getThemes().isEmpty()) {
                detail.append("<b>Active Themes:</b><br><ul>");
                for (Map.Entry<String, String> theme : wpInfo.getThemes().entrySet()) {
                    detail.append("<li>").append(theme.getKey());
                    if (theme.getValue() != null) {
                        detail.append(" <i>(version ").append(theme.getValue()).append(")</i>");
                    }
                    detail.append("</li>");
                }
                detail.append("</ul><br>");
            }
            
            // Plugins
            if (!wpInfo.getPlugins().isEmpty()) {
                detail.append("<b>Detected Plugins:</b><br><ul>");
                for (Map.Entry<String, String> plugin : wpInfo.getPlugins().entrySet()) {
                    detail.append("<li>").append(plugin.getKey());
                    if (plugin.getValue() != null) {
                        detail.append(" <i>(version ").append(plugin.getValue()).append(")</i>");
                    }
                    detail.append("</li>");
                }
                detail.append("</ul><br>");
            }
            
            // Users
            if (!wpInfo.getUsers().isEmpty()) {
                detail.append("<b>Enumerated Users:</b><br>");
                detail.append("<div style='background-color: #fff3e0; padding: 10px; border-left: 4px solid #ff9800; margin: 10px 0;'>");
                detail.append("<b style='color: #e65100;'>⚠️ User enumeration is possible</b><br>");
                detail.append("<ul>");
                for (String user : wpInfo.getUsers()) {
                    detail.append("<li><b>").append(user).append("</b></li>");
                }
                detail.append("</ul>");
                detail.append("</div><br>");
            }
            
            // Security Findings
            if (!wpInfo.getFindings().isEmpty()) {
                detail.append("<b>Security Findings:</b><br><ul>");
                for (WordPressScanner.SecurityFinding finding : wpInfo.getFindings()) {
                    String colorClass = "";
                    switch (finding.getSeverity().toLowerCase(Locale.ROOT)) {
                        case "high": colorClass = "color: #c62828;"; break;
                        case MEDIUM_LOWERCASE: colorClass = "color: #e65100;"; break;
                        case "low": colorClass = "color: #f57c00;"; break;
                        default: colorClass = "color: #1976d2;"; break;
                    }
                    
                    detail.append("<li><b style='").append(colorClass).append("'>[").append(finding.getSeverity()).append("]</b> ")
                        .append(finding.getTitle()).append("<br>")
                        .append("<i>").append(finding.getDescription()).append("</i></li>");
                }
                detail.append("</ul><br>");
            }
            
            // Recommendations
            detail.append("<b>Recommendations:</b><br>");
            detail.append("<ul>");
            detail.append("<li>Keep WordPress core, themes, and plugins updated</li>");
            detail.append("<li>Use strong passwords for all WordPress users</li>");
            detail.append("<li>Enable two-factor authentication</li>");
            detail.append("<li>Disable user enumeration via REST API</li>");
            detail.append("<li>Remove or protect sensitive files (readme.html, license.txt)</li>");
            detail.append("<li>Consider using a Web Application Firewall (WAF)</li>");
            detail.append("</ul>");
            
            // Count high severity findings
            long highSeverityCount = wpInfo.getFindings().stream()
                .filter(f -> SEVERITY_HIGH.equalsIgnoreCase(f.getSeverity()))
                .count();
            
            // Determine severity: Information for WordPress detection, Medium if findings exist, but only if high severity findings
            String severity;
            if (highSeverityCount > 0) {
                severity = SEVERITY_MEDIUM;
            } else {
                severity = SEVERITY_INFORMATION;
            }
            
            String issueName = highSeverityCount > 0 ? 
                "WordPress - " + highSeverityCount + " High Severity Issues Found" : 
                "WordPress Installation Detected";
            
            api.siteMap().add(CustomScanIssue.create(issueName, detail.toString(), null, url.toString(), severity, SEVERITY_CERTAIN));
            
        } catch (Exception e) {
            api.logging().logToError("Error creating WordPress issue: " + e.getMessage());
        }
    }
    
    /**
     * Create BurpSuite issue for SSL/TLS findings
     */
    private void createSSLIssue(String domain, SSLScanner.SSLInfo sslInfo) {
        try {
            URL url = URI.create(HTTPS_PREFIX + domain).toURL();
            
            StringBuilder detail = new StringBuilder();
            
            detail.append("<b>SSL/TLS Security Analysis</b><br>");
            detail.append("<b>Domain:</b> ").append(domain).append("<br><br>");
            
            // Certificate Information
            detail.append("<b>Certificate Information:</b><br>");
            detail.append("<ul>");
            detail.append("<li><b>Protocol:</b> ").append(sslInfo.getProtocol() != null ? sslInfo.getProtocol() : UNKNOWN).append("</li>");
            detail.append("<li><b>Cipher Suite:</b> ").append(sslInfo.getCipherSuite() != null ? sslInfo.getCipherSuite() : UNKNOWN).append("</li>");
            detail.append("<li><b>Issuer:</b> ").append(sslInfo.getIssuer() != null ? sslInfo.getIssuer() : UNKNOWN).append("</li>");
            detail.append("<li><b>Subject:</b> ").append(sslInfo.getSubject() != null ? sslInfo.getSubject() : UNKNOWN).append("</li>");
            if (sslInfo.getValidFrom() != null && sslInfo.getValidUntil() != null) {
                detail.append("<li><b>Valid From:</b> ").append(sslInfo.getValidFrom()).append("</li>");
                detail.append("<li><b>Valid To:</b> ").append(sslInfo.getValidUntil()).append("</li>");
            }
            detail.append("<li><b>Valid:</b> ").append(sslInfo.isValid() ? STATUS_YES : "✗ No").append("</li>");
            detail.append("<li><b>Hostname Match:</b> ").append(sslInfo.isHostnameMatch() ? STATUS_YES : "✗ No").append("</li>");
            detail.append("</ul><br>");
            
            // Security Findings
            if (!sslInfo.getFindings().isEmpty()) {
                detail.append("<b>Security Findings (").append(sslInfo.getFindings().size()).append("):</b><br>");
                
                for (SSLScanner.SecurityFinding finding : sslInfo.getFindings()) {
                    String colorClass = "";
                    switch (finding.getSeverity().toLowerCase(Locale.ROOT)) {
                        case "high": colorClass = "background-color: #ffebee; border-left: 4px solid #c62828;"; break;
                        case MEDIUM_LOWERCASE: colorClass = "background-color: #fff3e0; border-left: 4px solid #ff9800;"; break;
                        case "low": colorClass = "background-color: #e3f2fd; border-left: 4px solid #1976d2;"; break;
                        default: colorClass = "background-color: #f5f5f5; border-left: 4px solid #9e9e9e;"; break;
                    }
                    
                    detail.append("<div style='").append(colorClass).append(" padding: 10px; margin: 10px 0;'>");
                    detail.append("<b style='color: #212121;'>[").append(finding.getSeverity().toUpperCase(Locale.ROOT)).append("] ")
                        .append(finding.getTitle()).append("</b><br>");
                    detail.append("<i>").append(finding.getDescription()).append("</i>");
                    detail.append("</div>");
                }
            }
            
            // Recommendations
            detail.append("<br><b>Recommendations:</b><br>");
            detail.append("<ul>");
            detail.append("<li>Use TLS 1.2 or TLS 1.3 only</li>");
            detail.append("<li>Disable weak cipher suites</li>");
            detail.append("<li>Ensure certificates are issued by trusted CAs</li>");
            detail.append("<li>Monitor certificate expiration dates</li>");
            detail.append("<li>Implement Certificate Transparency monitoring</li>");
            detail.append("</ul>");
            
            // Determine severity
            String severity = SEVERITY_INFORMATION;
            long highCount = sslInfo.getFindings().stream()
                .filter(f -> SEVERITY_HIGH.equalsIgnoreCase(f.getSeverity()))
                .count();
            long mediumCount = sslInfo.getFindings().stream()
                .filter(f -> SEVERITY_MEDIUM.equalsIgnoreCase(f.getSeverity()))
                .count();
            
            if (highCount > 0) {
                severity = SEVERITY_HIGH;
            } else if (mediumCount > 0) {
                severity = SEVERITY_MEDIUM;
            } else if (!sslInfo.getFindings().isEmpty()) {
                severity = SEVERITY_LOW;
            }
            
            String issueName = highCount > 0 ? 
                "SSL/TLS - " + highCount + " High Severity Issue(s) Detected" : 
                "SSL/TLS Configuration Issues";
            
            api.siteMap().add(CustomScanIssue.create(issueName, detail.toString(), null, url.toString(), severity, SEVERITY_CERTAIN));
            
        } catch (Exception e) {
            api.logging().logToError("Error creating SSL/TLS issue: " + e.getMessage());
        }
    }
    
    /**
     * Create BurpSuite issue for HTTP Methods findings
     */
    private void createHTTPMethodsIssue(String domain, HTTPMethodsScanner.HTTPMethodsInfo httpInfo) {
        try {
            URL url = URI.create(HTTPS_PREFIX + domain).toURL();
            
            StringBuilder detail = new StringBuilder();
            
            detail.append("<b>HTTP Methods Security Analysis</b><br>");
            detail.append("<b>Domain:</b> ").append(domain).append("<br><br>");
            
            // Methods Results
            detail.append("<b>HTTP Methods Test Results:</b><br>");
            detail.append("<table style='border-collapse: collapse; width: 100%; margin: 10px 0;'>");
            detail.append("<tr style='background-color: #f5f5f5;'>");
            detail.append("<th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Method</th>");
            detail.append("<th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Status Code</th>");
            detail.append("<th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Status</th>");
            detail.append("<th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Allowed</th>");
            detail.append("</tr>");
            
            for (Map.Entry<String, HTTPMethodsScanner.MethodResult> entry : httpInfo.getMethodResults().entrySet()) {
                HTTPMethodsScanner.MethodResult result = entry.getValue();
                String rowColor = result.isAllowed() ? "background-color: #ffebee;" : "";
                String statusIcon = result.isAllowed() ? "⚠️" : "✓";
                
                detail.append("<tr style='").append(rowColor).append("'>");
                detail.append("<td style='border: 1px solid #ddd; padding: 8px;'><b>").append(entry.getKey()).append("</b></td>");
                detail.append("<td style='border: 1px solid #ddd; padding: 8px;'>").append(result.getStatusCode()).append("</td>");
                detail.append("<td style='border: 1px solid #ddd; padding: 8px;'>").append(result.getStatusMessage()).append("</td>");
                detail.append("<td style='border: 1px solid #ddd; padding: 8px;'>").append(statusIcon).append(" ")
                    .append(result.isAllowed() ? "YES" : "NO").append("</td>");
                detail.append("</tr>");
            }
            detail.append("</table><br>");
            
            // Security Findings
            if (!httpInfo.getFindings().isEmpty()) {
                detail.append("<b>Security Findings (").append(httpInfo.getFindings().size()).append("):</b><br>");
                
                for (HTTPMethodsScanner.SecurityFinding finding : httpInfo.getFindings()) {
                    String colorClass = "";
                    switch (finding.getSeverity().toLowerCase(Locale.ROOT)) {
                        case "high": colorClass = "background-color: #ffebee; border-left: 4px solid #c62828;"; break;
                        case MEDIUM_LOWERCASE: colorClass = "background-color: #fff3e0; border-left: 4px solid #ff9800;"; break;
                        case "low": colorClass = "background-color: #e3f2fd; border-left: 4px solid #1976d2;"; break;
                        default: colorClass = "background-color: #f5f5f5; border-left: 4px solid #9e9e9e;"; break;
                    }
                    
                    detail.append("<div style='").append(colorClass).append(" padding: 10px; margin: 10px 0;'>");
                    detail.append("<b style='color: #212121;'>[").append(finding.getSeverity().toUpperCase(Locale.ROOT)).append("] ")
                        .append(finding.getTitle()).append("</b><br>");
                    detail.append("<i>").append(finding.getDescription()).append("</i>");
                    detail.append("</div>");
                }
            }
            
            // Recommendations
            detail.append("<br><b>Recommendations:</b><br>");
            detail.append("<ul>");
            detail.append("<li>Disable unnecessary HTTP methods (PUT, DELETE, TRACE, PATCH)</li>");
            detail.append("<li>Return 405 Method Not Allowed for disabled methods</li>");
            detail.append("<li>Implement proper authentication and authorization for all methods</li>");
            detail.append("<li>Use security headers like X-Content-Type-Options</li>");
            detail.append("<li>Configure web server to only allow required methods</li>");
            detail.append("</ul>");
            
            // Set severity to Information (all HTTP methods findings are informational)
            String severity = SEVERITY_INFORMATION;
            long highCount = httpInfo.getFindings().stream()
                .filter(f -> SEVERITY_HIGH.equalsIgnoreCase(f.getSeverity()))
                .count();
            
            String issueName = highCount > 0 ? 
                "HTTP Methods - " + highCount + " Dangerous Method(s) Enabled (Informational)" : 
                "HTTP Methods Configuration (Informational)";
            
            api.siteMap().add(CustomScanIssue.create(issueName, detail.toString(), null, url.toString(), severity, SEVERITY_CERTAIN));
            
        } catch (Exception e) {
            api.logging().logToError("Error creating HTTP Methods issue: " + e.getMessage());
        }
    }
    
    /**
     * Create BurpSuite issue for Sensitive Files findings
     */
    private void createSensitiveFilesIssue(String domain, SensitiveFilesScanner.SensitiveFilesInfo filesInfo) {
        try {
            // Don't create issues if using custom dictionary
            if (filesInfo.isUsingCustomDictionary()) {
                log("  └─ Skipping issue creation (custom dictionary in use)");
                return;
            }
            
            // Create one issue per exposed file
            for (Map.Entry<String, SensitiveFilesScanner.FileCheckResult> entry : filesInfo.getExposedFiles().entrySet()) {
                String path = entry.getKey();
                SensitiveFilesScanner.FileCheckResult result = entry.getValue();
                
                // Get response from result
                burp.api.montoya.http.message.responses.HttpResponse response = result.getResponse();
                if (response == null) {
                    continue; // Skip if no response data
                }
                
                // Build URL for this specific file
                URL url = URI.create(HTTPS_PREFIX + domain + path).toURL();
                
                // Get status code
                int statusCode = result.getStatusCode();
                
                // Determine severity for this path
                String severity = determineSeverityForPath(path, statusCode);
                
                // Build detail
                StringBuilder detail = new StringBuilder();
                detail.append("<b>Sensitive File Exposed</b><br>");
                detail.append("<b>Domain:</b> ").append(domain).append("<br>");
                detail.append("<b>Path:</b> ").append(path).append("<br>");
                
                // Add status code
                detail.append("<b>Status Code:</b> ").append(statusCode);
                if (statusCode == 200) {
                    detail.append(" (OK - Directly accessible)");
                }
                detail.append("<br>");
                
                if (result.getContentLength() > 0) {
                    detail.append("<b>Content Length:</b> ").append(formatFileSize(result.getContentLength())).append("<br>");
                }
                
                detail.append("<br><b>Description:</b><br>");
                detail.append(getFileDescription(path));
                
                detail.append("<br><br><b>Security Impact:</b><br>");
                detail.append(getSecurityImpact(path, severity));
                
                detail.append("<br><br><b>Recommendations:</b><br>");
                detail.append("<ul>");
                detail.append("<li>Remove or restrict access to this sensitive file</li>");
                
                if (path.contains(".git") || path.contains(".svn") || path.contains(".hg")) {
                    detail.append("<li>Configure web server to deny access to version control directories</li>");
                } else if (path.contains("config") || path.contains(".env")) {
                    detail.append("<li>Move configuration files outside web root</li>");
                } else if (path.contains(BACKUP_KEYWORD) || path.contains(".sql") || path.contains(".zip") || path.contains(".tar")) {
                    detail.append("<li>Delete backup files and archives from production servers</li>");
                } else if (path.contains("admin") || path.contains("phpmyadmin")) {
                    detail.append("<li>Implement proper access controls for admin interfaces</li>");
                }
                
                detail.append("<li>Use .htaccess or web.config to block access to sensitive paths</li>");
                detail.append("<li>Implement proper file permissions</li>");
                detail.append("</ul>");
                
                // Create issue with response
                burp.api.montoya.http.message.HttpRequestResponse httpReqResp = 
                    burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                        burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(url.toString()),
                        response
                    );
                
                // Convert severity string to AuditIssueSeverity enum
                burp.api.montoya.scanner.audit.issues.AuditIssueSeverity auditSeverity = convertToAuditIssueSeverity(severity);
                
                burp.api.montoya.scanner.audit.issues.AuditIssue issue = 
                    burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue(
                        "Sensitive File: " + path,
                        detail.toString(),
                        null,  // remediation
                        url.toString(),
                        auditSeverity,
                        burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.CERTAIN,
                        null, null, null,
                        httpReqResp
                    );
                
                api.siteMap().add(issue);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error creating Sensitive Files issue: " + e.getMessage());
        }
    }
    
    /**
     * Create a Burp Suite issue for subdomain takeover vulnerability
     */
    private void createSubdomainTakeoverIssue(String domain, SubdomainTakeoverScanner.TakeoverInfo takeoverInfo) {
        try {
            URL url = URI.create(HTTPS_PREFIX + domain).toURL();
            
            // Build detailed description
            StringBuilder detail = new StringBuilder();
            detail.append("<b>Subdomain Takeover Vulnerability Detected</b><br><br>");
            detail.append("<b>Domain:</b> ").append(domain).append("<br>");
            detail.append("<b>DNS Resolvable:</b> ").append(takeoverInfo.isDnsResolvable() ? "Yes" : "No").append("<br>");
            
            if (takeoverInfo.getCnameTarget() != null) {
                detail.append("<b>CNAME Target:</b> ").append(takeoverInfo.getCnameTarget()).append("<br>");
            }
            
            if (takeoverInfo.getDetectedService() != null) {
                detail.append("<b>Detected Service:</b> ").append(takeoverInfo.getDetectedService()).append("<br>");
            }
            
            if (takeoverInfo.getHttpStatusCode() > 0) {
                detail.append("<b>HTTP Status:</b> ").append(takeoverInfo.getHttpStatusCode()).append("<br>");
            }
            
            detail.append("<br><b>Findings:</b><br>");
            for (SubdomainTakeoverScanner.Finding finding : takeoverInfo.getFindings()) {
                detail.append("<div style='margin: 10px 0; padding: 10px; background-color: #fff3cd;'>");
                detail.append("<b>[").append(finding.getSeverity()).append("] ").append(finding.getTitle()).append("</b><br>");
                detail.append(finding.getDescription());
                detail.append("</div>");
            }
            
            detail.append("<br><b>Description:</b><br>");
            detail.append("A subdomain takeover vulnerability allows an attacker to claim and control this subdomain. ");
            detail.append("This occurs when a subdomain's DNS record points to an external service that is no longer active or has not been claimed. ");
            detail.append("An attacker can register or claim the service and serve malicious content under your domain.");
            
            detail.append("<br><br><b>Security Impact:</b><br>");
            detail.append("<ul>");
            detail.append("<li><b>Phishing Attacks:</b> Attackers can create convincing phishing pages under your trusted domain</li>");
            detail.append("<li><b>Cookie Theft:</b> Session cookies for the parent domain may be accessible</li>");
            detail.append("<li><b>Credential Harvesting:</b> Users may enter sensitive information on attacker-controlled pages</li>");
            detail.append("<li><b>Malware Distribution:</b> Malicious content can be served from a trusted domain</li>");
            detail.append("<li><b>Reputation Damage:</b> Your domain's reputation and user trust will be severely impacted</li>");
            detail.append("</ul>");
            
            detail.append("<br><b>Remediation:</b><br>");
            detail.append("<ul>");
            detail.append("<li>Remove the DNS record (CNAME/A) for this subdomain if it's no longer needed</li>");
            detail.append("<li>If the service is still needed, reclaim or reactivate it with the service provider</li>");
            detail.append("<li>Implement monitoring for DNS changes and subdomain status</li>");
            detail.append("<li>Maintain an inventory of all subdomains and their purposes</li>");
            detail.append("<li>Regularly audit DNS records for dangling entries</li>");
            detail.append("</ul>");
            
            // Determine highest severity from findings
            String highestSeverity = "Medium";
            for (SubdomainTakeoverScanner.Finding finding : takeoverInfo.getFindings()) {
                if ("High".equalsIgnoreCase(finding.getSeverity())) {
                    highestSeverity = "High";
                    break;
                }
            }
            
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity auditSeverity = convertToAuditIssueSeverity(highestSeverity);
            
            burp.api.montoya.scanner.audit.issues.AuditIssue issue = 
                burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue(
                    "Subdomain Takeover Vulnerability: " + domain,
                    detail.toString(),
                    null,  // remediation
                    url.toString(),
                    auditSeverity,
                    burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.FIRM,
                    null, null, null  // background, remediationBackground, issueDetailSeverity
                );
            
            api.siteMap().add(issue);
            
        } catch (Exception e) {
            api.logging().logToError("Error creating Subdomain Takeover issue: " + e.getMessage());
        }
    }
    
    /**
     * Determine severity for a sensitive file path based on categorization
     */
    private String determineSeverityForPath(String path, int statusCode) {
        // HIGH severity files (13 paths)
        switch (path) {
            case "/.env":
            case "/.git/config":
            case "/phpmyadmin/":
            case "/adminer.php":
            case "/backup.sql":
            case "/database.sql":
            case "/dump.sql":
            case "/db_backup.sql":
            case "/backup.zip":
            case "/backup.tar.gz":
            case "/site-backup.zip":
            case "/web.config":
            case "/configuration.php":
                return "High";
            default:
                // Fall through to next check
                break;
        }
        
        // MEDIUM severity files (14 paths + additional similar)
        switch (path) {
            case "/wp-config.php":
            case "/.htaccess":
            case "/config.php":
            case "/settings.php":
            case "/app/config/parameters.yml":
            case "/config/database.yml":
            case "/.git/":
            case "/.svn/":
            case "/CVS/":
            case "/.hg/":
            case "/admin/":
            case "/administrator/":
            case "/wp-admin/":
            case "/backups/":
            // Additional medium severity from dictionary
            case "/.env.local":
            case "/.env.production":
            case "/app.config":
            case "/.htpasswd":
            case "/db.sql":
            case "/mysql.sql":
            case "/admin.php":
            case "/admin/login.php":
            case "/phpMyAdmin/":
            case "/.git/HEAD":
            case "/backup/":
            case "/old/":
            case "/.bak":
            case "/index.php.bak":
                return SEVERITY_MEDIUM;
            default:
                // Fall through to next check
                break;
        }
        
        // LOW severity files (11 paths + additional similar)
        switch (path) {
            case "/admin-console/":
            case "/manager/":
            case "/phpinfo.php":
            case "/info.php":
            case "/test.php":
            case "/dev/":
            case "/development/":
            case "/error_log":
            case "/debug.log":
            case "/app.log":
            case "/access.log":
            // Additional low severity from dictionary
            case "/test/":
            case "/debug/":
            case "/.vscode/":
            case "/.idea/":
            case "/error.log":
                return SEVERITY_LOW;
            default:
                // Fall through to next check
                break;
        }
        
        // INFORMATION severity files (10 paths + additional similar)
        switch (path) {
            case "/robots.txt":
            case "/sitemap.xml":
            case "/.well-known/security.txt":
            case "/crossdomain.xml":
            case "/clientaccesspolicy.xml":
            case "/package.json":
            case "/.DS_Store":
            case "/Thumbs.db":
            case "/composer.lock":
            case "/package-lock.json":
            // Additional information severity from dictionary
            case "/node_modules/":
            case "/README.md":
            case "/license.txt":
            case "/composer.json":
                return SEVERITY_INFORMATION;
            default:
                // Fall through to default
                break;
        }
        
        // Default to Medium for any unmatched paths
        return SEVERITY_MEDIUM;
    }
    
    /**
     * Get description for a sensitive file path
     */
    private String getFileDescription(String path) {
        if (path.contains(".git")) {
            return "Git version control directory or file exposed. This may allow attackers to download the entire source code repository.";
        } else if (path.contains(".svn") || path.contains(".hg")) {
            return "Version control directory exposed. This may reveal source code and development history.";
        } else if (path.contains(".env")) {
            return "Environment configuration file exposed. Often contains database credentials, API keys, and other sensitive information.";
        } else if (path.contains("wp-config.php")) {
            return "WordPress configuration file exposed. Contains database credentials and security keys.";
        } else if (path.contains("config")) {
            return "Configuration file exposed. May contain sensitive settings and credentials.";
        } else if (path.contains(".sql") || path.contains("dump")) {
            return "Database backup or SQL file exposed. May contain sensitive data from the database.";
        } else if (path.contains(BACKUP_KEYWORD) || path.contains(".zip") || path.contains(".tar")) {
            return "Backup archive exposed. May contain source code or sensitive data.";
        } else if (path.contains("admin") || path.contains("phpmyadmin")) {
            return "Administrative interface accessible. Could allow unauthorized access to admin features.";
        } else if (path.contains("phpinfo")) {
            return "PHP information disclosure page. Reveals detailed server configuration.";
        } else if (path.contains("robots.txt")) {
            return "Robots.txt file found. May reveal hidden directories and pages.";
        } else {
            return "Sensitive file or directory exposed that should not be publicly accessible.";
        }
    }
    
    /**
     * Get security impact based on file type and severity
     */
    private String getSecurityImpact(String path, String severity) {
        if (SEVERITY_HIGH.equals(severity)) {
            return "<span style='color: #c62828;'>HIGH RISK:</span> This file exposure could lead to complete system compromise, " +
                   "data breach, or unauthorized access to sensitive information and systems.";
        } else if (SEVERITY_MEDIUM.equals(severity)) {
            return "<span style='color: #ff9800;'>MEDIUM RISK:</span> This file exposure could reveal sensitive information " +
                   "about the application structure or configuration.";
        } else {
            return "<span style='color: #1976d2;'>LOW RISK:</span> This file provides information that could aid in reconnaissance " +
                   "but does not directly expose critical data.";
        }
    }
    
    /**
     * Converts severity string to Burp's AuditIssueSeverity enum
     */
    private burp.api.montoya.scanner.audit.issues.AuditIssueSeverity convertToAuditIssueSeverity(String severity) {
        if (SEVERITY_HIGH.equals(severity)) {
            return burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH;
        } else if (SEVERITY_MEDIUM.equals(severity)) {
            return burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.MEDIUM;
        } else {
            return burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.LOW;
        }
    }
    
    /**
     * Format file size for display
     */
    private String formatFileSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
    }
    
    /**
     * Get enabled WPScan modules from checkboxes
     */
    private Set<WordPressScanner.ScanModule> getEnabledWPScanModules() {
        Set<WordPressScanner.ScanModule> enabled = new HashSet<>();
        
        for (Map.Entry<WordPressScanner.ScanModule, JCheckBox> entry : wpScanModules.entrySet()) {
            if (entry.getValue().isSelected()) {
                enabled.add(entry.getKey());
            }
        }
        
        // If no modules selected, enable all by default
        if (enabled.isEmpty()) {
            enabled.addAll(Arrays.asList(WordPressScanner.ScanModule.values()));
        }
        
        return enabled;
    }
    
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        
        api.logging().logToOutput(message);
    }
    
    /**
     * Export results to CSV format
     */
    private void exportToCSV() {
        if (domainData.isEmpty()) {
            JOptionPane.showMessageDialog(getBurpFrame(), 
                "No scan results to export. Please run a scan first.", 
                "No Data", 
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save CSV Export");
        fileChooser.setSelectedFile(new java.io.File("domain-recon-results.csv"));
        
        int userSelection = fileChooser.showSaveDialog(getBurpFrame());
        
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            java.io.File fileToSave = fileChooser.getSelectedFile();
            
            try (java.io.PrintWriter writer = new java.io.PrintWriter(fileToSave)) {
                // CSV Header
                writer.println("Domain,Status,Active Port,Technologies,Technology Versions,Security Headers Present,Security Headers Missing," +
                              "IP Address,Country,City,Organization,Open Ports,Vulnerabilities," +
                              "SSL Protocol,SSL Valid,SSL Findings,HTTP Methods Dangerous,Sensitive Files Exposed," +
                              "WordPress,Subdomain Takeover");
                
                // Data rows
                for (Map.Entry<String, DomainInfo> entry : domainData.entrySet()) {
                    String domain = entry.getKey();
                    DomainInfo info = entry.getValue();
                    
                    // Status
                    String status = info.isAlive ? "Active" : "Inactive";
                    
                    // Technologies
                    StringBuilder techList = new StringBuilder();
                    StringBuilder versionList = new StringBuilder();
                    for (Map.Entry<String, String> tech : info.technologies.entrySet()) {
                        if (!techList.isEmpty()) {
                            techList.append("; ");
                            versionList.append("; ");
                        }
                        techList.append(tech.getKey());
                        versionList.append(tech.getValue().isEmpty() ? "N/A" : tech.getValue());
                    }
                    
                    // Security Headers
                    StringBuilder presentHeaders = new StringBuilder();
                    StringBuilder missingHeaders = new StringBuilder();
                    
                    for (SecurityHeadersScanner.HeaderInfo header : info.headers.values()) {
                        if (header.isPresent()) {
                            if (!presentHeaders.isEmpty()) {
                                presentHeaders.append("; ");
                            }
                            presentHeaders.append(header.getName());
                        } else {
                            if (!missingHeaders.isEmpty()) {
                                missingHeaders.append("; ");
                            }
                            missingHeaders.append(header.getName());
                        }
                    }
                    
                    // Shodan data
                    String ip = "";
                    String country = "";
                    String city = "";
                    String org = "";
                    String ports = "";
                    int vulnCount = 0;
                    
                    if (info.serverInfo != null && info.serverInfo.getShodanInfo() != null) {
                        ShodanScanner.ShodanInfo shodan = info.serverInfo.getShodanInfo();
                        ip = info.serverInfo.getIpAddress() != null ? info.serverInfo.getIpAddress() : "";
                        country = shodan.getCountry() != null ? shodan.getCountry() : "";
                        city = shodan.getCity() != null ? shodan.getCity() : "";
                        org = shodan.getOrganization() != null ? shodan.getOrganization() : "";
                        vulnCount = shodan.getVulnerabilitiesCount();
                        
                        StringBuilder portList = new StringBuilder();
                        for (int port : shodan.getOpenPorts()) {
                            if (!portList.isEmpty()) {
                                portList.append("; ");
                            }
                            portList.append(port);
                        }
                        ports = portList.toString();
                    }
                    
                    // SSL/TLS data
                    String sslProtocol = "N/A";
                    String sslValid = "N/A";
                    String sslFindings = "0";
                    if (info.sslInfo != null) {
                        sslProtocol = info.sslInfo.getProtocol() != null ? info.sslInfo.getProtocol() : UNKNOWN;
                        sslValid = info.sslInfo.isValid() ? "Yes" : "No";
                        sslFindings = String.valueOf(info.sslInfo.getFindings().size());
                    }
                    
                    // HTTP Methods data
                    String dangerousMethods = "0";
                    if (info.httpMethodsInfo != null) {
                        long dangerous = info.httpMethodsInfo.getFindings().stream()
                            .filter(f -> "High".equalsIgnoreCase(f.getSeverity()))
                            .count();
                        dangerousMethods = String.valueOf(dangerous);
                    }
                    
                    // Sensitive Files data
                    String exposedFiles = "0";
                    if (info.sensitiveFilesInfo != null) {
                        exposedFiles = String.valueOf(info.sensitiveFilesInfo.getExposedFiles().size());
                    }
                    
                    // Active Port
                    String activePort = info.activePort > 0 ? String.valueOf(info.activePort) : "N/A";
                    
                    // WordPress
                    String wordpress = info.isWordPress() ? "YES" : "NO";
                    
                    // Subdomain Takeover
                    String subdomainTakeover = "NO";
                    if (info.takeoverInfo != null && info.takeoverInfo.isVulnerable()) {
                        subdomainTakeover = "YES";
                    }
                    
                    // Write CSV row (escape commas and quotes)
                    writer.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                        escapeCsv(domain),
                        escapeCsv(status),
                        escapeCsv(activePort),
                        escapeCsv(techList.toString()),
                        escapeCsv(versionList.toString()),
                        escapeCsv(presentHeaders.toString()),
                        escapeCsv(missingHeaders.toString()),
                        escapeCsv(ip),
                        escapeCsv(country),
                        escapeCsv(city),
                        escapeCsv(org),
                        escapeCsv(ports),
                        vulnCount,
                        escapeCsv(sslProtocol),
                        escapeCsv(sslValid),
                        escapeCsv(sslFindings),
                        escapeCsv(dangerousMethods),
                        escapeCsv(exposedFiles),
                        escapeCsv(wordpress),
                        escapeCsv(subdomainTakeover)
                    );
                }
                
                JOptionPane.showMessageDialog(getBurpFrame(), 
                    "Results exported successfully to:\n" + fileToSave.getAbsolutePath(), 
                    "Export Successful", 
                    JOptionPane.INFORMATION_MESSAGE);
                
                log("[+] Results exported to CSV: " + fileToSave.getAbsolutePath());
                
            } catch (Exception e) {
                JOptionPane.showMessageDialog(getBurpFrame(), 
                    "Error exporting to CSV: " + e.getMessage(), 
                    "Export Error", 
                    JOptionPane.ERROR_MESSAGE);
                api.logging().logToError("CSV export error: " + e.getMessage());
                api.logging().logToError(e.toString());
            }
        }
    }
    
    /**
     * Generate HTML report
     */
    private void exportToHTML() {
        if (domainData.isEmpty()) {
            JOptionPane.showMessageDialog(getBurpFrame(), 
                "No scan results to export. Please run a scan first.", 
                "No Data", 
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save HTML Report");
        fileChooser.setSelectedFile(new java.io.File("domain-recon-report.html"));
        
        int userSelection = fileChooser.showSaveDialog(getBurpFrame());
        
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            java.io.File fileToSave = fileChooser.getSelectedFile();
            
            try (java.io.PrintWriter writer = new java.io.PrintWriter(fileToSave)) {
                generateHTMLReport(writer);
                
                JOptionPane.showMessageDialog(getBurpFrame(), 
                    "HTML report generated successfully:\n" + fileToSave.getAbsolutePath(), 
                    "Export Successful", 
                    JOptionPane.INFORMATION_MESSAGE);
                
                log("[+] HTML report generated: " + fileToSave.getAbsolutePath());
                
            } catch (Exception e) {
                JOptionPane.showMessageDialog(getBurpFrame(), 
                    "Error generating HTML report: " + e.getMessage(), 
                    "Export Error", 
                    JOptionPane.ERROR_MESSAGE);
                api.logging().logToError("HTML export error: " + e.getMessage());
                api.logging().logToError(e.toString());
            }
        }
    }
    
    /**
     * Generate HTML report content
     */
    private void generateHTMLReport(java.io.PrintWriter writer) {
        writer.println("<!DOCTYPE html>");
        writer.println("<html lang='en'>");
        writer.println("<head>");
        writer.println("    <meta charset='UTF-8'>");
        writer.println("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>");
        writer.println("    <title>Domain Reconnaissance Report</title>");
        writer.println("    <style>");
        writer.println("        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }");
        writer.println("        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
        writer.println("        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }");
        writer.println("        h2 { color: #555; margin-top: 30px; border-left: 4px solid #4CAF50; padding-left: 10px; }");
        writer.println("        h3 { color: #666; margin-top: 20px; }");
        writer.println("        .domain-section { margin-bottom: 40px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }");
        writer.println("        .status-active { color: #4CAF50; font-weight: bold; }");
        writer.println("        .status-inactive { color: #f44336; font-weight: bold; }");
        writer.println("        .tech-table, .header-table, .shodan-table { width: 100%; border-collapse: collapse; margin-top: 10px; }");
        writer.println("        .tech-table th, .header-table th, .shodan-table th { background-color: #4CAF50; color: white; padding: 10px; text-align: left; }");
        writer.println("        .tech-table td, .header-table td, .shodan-table td { padding: 8px; border-bottom: 1px solid #ddd; }");
        writer.println("        .tech-table tr:hover, .header-table tr:hover, .shodan-table tr:hover { background-color: #f5f5f5; }");
        writer.println("        .present { color: #4CAF50; font-weight: bold; }");
        writer.println("        .missing { color: #f44336; font-weight: bold; }");
        writer.println("        .summary-box { background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin: 15px 0; }");
        writer.println("        .warning-box { background-color: #fff3e0; padding: 15px; border-radius: 5px; margin: 15px 0; }");
        writer.println("        .info-box { background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin: 15px 0; }");
        writer.println("        .timestamp { color: #888; font-size: 0.9em; }");
        writer.println("        .badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 0.85em; margin: 2px; }");
        writer.println("        .badge-high { background-color: #f44336; color: white; }");
        writer.println("        .badge-medium { background-color: #ff9800; color: white; }");
        writer.println("        .badge-low { background-color: #ffc107; color: white; }");
        writer.println("        .badge-info { background-color: #2196F3; color: white; }");
        writer.println("    </style>");
        writer.println("</head>");
        writer.println("<body>");
        writer.println("    <div class='container'>");
        writer.println("        <h1>🔍 Domain Reconnaissance Report</h1>");
        writer.println("        <p class='timestamp'>Generated: " + new Date() + "</p>");
        
        // Summary
        writer.println("        <div class='summary-box'>");
        writer.println("            <h2>📊 Summary</h2>");
        writer.println("            <p><strong>Total Domains Analyzed:</strong> " + domainData.size() + "</p>");
        
        int activeCount = 0;
        int totalTechs = 0;
        int totalMissingHeaders = 0;
        int totalVulns = 0;
        
        for (DomainInfo info : domainData.values()) {
            if (info.isAlive) {
                activeCount++;
            }
            totalTechs += info.technologies.size();
            for (SecurityHeadersScanner.HeaderInfo header : info.headers.values()) {
                if (!header.isPresent()) {
                    totalMissingHeaders++;
                }
            }
            if (info.serverInfo != null && info.serverInfo.getShodanInfo() != null) {
                totalVulns += info.serverInfo.getShodanInfo().getVulnerabilitiesCount();
            }
        }
        
        writer.println("            <p><strong>Active Domains:</strong> " + activeCount + " / " + domainData.size() + "</p>");
        writer.println("            <p><strong>Technologies Detected:</strong> " + totalTechs + "</p>");
        writer.println("            <p><strong>Missing Security Headers:</strong> " + totalMissingHeaders + "</p>");
        writer.println("            <p><strong>Total Vulnerabilities Found:</strong> " + totalVulns + "</p>");
        writer.println("        </div>");
        
        // Individual domain reports
        for (Map.Entry<String, DomainInfo> entry : domainData.entrySet()) {
            String domain = entry.getKey();
            DomainInfo info = entry.getValue();
            
            writer.println("        <div class='domain-section'>");
            writer.println("            <h2>🌐 " + escapeHtml(domain) + "</h2>");
            writer.println("            <p>Status: <span class='" + (info.isAlive ? "status-active" : "status-inactive") + "'>" + 
                (info.isAlive ? STATUS_ACTIVE : STATUS_INACTIVE) + "</span></p>");
            
            // Technologies
            if (!info.technologies.isEmpty()) {
                writer.println("            <h3>🔧 Technologies Detected (" + info.technologies.size() + ")</h3>");
                writer.println("            <table class='tech-table'>");
                writer.println("                <tr><th>Technology</th><th>Version</th></tr>");
                for (Map.Entry<String, String> tech : info.technologies.entrySet()) {
                    writer.println("                <tr><td>" + escapeHtml(tech.getKey()) + "</td><td>" + 
                        (tech.getValue().isEmpty() ? "<i>N/A</i>" : escapeHtml(tech.getValue())) + "</td></tr>");
                }
                writer.println("            </table>");
            }
            
            // Security Headers
            if (!info.headers.isEmpty()) {
                int present = 0;
                int missing = 0;
                for (SecurityHeadersScanner.HeaderInfo header : info.headers.values()) {
                    if (header.isPresent()) {
                        present++;
                    } else {
                        missing++;
                    }
                }
                
                writer.println("            <h3>🛡️ Security Headers (" + present + " present, " + missing + " missing)</h3>");
                
                if (missing > 0) {
                    writer.println("            <div class='warning-box'>");
                    writer.println("                <strong>⚠️ Warning:</strong> " + missing + " security header(s) missing");
                    writer.println("            </div>");
                }
                
                writer.println("            <table class='header-table'>");
                writer.println("                <tr><th>Header</th><th>Status</th><th>Value / Recommendation</th></tr>");
                for (SecurityHeadersScanner.HeaderInfo header : info.headers.values()) {
                    String statusClass = header.isPresent() ? "present" : "missing";
                    String statusText = header.isPresent() ? "✓ Present" : "✗ Missing";
                    String valueText = header.isPresent() ? 
                        escapeHtml(header.getValue()) : 
                        "<i>" + escapeHtml(header.getRecommendation()) + "</i>";
                    
                    writer.println("                <tr><td>" + escapeHtml(header.getName()) + "</td><td class='" + 
                        statusClass + "'>" + statusText + "</td><td>" + valueText + "</td></tr>");
                }
                writer.println("            </table>");
            }
            
            // Shodan Information
            if (info.serverInfo != null && info.serverInfo.getShodanInfo() != null) {
                ShodanScanner.ShodanInfo shodan = info.serverInfo.getShodanInfo();
                
                if (shodan.isSuccess()) {
                    writer.println("            <h3>🌍 Server Intelligence (Shodan)</h3>");
                    writer.println("            <div class='info-box'>");
                    writer.println("                <p><strong>IP Address:</strong> " + escapeHtml(info.serverInfo.getIpAddress()) + "</p>");
                    if (shodan.getCountry() != null) {
                        writer.println("                <p><strong>Location:</strong> " + escapeHtml(shodan.getCity() + ", " + shodan.getCountry()) + "</p>");
                    }
                    if (shodan.getOrganization() != null) {
                        writer.println("                <p><strong>Organization:</strong> " + escapeHtml(shodan.getOrganization()) + "</p>");
                    }
                    if (shodan.getIsp() != null) {
                        writer.println("                <p><strong>ISP:</strong> " + escapeHtml(shodan.getIsp()) + "</p>");
                    }
                    writer.println("            </div>");
                    
                    if (!shodan.getOpenPorts().isEmpty() || !shodan.getServices().isEmpty() || shodan.getVulnerabilitiesCount() > 0) {
                        writer.println("            <table class='shodan-table'>");
                        writer.println("                <tr><th>Category</th><th>Details</th></tr>");
                        
                        if (!shodan.getOpenPorts().isEmpty()) {
                            StringBuilder ports = new StringBuilder();
                            for (int port : shodan.getOpenPorts()) {
                                if (!ports.isEmpty()) ports.append(", ");
                                ports.append(port);
                            }
                            writer.println("                <tr><td>Open Ports</td><td>" + ports.toString() + "</td></tr>");
                        }
                        
                        if (!shodan.getServices().isEmpty()) {
                            for (String service : shodan.getServices()) {
                                writer.println("                <tr><td>Service</td><td>" + escapeHtml(service) + "</td></tr>");
                            }
                        }
                        
                        if (shodan.getVulnerabilitiesCount() > 0) {
                            writer.println("                <tr><td><span class='badge badge-high'>Vulnerabilities</span></td><td><strong>" + 
                                shodan.getVulnerabilitiesCount() + " CVE(s) found</strong></td></tr>");
                        }
                        
                        writer.println("            </table>");
                    }
                } else {
                    writer.println("            <h3>🌍 Server Intelligence (Shodan)</h3>");
                    writer.println("            <div class='warning-box'>");
                    writer.println("                <p><strong>IP:</strong> " + escapeHtml(info.serverInfo.getIpAddress()) + "</p>");
                    writer.println("                <p>" + escapeHtml(shodan.getError()) + "</p>");
                    writer.println("            </div>");
                }
            }
            
            // SSL/TLS Information
            if (info.sslInfo != null) {
                writer.println("            <h3>🔐 SSL/TLS Security Analysis</h3>");
                
                // Warning box for critical SSL issues
                if (!info.sslInfo.isValid() || !info.sslInfo.getFindings().isEmpty()) {
                    int highFindings = 0;
                    for (SSLScanner.SecurityFinding finding : info.sslInfo.getFindings()) {
                        if ("High".equalsIgnoreCase(finding.getSeverity())) {
                            highFindings++;
                        }
                    }
                    
                    if (highFindings > 0 || !info.sslInfo.isValid()) {
                        writer.println("            <div class='warning-box'>");
                        writer.println("                <strong>⚠️ Critical SSL/TLS Issues Found!</strong>");
                        if (!info.sslInfo.isValid()) {
                            writer.println("                <p>Certificate is INVALID or EXPIRED</p>");
                        }
                        if (highFindings > 0) {
                            writer.println("                <p>" + highFindings + " high severity issue(s) detected</p>");
                        }
                        writer.println("            </div>");
                    }
                }
                
                writer.println("            <table class='tech-table'>");
                writer.println("                <tr><th>Property</th><th>Value</th></tr>");
                writer.println("                <tr><td>Protocol</td><td>" + escapeHtml(info.sslInfo.getProtocol()) + "</td></tr>");
                writer.println("                <tr><td>Certificate Valid</td><td>" + 
                    (info.sslInfo.isValid() ? "<span style='color: green;'>✓ Yes</span>" : "<span style='color: red;'>✗ No</span>") + "</td></tr>");
                
                if (info.sslInfo.getCipherSuite() != null && !info.sslInfo.getCipherSuite().isEmpty()) {
                    writer.println("                <tr><td>Cipher Suite</td><td>" + escapeHtml(info.sslInfo.getCipherSuite()) + "</td></tr>");
                }
                
                if (info.sslInfo.getIssuer() != null) {
                    writer.println("                <tr><td>Issuer</td><td>" + escapeHtml(info.sslInfo.getIssuer()) + "</td></tr>");
                }
                
                if (info.sslInfo.getSubject() != null) {
                    writer.println("                <tr><td>Subject</td><td>" + escapeHtml(info.sslInfo.getSubject()) + "</td></tr>");
                }
                
                if (info.sslInfo.getValidFrom() != null) {
                    writer.println("                <tr><td>Valid From</td><td>" + info.sslInfo.getValidFrom() + "</td></tr>");
                }
                
                if (info.sslInfo.getValidUntil() != null) {
                    writer.println("                <tr><td>Valid Until</td><td>" + info.sslInfo.getValidUntil() + "</td></tr>");
                }
                
                writer.println("                <tr><td>Hostname Match</td><td>" + 
                    (info.sslInfo.isHostnameMatch() ? "<span style='color: green;'>✓ Yes</span>" : "<span style='color: red;'>✗ No</span>") + "</td></tr>");
                writer.println("                <tr><td>Self-Signed</td><td>" + 
                    (info.sslInfo.isSelfSigned() ? "<span style='color: red;'>Yes</span>" : "<span style='color: green;'>No</span>") + "</td></tr>");
                
                writer.println("            </table>");
                
                // SSL Findings
                if (!info.sslInfo.getFindings().isEmpty()) {
                    writer.println("            <h4>🔍 SSL/TLS Security Findings</h4>");
                    writer.println("            <table class='tech-table'>");
                    writer.println(HTML_TABLE_HEADER_ROW);
                    for (SSLScanner.SecurityFinding finding : info.sslInfo.getFindings()) {
                        String badgeClass = HTML_BADGE_INFO;
                        if (SEVERITY_HIGH.equalsIgnoreCase(finding.getSeverity())) {
                            badgeClass = HTML_BADGE_HIGH;
                        }
                        else if (SEVERITY_MEDIUM.equalsIgnoreCase(finding.getSeverity())) {
                            badgeClass = HTML_BADGE_MEDIUM;
                        }
                        else if (SEVERITY_LOW.equalsIgnoreCase(finding.getSeverity())) {
                            badgeClass = HTML_BADGE_LOW;
                        }
                        
                        writer.println(HTML_TABLE_ROW_START + badgeClass + "'>" + 
                            escapeHtml(finding.getSeverity()) + HTML_SPAN_END_TD + 
                            escapeHtml(finding.getTitle()) + "</td><td>" + 
                            escapeHtml(finding.getDescription()) + "</td></tr>");
                    }
                    writer.println("            </table>");
                }
            }
            
            // HTTP Methods Analysis
            if (info.httpMethodsInfo != null && !info.httpMethodsInfo.getMethodResults().isEmpty()) {
                writer.println("            <h3>🔧 HTTP Methods Analysis</h3>");
                
                // Check for dangerous methods
                boolean hasDangerous = false;
                for (HTTPMethodsScanner.SecurityFinding finding : info.httpMethodsInfo.getFindings()) {
                    if ("High".equalsIgnoreCase(finding.getSeverity())) {
                        hasDangerous = true;
                        break;
                    }
                }
                
                if (hasDangerous) {
                    writer.println("            <div class='warning-box'>");
                    writer.println("                <strong>⚠️ Dangerous HTTP Methods Enabled!</strong>");
                    writer.println("                <p>PUT and/or DELETE methods are allowed - potential security risk</p>");
                    writer.println("            </div>");
                }
                
                writer.println("            <table class='tech-table'>");
                writer.println("                <tr><th>Method</th><th>Status Code</th><th>Allowed</th><th>Risk</th></tr>");
                
                for (Map.Entry<String, HTTPMethodsScanner.MethodResult> methodEntry : info.httpMethodsInfo.getMethodResults().entrySet()) {
                    HTTPMethodsScanner.MethodResult result = methodEntry.getValue();
                    String allowedText = result.isAllowed() ? 
                        "<span style='color: orange;'>✓ Allowed</span>" : 
                        "<span style='color: green;'>✗ Not Allowed</span>";
                    
                    String riskBadge = "";
                    if (result.isAllowed()) {
                        String method = methodEntry.getKey().toUpperCase(Locale.ROOT);
                        if ("PUT".equals(method) || "DELETE".equals(method)) {
                            riskBadge = "<span class='badge badge-high'>High</span>";
                        } else if ("TRACE".equals(method) || "PATCH".equals(method)) {
                            riskBadge = "<span class='badge badge-medium'>Medium</span>";
                        } else {
                            riskBadge = "<span class='badge badge-low'>Low</span>";
                        }
                    } else {
                        riskBadge = "<span style='color: #888;'>N/A</span>";
                    }
                    
                    writer.println("                <tr><td><strong>" + escapeHtml(methodEntry.getKey()) + "</strong></td><td>" + 
                        result.getStatusCode() + "</td><td>" + allowedText + "</td><td>" + riskBadge + "</td></tr>");
                }
                writer.println("            </table>");
                
                // HTTP Methods Findings
                if (!info.httpMethodsInfo.getFindings().isEmpty()) {
                    writer.println("            <h4>🔍 HTTP Methods Security Findings</h4>");
                    writer.println("            <table class='tech-table'>");
                    writer.println(HTML_TABLE_HEADER_ROW);
                    for (HTTPMethodsScanner.SecurityFinding finding : info.httpMethodsInfo.getFindings()) {
                        String badgeClass = HTML_BADGE_INFO;
                        if (SEVERITY_HIGH.equalsIgnoreCase(finding.getSeverity())) {
                            badgeClass = HTML_BADGE_HIGH;
                        }
                        else if (SEVERITY_MEDIUM.equalsIgnoreCase(finding.getSeverity())) {
                            badgeClass = HTML_BADGE_MEDIUM;
                        }
                        else if (SEVERITY_LOW.equalsIgnoreCase(finding.getSeverity())) {
                            badgeClass = HTML_BADGE_LOW;
                        }
                        
                        writer.println(HTML_TABLE_ROW_START + badgeClass + "'>" + 
                            escapeHtml(finding.getSeverity()) + HTML_SPAN_END_TD + 
                            escapeHtml(finding.getTitle()) + "</td><td>" + 
                            escapeHtml(finding.getDescription()) + "</td></tr>");
                    }
                    writer.println("            </table>");
                }
            }
            
            // Sensitive Files Detection
            if (info.sensitiveFilesInfo != null && !info.sensitiveFilesInfo.getExposedFiles().isEmpty()) {
                writer.println("            <h3>📂 Sensitive Files Exposed</h3>");
                
                writer.println("            <div class='warning-box'>");
                writer.println("                <strong>⚠️ " + info.sensitiveFilesInfo.getExposedFiles().size() + 
                    " Sensitive File(s) Exposed!</strong>");
                writer.println("                <p>These files should not be publicly accessible</p>");
                writer.println("            </div>");
                
                // Display exposed files
                writer.println("            <h4>Exposed Files List</h4>");
                writer.println("            <table class='tech-table'>");
                writer.println("                <tr><th>File Path</th><th>Status Code</th><th>Content Length</th></tr>");
                
                for (Map.Entry<String, SensitiveFilesScanner.FileCheckResult> fileEntry : info.sensitiveFilesInfo.getExposedFiles().entrySet()) {
                    SensitiveFilesScanner.FileCheckResult result = fileEntry.getValue();
                    String sizeText = result.getContentLength() > 0 ? formatFileSize(result.getContentLength()) : "N/A";
                    
                    writer.println("                <tr><td><code>" + escapeHtml(fileEntry.getKey()) + "</code></td><td>" + 
                        result.getStatusCode() + "</td><td>" + sizeText + "</td></tr>");
                }
                writer.println("            </table>");
                
                // Sensitive Files Findings
                if (!info.sensitiveFilesInfo.getFindings().isEmpty()) {
                    writer.println("            <h4>🔍 Sensitive Files Security Findings</h4>");
                    writer.println("            <table class='tech-table'>");
                    writer.println(HTML_TABLE_HEADER_ROW);
                    for (SensitiveFilesScanner.SecurityFinding finding : info.sensitiveFilesInfo.getFindings()) {
                        String badgeClass = HTML_BADGE_INFO;
                        if (SEVERITY_HIGH.equalsIgnoreCase(finding.getSeverity())) {
                            badgeClass = HTML_BADGE_HIGH;
                        }
                        else if (SEVERITY_MEDIUM.equalsIgnoreCase(finding.getSeverity())) {
                            badgeClass = HTML_BADGE_MEDIUM;
                        }
                        else if (SEVERITY_LOW.equalsIgnoreCase(finding.getSeverity())) {
                            badgeClass = HTML_BADGE_LOW;
                        }
                        
                        writer.println(HTML_TABLE_ROW_START + badgeClass + "'>" + 
                            escapeHtml(finding.getSeverity()) + HTML_SPAN_END_TD + 
                            escapeHtml(finding.getTitle()) + "</td><td>" + 
                            escapeHtml(finding.getDescription()) + "</td></tr>");
                    }
                    writer.println("            </table>");
                }
            }
            
            // WordPress Detection
            writer.println("            <h3>🔧 WordPress Detection</h3>");
            if (info.isWordPress()) {
                writer.println("            <div class='warning-box'>");
                writer.println("                <strong>✅ WordPress Detected</strong>");
                if (info.wpInfo != null) {
                    if (info.wpInfo.getVersion() != null && !info.wpInfo.getVersion().isEmpty()) {
                        writer.println("                <p><strong>Version:</strong> " + escapeHtml(info.wpInfo.getVersion()) + "</p>");
                    }
                    if (info.wpInfo.getPlugins() != null && !info.wpInfo.getPlugins().isEmpty()) {
                        writer.println("                <p><strong>Plugins:</strong> " + info.wpInfo.getPlugins().size() + " detected</p>");
                    }
                    if (info.wpInfo.getThemes() != null && !info.wpInfo.getThemes().isEmpty()) {
                        writer.println("                <p><strong>Themes:</strong> " + info.wpInfo.getThemes().size() + " detected</p>");
                    }
                }
                writer.println("            </div>");
            } else {
                writer.println("            <div class='info-box'>");
                writer.println("                <strong>❌ WordPress Not Detected</strong>");
                writer.println("            </div>");
            }
            
            // Subdomain Takeover Vulnerability
            writer.println("            <h3>🎯 Subdomain Takeover</h3>");
            if (info.takeoverInfo != null && info.takeoverInfo.isVulnerable()) {
                writer.println("            <div class='warning-box'>");
                writer.println("                <strong>⚠️ VULNERABLE TO SUBDOMAIN TAKEOVER</strong>");
                if (info.takeoverInfo.getDetectedService() != null && !info.takeoverInfo.getDetectedService().isEmpty()) {
                    writer.println("                <p><strong>Service:</strong> " + escapeHtml(info.takeoverInfo.getDetectedService()) + "</p>");
                }
                if (info.takeoverInfo.getCnameTarget() != null && !info.takeoverInfo.getCnameTarget().isEmpty()) {
                    writer.println("                <p><strong>CNAME Target:</strong> " + escapeHtml(info.takeoverInfo.getCnameTarget()) + "</p>");
                }
                writer.println("            </div>");
            } else {
                writer.println("            <div class='info-box'>");
                writer.println("                <strong>✅ Not Vulnerable</strong>");
                writer.println("            </div>");
            }
            
            writer.println("        </div>");
        }
        
        writer.println("        <footer style='margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #888;'>");
        writer.println("            <p>Generated by BurpSuite Domain Reconnaissance Extension</p>");
        writer.println("        </footer>");
        writer.println("    </div>");
        writer.println("</body>");
        writer.println("</html>");
    }
    
    private String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\"", "\"\"");
    }
    
    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#39;");
    }
    
    /**
     * Get the Burp Suite main frame for proper dialog parent
     * This ensures dialogs appear on the correct monitor in multi-monitor setups
     */
    /**
     * Get the Burp Suite frame using Montoya API
     */
    private Frame getBurpFrame() {
        try {
            return api.userInterface().swingUtils().suiteFrame();
        } catch (Exception e) {
            api.logging().logToError("Failed to get Burp Suite frame: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Cleanup method called when extension is unloaded
     * Stops all active scans and releases resources
     */
    public void cleanup() {
        api.logging().logToOutput("Cleaning up Domain Reconnaissance extension...");
        
        // Stop any running scans
        shouldStop.set(true);
        
        // Signal all scanners to stop
        if (subdomainEnumerator != null) {
            subdomainEnumerator.setShouldStop(shouldStop);
        }
        if (sensitiveFilesScanner != null) {
            sensitiveFilesScanner.setShouldStop(shouldStop);
        }
        
        // Update UI to reflect stopped state
        SwingUtilities.invokeLater(() -> {
            if (scanButton != null) {
                scanButton.setEnabled(true);
            }
            if (stopButton != null) {
                stopButton.setEnabled(false);
            }
            if (skipDomainButton != null) {
                skipDomainButton.setEnabled(false);
            }
            if (progressBar != null) {
                progressBar.setIndeterminate(false);
                progressBar.setString("Extension unloaded");
            }
        });
        
        scanRunning.set(false);
        api.logging().logToOutput("Cleanup completed");
    }
    
    /**
     * Class to hold domain information
     * 
     * IMPORTANT for large projects:
     * - This class DOES NOT store HttpRequestResponse objects from Burp
     * - Only processed scan results (strings, maps, custom objects) are stored
     * - This approach prevents memory issues with large site maps
     * - All HTTP responses are processed immediately and discarded
     */
    private static class DomainInfo {
        boolean isAlive;
        Map<String, String> technologies;
        Map<String, SecurityHeadersScanner.HeaderInfo> headers;
        ShodanScanner.ServerInfo serverInfo;
        WordPressScanner.WordPressInfo wpInfo;
        SSLScanner.SSLInfo sslInfo;
        HTTPMethodsScanner.HTTPMethodsInfo httpMethodsInfo;
        SensitiveFilesScanner.SensitiveFilesInfo sensitiveFilesInfo;
        SubdomainTakeoverScanner.TakeoverInfo takeoverInfo;
        
        // New fields for enhanced reporting
        int activePort = -1;           // Port where domain responds (-1 = standard ports 80/443)
        
        DomainInfo(String domain) {
            this.isAlive = false;
            this.technologies = new LinkedHashMap<>();
            this.headers = new LinkedHashMap<>();
            this.activePort = -1;      // Default to standard ports
        }
        
        /**
         * Check if this is a WordPress site (convenience method)
         */
        boolean isWordPress() {
            return wpInfo != null && wpInfo.isWordPress();
        }
    }
}
