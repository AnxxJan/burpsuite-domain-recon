# BurpSuite Domain Reconnaissance

![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Burp Suite Badge](https://img.shields.io/badge/Burp%20Suite-F63?logo=burpsuite&logoColor=fff&style=flat)

Automated domain reconnaissance and security analysis extension for BurpSuite.

## Features

- **Subdomain Enumeration** - Automatic discovery via crt.sh, HackerTarget, and ThreatCrowd
- **Security Headers Analysis** - Detection of 12 critical headers (HSTS, CSP, X-Frame-Options, etc.)
- **SSL/TLS Analysis** - Certificate validation, protocol security, and vulnerability detection
- **HTTP Methods Detection** - Identifies dangerous methods (TRACE, CONNECT, DELETE, PUT)
- **Sensitive Files Scanner** - Searches for 62+ exposed paths (.git, .env, backups, etc.)
- **Technology Detection** - Identifies 60+ frameworks and CMS platforms
- **Shodan Integration** - Server intelligence and exposed ports information
- **Subdomain Takeover Detection** - Identifies subdomain takeover vulnerabilities
- **WordPress Scanner** - WordPress-specific security analysis
- **Results Export** - CSV and HTML formats with all findings

## Screenshots

### Main Interface
<img width="1916" height="942" alt="image" src="https://github.com/user-attachments/assets/c2712ff0-455e-4d75-9897-cd548f1d0fe9" />


### Options
<img width="1913" height="942" alt="image" src="https://github.com/user-attachments/assets/36c4f64d-6785-466a-b450-0754231cdfa5" />


## Installation

**Requirements:** BurpSuite 2023.10.3.4+, Java 21+

1. Download the JAR from [Releases](https://github.com/AnxxJan/burpsuite-domain-recon/releases)
2. BurpSuite → Extensions → Add → Select JAR file
3. Navigate to the **Domain Reconnaissance** tab

## Usage

1. Enter one or multiple domains: `example.com, test.com`
2. (Optional) Configure scan modules in the **Settings** tab
3. Click **Start Reconnaissance**
4. Review results and export to CSV/HTML

## Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed exclusively for security professionals conducting authorized testing:

- ✅ Use only on systems you own or have explicit written authorization to test
- ✅ Obtain legal permission before performing any scanning activities
- ❌ Unauthorized scanning may violate local and international laws
- ❌ The authors are not responsible for misuse of this tool

See [DISCLAIMER.md](DISCLAIMER.md) for complete legal information.

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<div align="center">
Developed by <strong>Anxx</strong> with GitHub Copilot 🤖
</div>
