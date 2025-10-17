# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-10-17

### 🚀 Major Changes

#### Migration to Montoya API
- **BREAKING CHANGE**: Complete migration from legacy Burp Extender API to modern Montoya API
- Updated for Burp Suite 2023.10.3.4+ compatibility
- Improved extension lifecycle management and resource handling
- Better integration with modern Burp Suite features

#### Architecture Improvements
- Refactored extension initialization and registration
- Improved thread management with proper cleanup handlers
- Enhanced error handling and logging through Montoya API
- Better memory management for large projects (max 10,000 domains)

### ✨ New Features

#### Enhanced Security Analysis
- **Subdomain Takeover Detection**: Automatic detection of vulnerable subdomains
  - CNAME fingerprinting for popular services (GitHub Pages, AWS, Azure, Heroku, etc.)
  - DNS resolution analysis
  - HTTP response pattern matching
  
- **WordPress Security Scanner**: Comprehensive WordPress analysis
  - Version detection
  - Plugin enumeration
  - Theme detection
  - User enumeration via REST API
  - Security findings with severity levels

- **HTTP Methods Testing**: Security analysis of allowed HTTP methods
  - Detection of dangerous methods (PUT, DELETE, TRACE, PATCH)
  - Risk assessment and recommendations
  - Detailed findings for each method

- **Sensitive Files Detection**: Enhanced file exposure detection
  - Expanded file dictionary (backup files, config files, logs)
  - Status code analysis
  - Content-length validation
  - Custom dictionary support

#### Improved User Interface
- **New Table Columns**:
  - Subdomain Takeover status (🔴 YES / ✅ NO)
  - Sensitive Files count with color coding
  - WordPress detection status
  - Active port information

- **Enhanced Export Features**:
  - **CSV Export**: Complete data export with all scan results
  - **HTML Export**: Professional styled reports with:
    - Summary statistics
    - Detailed findings per domain
    - Color-coded severity badges
    - Technology stack visualization
    - Security recommendations

- **Scan Control**:
  - Instant scan stopping capability
  - Skip current domain option
  - Proper abort vs completion messaging
  - Real-time progress updates

### 🔧 Technical Improvements

#### Performance & Reliability
- Reduced default timeouts (5s) and retries (1) for faster, safer scanning
- Removed multi-port probing (only standard 80/443)
- Background thread optimization
- Proper resource cleanup on extension unload

#### Code Quality
- Complete refactoring to Montoya API standards
- Improved exception handling
- Better separation of concerns
- Thread-safe operations with AtomicBoolean flags
- Comprehensive JavaDoc documentation

#### BApp Store Compliance
- ✅ All 11 applicable requirements verified
- ✅ Secure operation with proper output escaping
- ✅ Uses Burp networking (api.http())
- ✅ Background threads for responsiveness
- ✅ Clean unloading handler
- ✅ Offline working support
- ✅ Handles large projects efficiently
- ✅ GUI parent frame properly set

### 🐛 Bug Fixes
- Fixed memory leaks with HttpRequestResponse objects
- Fixed dialog positioning on multi-monitor setups
- Fixed race conditions in scan state management
- Fixed CSV/HTML export escaping issues
- Fixed SSL certificate validation edge cases

### 🗑️ Removed Features
- **Security Score**: Removed scoring system (was too simplistic)
- Multi-port subdomain probing (unreliable and slow)
- Legacy Burp Extender API dependencies

### 📝 Documentation
- Created comprehensive BApp Store compliance documentation
- Added detailed README with installation instructions
- Included security disclaimer
- Added code examples and usage guidelines

### ⚙️ Configuration Changes
- Default request timeout: 10s → 5s
- Default max retries: 2 → 1
- WordPress detection severity: Medium → Information (unless high-risk findings)
- Memory limits: 10,000 domains (warning at 8,000)

---

## [1.1.0] - 2024 (Legacy)

### Features
- Basic subdomain enumeration
- Security headers checking
- Technology detection
- Shodan integration
- SSL/TLS analysis

### Notes
- Used legacy Burp Extender API
- Not compatible with modern Burp Suite versions

---

## Migration Guide: 1.x → 2.0.0

### Breaking Changes

1. **API Migration**
   - Extension now requires Burp Suite 2023.10.3.4 or newer
   - Legacy Extender API code removed completely
   - All HTTP requests now use Montoya API

2. **Removed Features**
   - Security Score column removed from UI and exports
   - Multi-port probing no longer available

3. **Behavioral Changes**
   - WordPress detection issues now have "Information" severity by default
   - Faster scanning with reduced timeouts
   - More conservative network behavior

### Upgrade Steps

1. **Unload old extension** (version 1.x) from Burp Suite
2. **Delete old JAR** from extensions directory
3. **Download new JAR** (domain-recon-2.0.0.jar)
4. **Load extension** in Burp Suite
5. **Verify** Montoya API compatibility (Burp 2023.10+)

### What to Expect

- ✅ Faster scanning performance
- ✅ More stable and reliable
- ✅ Better memory management
- ✅ Enhanced reporting capabilities
- ✅ New vulnerability detection features
- ❌ No more security score (was removed)
- ❌ Slightly different UI layout (removed score column)

---

## Roadmap

### Planned for 2.1.0
- [ ] Custom scan profiles (save/load configurations)
- [ ] Parallel domain scanning
- [ ] Integration with external APIs (SecurityTrails, VirusTotal)
- [ ] Advanced filtering and search in results
- [ ] Export to JSON format

### Future Considerations
- GraphQL endpoint detection
- API security testing
- Cloud service detection (AWS, Azure, GCP)
- Container/Kubernetes fingerprinting
- CI/CD integration support

---

## Contributors

- **AnxxJan** - Lead Developer

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- PortSwigger for Burp Suite and Montoya API
- Community feedback and bug reports
- Open source security tools that inspired features

---

**For more information**: See [README.md](README.md)  
**Security Policy**: See [DISCLAIMER.md](DISCLAIMER.md)  
**BApp Store Compliance**: See [BAPPSTORE_COMPLIANCE.md](BAPPSTORE_COMPLIANCE.md)
