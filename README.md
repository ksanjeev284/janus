# Janus Security Scanner 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Docker Deploy](https://github.com/ksanjeev284/janus/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/ksanjeev284/janus/actions/workflows/docker-publish.yml)
[![PyPI version](https://badge.fury.io/py/janus-security.svg)](https://badge.fury.io/py/janus-security)

**Janus** is an enterprise-grade API security scanner designed for Red Teams and advanced security testing. Features 15+ security testing modules for comprehensive vulnerability assessment.

![Janus Dashboard Demo](docs/dashboard-demo.webp)


## Features 🚀

### Authorization Testing
- **BOLA/IDOR Detection** - Automatic analysis of resource access patterns
- **BFLA Scanner** - Vertical privilege escalation testing
- **JWT Attacks** - Token manipulation and weak secret detection

### Injection Testing
- **SQL Injection** - Error-based and time-based detection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **XSS Scanner** - Context-aware cross-site scripting detection with 30+ payloads
- **SSRF Testing** - Server-side request forgery with 25+ payloads (internal networks, cloud metadata)
- **Path Traversal/LFI** - Directory traversal with encoding bypasses

### Configuration Analysis
- **Security Headers** - HSTS, CSP, X-Frame-Options analysis with A-F grading
- **CORS Scanner** - Origin reflection, wildcard, null origin detection
- **Open Redirect** - Unvalidated redirect testing with 30+ bypass payloads
- **Rate Limiting** - API rate limit and brute force protection testing

### Reconnaissance
- **Sensitive Files** - Find exposed .git, .env, backups, logs (80+ paths)
- **Tech Fingerprint** - Detect servers, frameworks, CMS, CDN
- **PII Scanner** - Detect sensitive data leaks in API responses
- **CVE Lookup** - Check for known vulnerabilities

### Advanced Features
- **Proxy Support** - HTTP, HTTPS, SOCKS5 (including Tor)
- **Custom Headers** - Add custom headers to all requests
- **Stealth Mode** - WAF evasion with header rotation and jitter
- **Webhook Notifications** - Discord, Slack, Email alerts
- **CI/CD Integration** - SARIF export for GitHub Security tab

## Installation 📦

### PyPI (Recommended)
```bash
pip install janus-security
```

### From Source
```bash
git clone https://github.com/ksanjeev284/janus.git
cd janus
pip install .
```

## Quick Start 🏃‍♂️

### Web Dashboard
```bash
# Start dashboard
python -m janus.interface.web.server
# Access at http://localhost:8000
```

### CLI Commands

#### Authorization Testing
```bash
# BOLA/IDOR Scan
janus scan --victim <token> --attacker <token> --host <url>

# BFLA (Privilege Escalation)
janus bfla --host https://api.example.com --low <user_token>

# JWT Analysis
janus jwt --token <jwt_token>
```

#### Injection Testing
```bash
# SQL Injection
janus sqli --url "https://api.example.com/search?q=test" --param q

# XSS Detection
janus xss --url "https://example.com/page?name=test" --param name

# SSRF Testing
janus ssrf --endpoint https://api.example.com/fetch --param url

# Path Traversal / LFI
janus lfi --url "https://example.com/view?file=test" --param file
```

#### Configuration Analysis
```bash
# Security Headers (A-F Grade)
janus security-headers --url https://example.com

# CORS Misconfiguration
janus cors --url https://api.example.com

# Open Redirect
janus open-redirect --url https://example.com/login?next=

# Rate Limiting
janus rate-limit --url https://api.example.com/login --requests 50
```

#### Reconnaissance
```bash
# Sensitive Files (.git, .env, backups)
janus sensitive-files --url https://example.com

# Technology Fingerprint
janus fingerprint --url https://example.com

# PII Scanner
janus pii --url https://api.example.com/user/1 --token <token>

# Race Condition
janus race --url https://api.example.com/withdraw --token <token>
```

## Proxy & Custom Headers

```python
from janus.core.http_client import JanusHTTPClient

client = JanusHTTPClient()
client.set_proxy("http://proxy.example.com:8080")  # HTTP
client.set_proxy("socks5://127.0.0.1:9050", "socks5")  # Tor
client.add_global_header("X-API-Key", "your-key")
client.set_ssl_verify(False)  # For testing

status, body, raw = client.get("https://api.example.com", token="Bearer xyz")
```

## Tor Support 🧅

Route all scan traffic through Tor for anonymity:

### Requirements
1. **Install Tor** on your system
2. **Start Tor service** (listens on port 9050)

### Installation

**Windows (Chocolatey):**
```bash
choco install tor
tor  # Start the service
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install tor
sudo systemctl start tor
```

**macOS:**
```bash
brew install tor
tor  # Start the service
```

### Usage

**Dashboard:** Settings tab → Check "Use Tor" → Click Test

**CLI:**
```bash
janus stealth-test --tor
```

**Programmatic:**
```python
client.set_proxy("socks5://127.0.0.1:9050", "socks5")
```

> **Note:** Tor Browser uses port **9150**, while Tor service uses **9050**.

## CI/CD Integration

```bash
# Generate SARIF report (exits with code 1 if vulnerabilities found)
janus ci-scan --victim <token> --attacker <token> --host <url>
```

## Architecture 🏗️

Janus operates by "learning" from legitimate traffic to understand API resource structures, then attempts access using a different user's context, analyzing response similarity to determine vulnerability.

## Contributing 🤝

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License 📄

MIT License - see [LICENSE](LICENSE) for details.
