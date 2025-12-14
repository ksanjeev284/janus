# Janus Security Scanner 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Docker Deploy](https://github.com/ksanjeev284/janus/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/ksanjeev284/janus/actions/workflows/docker-publish.yml)
[![PyPI version](https://badge.fury.io/py/janus-security.svg)](https://badge.fury.io/py/janus-security)

**Janus** is an enterprise-grade API security scanner designed for Red Teams and advanced security testing. Unlike traditional scanners, Janus uses a distinct approach for detecting **BOLA (Broken Object Level Authorization)**, **BFLA**, and **Race Conditions** without relying on external AI APIs.

![Janus Dashboard](docs/dashboard-preview.png)

## Features 🚀

-   **BOLA/IDOR Detection**: Automatic analysis of resource access patterns.
-   **Broken Function Level Authorization (BFLA)**: Vertical privilege escalation testing.
-   **PII & Secrets Scanning**: Detect sensitive data leaks in API responses.
-   **Race Condition Testing**: Multi-threaded exploitation of concurrency bugs.
-   **SSRF Testing**: Server-Side Request Forgery with 25+ payloads (internal networks, cloud metadata, file protocols).
-   **Stealth Mode**: WAF evasion with header rotation, jitter, and proxies.
-   **Proxy Support**: HTTP, HTTPS, and SOCKS5 proxies (including Tor).
-   **Custom Headers**: Add custom headers to all requests.
-   **Team Collaboration**: Real-time finding synchronization via Redis/Hive-Mind.
-   **CI/CD Integration**: Export findings to SARIF for GitHub Security tab.
-   **Web Dashboard**: Modern UI for managing scans and viewing reports.
-   **Webhook Notifications**: Send alerts to Discord, Slack, or custom endpoints.

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

### 1. Web Dashboard (Recommended)

**Option A: Using Docker (Fastest)**
```bash
# Pull and run the latest image
docker run -p 8000:8000 ghcr.io/ksanjeev284/janus:latest
```

**Option B: From Source**
Start the web server and dashboard:
```bash
python -m janus.interface.web.server
# Access at http://localhost:8000
```

### 2. CLI Usage
Janus provides a powerful CLI for automation testing.

**Basic BOLA Scan:**
```bash
janus scan --victim <token> --attacker <token> --host <url>
```

**SSRF Testing:**
```bash
janus ssrf --endpoint https://api.example.com/fetch --param url --quick
```

**Stealth Test:**
```bash
janus stealth-test
```

**Vertical Escalation (BFLA):**
```bash
janus bfla --host https://api.example.com --low <user_token>
```

### 3. Proxy & Custom Headers

Using the HTTP client programmatically:
```python
from janus.core.http_client import JanusHTTPClient

client = JanusHTTPClient()
client.set_proxy("http://proxy.example.com:8080")  # HTTP proxy
client.set_proxy("socks5://127.0.0.1:9050", "socks5")  # Tor
client.add_global_header("X-API-Key", "your-key")
client.set_ssl_verify(False)  # For testing

status, body, raw = client.get("https://api.example.com", token="Bearer xyz")
```

## Architecture 🏗️

Janus operates by "learning" from legitimate traffic (via its proxy or provided tokens) to understand the structure of API resources. It then attempts to access those same resources using a different user's context (the attacker), analyzing the structural similarity of the responses to determine vulnerability.

## Contributing 🤝

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License 📄

MIT License - see [LICENSE](LICENSE) for details.

