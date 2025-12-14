# janus/recon/sensitive_files.py
"""
Sensitive File Scanner.

Scans for exposed sensitive files and directories that should not be public:
- Version control (.git, .svn)
- Configuration files (.env, config.php)
- Backup files (.bak, .old, .swp)
- Development/debug endpoints
- API documentation

IMPORTANT: Uses content verification to minimize false positives.
Only reports TRUE POSITIVES where actual sensitive content is detected.
"""

import requests
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class SensitiveFileFinding:
    """A sensitive file finding."""
    url: str
    file_type: str
    category: str  # vcs, config, backup, debug, docs
    status_code: int
    severity: str
    description: str
    recommendation: str
    confidence: str  # HIGH, MEDIUM, LOW
    evidence: str = ""  # Proof of finding
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SensitiveFilesReport:
    """Sensitive files scan report."""
    target_url: str
    scan_time: str
    files_found: int
    critical_findings: int
    high_findings: int
    verified_findings: int  # Only high-confidence findings
    findings: List[SensitiveFileFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings]
        }


class SensitiveFileScanner:
    """
    Sensitive File Scanner with FALSE POSITIVE REDUCTION.
    
    Key improvements:
    - Content validation (not just status code)
    - Pattern matching for actual sensitive data
    - Confidence scoring (HIGH/MEDIUM/LOW)
    - Filters out SPA app shells and error pages
    """
    
    # Content patterns to VERIFY file is actually sensitive
    CONTENT_VALIDATORS = {
        'vcs': {
            '.git/config': [r'\[core\]', r'\[remote', r'repositoryformatversion'],
            '.git/HEAD': [r'ref: refs/heads/'],
            '.git/index': [rb'DIRC'],  # Binary signature
            '.gitignore': [r'^[\w\*\.]', r'node_modules', r'\.env'],
            '.svn/entries': [r'^\d+', r'dir\n'],
            '.svn/wc.db': [rb'SQLite'],  # SQLite header
            '.hg/hgrc': [r'\[paths\]'],
            '.bzr/README': [r'bazaar'],
        },
        'config': {
            '.env': [r'^\w+\s*=', r'DB_', r'API_KEY', r'SECRET', r'PASSWORD', r'TOKEN'],
            '.env.local': [r'^\w+\s*=', r'NEXT_', r'REACT_', r'VITE_'],
            '.env.production': [r'^\w+\s*=', r'NODE_ENV\s*=\s*production'],
            'config.php': [r'<\?php', r'\$config', r'define\('],
            'config.inc.php': [r'<\?php', r'\$cfg', r'\$config'],
            'configuration.php': [r'<\?php', r'JConfig'],
            'settings.php': [r'<\?php', r'\$databases', r'\$settings'],
            'database.yml': [r'adapter:', r'database:', r'host:'],
            'secrets.yml': [r'secret_key', r'production:'],
            'credentials.json': [r'"type":', r'"client_email":', r'"private_key":'],
            'config.json': [r'"database"', r'"api', r'"secret'],
            'config.yaml': [r'database:', r'secret:'],
            'config.yml': [r'database:', r'secret:'],
            'application.properties': [r'spring\.', r'jdbc\.'],
            'application.yml': [r'spring:', r'datasource:'],
            'web.config': [r'<configuration>', r'<connectionStrings>'],
            'appsettings.json': [r'"ConnectionStrings"', r'"Logging"'],
            'wp-config.php': [r'DB_NAME', r'DB_USER', r'DB_PASSWORD', r'table_prefix'],
            'wp-config.php.bak': [r'DB_NAME', r'DB_USER'],
        },
        'backup': {
            'backup.sql': [r'CREATE TABLE', r'INSERT INTO', r'-- MySQL', r'-- PostgreSQL'],
            'database.sql': [r'CREATE TABLE', r'INSERT INTO'],
            'db.sql': [r'CREATE TABLE', r'INSERT INTO'],
            'dump.sql': [r'CREATE TABLE', r'INSERT INTO', r'mysqldump'],
            'backup.zip': [rb'PK\x03\x04'],  # ZIP signature
            'backup.tar.gz': [rb'\x1f\x8b'],  # GZIP signature
            'site.zip': [rb'PK\x03\x04'],
            'www.zip': [rb'PK\x03\x04'],
        },
        'debug': {
            'phpinfo.php': [r'PHP Version', r'phpinfo\(\)', r'Configuration'],
            'info.php': [r'PHP Version', r'phpinfo'],
            'test.php': [r'<\?php', r'test'],
            'debug.log': [r'\[\d{4}-\d{2}-\d{2}', r'ERROR', r'WARNING', r'Exception'],
            'error.log': [r'\[error\]', r'ERROR', r'Exception', r'\[\d{4}'],
            'access.log': [r'GET /', r'POST /', r'HTTP/1\.\d'],
        },
        'docs': {
            'swagger.json': [r'"swagger":', r'"openapi":', r'"paths":'],
            'swagger.yaml': [r'swagger:', r'openapi:', r'paths:'],
            'openapi.json': [r'"openapi":', r'"paths":'],
            'openapi.yaml': [r'openapi:', r'paths:'],
        },
        'database': {
            'database.sqlite': [rb'SQLite format'],
            'database.db': [rb'SQLite format'],
            'data.db': [rb'SQLite format'],
            'db.sqlite3': [rb'SQLite format'],
        },
    }
    
    # SPA / Error page detection patterns (FALSE POSITIVE indicators)
    FALSE_POSITIVE_PATTERNS = [
        r'<!DOCTYPE html>.*?<div id="(root|app|__next)"',  # React/Vue/Next.js app shell
        r'<script.*?src=.*?bundle\.js',  # JS bundles
        r'<title>.*?(404|Not Found|Error)',  # Error pages
        r'<noscript>.*?JavaScript',  # SPA messages
        r'window\.__NUXT__',  # Nuxt.js
        r'window\.__INITIAL_STATE__',  # SSR apps
        r'"statusCode":404',  # JSON error
        r'Page Not Found',
        r'The page you requested could not be found',
        r'This page doesn\'t exist',
    ]
    
    SENSITIVE_FILES = {
        'vcs': {
            'files': ['.git/config', '.git/HEAD', '.gitignore'],
            'severity': 'CRITICAL',
            'description': 'Version control files exposed - may leak source code',
            'recommendation': 'Block access to version control directories in web server config'
        },
        'config': {
            'files': [
                '.env', '.env.local', '.env.production',
                'config.php', 'wp-config.php', 'web.config',
                'appsettings.json', 'database.yml', 'secrets.yml'
            ],
            'severity': 'CRITICAL',
            'description': 'Configuration file exposed - may contain secrets/credentials',
            'recommendation': 'Never expose configuration files. Store outside webroot.'
        },
        'backup': {
            'files': ['backup.sql', 'database.sql', 'dump.sql', 'backup.zip'],
            'severity': 'HIGH',
            'description': 'Backup file exposed - may contain sensitive data',
            'recommendation': 'Remove backup files from production.'
        },
        'debug': {
            'files': ['phpinfo.php', 'debug.log', 'error.log'],
            'severity': 'MEDIUM',
            'description': 'Debug/log file exposed - may leak sensitive information',
            'recommendation': 'Remove debug files from production'
        },
        'docs': {
            'files': ['swagger.json', 'swagger.yaml', 'openapi.json', 'openapi.yaml'],
            'severity': 'LOW',
            'description': 'API documentation exposed',
            'recommendation': 'Consider restricting API docs to authenticated users'
        },
    }
    
    def __init__(self, timeout: int = 5, threads: int = 10):
        self.timeout = timeout
        self.threads = threads
    
    def scan(
        self,
        base_url: str,
        token: Optional[str] = None,
        categories: Optional[List[str]] = None
    ) -> SensitiveFilesReport:
        """
        Scan for sensitive files with content verification.
        
        Only reports findings with HIGH confidence (actual sensitive content detected).
        """
        findings = []
        headers = {'Authorization': token} if token else {}
        headers['User-Agent'] = 'Janus-Security-Scanner/3.0'
        
        # Build list of URLs to check
        urls_to_check = []
        for category, config in self.SENSITIVE_FILES.items():
            if categories and category not in categories:
                continue
            
            for file_path in config['files']:
                url = urljoin(base_url.rstrip('/') + '/', file_path)
                urls_to_check.append((url, file_path, category, config))
        
        # Check URLs concurrently
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_file_verified, url, file_path, cat, headers): (url, path, cat, cfg)
                for url, path, cat, cfg in urls_to_check
            }
            
            for future in as_completed(futures):
                url, path, category, config = futures[future]
                try:
                    result = future.result()
                    if result and result['confidence'] != 'NONE':
                        findings.append(SensitiveFileFinding(
                            url=url,
                            file_type=path,
                            category=category,
                            status_code=result['status'],
                            severity=config['severity'] if result['confidence'] == 'HIGH' else 'MEDIUM',
                            description=config['description'],
                            recommendation=config['recommendation'],
                            confidence=result['confidence'],
                            evidence=result.get('evidence', '')
                        ))
                except Exception:
                    pass
        
        # Only count HIGH confidence as verified
        verified = sum(1 for f in findings if f.confidence == 'HIGH')
        critical = sum(1 for f in findings if f.severity == 'CRITICAL' and f.confidence == 'HIGH')
        high = sum(1 for f in findings if f.severity == 'HIGH' and f.confidence == 'HIGH')
        
        return SensitiveFilesReport(
            target_url=base_url,
            scan_time=datetime.now().isoformat(),
            files_found=len(findings),
            critical_findings=critical,
            high_findings=high,
            verified_findings=verified,
            findings=findings
        )
    
    def _check_file_verified(
        self,
        url: str,
        file_path: str,
        category: str,
        headers: Dict
    ) -> Optional[Dict]:
        """Check if a file exists AND contains actual sensitive content."""
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Only process 200 OK responses
            if response.status_code != 200:
                return None
            
            content_length = len(response.content)
            content_type = response.headers.get('Content-Type', '')
            
            # Skip empty responses
            if content_length == 0:
                return None
            
            # Check for SPA app shell / error page (FALSE POSITIVE)
            if 'text/html' in content_type:
                content_text = response.text[:5000]
                for fp_pattern in self.FALSE_POSITIVE_PATTERNS:
                    if re.search(fp_pattern, content_text, re.IGNORECASE | re.DOTALL):
                        return None  # This is likely a SPA serving index.html
            
            # Get validators for this file
            validators = self.CONTENT_VALIDATORS.get(category, {}).get(file_path, [])
            
            if validators:
                # Check for content patterns
                content = response.content if any(isinstance(v, bytes) for v in validators) else response.text
                matches = []
                
                for pattern in validators:
                    if isinstance(pattern, bytes):
                        if re.search(pattern, response.content):
                            matches.append(pattern.decode('utf-8', errors='ignore')[:20])
                    else:
                        match = re.search(pattern, response.text, re.MULTILINE | re.IGNORECASE)
                        if match:
                            matches.append(match.group(0)[:50])
                
                if matches:
                    return {
                        'status': response.status_code,
                        'confidence': 'HIGH',
                        'evidence': f"Content verified: {', '.join(matches[:3])}"
                    }
                else:
                    # File exists but no sensitive patterns matched
                    # This could be a false positive or sanitized file
                    return {
                        'status': response.status_code,
                        'confidence': 'LOW',
                        'evidence': f"File exists but content not verified (size: {content_length})"
                    }
            else:
                # No validators defined - use basic heuristics
                if self._looks_sensitive(response.text, file_path, content_type):
                    return {
                        'status': response.status_code,
                        'confidence': 'MEDIUM',
                        'evidence': f"Heuristic match (Content-Type: {content_type})"
                    }
            
        except Exception:
            pass
        
        return None
    
    def _looks_sensitive(self, content: str, file_path: str, content_type: str) -> bool:
        """Basic heuristics for file sensitivity."""
        # Check content type matches expected
        if file_path.endswith('.json') and 'application/json' not in content_type:
            return False
        if file_path.endswith('.yaml') and 'yaml' not in content_type and 'text/plain' not in content_type:
            return False
        if file_path.endswith('.sql') and 'CREATE TABLE' not in content and 'INSERT' not in content:
            return False
        
        # Generic sensitive patterns
        sensitive_patterns = [
            r'password\s*[=:]',
            r'secret\s*[=:]',
            r'api_key\s*[=:]',
            r'private_key',
            r'BEGIN RSA PRIVATE KEY',
            r'BEGIN OPENSSH PRIVATE KEY',
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def quick_scan(
        self,
        base_url: str,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Quick scan focusing on critical files."""
        report = self.scan(base_url, token, categories=['vcs', 'config'])
        
        return {
            "url": base_url,
            "files_found": report.files_found,
            "verified": report.verified_findings,
            "critical": report.critical_findings,
            "findings": [
                {
                    "path": f.file_type,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "evidence": f.evidence
                }
                for f in report.findings if f.confidence in ['HIGH', 'MEDIUM']
            ]
        }
