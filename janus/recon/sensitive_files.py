# janus/recon/sensitive_files.py
"""
Sensitive File Scanner.

Scans for exposed sensitive files and directories that should not be public:
- Version control (.git, .svn)
- Configuration files (.env, config.php)
- Backup files (.bak, .old, .swp)
- Development/debug endpoints
- API documentation
"""

import requests
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
    findings: List[SensitiveFileFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings]
        }


class SensitiveFileScanner:
    """
    Sensitive File Scanner.
    
    Checks for:
    - Version control exposure (.git, .svn, .hg)
    - Configuration files (.env, config.php, web.config)
    - Backup files (.bak, .old, .backup)
    - Debug/development files
    - API documentation (swagger, openapi)
    - Database files
    """
    
    # Files to check, organized by category
    SENSITIVE_FILES = {
        'vcs': {
            'files': [
                '.git/config',
                '.git/HEAD',
                '.git/index',
                '.gitignore',
                '.svn/entries',
                '.svn/wc.db',
                '.hg/hgrc',
                '.bzr/README',
            ],
            'severity': 'CRITICAL',
            'description': 'Version control files exposed - may leak source code',
            'recommendation': 'Block access to version control directories in web server config'
        },
        'config': {
            'files': [
                '.env',
                '.env.local',
                '.env.production',
                '.env.backup',
                'config.php',
                'config.inc.php',
                'configuration.php',
                'settings.php',
                'database.yml',
                'secrets.yml',
                'credentials.json',
                'config.json',
                'config.yaml',
                'config.yml',
                'application.properties',
                'application.yml',
                'web.config',
                'appsettings.json',
                'wp-config.php',
                'wp-config.php.bak',
            ],
            'severity': 'CRITICAL',
            'description': 'Configuration file exposed - may contain secrets/credentials',
            'recommendation': 'Never expose configuration files. Store outside webroot.'
        },
        'backup': {
            'files': [
                'backup.sql',
                'backup.zip',
                'backup.tar.gz',
                'database.sql',
                'db.sql',
                'dump.sql',
                'site.zip',
                'www.zip',
                'htdocs.zip',
                'public_html.zip',
                'index.php.bak',
                'index.php.old',
                'index.php~',
                '.index.php.swp',
            ],
            'severity': 'HIGH',
            'description': 'Backup file exposed - may contain sensitive data or source code',
            'recommendation': 'Remove backup files from production. Store securely offline.'
        },
        'debug': {
            'files': [
                'phpinfo.php',
                'info.php',
                'test.php',
                'debug.php',
                'debug.log',
                'error.log',
                'error_log',
                'access.log',
                'debug/',
                'test/',
                '_debug/',
                'server-status',
                'server-info',
                'elmah.axd',
                'trace.axd',
            ],
            'severity': 'MEDIUM',
            'description': 'Debug/test file exposed - may leak sensitive information',
            'recommendation': 'Remove debug files from production environments'
        },
        'docs': {
            'files': [
                'swagger.json',
                'swagger.yaml',
                'openapi.json',
                'openapi.yaml',
                'api-docs',
                'api-docs/',
                'swagger-ui/',
                'swagger-ui.html',
                'redoc/',
                'docs/',
                'api/docs',
                'api/swagger',
                'graphql',
                'graphiql',
                'playground',
            ],
            'severity': 'LOW',
            'description': 'API documentation exposed - may help attackers understand API',
            'recommendation': 'Consider restricting API docs to authenticated users in production'
        },
        'database': {
            'files': [
                'database.sqlite',
                'database.db',
                'data.db',
                'users.db',
                'app.db',
                '.sqlite',
                'db.sqlite3',
            ],
            'severity': 'CRITICAL',
            'description': 'Database file exposed - contains application data',
            'recommendation': 'Never expose database files. Store outside webroot.'
        },
        'logs': {
            'files': [
                'logs/',
                'log/',
                'error.log',
                'access.log',
                'debug.log',
                'application.log',
                'app.log',
                'npm-debug.log',
                'yarn-error.log',
            ],
            'severity': 'MEDIUM',
            'description': 'Log files exposed - may contain sensitive information',
            'recommendation': 'Block access to log files and directories'
        },
        'ci': {
            'files': [
                '.travis.yml',
                '.gitlab-ci.yml',
                'Jenkinsfile',
                '.circleci/config.yml',
                '.github/workflows/',
                'docker-compose.yml',
                'docker-compose.yaml',
                'Dockerfile',
                '.dockerignore',
            ],
            'severity': 'LOW',
            'description': 'CI/CD configuration exposed - may reveal deployment details',
            'recommendation': 'Block access to CI/CD configuration files'
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
        Scan for sensitive files.
        
        Args:
            base_url: Target base URL
            token: Authorization token
            categories: Categories to scan (all if None)
        
        Returns:
            SensitiveFilesReport
        """
        findings = []
        headers = {'Authorization': token} if token else {}
        
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
                executor.submit(self._check_file, url, headers): (url, path, cat, cfg)
                for url, path, cat, cfg in urls_to_check
            }
            
            for future in as_completed(futures):
                url, path, category, config = futures[future]
                try:
                    result = future.result()
                    if result:
                        findings.append(SensitiveFileFinding(
                            url=url,
                            file_type=path,
                            category=category,
                            status_code=result['status'],
                            severity=config['severity'],
                            description=config['description'],
                            recommendation=config['recommendation']
                        ))
                except Exception:
                    pass
        
        critical = sum(1 for f in findings if f.severity == 'CRITICAL')
        high = sum(1 for f in findings if f.severity == 'HIGH')
        
        return SensitiveFilesReport(
            target_url=base_url,
            scan_time=datetime.now().isoformat(),
            files_found=len(findings),
            critical_findings=critical,
            high_findings=high,
            findings=findings
        )
    
    def _check_file(self, url: str, headers: Dict) -> Optional[Dict]:
        """Check if a file exists and is accessible."""
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Consider 200 OK as found
            if response.status_code == 200:
                # Additional validation - check content length and type
                content_length = len(response.content)
                content_type = response.headers.get('Content-Type', '')
                
                # Skip if it's a custom error page (usually HTML with certain patterns)
                if 'text/html' in content_type and content_length > 0:
                    if '404' in response.text.lower() or 'not found' in response.text.lower():
                        return None
                
                # File found
                if content_length > 0:
                    return {
                        'status': response.status_code,
                        'size': content_length,
                        'type': content_type
                    }
            
            # 403 Forbidden might indicate the file exists but is protected
            elif response.status_code == 403:
                return {
                    'status': response.status_code,
                    'size': 0,
                    'type': 'forbidden'
                }
                
        except Exception:
            pass
        
        return None
    
    def quick_scan(
        self,
        base_url: str,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Quick scan focusing on critical files."""
        report = self.scan(base_url, token, categories=['vcs', 'config', 'database'])
        
        return {
            "url": base_url,
            "files_found": report.files_found,
            "critical": report.critical_findings,
            "findings": [
                {
                    "path": f.file_type,
                    "category": f.category,
                    "severity": f.severity
                }
                for f in report.findings
            ]
        }
