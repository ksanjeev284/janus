# janus/recon/cve_lookup.py
"""
CVE Lookup Module - Live Vulnerability Intelligence.
Queries NIST NVD API and CISA KEV for known vulnerabilities.
"""

import asyncio
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json
import requests  # Always available

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


@dataclass
class CVEResult:
    """A single CVE finding."""
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    published_date: str
    affected_product: str
    affected_version: str
    references: List[str]
    exploited_in_wild: bool = False
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass 
class TechStackInfo:
    """Detected technology information."""
    name: str
    version: Optional[str]
    source: str  # header, body, fingerprint
    raw_value: str


class CVELookup:
    """
    Live CVE lookup using public vulnerability databases.
    
    Sources:
    - NIST NVD (National Vulnerability Database)
    - CISA KEV (Known Exploited Vulnerabilities)
    """
    
    # NIST NVD API
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # CISA KEV Catalog (JSON)
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    # Common server headers to detect
    TECH_PATTERNS = {
        'server': [
            (r'nginx/?([\d.]+)?', 'nginx'),
            (r'Apache/?([\d.]+)?', 'Apache HTTP Server'),
            (r'gunicorn/?([\d.]+)?', 'gunicorn'),
            (r'Werkzeug/?([\d.]+)?', 'Werkzeug'),
            (r'uvicorn', 'uvicorn'),
            (r'Microsoft-IIS/?([\d.]+)?', 'Microsoft IIS'),
            (r'cloudflare', 'Cloudflare'),
        ],
        'x-powered-by': [
            (r'PHP/?([\d.]+)?', 'PHP'),
            (r'Express', 'Express.js'),
            (r'ASP\.NET', 'ASP.NET'),
            (r'Django', 'Django'),
            (r'Flask', 'Flask'),
            (r'Rails', 'Ruby on Rails'),
            (r'Next\.js', 'Next.js'),
        ],
        'x-aspnet-version': [
            (r'([\d.]+)', 'ASP.NET'),
        ],
    }
    
    # Cache for CISA KEV (refreshed daily)
    _kev_cache: Optional[List[Dict]] = None
    _kev_cache_time: Optional[datetime] = None
    
    def __init__(self, nvd_api_key: Optional[str] = None):
        """
        Initialize CVE Lookup.
        
        Args:
            nvd_api_key: Optional NVD API key (increases rate limits from 5 to 50 req/30s)
        """
        self.nvd_api_key = nvd_api_key
        self.timeout = 30
    
    def detect_tech_from_headers(self, headers: Dict[str, str]) -> List[TechStackInfo]:
        """
        Detect technology stack from HTTP response headers.
        """
        detected = []
        
        for header_name, patterns in self.TECH_PATTERNS.items():
            header_value = headers.get(header_name, '') or headers.get(header_name.title(), '')
            if not header_value:
                continue
            
            for pattern, tech_name in patterns:
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else None
                    detected.append(TechStackInfo(
                        name=tech_name,
                        version=version,
                        source=f"header:{header_name}",
                        raw_value=header_value
                    ))
        
        return detected
    
    def detect_tech_from_response(self, body: str, headers: Dict = None) -> List[TechStackInfo]:
        """
        Detect technology from response body and headers combined.
        """
        detected = []
        
        # Check headers first
        if headers:
            detected.extend(self.detect_tech_from_headers(headers))
        
        # Check body for common patterns
        body_patterns = [
            (r'react["\s]*[:,]\s*["\']?([\d.]+)', 'React'),
            (r'vue["\s]*[:,]\s*["\']?([\d.]+)', 'Vue.js'),
            (r'angular["\s]*[:,]\s*["\']?([\d.]+)', 'Angular'),
            (r'jquery["\s]*[:,]\s*["\']?([\d.]+)', 'jQuery'),
            (r'bootstrap["\s]*[:,]\s*["\']?([\d.]+)', 'Bootstrap'),
            (r'wordpress', 'WordPress'),
            (r'drupal', 'Drupal'),
            (r'laravel', 'Laravel'),
            (r'spring\s*boot', 'Spring Boot'),
        ]
        
        for pattern, tech_name in body_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                detected.append(TechStackInfo(
                    name=tech_name,
                    version=version,
                    source="body",
                    raw_value=match.group(0)[:50]
                ))
        
        return detected
    
    async def _fetch_nvd_async(self, keyword: str, version: str = None) -> List[CVEResult]:
        """Async fetch from NVD API."""
        if not AIOHTTP_AVAILABLE:
            # Fallback to sync
            return self._fetch_nvd_sync(keyword, version)
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 20,
        }
        
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.NVD_API_BASE,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status != 200:
                        print(f"[!] NVD API returned {response.status}")
                        return []
                    
                    data = await response.json()
                    return self._parse_nvd_response(data, version)
                    
        except Exception as e:
            print(f"[!] NVD API error: {e}")
            return []
    
    def _fetch_nvd_sync(self, keyword: str, version: str = None) -> List[CVEResult]:
        """Synchronous fetch from NVD API."""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 20,
        }
        
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        
        try:
            response = requests.get(
                self.NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                print(f"[!] NVD API returned {response.status_code}")
                return []
            
            return self._parse_nvd_response(response.json(), version)
            
        except Exception as e:
            print(f"[!] NVD API error: {e}")
            return []
    
    def _parse_nvd_response(self, data: Dict, version_filter: str = None) -> List[CVEResult]:
        """Parse NVD API response into CVEResult objects."""
        results = []
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            
            # Get description
            descriptions = cve.get("descriptions", [])
            description = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                ""
            )
            
            # Get CVSS score
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            # Try CVSS 3.1, then 3.0, then 2.0
            for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_key in metrics and metrics[cvss_key]:
                    cvss_data = metrics[cvss_key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break
            
            # Filter by severity (only HIGH and CRITICAL by default)
            if severity not in ["HIGH", "CRITICAL"]:
                continue
            
            # Get affected products
            configurations = cve.get("configurations", [])
            affected_products = []
            for config in configurations:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            affected_products.append(match.get("criteria", ""))
            
            # Version filter
            if version_filter:
                version_in_cpe = any(version_filter in p for p in affected_products)
                if not version_in_cpe:
                    continue
            
            # Get references
            references = [ref.get("url", "") for ref in cve.get("references", [])[:3]]
            
            results.append(CVEResult(
                cve_id=cve_id,
                description=description[:300] + "..." if len(description) > 300 else description,
                severity=severity,
                cvss_score=cvss_score,
                published_date=cve.get("published", ""),
                affected_product=", ".join(affected_products[:2]) if affected_products else "",
                affected_version=version_filter or "",
                references=references
            ))
        
        return results
    
    async def _fetch_kev_async(self) -> List[Dict]:
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        # Check cache
        if self._kev_cache and self._kev_cache_time:
            if datetime.now() - self._kev_cache_time < timedelta(hours=24):
                return self._kev_cache
        
        try:
            if AIOHTTP_AVAILABLE:
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.CISA_KEV_URL, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        if response.status == 200:
                            data = await response.json()
                            CVELookup._kev_cache = data.get("vulnerabilities", [])
                            CVELookup._kev_cache_time = datetime.now()
                            return CVELookup._kev_cache
            else:
                response = requests.get(self.CISA_KEV_URL, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    CVELookup._kev_cache = data.get("vulnerabilities", [])
                    CVELookup._kev_cache_time = datetime.now()
                    return CVELookup._kev_cache
        except Exception as e:
            print(f"[!] CISA KEV fetch error: {e}")
        
        return []
    
    def check_kev(self, cve_ids: List[str]) -> List[str]:
        """Check if any CVEs are in the CISA KEV (Known Exploited) catalog."""
        if not self._kev_cache:
            # Sync fetch
            try:
                response = requests.get(self.CISA_KEV_URL, timeout=30)
                if response.status_code == 200:
                    self._kev_cache = response.json().get("vulnerabilities", [])
            except:
                return []
        
        kev_cves = {v.get("cveID") for v in (self._kev_cache or [])}
        return [cve for cve in cve_ids if cve in kev_cves]
    
    def check_cve(self, tech_name: str, version: Optional[str] = None) -> List[CVEResult]:
        """
        Check for CVEs affecting a specific technology and version.
        
        Args:
            tech_name: Technology name (e.g., "nginx", "Django", "React")
            version: Optional version string (e.g., "1.19.0")
        
        Returns:
            List of CVEResult objects for HIGH/CRITICAL vulnerabilities
        """
        print(f"[*] Checking CVEs for {tech_name} {version or ''}")
        
        search_term = f"{tech_name} {version}" if version else tech_name
        results = self._fetch_nvd_sync(search_term, version)
        
        # Check which are in KEV
        cve_ids = [r.cve_id for r in results]
        exploited_cves = set(self.check_kev(cve_ids))
        
        for result in results:
            if result.cve_id in exploited_cves:
                result.exploited_in_wild = True
        
        # Sort by severity and CVSS score
        results.sort(key=lambda x: (
            x.exploited_in_wild,  # Exploited first
            x.severity == "CRITICAL",
            x.cvss_score
        ), reverse=True)
        
        return results
    
    async def check_cve_async(self, tech_name: str, version: Optional[str] = None) -> List[CVEResult]:
        """Async version of check_cve."""
        print(f"[*] Checking CVEs for {tech_name} {version or ''}")
        
        search_term = f"{tech_name} {version}" if version else tech_name
        
        # Fetch both NVD and KEV in parallel
        nvd_task = self._fetch_nvd_async(search_term, version)
        kev_task = self._fetch_kev_async()
        
        results, kev_data = await asyncio.gather(nvd_task, kev_task)
        
        # Mark exploited CVEs
        kev_cves = {v.get("cveID") for v in kev_data}
        for result in results:
            if result.cve_id in kev_cves:
                result.exploited_in_wild = True
        
        results.sort(key=lambda x: (x.exploited_in_wild, x.severity == "CRITICAL", x.cvss_score), reverse=True)
        
        return results
    
    def scan_target(self, url: str) -> Tuple[List[TechStackInfo], List[CVEResult]]:
        """
        Scan a target URL, detect technology, and check for CVEs.
        
        Returns:
            Tuple of (detected_tech, cve_findings)
        """
        print(f"[*] Scanning {url} for technology fingerprints...")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = dict(response.headers)
            body = response.text[:5000]  # First 5KB
            
            # Detect technology
            tech_detected = self.detect_tech_from_response(body, headers)
            
            if not tech_detected:
                print("[*] No technology fingerprints detected")
                return [], []
            
            print(f"[+] Detected {len(tech_detected)} technologies")
            for tech in tech_detected:
                print(f"    - {tech.name} {tech.version or '(version unknown)'}")
            
            # Check CVEs for each
            all_cves = []
            for tech in tech_detected:
                cves = self.check_cve(tech.name, tech.version)
                all_cves.extend(cves)
            
            # Deduplicate by CVE ID
            seen = set()
            unique_cves = []
            for cve in all_cves:
                if cve.cve_id not in seen:
                    seen.add(cve.cve_id)
                    unique_cves.append(cve)
            
            return tech_detected, unique_cves
            
        except Exception as e:
            print(f"[!] Scan error: {e}")
            return [], []
