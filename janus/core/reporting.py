# janus/core/reporting.py
"""
Professional HTML Report Generator.
Creates beautiful, dark-themed security reports using Jinja2.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import os

try:
    from jinja2 import Template, Environment
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    print("[!] Warning: Jinja2 not installed. Install with: pip install jinja2")


@dataclass
class VulnerabilityReport:
    """A single vulnerability entry for the report."""
    id: int
    endpoint: str
    method: str
    attack_type: str  # BOLA, Mass Assignment, JWT, etc.
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    evidence: str
    recommendation: str
    curl_command: str
    request_body: Optional[str] = None
    response_sample: Optional[str] = None


class HTMLReportGenerator:
    """
    Generates professional HTML security reports.
    """
    
    REPORT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Janus Security Report - {{ scan_id }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        janus: {
                            bg: '#0a0a0f',
                            card: '#12121a',
                            accent: '#e94560',
                            border: '#1e1e2e'
                        }
                    }
                }
            }
        }
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        code { font-family: 'JetBrains Mono', monospace; }
        .glow { box-shadow: 0 0 15px rgba(233, 69, 96, 0.2); }
        @media print {
            .no-print { display: none !important; }
            body { background: white !important; color: black !important; }
            .bg-janus-bg, .bg-janus-card { background: white !important; }
            .text-white, .text-gray-100, .text-gray-300, .text-gray-400 { color: black !important; }
        }
    </style>
</head>
<body class="bg-janus-bg text-gray-100 min-h-screen">
    <!-- Header -->
    <header class="border-b border-janus-border bg-janus-card print:bg-white">
        <div class="container mx-auto px-6 py-8">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-3xl font-bold">
                        <span class="text-janus-accent">JANUS</span>
                        <span class="text-gray-400 font-normal ml-2">Security Assessment Report</span>
                    </h1>
                    <p class="text-gray-500 mt-2">Generated: {{ timestamp }}</p>
                </div>
                <div class="text-right no-print">
                    <button onclick="window.print()" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
                        🖨️ Print Report
                    </button>
                </div>
            </div>
        </div>
    </header>

    <main class="container mx-auto px-6 py-8">
        <!-- Executive Summary -->
        <section class="mb-10">
            <h2 class="text-2xl font-semibold mb-6 flex items-center gap-2">
                <span class="text-janus-accent">📊</span> Executive Summary
            </h2>
            
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div class="bg-janus-card rounded-xl p-6 border border-janus-border text-center">
                    <div class="text-4xl font-bold text-gray-100">{{ total_findings }}</div>
                    <div class="text-sm text-gray-400 mt-1">Total Findings</div>
                </div>
                <div class="bg-janus-card rounded-xl p-6 border border-red-900/50 text-center glow">
                    <div class="text-4xl font-bold text-red-500">{{ critical_count }}</div>
                    <div class="text-sm text-gray-400 mt-1">Critical</div>
                </div>
                <div class="bg-janus-card rounded-xl p-6 border border-orange-900/50 text-center">
                    <div class="text-4xl font-bold text-orange-500">{{ high_count }}</div>
                    <div class="text-sm text-gray-400 mt-1">High</div>
                </div>
                <div class="bg-janus-card rounded-xl p-6 border border-yellow-900/50 text-center">
                    <div class="text-4xl font-bold text-yellow-500">{{ medium_count }}</div>
                    <div class="text-sm text-gray-400 mt-1">Medium</div>
                </div>
            </div>

            <div class="bg-janus-card rounded-xl p-6 border border-janus-border">
                <h3 class="font-semibold mb-4">Scan Information</h3>
                <div class="grid grid-cols-2 gap-4 text-sm">
                    <div><span class="text-gray-400">Scan ID:</span> <span class="mono">{{ scan_id }}</span></div>
                    <div><span class="text-gray-400">Target:</span> <span class="mono">{{ target_host }}</span></div>
                    <div><span class="text-gray-400">Duration:</span> {{ duration }}</div>
                    <div><span class="text-gray-400">Endpoints Tested:</span> {{ endpoints_tested }}</div>
                </div>
            </div>
        </section>

        <!-- Findings by Attack Type -->
        <section class="mb-10">
            <h2 class="text-2xl font-semibold mb-6 flex items-center gap-2">
                <span class="text-janus-accent">🎯</span> Findings by Attack Type
            </h2>
            
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                {% for attack_type, count in attack_type_counts.items() %}
                <div class="bg-janus-card rounded-lg p-4 border border-janus-border">
                    <div class="text-2xl font-bold">{{ count }}</div>
                    <div class="text-sm text-gray-400">{{ attack_type }}</div>
                </div>
                {% endfor %}
            </div>
        </section>

        <!-- Detailed Findings -->
        <section class="mb-10">
            <h2 class="text-2xl font-semibold mb-6 flex items-center gap-2">
                <span class="text-janus-accent">🔍</span> Detailed Findings
            </h2>
            
            {% for vuln in vulnerabilities %}
            <div class="bg-janus-card rounded-xl border border-janus-border mb-6 overflow-hidden">
                <!-- Finding Header -->
                <div class="p-6 border-b border-janus-border flex items-start justify-between">
                    <div>
                        <div class="flex items-center gap-3 mb-2">
                            <span class="px-3 py-1 rounded-full text-xs font-semibold
                                {% if vuln.severity == 'CRITICAL' %}bg-red-500/20 text-red-400 border border-red-500/50
                                {% elif vuln.severity == 'HIGH' %}bg-orange-500/20 text-orange-400 border border-orange-500/50
                                {% elif vuln.severity == 'MEDIUM' %}bg-yellow-500/20 text-yellow-400 border border-yellow-500/50
                                {% else %}bg-blue-500/20 text-blue-400 border border-blue-500/50{% endif %}">
                                {{ vuln.severity }}
                            </span>
                            <span class="px-3 py-1 rounded-full text-xs bg-gray-700 text-gray-300">
                                {{ vuln.attack_type }}
                            </span>
                        </div>
                        <h3 class="text-lg font-semibold">
                            <span class="text-gray-400">{{ vuln.method }}</span>
                            <span class="mono text-sm ml-2">{{ vuln.endpoint }}</span>
                        </h3>
                    </div>
                    <div class="text-right">
                        <div class="text-sm text-gray-400">Confidence</div>
                        <div class="text-lg font-bold text-janus-accent">{{ (vuln.confidence * 100)|round }}%</div>
                    </div>
                </div>
                
                <!-- Finding Details -->
                <div class="p-6 space-y-4">
                    <div>
                        <h4 class="text-sm font-semibold text-gray-400 mb-2">Evidence</h4>
                        <p class="text-gray-300">{{ vuln.evidence }}</p>
                    </div>
                    
                    <div>
                        <h4 class="text-sm font-semibold text-gray-400 mb-2">Recommendation</h4>
                        <p class="text-gray-300">{{ vuln.recommendation }}</p>
                    </div>
                    
                    <div>
                        <h4 class="text-sm font-semibold text-gray-400 mb-2">Reproduction</h4>
                        <div class="bg-janus-bg rounded-lg p-4 overflow-x-auto">
                            <code class="text-green-400 text-sm whitespace-pre">{{ vuln.curl_command }}</code>
                        </div>
                    </div>
                    
                    {% if vuln.response_sample %}
                    <div>
                        <h4 class="text-sm font-semibold text-gray-400 mb-2">Response Sample</h4>
                        <div class="bg-janus-bg rounded-lg p-4 overflow-x-auto">
                            <code class="text-blue-400 text-sm whitespace-pre">{{ vuln.response_sample }}</code>
                        </div>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </section>

        <!-- Remediation Summary -->
        <section class="mb-10">
            <h2 class="text-2xl font-semibold mb-6 flex items-center gap-2">
                <span class="text-janus-accent">🛠️</span> Remediation Summary
            </h2>
            
            <div class="bg-janus-card rounded-xl border border-janus-border p-6">
                <div class="space-y-4">
                    {% if bola_count > 0 %}
                    <div class="flex items-start gap-4">
                        <span class="text-2xl">🔐</span>
                        <div>
                            <h4 class="font-semibold">BOLA/IDOR ({{ bola_count }} findings)</h4>
                            <p class="text-gray-400 text-sm">Implement object-level authorization. Verify the authenticated user has permission to access each resource before returning data.</p>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if mass_assignment_count > 0 %}
                    <div class="flex items-start gap-4">
                        <span class="text-2xl">📝</span>
                        <div>
                            <h4 class="font-semibold">Mass Assignment ({{ mass_assignment_count }} findings)</h4>
                            <p class="text-gray-400 text-sm">Use explicit allowlist for acceptable fields. Never bind user input directly to internal objects.</p>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if jwt_count > 0 %}
                    <div class="flex items-start gap-4">
                        <span class="text-2xl">🎫</span>
                        <div>
                            <h4 class="font-semibold">JWT Vulnerabilities ({{ jwt_count }} findings)</h4>
                            <p class="text-gray-400 text-sm">Use strong secrets, reject 'none' algorithm, validate all claims server-side, and implement proper expiration.</p>
                        </div>
                    </div>
                    {% endif %}
                </div>
            </div>
        </section>
    </main>

    <!-- Footer -->
    <footer class="border-t border-janus-border py-6 mt-10">
        <div class="container mx-auto px-6 text-center text-gray-500 text-sm">
            <p>Generated by <strong>Janus Security Scanner</strong> • Local Intelligence • No AI APIs</p>
            <p class="mt-1">Report ID: {{ scan_id }} • {{ timestamp }}</p>
        </div>
    </footer>
</body>
</html>
'''

    def __init__(self):
        if not JINJA2_AVAILABLE:
            raise ImportError("Jinja2 is required for HTML reports. Install with: pip install jinja2")
        self.template = Template(self.REPORT_TEMPLATE)
    
    def generate_report(
        self,
        vulnerabilities: List[VulnerabilityReport],
        scan_id: str,
        target_host: str,
        start_time: datetime,
        end_time: datetime,
        endpoints_tested: int = 0
    ) -> str:
        """
        Generate an HTML report from vulnerability findings.
        
        Args:
            vulnerabilities: List of VulnerabilityReport objects
            scan_id: Unique scan identifier
            target_host: Target API base URL
            start_time: Scan start time
            end_time: Scan end time
            endpoints_tested: Number of endpoints tested
        
        Returns:
            HTML string of the complete report
        """
        # Calculate statistics
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        attack_type_counts = {}
        
        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1
            
            if vuln.attack_type not in attack_type_counts:
                attack_type_counts[vuln.attack_type] = 0
            attack_type_counts[vuln.attack_type] += 1
        
        # Calculate duration
        duration = end_time - start_time
        duration_str = f"{duration.seconds // 60}m {duration.seconds % 60}s"
        
        # Render template
        html = self.template.render(
            scan_id=scan_id,
            target_host=target_host,
            timestamp=end_time.strftime("%Y-%m-%d %H:%M:%S"),
            duration=duration_str,
            endpoints_tested=endpoints_tested,
            total_findings=len(vulnerabilities),
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            vulnerabilities=vulnerabilities,
            attack_type_counts=attack_type_counts,
            bola_count=attack_type_counts.get("BOLA", 0) + attack_type_counts.get("BOLA/IDOR", 0),
            mass_assignment_count=attack_type_counts.get("Mass Assignment", 0) + attack_type_counts.get("mass_assignment", 0),
            jwt_count=attack_type_counts.get("JWT", 0)
        )
        
        return html
    
    def save_report(self, html: str, output_path: str) -> None:
        """Save HTML report to file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] HTML report saved to: {output_path}")
    
    def from_scan_report(self, scan_report: Dict) -> str:
        """
        Generate HTML from a JanusEngine ScanReport dict.
        """
        vulnerabilities = []
        vuln_id = 1
        
        for finding in scan_report.get("findings", []):
            if finding.get("status") in ["VULNERABLE", "NEEDS_REVIEW"]:
                # Build curl command
                curl_cmd = f'curl -H "Authorization: TOKEN" "{finding.get("endpoint", "")}"'
                
                vulnerabilities.append(VulnerabilityReport(
                    id=vuln_id,
                    endpoint=finding.get("endpoint", ""),
                    method=finding.get("method", "GET"),
                    attack_type=finding.get("vulnerability_type", "BOLA"),
                    severity=finding.get("severity", "HIGH"),
                    confidence=finding.get("confidence", 0.0),
                    evidence=finding.get("evidence", ""),
                    recommendation=finding.get("recommendation", "Implement authorization checks"),
                    curl_command=curl_cmd,
                    response_sample=json.dumps(finding.get("attack_response", {}), indent=2)[:300] if finding.get("attack_response") else None
                ))
                vuln_id += 1
        
        return self.generate_report(
            vulnerabilities=vulnerabilities,
            scan_id=scan_report.get("scan_id", "unknown"),
            target_host=scan_report.get("target_host", ""),
            start_time=datetime.fromisoformat(scan_report.get("start_time", datetime.now().isoformat())),
            end_time=datetime.fromisoformat(scan_report.get("end_time", datetime.now().isoformat())),
            endpoints_tested=scan_report.get("total_endpoints", 0)
        )
