# janus/reporting/report_manager.py
"""
Robust Report Management for Janus Security Scanner.

Features:
- Persistent storage of all scan reports
- Report history with search/filter
- Export to HTML, PDF, JSON, SARIF
- Comparison between reports
- Tag-based organization
"""

import json
import os
import shutil
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from pathlib import Path
import uuid


@dataclass
class ReportMetadata:
    """Metadata for a stored report."""
    id: str
    target_url: str
    scan_type: str  # autoscan, bola, sqli, etc.
    created_at: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    duration_seconds: float
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ReportMetadata':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class ReportManager:
    """
    Manage storage and retrieval of scan reports.
    
    Reports are stored in .janus/reports/ directory with:
    - {id}.json - Full report data
    - {id}_meta.json - Metadata for quick listing
    """
    
    def __init__(self, data_dir: str = ".janus"):
        self.data_dir = Path(data_dir)
        self.reports_dir = self.data_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.reports_dir / "index.json"
        
        self._index: Dict[str, ReportMetadata] = {}
        self._load_index()
    
    def _load_index(self):
        """Load report index from file."""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    data = json.load(f)
                    self._index = {
                        k: ReportMetadata.from_dict(v) 
                        for k, v in data.items()
                    }
            except:
                self._rebuild_index()
        else:
            self._rebuild_index()
    
    def _save_index(self):
        """Save report index to file."""
        try:
            with open(self.index_file, 'w') as f:
                json.dump({k: v.to_dict() for k, v in self._index.items()}, f, indent=2)
        except:
            pass
    
    def _rebuild_index(self):
        """Rebuild index from stored report files."""
        self._index = {}
        for meta_file in self.reports_dir.glob("*_meta.json"):
            try:
                with open(meta_file, 'r') as f:
                    meta = ReportMetadata.from_dict(json.load(f))
                    self._index[meta.id] = meta
            except:
                pass
        self._save_index()
    
    def save_report(
        self,
        report_data: Dict[str, Any],
        scan_type: str = "autoscan",
        tags: Optional[List[str]] = None,
        notes: str = ""
    ) -> str:
        """
        Save a scan report to persistent storage.
        
        Args:
            report_data: The full report dictionary
            scan_type: Type of scan (autoscan, bola, sqli, etc.)
            tags: Optional tags for organization
            notes: Optional notes about the scan
        
        Returns:
            Report ID
        """
        report_id = report_data.get('scan_id') or str(uuid.uuid4())[:8]
        
        # Extract metadata
        target_url = report_data.get('target_url', 'Unknown')
        total_findings = report_data.get('total_findings', 0)
        critical = report_data.get('critical_count', 0)
        high = report_data.get('high_count', 0)
        medium = report_data.get('medium_count', 0)
        low = report_data.get('low_count', 0)
        duration = report_data.get('duration_seconds', 0)
        
        # Create metadata
        metadata = ReportMetadata(
            id=report_id,
            target_url=target_url,
            scan_type=scan_type,
            created_at=datetime.now().isoformat(),
            total_findings=total_findings,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            duration_seconds=duration,
            tags=tags or [],
            notes=notes
        )
        
        # Save full report
        report_file = self.reports_dir / f"{report_id}.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Save metadata
        meta_file = self.reports_dir / f"{report_id}_meta.json"
        with open(meta_file, 'w') as f:
            json.dump(metadata.to_dict(), f, indent=2)
        
        # Update index
        self._index[report_id] = metadata
        self._save_index()
        
        return report_id
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get full report by ID."""
        report_file = self.reports_dir / f"{report_id}.json"
        if report_file.exists():
            with open(report_file, 'r') as f:
                return json.load(f)
        return None
    
    def get_metadata(self, report_id: str) -> Optional[ReportMetadata]:
        """Get report metadata by ID."""
        return self._index.get(report_id)
    
    def list_reports(
        self,
        limit: int = 50,
        scan_type: Optional[str] = None,
        tag: Optional[str] = None,
        target_url: Optional[str] = None
    ) -> List[ReportMetadata]:
        """
        List reports with optional filters.
        
        Args:
            limit: Maximum number of reports to return
            scan_type: Filter by scan type
            tag: Filter by tag
            target_url: Filter by target URL (partial match)
        
        Returns:
            List of report metadata, sorted by date (newest first)
        """
        reports = list(self._index.values())
        
        # Apply filters
        if scan_type:
            reports = [r for r in reports if r.scan_type == scan_type]
        if tag:
            reports = [r for r in reports if tag in r.tags]
        if target_url:
            reports = [r for r in reports if target_url.lower() in r.target_url.lower()]
        
        # Sort by date (newest first)
        reports.sort(key=lambda r: r.created_at, reverse=True)
        
        return reports[:limit]
    
    def delete_report(self, report_id: str) -> bool:
        """Delete a report by ID."""
        if report_id in self._index:
            del self._index[report_id]
            self._save_index()
            
            # Delete files
            report_file = self.reports_dir / f"{report_id}.json"
            meta_file = self.reports_dir / f"{report_id}_meta.json"
            
            if report_file.exists():
                report_file.unlink()
            if meta_file.exists():
                meta_file.unlink()
            
            return True
        return False
    
    def add_tag(self, report_id: str, tag: str) -> bool:
        """Add a tag to a report."""
        if report_id in self._index:
            if tag not in self._index[report_id].tags:
                self._index[report_id].tags.append(tag)
                self._save_index()
                
                # Update meta file
                meta_file = self.reports_dir / f"{report_id}_meta.json"
                with open(meta_file, 'w') as f:
                    json.dump(self._index[report_id].to_dict(), f, indent=2)
            return True
        return False
    
    def add_notes(self, report_id: str, notes: str) -> bool:
        """Add notes to a report."""
        if report_id in self._index:
            self._index[report_id].notes = notes
            self._save_index()
            
            # Update meta file
            meta_file = self.reports_dir / f"{report_id}_meta.json"
            with open(meta_file, 'w') as f:
                json.dump(self._index[report_id].to_dict(), f, indent=2)
            return True
        return False
    
    def export_report(
        self,
        report_id: str,
        format: str = "json",
        output_path: Optional[str] = None
    ) -> Optional[str]:
        """
        Export a report to various formats.
        
        Args:
            report_id: Report ID to export
            format: Output format (json, html, pdf, sarif)
            output_path: Output file path (auto-generated if None)
        
        Returns:
            Path to exported file, or None if failed
        """
        report = self.get_report(report_id)
        if not report:
            return None
        
        metadata = self.get_metadata(report_id)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if not output_path:
            output_path = f"janus_report_{report_id}_{timestamp}.{format}"
        
        if format == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            return output_path
        
        elif format == "html":
            html = self._generate_html(report, metadata)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            return output_path
        
        elif format == "pdf":
            try:
                from janus.reporting.pdf_generator import PDFReportGenerator
                generator = PDFReportGenerator()
                generator.generate(report, output_path)
                return output_path
            except ImportError:
                return None
        
        elif format == "sarif":
            sarif = self._generate_sarif(report)
            with open(output_path, 'w') as f:
                json.dump(sarif, f, indent=2)
            return output_path
        
        return None
    
    def _generate_html(self, report: Dict, metadata: Optional[ReportMetadata]) -> str:
        """Generate HTML report."""
        target = report.get('target_url', 'Unknown')
        total = report.get('total_findings', 0)
        critical = report.get('critical_count', 0)
        high = report.get('high_count', 0)
        medium = report.get('medium_count', 0)
        low = report.get('low_count', 0)
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Janus Security Report - {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; padding: 40px; max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #f43f5e; border-bottom: 2px solid #30363d; padding-bottom: 20px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #161b22; padding: 20px; border-radius: 12px; text-align: center; flex: 1; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #f43f5e; }} .high {{ color: #fb923c; }} .medium {{ color: #fbbf24; }} .low {{ color: #38bdf8; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; margin: 20px 0; }}
        pre {{ background: #0d1117; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🔱 Janus Security Report</h1>
    <p style="color:#8b949e;">Target: {target}<br>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="stats">
        <div class="stat"><div class="stat-value">{total}</div>Total Findings</div>
        <div class="stat"><div class="stat-value critical">{critical}</div>Critical</div>
        <div class="stat"><div class="stat-value high">{high}</div>High</div>
        <div class="stat"><div class="stat-value medium">{medium}</div>Medium</div>
        <div class="stat"><div class="stat-value low">{low}</div>Low</div>
    </div>
'''
        
        # Add results
        results = report.get('results', [])
        for r in results:
            if r.get('findings_count', 0) > 0:
                sev = r.get('severity', 'INFO')
                sev_color = {'CRITICAL':'#f43f5e','HIGH':'#fb923c','MEDIUM':'#fbbf24','LOW':'#38bdf8'}.get(sev, '#8b949e')
                html += f'''
    <div class="card">
        <h3 style="color:{sev_color}">{r.get('module', 'Unknown')} - {sev}</h3>
        <p>Findings: {r.get('findings_count', 0)}</p>
        <pre>{json.dumps(r.get('findings', [])[:10], indent=2)}</pre>
    </div>
'''
        
        html += '''
    <footer style="text-align:center;margin-top:40px;color:#8b949e;">Generated by Janus Security Scanner</footer>
</body>
</html>
'''
        return html
    
    def _generate_sarif(self, report: Dict) -> Dict:
        """Generate SARIF format report."""
        results = []
        
        for r in report.get('results', []):
            for finding in r.get('findings', []):
                results.append({
                    "ruleId": r.get('module', 'unknown'),
                    "level": self._sarif_level(r.get('severity', 'INFO')),
                    "message": {
                        "text": finding.get('description', str(finding)[:100]) if isinstance(finding, dict) else str(finding)[:100]
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": report.get('target_url', 'unknown')
                            }
                        }
                    }]
                })
        
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Janus Security Scanner",
                        "version": "3.0.0"
                    }
                },
                "results": results
            }]
        }
    
    def _sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        return {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note',
            'INFO': 'none'
        }.get(severity, 'none')
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about stored reports."""
        reports = list(self._index.values())
        
        if not reports:
            return {
                "total_reports": 0,
                "total_findings": 0,
                "targets_scanned": 0
            }
        
        return {
            "total_reports": len(reports),
            "total_findings": sum(r.total_findings for r in reports),
            "critical_total": sum(r.critical_count for r in reports),
            "high_total": sum(r.high_count for r in reports),
            "targets_scanned": len(set(r.target_url for r in reports)),
            "scan_types": list(set(r.scan_type for r in reports)),
            "latest_scan": max(reports, key=lambda r: r.created_at).created_at if reports else None
        }


# Global report manager instance
_report_manager: Optional[ReportManager] = None

def get_report_manager() -> ReportManager:
    """Get the global report manager instance."""
    global _report_manager
    if _report_manager is None:
        _report_manager = ReportManager()
    return _report_manager
