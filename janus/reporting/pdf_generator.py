# janus/reporting/pdf_generator.py
"""
PDF Report Generator for Janus Security Scanner.

Generates professional PDF security reports with:
- Executive summary
- Vulnerability findings by severity
- Technical details and recommendations
- Charts and statistics
"""

import os
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


@dataclass
class PDFReportConfig:
    """Configuration for PDF report generation."""
    title: str = "Janus Security Report"
    pagesize: tuple = letter
    include_executive_summary: bool = True
    include_charts: bool = True
    include_recommendations: bool = True
    company_name: str = ""
    logo_path: str = ""


class PDFReportGenerator:
    """
    Generate professional PDF security reports.
    
    Requires: pip install reportlab
    """
    
    SEVERITY_COLORS = {
        'CRITICAL': colors.Color(0.96, 0.24, 0.37),  # #f43f5e
        'HIGH': colors.Color(0.98, 0.57, 0.24),      # #fb923c
        'MEDIUM': colors.Color(0.98, 0.75, 0.15),    # #fbbf24
        'LOW': colors.Color(0.22, 0.74, 0.97),       # #38bdf8
        'INFO': colors.Color(0.55, 0.58, 0.61)       # #8b949e
    }
    
    def __init__(self, config: Optional[PDFReportConfig] = None):
        self.config = config or PDFReportConfig()
        
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required for PDF generation. Install with: pip install reportlab")
        
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='Title',
            fontSize=24,
            spaceAfter=30,
            textColor=colors.Color(0.96, 0.24, 0.37)
        ))
        self.styles.add(ParagraphStyle(
            name='Heading2',
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.Color(0.05, 0.07, 0.09)
        ))
        self.styles.add(ParagraphStyle(
            name='Finding',
            fontSize=10,
            leftIndent=20,
            spaceBefore=5
        ))
    
    def generate(
        self,
        scan_report: Dict[str, Any],
        output_path: str = "janus_report.pdf"
    ) -> str:
        """
        Generate PDF report from scan results.
        
        Args:
            scan_report: Dictionary containing scan results
            output_path: Path to save PDF
        
        Returns:
            Path to generated PDF
        """
        doc = SimpleDocTemplate(
            output_path,
            pagesize=self.config.pagesize,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        story = []
        
        # Header/Title
        story.extend(self._build_header(scan_report))
        
        # Executive Summary
        if self.config.include_executive_summary:
            story.extend(self._build_executive_summary(scan_report))
        
        # Findings by Severity
        story.extend(self._build_findings_section(scan_report))
        
        # Charts
        if self.config.include_charts:
            story.extend(self._build_charts(scan_report))
        
        # Detailed Findings
        story.extend(self._build_detailed_findings(scan_report))
        
        # Recommendations
        if self.config.include_recommendations:
            story.extend(self._build_recommendations(scan_report))
        
        # Build PDF
        doc.build(story)
        return output_path
    
    def _build_header(self, scan_report: Dict) -> List:
        """Build report header."""
        elements = []
        
        # Title
        title = Paragraph(
            f"🔱 {self.config.title}",
            self.styles['Title']
        )
        elements.append(title)
        
        # Metadata
        target_url = scan_report.get('target_url', 'Unknown')
        scan_time = scan_report.get('scan_time', datetime.now().isoformat())
        
        meta_text = f"""
        <b>Target:</b> {target_url}<br/>
        <b>Scan Date:</b> {scan_time}<br/>
        <b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        if self.config.company_name:
            meta_text += f"<br/><b>Prepared for:</b> {self.config.company_name}"
        
        elements.append(Paragraph(meta_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        return elements
    
    def _build_executive_summary(self, scan_report: Dict) -> List:
        """Build executive summary section."""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['Heading2']))
        
        # Count findings by severity
        results = scan_report.get('results', [])
        critical = sum(r.get('findings_count', 0) for r in results if r.get('severity') == 'CRITICAL')
        high = sum(r.get('findings_count', 0) for r in results if r.get('severity') == 'HIGH')
        medium = sum(r.get('findings_count', 0) for r in results if r.get('severity') == 'MEDIUM')
        low = sum(r.get('findings_count', 0) for r in results if r.get('severity') == 'LOW')
        total = scan_report.get('total_findings', critical + high + medium + low)
        
        # Summary table
        summary_data = [
            ['Severity', 'Count', 'Risk Level'],
            ['CRITICAL', str(critical), 'Immediate Action Required'],
            ['HIGH', str(high), 'Priority Remediation'],
            ['MEDIUM', str(medium), 'Scheduled Remediation'],
            ['LOW', str(low), 'Monitor/Accept'],
            ['TOTAL', str(total), '']
        ]
        
        table = Table(summary_data, colWidths=[2*inch, 1*inch, 3*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.13, 0.15, 0.17)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (0, 1), self.SEVERITY_COLORS['CRITICAL']),
            ('BACKGROUND', (0, 2), (0, 2), self.SEVERITY_COLORS['HIGH']),
            ('BACKGROUND', (0, 3), (0, 3), self.SEVERITY_COLORS['MEDIUM']),
            ('BACKGROUND', (0, 4), (0, 4), self.SEVERITY_COLORS['LOW']),
            ('TEXTCOLOR', (0, 1), (0, 4), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.3, 0.3, 0.3)),
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 20))
        
        # Risk assessment
        if critical > 0:
            risk_level = "CRITICAL"
            risk_text = "Immediate remediation required. Critical vulnerabilities pose significant risk."
        elif high > 0:
            risk_level = "HIGH"
            risk_text = "Priority remediation recommended. High-severity vulnerabilities should be addressed soon."
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_text = "Scheduled remediation advised. Address vulnerabilities in regular maintenance cycle."
        else:
            risk_level = "LOW"
            risk_text = "Security posture is acceptable. Continue monitoring and maintenance."
        
        elements.append(Paragraph(f"<b>Overall Risk Level:</b> {risk_level}", self.styles['Normal']))
        elements.append(Paragraph(risk_text, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        return elements
    
    def _build_findings_section(self, scan_report: Dict) -> List:
        """Build findings overview section."""
        elements = []
        
        elements.append(Paragraph("Findings Overview", self.styles['Heading2']))
        
        results = scan_report.get('results', [])
        
        # Table of modules and findings
        module_data = [['Module', 'Category', 'Status', 'Severity', 'Findings']]
        
        for r in results:
            status = '🚨 VULNERABLE' if r.get('vulnerable') else '✓ OK'
            module_data.append([
                r.get('module', 'Unknown'),
                r.get('category', 'N/A'),
                status,
                r.get('severity', 'INFO'),
                str(r.get('findings_count', 0))
            ])
        
        if len(module_data) > 1:
            table = Table(module_data, colWidths=[1.5*inch, 1.2*inch, 1*inch, 0.8*inch, 0.8*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.13, 0.15, 0.17)),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.3, 0.3, 0.3)),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.Color(0.95, 0.95, 0.95), colors.white])
            ]))
            elements.append(table)
        
        elements.append(Spacer(1, 20))
        return elements
    
    def _build_charts(self, scan_report: Dict) -> List:
        """Build charts section."""
        elements = []
        
        elements.append(Paragraph("Vulnerability Distribution", self.styles['Heading2']))
        
        # Count by severity
        results = scan_report.get('results', [])
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for r in results:
            sev = r.get('severity', 'INFO')
            count = r.get('findings_count', 0)
            if sev in severity_counts:
                severity_counts[sev] += count
        
        # Create pie chart
        if sum(severity_counts.values()) > 0:
            drawing = Drawing(400, 200)
            pie = Pie()
            pie.x = 150
            pie.y = 25
            pie.width = 150
            pie.height = 150
            pie.data = [severity_counts[s] for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] if severity_counts[s] > 0]
            pie.labels = [f"{s}: {severity_counts[s]}" for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] if severity_counts[s] > 0]
            pie.slices.strokeWidth = 0.5
            
            # Set colors
            color_map = [self.SEVERITY_COLORS[s] for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] if severity_counts[s] > 0]
            for i, c in enumerate(color_map):
                pie.slices[i].fillColor = c
            
            drawing.add(pie)
            elements.append(drawing)
        
        elements.append(Spacer(1, 20))
        return elements
    
    def _build_detailed_findings(self, scan_report: Dict) -> List:
        """Build detailed findings section."""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Findings", self.styles['Heading2']))
        
        results = scan_report.get('results', [])
        
        for r in results:
            if r.get('findings_count', 0) == 0:
                continue
            
            # Module header
            sev = r.get('severity', 'INFO')
            color = self.SEVERITY_COLORS.get(sev, colors.gray)
            
            elements.append(Paragraph(
                f"<b>{r.get('module', 'Unknown')}</b> - {sev}",
                ParagraphStyle('ModuleHeader', fontSize=12, textColor=color, spaceBefore=15)
            ))
            
            # Findings list
            findings = r.get('findings', [])
            for i, f in enumerate(findings[:20], 1):  # Limit to 20 per module
                if isinstance(f, dict):
                    desc = f.get('description', f.get('evidence', str(f)[:100]))
                    rec = f.get('recommendation', '')
                    finding_text = f"{i}. {desc}"
                    if rec:
                        finding_text += f" <i>(Fix: {rec})</i>"
                else:
                    finding_text = f"{i}. {str(f)[:100]}"
                
                elements.append(Paragraph(finding_text, self.styles['Finding']))
            
            if len(findings) > 20:
                elements.append(Paragraph(f"... and {len(findings) - 20} more findings", self.styles['Finding']))
        
        elements.append(Spacer(1, 20))
        return elements
    
    def _build_recommendations(self, scan_report: Dict) -> List:
        """Build recommendations section."""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Paragraph("Recommendations", self.styles['Heading2']))
        
        recommendations = [
            ("Implement Input Validation", "Validate and sanitize all user input to prevent injection attacks."),
            ("Update Dependencies", "Keep all software dependencies up to date to patch known vulnerabilities."),
            ("Configure Security Headers", "Implement HSTS, CSP, X-Frame-Options, and other security headers."),
            ("Review Authentication", "Ensure proper authentication and authorization on all endpoints."),
            ("Enable Rate Limiting", "Implement rate limiting to prevent brute force and DoS attacks."),
            ("Monitor and Log", "Enable comprehensive logging and monitoring for security events."),
        ]
        
        for title, desc in recommendations:
            elements.append(Paragraph(f"<b>• {title}:</b> {desc}", self.styles['Normal']))
            elements.append(Spacer(1, 5))
        
        return elements
    
    def generate_from_autoscan(self, autoscan_report, output_path: str = "janus_report.pdf") -> str:
        """Generate PDF from AutoScanReport object."""
        return self.generate(autoscan_report.to_dict(), output_path)


def generate_pdf_report(
    scan_data: Dict[str, Any],
    output_path: str = "janus_report.pdf",
    config: Optional[PDFReportConfig] = None
) -> str:
    """
    Convenience function to generate PDF report.
    
    Args:
        scan_data: Scan results dictionary
        output_path: Output PDF path
        config: Optional PDF configuration
    
    Returns:
        Path to generated PDF
    """
    generator = PDFReportGenerator(config)
    return generator.generate(scan_data, output_path)
