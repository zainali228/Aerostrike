#!/usr/bin/env python3
"""
Report Generator Module for NetworkPentestPro
Generates detailed PDF and HTML reports of wireless security assessments
"""
import os
import json
import time
import datetime
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import jinja2
import webbrowser
import tempfile
import shutil

# Conditionally import reportlab only when needed
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.platypus import PageBreak, ListFlowable, ListItem
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

class ReportGenerator:
    """Generates security assessment reports in PDF and HTML formats"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize report generator"""
        self.logger = logger or logging.getLogger(__name__)
        
        # Load templates
        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                       "templates")
        
        # Set up Jinja2 environment
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Ensure ReportLab is available for PDF generation
        if not REPORTLAB_AVAILABLE:
            self.logger.warning("ReportLab is not installed. PDF report generation will be unavailable.")
    
    def generate_html_report(self, networks: List[Dict[str, Any]], 
                           output_path: str = None, 
                           custom_data: Dict[str, Any] = None) -> str:
        """
        Generate HTML report from template
        
        Args:
            networks: List of network dictionaries
            output_path: Path to save the HTML file (if None, a temporary file is created)
            custom_data: Additional custom data for the report
            
        Returns:
            Path to the generated HTML file
        """
        try:
            # Load template
            template = self.jinja_env.get_template("report_template.html")
            
            # Prepare data
            report_data = {
                "title": custom_data.get("title", "Wireless Security Assessment Report"),
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "networks": networks,
                "total_networks": len(networks),
                "vulnerable_networks": sum(1 for n in networks if n.get("vulnerabilities") or n.get("risk_score", 0) > 50),
                "custom_data": custom_data or {},
                "summary": custom_data.get("summary", "This report contains the results of a wireless security assessment.")
            }
            
            # Generate HTML
            html_content = template.render(**report_data)
            
            # Determine output path
            if not output_path:
                # Create temporary file
                fd, output_path = tempfile.mkstemp(suffix=".html", prefix="network_report_")
                os.close(fd)
            
            # Write HTML to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            self.logger.info(f"HTML report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            raise
    
    def generate_pdf_report(self, networks: List[Dict[str, Any]], 
                          output_path: str = None, 
                          custom_data: Dict[str, Any] = None) -> str:
        """
        Generate PDF report using ReportLab
        
        Args:
            networks: List of network dictionaries
            output_path: Path to save the PDF file (if None, a temporary file is created)
            custom_data: Additional custom data for the report
            
        Returns:
            Path to the generated PDF file
        """
        if not REPORTLAB_AVAILABLE:
            self.logger.error("ReportLab is not installed. Cannot generate PDF report.")
            raise ImportError("ReportLab is required for PDF generation")
            
        try:
            # Determine output path
            if not output_path:
                # Create temporary file
                fd, output_path = tempfile.mkstemp(suffix=".pdf", prefix="network_report_")
                os.close(fd)
            
            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            
            # Get styles
            styles = getSampleStyleSheet()
            title_style = styles['Title']
            heading_style = styles['Heading1']
            heading2_style = styles['Heading2']
            normal_style = styles['Normal']
            
            # Create custom styles
            warning_style = ParagraphStyle(
                'WarningStyle',
                parent=normal_style,
                textColor=colors.red
            )
            
            info_style = ParagraphStyle(
                'InfoStyle',
                parent=normal_style,
                textColor=colors.blue
            )
            
            # Create content elements
            elements = []
            
            # Title
            report_title = custom_data.get("title", "Wireless Security Assessment Report")
            elements.append(Paragraph(report_title, title_style))
            
            # Date and time
            date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            elements.append(Paragraph(f"Generated on: {date_str}", styles['Italic']))
            elements.append(Spacer(1, 12))
            
            # Summary
            elements.append(Paragraph("Executive Summary", heading_style))
            summary = custom_data.get("summary", "This report contains the results of a wireless security assessment.")
            elements.append(Paragraph(summary, normal_style))
            elements.append(Spacer(1, 12))
            
            # Statistics
            elements.append(Paragraph("Assessment Statistics", heading_style))
            
            stats_data = [
                ["Total Networks Scanned", str(len(networks))],
                ["Vulnerable Networks", str(sum(1 for n in networks if n.get("vulnerabilities") or n.get("risk_score", 0) > 50))],
                ["Open Networks", str(sum(1 for n in networks if not n.get("security")))],
                ["WEP Networks", str(sum(1 for n in networks if any(s == "WEP" for s in n.get("security", []))))],
                ["WPA/WPA2 Networks", str(sum(1 for n in networks if any(s in ["WPA", "WPA2"] for s in n.get("security", []))))]
            ]
            
            stats_table = Table(stats_data, colWidths=[300, 100])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ]))
            
            elements.append(stats_table)
            elements.append(Spacer(1, 12))
            
            # Vulnerability summary
            elements.append(Paragraph("Vulnerability Summary", heading_style))
            
            vulnerable_networks = [n for n in networks if n.get("vulnerabilities") or n.get("risk_score", 0) > 50]
            if vulnerable_networks:
                vuln_items = []
                for n in vulnerable_networks:
                    vuln_text = f"{n.get('ssid', 'Unknown')} ({n.get('bssid', 'Unknown')}) - Risk Score: {n.get('risk_score', 0)}"
                    vuln_items.append(ListItem(Paragraph(vuln_text, normal_style)))
                    
                    if n.get("vulnerabilities"):
                        sub_items = []
                        for v in n.get("vulnerabilities", []):
                            sub_items.append(ListItem(Paragraph(v, warning_style)))
                        vuln_items.append(ListFlowable(sub_items, bulletType='bullet', start='square'))
                
                elements.append(ListFlowable(vuln_items, bulletType='bullet'))
            else:
                elements.append(Paragraph("No significant vulnerabilities found.", normal_style))
                
            elements.append(Spacer(1, 12))
            
            # Network details
            elements.append(PageBreak())
            elements.append(Paragraph("Detailed Network Findings", heading_style))
            
            for i, network in enumerate(networks):
                # Add page break between networks except for the first one
                if i > 0:
                    elements.append(PageBreak())
                
                # Network header
                ssid = network.get("ssid", "Unknown SSID")
                bssid = network.get("bssid", "Unknown BSSID")
                elements.append(Paragraph(f"Network: {ssid}", heading2_style))
                elements.append(Paragraph(f"BSSID: {bssid}", normal_style))
                elements.append(Spacer(1, 12))
                
                # Basic information
                basic_data = [
                    ["Channel", network.get("channel", "Unknown")],
                    ["Security", ", ".join(network.get("security", ["None"]))],
                    ["Signal Strength", f"{network.get('signal_strength', 0)}%"],
                    ["Vendor", network.get("vendor", "Unknown")],
                    ["Client Count", str(network.get("client_count", 0))],
                    ["Risk Score", f"{network.get('risk_score', 0)}/100"]
                ]
                
                basic_table = Table(basic_data, colWidths=[150, 250])
                basic_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                
                elements.append(basic_table)
                elements.append(Spacer(1, 12))
                
                # Vulnerabilities
                elements.append(Paragraph("Vulnerabilities", styles['Heading3']))
                
                if network.get("vulnerabilities"):
                    vuln_items = []
                    for vuln in network.get("vulnerabilities", []):
                        vuln_items.append(ListItem(Paragraph(vuln, warning_style)))
                    elements.append(ListFlowable(vuln_items, bulletType='bullet'))
                else:
                    elements.append(Paragraph("No vulnerabilities detected", normal_style))
                
                elements.append(Spacer(1, 12))
                
                # Client information
                if network.get("clients"):
                    elements.append(Paragraph("Connected Clients", styles['Heading3']))
                    
                    client_items = []
                    for client in network.get("clients", []):
                        client_items.append(ListItem(Paragraph(client, normal_style)))
                    elements.append(ListFlowable(client_items, bulletType='bullet'))
                    elements.append(Spacer(1, 12))
                
                # Attack results
                if network.get("attack_results"):
                    elements.append(Paragraph("Security Test Results", styles['Heading3']))
                    
                    for attack_type, result in network.get("attack_results", {}).items():
                        if result.get("success"):
                            elements.append(Paragraph(f"{attack_type}: Successful", warning_style))
                            
                            if attack_type == "wps" and result.get("password"):
                                elements.append(Paragraph(f"WPS PIN: {result.get('pin')}", warning_style))
                                elements.append(Paragraph(f"Password: {result.get('password')}", warning_style))
                            
                            if attack_type in ["wpa", "wep", "pmkid"] and result.get("capture_file"):
                                elements.append(Paragraph(f"Capture file: {result.get('capture_file')}", info_style))
                        else:
                            elements.append(Paragraph(f"{attack_type}: Failed", normal_style))
                    
                    elements.append(Spacer(1, 12))
                
                # Security recommendations
                elements.append(Paragraph("Security Recommendations", styles['Heading3']))
                
                recommendations = []
                
                # Generate recommendations based on network properties
                if not network.get("security"):
                    recommendations.append("Enable WPA2 encryption with a strong password.")
                
                if any(s == "WEP" for s in network.get("security", [])):
                    recommendations.append("Replace WEP encryption with WPA2-PSK or WPA2-Enterprise.")
                
                if any(s == "WPA" for s in network.get("security", [])) and not any(s == "WPA2" for s in network.get("security", [])):
                    recommendations.append("Upgrade from WPA to WPA2 for stronger security.")
                
                if network.get("wps_status") == "Enabled":
                    recommendations.append("Disable WPS to prevent PIN-based attacks.")
                
                if network.get("vulnerabilities") and any("Default Credentials" in v for v in network.get("vulnerabilities", [])):
                    recommendations.append("Change default administrator credentials immediately.")
                
                # Add generic recommendations if none are specific
                if not recommendations:
                    recommendations = [
                        "Use WPA2-PSK with a strong, unique password.",
                        "Change the default SSID to avoid revealing the router model.",
                        "Enable MAC address filtering for additional security.",
                        "Regularly update router firmware.",
                        "Use separate networks for guests and IoT devices."
                    ]
                
                # Add recommendations to report
                rec_items = []
                for rec in recommendations:
                    rec_items.append(ListItem(Paragraph(rec, normal_style)))
                elements.append(ListFlowable(rec_items, bulletType='bullet'))
            
            # Build PDF
            doc.build(elements)
            
            self.logger.info(f"PDF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {str(e)}")
            raise
    
    def generate_report(self, networks: List, output_format: str = "pdf", 
                      output_path: str = None, custom_data: Dict[str, Any] = None,
                      open_after: bool = False) -> str:
        """
        Generate security assessment report
        
        Args:
            networks: List of NetworkTarget objects
            output_format: 'pdf' or 'html'
            output_path: Path to save the report (if None, a temporary file is created)
            custom_data: Additional custom data for the report
            open_after: Whether to open the report after generation
            
        Returns:
            Path to the generated report file
        """
        # Convert networks to dictionaries if they are objects
        network_dicts = []
        for network in networks:
            if hasattr(network, 'to_dict'):
                network_dicts.append(network.to_dict())
            else:
                network_dicts.append(network)
        
        try:
            # Generate report based on format
            if output_format.lower() == 'pdf':
                report_path = self.generate_pdf_report(network_dicts, output_path, custom_data)
            else:  # html
                report_path = self.generate_html_report(network_dicts, output_path, custom_data)
            
            # Open report if requested
            if open_after and report_path:
                webbrowser.open(f"file://{os.path.abspath(report_path)}")
            
            return report_path
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
