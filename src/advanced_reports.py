#!/usr/bin/env python3
"""
Advanced Report Generator for WiFi Penetration Testing Tool
Generates professional PDF reports with visual elements and security metrics
"""

import os
import time
from datetime import datetime
import tempfile
from typing import Dict, List, Any, Tuple, Optional, Union

# Try to import optional dependencies with graceful fallbacks
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("ReportLab not available, advanced PDF report generation will be disabled")

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Matplotlib not available, chart generation will be limited")

class ReportGenerator:
    """Advanced report generator for wireless network security assessments"""
    
    def __init__(self, controller=None):
        """Initialize the report generator"""
        self.controller = controller
        self.company_name = "Client Organization"
        self.tester_name = "Security Analyst"
        self.data = {}
        
    def load_data_from_controller(self):
        """Load data from the main controller for the report
        
        This method fetches all necessary data from the controller
        including network scan results, attack data, and any other
        information needed for the report.
        """
        if not self.controller:
            return
            
        # Initialize data structure if not already done
        if not self.data:
            self.data = {
                "networks": [],
                "attacks": [],
                "traffic_analysis": {},
                "vulnerabilities": [],
                "post_exploitation": {}
            }
            
        # Get networks from controller if available
        if hasattr(self.controller, 'networks') and self.controller.networks:
            self.data["networks"] = self.controller.networks
            
        # Get attacks from controller's attack history if available
        if hasattr(self.controller, 'attack_history') and self.controller.attack_history:
            self.data["attacks"] = self.controller.attack_history
            
        # Add sample data if nothing is available from controller
        if not self.data["networks"]:
            self.data["networks"] = self._generate_sample_networks()
            
        if not self.data["attacks"]:
            self.data["attacks"] = self._generate_sample_attacks()
            
    def _generate_sample_networks(self):
        """Generate sample network data if no real data is available"""
        return [
            {"ssid": "Example-Network", "bssid": "00:11:22:33:44:55", "security": ["WPA2"], "signal_strength": 65},
            {"ssid": "Office-WiFi", "bssid": "AA:BB:CC:DD:EE:FF", "security": ["WPA2-Enterprise"], "signal_strength": 80},
            {"ssid": "Guest-Network", "bssid": "11:22:33:44:55:66", "security": ["Open"], "signal_strength": 45}
        ]
        
    def _generate_sample_attacks(self):
        """Generate sample attack data if no real data is available"""
        return [
            {"type": "WPA Handshake", "target": "Example-Network", "result": "Captured", "time_taken": "1m 23s"},
            {"type": "Default Credentials", "target": "Office-Printer", "result": "Success", "time_taken": "15s"}
        ]
        
        if REPORTLAB_AVAILABLE:
            self.styles = getSampleStyleSheet()
            # Modify existing styles
            self.styles['Heading1'].fontSize = 16
            self.styles['Heading1'].spaceAfter = 10
            
            self.styles['Heading2'].fontSize = 14
            self.styles['Heading2'].spaceAfter = 8
            
            self.styles['Heading3'].fontSize = 12
            self.styles['Heading3'].spaceAfter = 6
            
            # Add custom styles
            self.styles.add(ParagraphStyle(
                name='CustomHeading1',
                parent=self.styles['Heading1'],
                fontSize=16,
                spaceAfter=10
            ))
            self.styles['Normal'].fontSize = 10
            self.styles['Normal'].spaceAfter = 6
            self.styles.add(ParagraphStyle(
                name='Table',
                parent=self.styles['Normal'],
                fontSize=8
            ))
            self.styles.add(ParagraphStyle(
                name='Alert',
                parent=self.styles['Normal'],
                textColor=colors.red,
                fontSize=10,
                spaceAfter=6
            ))
        
        # Ensure reports directory exists
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def set_company_info(self, company_name, tester_name):
        """Set company and tester information
        
        Args:
            company_name: Client company name
            tester_name: Security tester name
        """
        self.company_name = company_name
        self.tester_name = tester_name
    
    def load_data_from_controller(self):
        """Load network and attack data from controller"""
        if not self.controller:
            return
        
        # Get network and attack data
        networks = []
        if hasattr(self.controller, 'get_networks'):
            networks = self.controller.get_networks()
        
        attack_results = {}
        if hasattr(self.controller, 'get_results'):
            attack_results = self.controller.get_results()
        
        # Store data
        self.data = {
            "networks": networks,
            "attack_results": attack_results
        }
    
    def create_report_preview(self, parent_frame):
        """Create a preview of the report in the given frame
        
        Args:
            parent_frame: Parent frame to add preview
        """
        if not REPORTLAB_AVAILABLE:
            tk.Label(parent_frame, text="ReportLab not available, PDF preview disabled").pack(padx=10, pady=10)
            return
            
        import tkinter as tk
        from tkinter import ttk
        
        # Add preview text
        ttk.Label(parent_frame, text=f"Security Report for {self.company_name}", 
                 font=("Helvetica", 16, "bold")).pack(pady=10)
                 
        ttk.Label(parent_frame, text=f"Prepared by: {self.tester_name}", 
                 font=("Helvetica", 12)).pack(pady=5)
                 
        ttk.Label(parent_frame, text=f"Date: {datetime.now().strftime('%Y-%m-%d')}", 
                 font=("Helvetica", 10)).pack(pady=5)
        
        # Add report sections
        sections_frame = ttk.LabelFrame(parent_frame, text="Report Sections")
        sections_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        sections = [
            "Executive Summary",
            "Network Security Overview",
            "Vulnerability Details",
            "Network Details",
            "Attack Results",
            "Security Recommendations",
            "Appendix: Methodology",
            "Appendix: Tools Used"
        ]
        
        for section in sections:
            ttk.Checkbutton(sections_frame, text=section, state=tk.DISABLED).pack(anchor=tk.W, padx=20, pady=5)
            
        # Add report preview
        preview_frame = ttk.LabelFrame(parent_frame, text="Chart Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Check if we can generate preview chart
        if MATPLOTLIB_AVAILABLE:
            try:
                self._create_preview_chart(preview_frame)
            except Exception as e:
                ttk.Label(preview_frame, text=f"Error generating preview: {str(e)}").pack(padx=10, pady=10)
        else:
            ttk.Label(preview_frame, text="Matplotlib not available, chart preview disabled").pack(padx=10, pady=10)
    
    def _create_preview_chart(self, parent_frame):
        """Create a preview chart in the given frame
        
        Args:
            parent_frame: Parent frame to add chart
        """
        import tkinter as tk
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        
        # Create figure
        fig = Figure(figsize=(5, 4))
        ax = fig.add_subplot(111)
        
        # Create sample data
        labels = ['High', 'Medium', 'Low', 'Secure']
        sizes = [15, 30, 45, 10]
        colors = ['#ff5252', '#ffb142', '#ffd966', '#2ed573']
        
        # Create pie chart
        ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')
        ax.set_title('Network Risk Distribution')
        
        # Create canvas
        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def generate_pdf_report(self, output_filename=None):
        """Generate a comprehensive PDF report
        
        Args:
            output_filename: Optional filename for the report
            
        Returns:
            str: Path to the generated report
        """
        if not REPORTLAB_AVAILABLE:
            print("Cannot generate PDF report: ReportLab library not available")
            return None
            
        try:
            # Generate filename if not provided
            if not output_filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_filename = os.path.join(self.reports_dir, f"security_report_{timestamp}.pdf")
            
            # Load data if not already loaded
            if not self.data and self.controller:
                self.load_data_from_controller()
                
            # Create document
            doc = SimpleDocTemplate(output_filename, pagesize=letter)
            story = []
            
            # Add cover page
            self.add_cover_page(story)
            
            # Add executive summary
            self.add_executive_summary(story)
            
            # Add security overview
            self.add_security_overview(story)
            
            # Add vulnerability details
            self.add_vulnerability_details(story)
            
            # Add detailed network list
            self.add_network_details(story)
            
            # Add attack results
            self.add_attack_results(story)
            
            # Add recommendations
            self.add_recommendations(story)
            
            # Add appendices
            self.add_appendices(story)
            
            # Build the PDF
            doc.build(story)
            
            return output_filename
            
        except Exception as e:
            print(f"Error generating PDF report: {str(e)}")
            return None
    
    def add_cover_page(self, story):
        """Add a cover page to the report
        
        Args:
            story: ReportLab story list
        """
        # Title
        title = Paragraph("Wireless Network Security Assessment", self.styles['Title'])
        story.append(Spacer(1, 2*inch))
        story.append(title)
        
        # Subtitle
        subtitle = Paragraph("CONFIDENTIAL", self.styles['Title'])
        story.append(Spacer(1, 0.5*inch))
        story.append(subtitle)
        
        # Client name and date
        story.append(Spacer(1, 2*inch))
        client = Paragraph(f"Prepared for: {self.company_name}", self.styles['Heading2'])
        story.append(client)
        
        story.append(Spacer(1, 0.25*inch))
        date = Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", self.styles['Heading2'])
        story.append(date)
        
        story.append(Spacer(1, 0.25*inch))
        analyst = Paragraph(f"Security Analyst: {self.tester_name}", self.styles['Heading2'])
        story.append(analyst)
        
        # Add a page break
        story.append(PageBreak())
    
    def add_executive_summary(self, story):
        """Add executive summary
        
        Args:
            story: ReportLab story list
        """
        # Add executive summary header
        summary_title = Paragraph("Executive Summary", self.styles['Heading1'])
        story.append(summary_title)
        
        # Get network data
        networks = self.data.get("networks", [])
        attack_results = self.data.get("attack_results", {})
        
        # Calculate statistics
        total_networks = len(networks)
        vulnerable_networks = sum(1 for n in networks if getattr(n, 'risk_score', 0) > 50)
        high_risk_networks = sum(1 for n in networks if getattr(n, 'risk_score', 0) > 75)
        medium_risk_networks = sum(1 for n in networks if 50 < getattr(n, 'risk_score', 0) <= 75)
        low_risk_networks = sum(1 for n in networks if 25 < getattr(n, 'risk_score', 0) <= 50)
        secure_networks = sum(1 for n in networks if getattr(n, 'risk_score', 0) <= 25)
        
        # Network security overview text
        overview_text = f"""
        This report presents the findings of a wireless network security assessment conducted on {total_networks} discovered networks.
        The assessment identified {vulnerable_networks} networks with significant security vulnerabilities.
        
        <b>Risk Breakdown:</b>
        • High Risk Networks: {high_risk_networks}
        • Medium Risk Networks: {medium_risk_networks}
        • Low Risk Networks: {low_risk_networks}
        • Secure Networks: {secure_networks}
        """
        
        overview = Paragraph(overview_text, self.styles['Normal'])
        story.append(overview)
        story.append(Spacer(1, 0.25*inch))
        
        # Add pie chart for risk breakdown
        if total_networks > 0 and REPORTLAB_AVAILABLE:
            self.add_risk_chart(story, high_risk_networks, medium_risk_networks, low_risk_networks, secure_networks)
        
        # Summary of key findings
        findings_title = Paragraph("Key Findings:", self.styles['Heading3'])
        story.append(findings_title)
        
        # Collect key findings
        key_findings = []
        
        # Check for open networks
        open_networks = sum(1 for n in networks if not getattr(n, 'security', True))
        if open_networks > 0:
            key_findings.append(f"• {open_networks} networks are operating without any encryption")
            
        # Check for WEP
        wep_networks = sum(1 for n in networks if hasattr(n, 'security_type') and "WEP" in n.security_type)
        if wep_networks > 0:
            key_findings.append(f"• {wep_networks} networks are using obsolete WEP encryption")
            
        # Check for WPS
        wps_networks = sum(1 for n in networks if hasattr(n, 'wps_status') and n.wps_status == "Enabled")
        if wps_networks > 0:
            key_findings.append(f"• {wps_networks} networks have WPS enabled, which may be vulnerable to PIN attacks")
            
        # Check for default credentials
        default_creds_found = False
        for bssid, result in attack_results.items():
            if "DEFAULT_CREDS" in result.get("results", {}) and result["results"]["DEFAULT_CREDS"].get("success", False):
                default_creds_found = True
                break
                
        if default_creds_found:
            key_findings.append("• Default credentials were found on at least one device")
            
        # Add general findings if we don't have specific ones
        if not key_findings:
            key_findings.append("• Overall network security posture needs improvement")
            key_findings.append("• Multiple vulnerabilities were identified that could lead to unauthorized access")
            key_findings.append("• Networks should implement stronger authentication and encryption mechanisms")
            
        # Add findings to story
        for finding in key_findings:
            finding_p = Paragraph(finding, self.styles['Normal'])
            story.append(finding_p)
            
        story.append(Spacer(1, 0.25*inch))
        story.append(PageBreak())
    
    def add_risk_chart(self, story, high, medium, low, secure):
        """Add risk distribution pie chart
        
        Args:
            story: ReportLab story list
            high: Number of high risk networks
            medium: Number of medium risk networks
            low: Number of low risk networks
            secure: Number of secure networks
        """
        # Create drawing
        d = Drawing(400, 200)
        
        # Create pie chart
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 100
        pie.height = 100
        
        # Data
        pie.data = [high, medium, low, secure]
        
        # Labels
        pie.labels = ['High', 'Medium', 'Low', 'Secure']
        
        # Colors
        pie.slices.strokeWidth = 0.5
        pie.slices[0].fillColor = colors.red
        pie.slices[1].fillColor = colors.orange
        pie.slices[2].fillColor = colors.yellow
        pie.slices[3].fillColor = colors.green
        
        # Add chart to drawing
        d.add(pie)
        
        # Chart title
        chart_title = Paragraph("Network Risk Distribution", self.styles['Heading3'])
        story.append(chart_title)
        story.append(d)
        story.append(Spacer(1, 0.25*inch))
        
    def add_vulnerability_severity_chart(self, story, networks, attack_results):
        """Add vulnerability severity breakdown chart
        
        Args:
            story: ReportLab story list
            networks: List of network objects
            attack_results: Dictionary of attack results
        """
        # Create section header
        section_title = Paragraph("Vulnerability Severity Breakdown", self.styles['Heading3'])
        story.append(section_title)
        
        # Count vulnerabilities by severity
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0
        
        # Process attack results to count vulnerabilities
        for bssid, attack_data in attack_results.items():
            for attack_type, result in attack_data.get("results", {}).items():
                if result.get("success", False):
                    if attack_type in ["WEP", "DEFAULT_CREDS"]:
                        critical_vulns += 1
                    elif attack_type in ["WPS"]:
                        high_vulns += 1
                    elif attack_type in ["WPA"]:
                        medium_vulns += 1
                    else:
                        low_vulns += 1
        
        # Create drawing
        d = Drawing(500, 200)
        
        # Create bar chart
        chart = VerticalBarChart()
        chart.x = 50
        chart.y = 50
        chart.height = 125
        chart.width = 350
        chart.data = [[critical_vulns, high_vulns, medium_vulns, low_vulns]]
        chart.strokeWidth = 0.5
        
        # Add axis labels
        chart.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low']
        chart.categoryAxis.labels.fontName = 'Helvetica'
        chart.categoryAxis.labels.fontSize = 8
        chart.valueAxis.labels.fontName = 'Helvetica'
        chart.valueAxis.labels.fontSize = 8
        
        # Set colors
        chart.bars[0].fillColor = colors.purple
        chart.bars[0].strokeColor = colors.black
        chart.bars[0].strokeWidth = 0.5
        
        # Add chart to drawing
        d.add(chart)
        
        # Add to story
        story.append(d)
        
        # Add description
        description_text = f"""
        The chart above shows the breakdown of discovered vulnerabilities by severity level.
        <b>Critical</b> vulnerabilities ({critical_vulns}) pose an immediate risk and require urgent remediation.
        <b>High</b> vulnerabilities ({high_vulns}) should be addressed within 30 days.
        <b>Medium</b> vulnerabilities ({medium_vulns}) should be addressed within 90 days.
        <b>Low</b> vulnerabilities ({low_vulns}) should be addressed as part of regular maintenance.
        """
        description = Paragraph(description_text, self.styles['Normal'])
        story.append(description)
        story.append(Spacer(1, 0.25*inch))
    
    def add_attack_timeline_chart(self, story, attack_results):
        """Add attack timeline chart showing time to exploitation
        
        Args:
            story: ReportLab story list
            attack_results: Dictionary of attack results
        """
        # Create section header
        section_title = Paragraph("Attack Complexity and Time to Exploit", self.styles['Heading3'])
        story.append(section_title)
        
        # Create data for chart (attack type and time taken)
        attack_times = {
            "WEP": [],
            "WPA": [],
            "WPS": [],
            "DEFAULT_CREDS": []
        }
        
        # Extract times from attack results
        for bssid, attack_data in attack_results.items():
            for attack_type, result in attack_data.get("results", {}).items():
                if result.get("success", False) and "time_taken" in result:
                    if attack_type in attack_times:
                        attack_times[attack_type].append(result["time_taken"])
        
        # Calculate average time for each attack type
        avg_times = []
        attack_labels = []
        
        for attack_type, times in attack_times.items():
            if times:
                avg_time = sum(times) / len(times)
                avg_times.append(avg_time)
                attack_labels.append(attack_type)
        
        # Only create chart if we have data
        if avg_times:
            # Create drawing
            d = Drawing(500, 200)
            
            # Create bar chart
            chart = VerticalBarChart()
            chart.x = 50
            chart.y = 50
            chart.height = 125
            chart.width = 350
            chart.data = [avg_times]
            chart.strokeWidth = 0.5
            
            # Add axis labels
            chart.categoryAxis.categoryNames = attack_labels
            chart.categoryAxis.labels.fontName = 'Helvetica'
            chart.categoryAxis.labels.fontSize = 8
            chart.valueAxis.labels.fontName = 'Helvetica'
            chart.valueAxis.labels.fontSize = 8
            chart.valueAxis.valueMin = 0
            
            # Set colors
            chart.bars[0].fillColor = colors.blue
            chart.bars[0].strokeColor = colors.black
            chart.bars[0].strokeWidth = 0.5
            
            # Add chart to drawing
            d.add(chart)
            
            # Add to story
            story.append(d)
            
            # Add description
            description_text = """
            The chart above shows the average time required to successfully exploit each vulnerability type.
            Shorter bars indicate vulnerabilities that can be exploited more quickly, representing a higher risk.
            """
            description = Paragraph(description_text, self.styles['Normal'])
            story.append(description)
        else:
            # No data available
            message = Paragraph("No attack timing data available for chart generation.", self.styles['Normal'])
            story.append(message)
            
        story.append(Spacer(1, 0.25*inch))
    
    def add_vulnerability_breakdown(self, story, networks, attack_results):
        """Add vulnerability breakdown table with detailed information
        
        Args:
            story: ReportLab story list
            networks: List of network objects
            attack_results: Dictionary of attack results
        """
        # Create section header
        section_title = Paragraph("Vulnerability Details by Network", self.styles['Heading3'])
        story.append(section_title)
        
        # Create table data
        table_data = [
            ['Network Name', 'Vulnerability', 'Severity', 'Details', 'Recommendation']
        ]
        
        # Process attack results to fill table
        for bssid, attack_data in attack_results.items():
            # Find network name
            network_name = "Unknown"
            for network in networks:
                if hasattr(network, 'bssid') and network.bssid == bssid:
                    network_name = getattr(network, 'ssid', "Unknown")
                    break
            
            # Process each successful attack
            for attack_type, result in attack_data.get("results", {}).items():
                if result.get("success", False):
                    # Determine severity and details
                    severity = "Critical" if attack_type in ["WEP", "DEFAULT_CREDS"] else (
                               "High" if attack_type == "WPS" else 
                               "Medium" if attack_type == "WPA" else "Low")
                    
                    details = "Unknown"
                    recommendation = "Unknown"
                    
                    # Set details and recommendations based on attack type
                    if attack_type == "WEP":
                        details = "WEP encryption was broken and the key was recovered"
                        recommendation = "Replace WEP with WPA2/WPA3 encryption immediately"
                    elif attack_type == "WPA":
                        details = "WPA key was captured and cracked"
                        recommendation = "Use WPA2/WPA3 with a strong, complex passphrase (14+ chars)"
                    elif attack_type == "WPS":
                        details = "WPS PIN was recovered, allowing network access"
                        recommendation = "Disable WPS functionality or use more secure implementation"
                    elif attack_type == "DEFAULT_CREDS":
                        details = "Default credentials were found on device"
                        recommendation = "Change all default credentials, implement strong password policy"
                    
                    # Add row to table
                    table_data.append([
                        network_name,
                        attack_type,
                        severity,
                        details,
                        recommendation
                    ])
        
        # If no vulnerabilities found, add message
        if len(table_data) == 1:
            table_data.append([
                "N/A", "None detected", "N/A", "No vulnerabilities were exploited during testing", "Continue regular security maintenance"
            ])
        
        # Create and style the table
        vuln_table = Table(table_data, colWidths=[1*inch, 1*inch, 0.75*inch, 1.75*inch, 1.75*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BOX', (0, 0), (-1, -1), 2, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('WORDWRAP', (0, 0), (-1, -1), True),
        ]))
        
        # Add table to story
        story.append(vuln_table)
        story.append(Spacer(1, 0.25*inch))
        story.append(PageBreak())
    
    def add_security_overview(self, story):
        """Add security overview section
        
        Args:
            story: ReportLab story list
        """
        # Add security overview header
        overview_title = Paragraph("Network Security Overview", self.styles['Heading1'])
        story.append(overview_title)
        
        # Get network data
        networks = self.data.get("networks", [])
        
        # Security statistics
        total_networks = len(networks)
        open_networks = sum(1 for n in networks if not getattr(n, 'security', True))
        wep_networks = sum(1 for n in networks if hasattr(n, 'security_type') and "WEP" in n.security_type)
        wpa_networks = sum(1 for n in networks if hasattr(n, 'security_type') and "WPA" in n.security_type 
                           and "WPA2" not in n.security_type)
        wpa2_networks = sum(1 for n in networks if hasattr(n, 'security_type') and "WPA2" in n.security_type)
        
        # Security protocols table
        data = [
            ['Security Protocol', 'Count', 'Percentage'],
            ['WPA2', wpa2_networks, f"{(wpa2_networks/total_networks)*100:.1f}%" if total_networks > 0 else "0%"],
            ['WPA', wpa_networks, f"{(wpa_networks/total_networks)*100:.1f}%" if total_networks > 0 else "0%"],
            ['WEP', wep_networks, f"{(wep_networks/total_networks)*100:.1f}%" if total_networks > 0 else "0%"],
            ['Open (No Encryption)', open_networks, f"{(open_networks/total_networks)*100:.1f}%" if total_networks > 0 else "0%"]
        ]
        
        # Create and style the table
        security_table = Table(data, colWidths=[2*inch, 1*inch, 1*inch])
        security_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, 1), colors.lightgreen),
            ('BACKGROUND', (0, 2), (-1, 2), colors.lightgreen),
            ('BACKGROUND', (0, 3), (-1, 3), colors.lightcoral),
            ('BACKGROUND', (0, 4), (-1, 4), colors.lightcoral),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BOX', (0, 0), (-1, -1), 2, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        # Add table to story
        story.append(security_table)
        story.append(Spacer(1, 0.25*inch))
        
        # Add security assessment
        assessment_text = """
        <b>Security Assessment:</b><br/>
        <b>WPA2</b> provides strong security when configured correctly with a strong pre-shared key.<br/>
        <b>WPA</b> is vulnerable to various attacks and should be upgraded to WPA2 or WPA3.<br/>
        <b>WEP</b> is severely compromised and can be cracked in minutes. It should never be used.<br/>
        <b>Open Networks</b> provide no encryption protection and all data can be intercepted by anyone within range.
        """
        assessment = Paragraph(assessment_text, self.styles['Normal'])
        story.append(assessment)
        
        story.append(Spacer(1, 0.25*inch))
        story.append(PageBreak())
    
    def add_vulnerability_details(self, story):
        """Add vulnerability details section with enhanced visualization
        
        Args:
            story: ReportLab story list
        """
        # Add vulnerability details header
        vuln_title = Paragraph("Vulnerability Details", self.styles['Heading1'])
        story.append(vuln_title)
        
        # Get network data
        networks = self.data.get("networks", [])
        attack_results = self.data.get("attack_results", {})
        
        # Introduction to vulnerability findings
        intro_text = """
        This section details the security vulnerabilities discovered during the assessment.
        Each vulnerability is categorized by severity level and includes information about
        the affected network, attack vector, potential impact, and remediation steps.
        """
        intro = Paragraph(intro_text, self.styles['Normal'])
        story.append(intro)
        story.append(Spacer(1, 0.25*inch))
        
        # Add vulnerability severity chart
        self.add_vulnerability_severity_chart(story, networks, attack_results)
        
        # Add vulnerability timeline chart
        self.add_attack_timeline_chart(story, attack_results)
        
        # Add vulnerability breakdown table
        self.add_vulnerability_breakdown(story, networks, attack_results)
        
        # List high-risk networks
        high_risk_title = Paragraph("High Risk Networks", self.styles['Heading2'])
        story.append(high_risk_title)
        
        high_risk_networks = [n for n in networks if getattr(n, 'risk_score', 0) > 75]
        
        if high_risk_networks:
            # Create table data
            data = [['Network Name (SSID)', 'Security Type', 'Risk Score', 'Key Vulnerabilities']]
            
            for network in high_risk_networks:
                # Format vulnerabilities
                vuln_text = ", ".join(getattr(network, 'vulnerabilities', [])) if hasattr(network, 'vulnerabilities') else "None detected"
                
                # Add network to table
                data.append([
                    getattr(network, 'ssid', 'Unknown'),
                    getattr(network, 'security_type', 'Unknown'),
                    f"{getattr(network, 'risk_score', 0)}%",
                    vuln_text
                ])
                
            # Create and style the table
            high_risk_table = Table(data, colWidths=[1.5*inch, 1*inch, 0.8*inch, 2.5*inch])
            high_risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BOX', (0, 0), (-1, -1), 2, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            # Add table to story
            story.append(high_risk_table)
        else:
            none_text = Paragraph("No high risk networks detected.", self.styles['Normal'])
            story.append(none_text)
            
        story.append(Spacer(1, 0.25*inch))
        
        # List medium-risk networks
        medium_risk_title = Paragraph("Medium Risk Networks", self.styles['Heading2'])
        story.append(medium_risk_title)
        
        medium_risk_networks = [n for n in networks if 50 < getattr(n, 'risk_score', 0) <= 75]
        
        if medium_risk_networks:
            # Create table data
            data = [['Network Name (SSID)', 'Security Type', 'Risk Score', 'Key Vulnerabilities']]
            
            for network in medium_risk_networks:
                # Format vulnerabilities
                vuln_text = ", ".join(getattr(network, 'vulnerabilities', [])) if hasattr(network, 'vulnerabilities') else "None detected"
                
                # Add network to table
                data.append([
                    getattr(network, 'ssid', 'Unknown'),
                    getattr(network, 'security_type', 'Unknown'),
                    f"{getattr(network, 'risk_score', 0)}%",
                    vuln_text
                ])
                
            # Create and style the table
            medium_risk_table = Table(data, colWidths=[1.5*inch, 1*inch, 0.8*inch, 2.5*inch])
            medium_risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkorange),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightyellow),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BOX', (0, 0), (-1, -1), 2, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            # Add table to story
            story.append(medium_risk_table)
        else:
            none_text = Paragraph("No medium risk networks detected.", self.styles['Normal'])
            story.append(none_text)
            
        story.append(Spacer(1, 0.25*inch))
        story.append(PageBreak())
    
    def add_network_details(self, story):
        """Add detailed network list
        
        Args:
            story: ReportLab story list
        """
        # Add network details header
        details_title = Paragraph("Network Details", self.styles['Heading1'])
        story.append(details_title)
        
        # Get network data
        networks = self.data.get("networks", [])
        
        # Add each network
        for i, network in enumerate(networks):
            ssid = getattr(network, 'ssid', 'Unknown')
            bssid = getattr(network, 'bssid', 'Unknown')
            channel = getattr(network, 'channel', 'Unknown')
            security_type = getattr(network, 'security_type', 'Unknown')
            signal_strength = getattr(network, 'signal_strength', 'Unknown')
            wps_status = getattr(network, 'wps_status', 'Unknown')
            vendor = getattr(network, 'vendor', 'Unknown')
            
            # Add network header
            network_title = Paragraph(f"Network {i+1}: {ssid}", self.styles['Heading2'])
            story.append(network_title)
            
            # Create network details table
            data = [
                ['Property', 'Value'],
                ['SSID', ssid],
                ['BSSID', bssid],
                ['Channel', str(channel)],
                ['Security Type', security_type],
                ['Signal Strength', str(signal_strength)],
                ['WPS Status', wps_status],
                ['Vendor', vendor]
            ]
            
            # Add custom properties if available
            if hasattr(network, 'custom_properties'):
                for prop, value in network.custom_properties.items():
                    data.append([prop, str(value)])
            
            # Create and style the table
            network_table = Table(data, colWidths=[1.5*inch, 4.5*inch])
            network_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BOX', (0, 0), (-1, -1), 2, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            # Add table to story
            story.append(network_table)
            story.append(Spacer(1, 0.25*inch))
            
            # Add vulnerabilities if available
            if hasattr(network, 'vulnerabilities') and network.vulnerabilities:
                vuln_title = Paragraph("Vulnerabilities:", self.styles['Heading3'])
                story.append(vuln_title)
                
                for vuln in network.vulnerabilities:
                    vuln_text = Paragraph(f"• {vuln}", self.styles['Normal'])
                    story.append(vuln_text)
                    
                story.append(Spacer(1, 0.25*inch))
            
            # Add page break between networks (except the last one)
            if i < len(networks) - 1:
                story.append(PageBreak())
                
        if not networks:
            none_text = Paragraph("No networks were scanned.", self.styles['Normal'])
            story.append(none_text)
            
        story.append(PageBreak())
    
    def add_attack_results(self, story):
        """Add attack results section
        
        Args:
            story: ReportLab story list
        """
        # Add attack results header
        attack_title = Paragraph("Attack Results", self.styles['Heading1'])
        story.append(attack_title)
        
        # Get attack data
        attack_results = self.data.get("attack_results", {})
        
        if not attack_results:
            none_text = Paragraph("No attacks were performed.", self.styles['Normal'])
            story.append(none_text)
            story.append(PageBreak())
            return
            
        # Add results for each target
        for target, result in attack_results.items():
            # Get target info
            target_ssid = result.get('ssid', 'Unknown')
            target_bssid = target
            
            # Add target header
            target_title = Paragraph(f"Target: {target_ssid} ({target_bssid})", self.styles['Heading2'])
            story.append(target_title)
            
            # Add attack results
            attack_types = result.get('results', {})
            
            if not attack_types:
                none_text = Paragraph("No attack results available for this target.", self.styles['Normal'])
                story.append(none_text)
                story.append(Spacer(1, 0.25*inch))
                continue
                
            # Create table data
            data = [['Attack Type', 'Success', 'Details']]
            
            for attack_type, attack_result in attack_types.items():
                success = attack_result.get('success', False)
                details = attack_result.get('details', 'No details available')
                
                data.append([
                    attack_type,
                    "Yes" if success else "No",
                    details
                ])
                
            # Create and style the table
            attack_table = Table(data, colWidths=[1.5*inch, 0.8*inch, 3.7*inch])
            attack_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BOX', (0, 0), (-1, -1), 2, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            # Conditional coloring based on success
            for i in range(1, len(data)):
                if data[i][1] == "Yes":
                    attack_table.setStyle(TableStyle([
                        ('BACKGROUND', (1, i), (1, i), colors.lightgreen)
                    ]))
                else:
                    attack_table.setStyle(TableStyle([
                        ('BACKGROUND', (1, i), (1, i), colors.lightcoral)
                    ]))
            
            # Add table to story
            story.append(attack_table)
            story.append(Spacer(1, 0.25*inch))
            
            # Add additional information if available
            if 'additional_info' in result:
                info_title = Paragraph("Additional Information:", self.styles['Heading3'])
                story.append(info_title)
                
                info_text = Paragraph(result['additional_info'], self.styles['Normal'])
                story.append(info_text)
                story.append(Spacer(1, 0.25*inch))
                
            # Add page break between targets (except the last one)
            if target != list(attack_results.keys())[-1]:
                story.append(PageBreak())
                
        story.append(PageBreak())
    
    def add_recommendations(self, story):
        """Add recommendations section
        
        Args:
            story: ReportLab story list
        """
        # Add recommendations header
        recommendations_title = Paragraph("Security Recommendations", self.styles['Heading1'])
        story.append(recommendations_title)
        
        # Get network data
        networks = self.data.get("networks", [])
        
        # General recommendations
        general_title = Paragraph("General Recommendations", self.styles['Heading2'])
        story.append(general_title)
        
        # Add standard recommendations
        recommendations = [
            "Ensure all wireless networks use WPA2 or WPA3 encryption with strong pre-shared keys.",
            "Disable WPS (Wi-Fi Protected Setup) on all access points and routers.",
            "Change default credentials on all network devices.",
            "Implement network segregation to isolate guest networks from internal resources.",
            "Regularly update firmware on all wireless access points, routers, and other network devices.",
            "Use MAC address filtering as an additional layer of security.",
            "Implement a wireless intrusion detection/prevention system (WIDS/WIPS) to detect and respond to attacks.",
            "Conduct regular wireless security assessments to identify and address vulnerabilities."
        ]
        
        for recommendation in recommendations:
            rec_text = Paragraph(f"• {recommendation}", self.styles['Normal'])
            story.append(rec_text)
            
        story.append(Spacer(1, 0.25*inch))
        
        # Specific recommendations based on findings
        specific_title = Paragraph("Specific Recommendations", self.styles['Heading2'])
        story.append(specific_title)
        
        specific_recommendations = []
        
        # Check for open networks
        open_networks = [n for n in networks if not getattr(n, 'security', True)]
        if open_networks:
            ssids = [getattr(n, 'ssid', 'Unknown') for n in open_networks]
            specific_recommendations.append(f"Configure encryption on open networks: {', '.join(ssids)}")
            
        # Check for WEP networks
        wep_networks = [n for n in networks if hasattr(n, 'security_type') and "WEP" in n.security_type]
        if wep_networks:
            ssids = [getattr(n, 'ssid', 'Unknown') for n in wep_networks]
            specific_recommendations.append(f"Upgrade WEP encryption to WPA2/WPA3 on networks: {', '.join(ssids)}")
            
        # Check for WPS enabled
        wps_networks = [n for n in networks if hasattr(n, 'wps_status') and n.wps_status == "Enabled"]
        if wps_networks:
            ssids = [getattr(n, 'ssid', 'Unknown') for n in wps_networks]
            specific_recommendations.append(f"Disable WPS on networks: {', '.join(ssids)}")
            
        # Add specific recommendations
        if specific_recommendations:
            for recommendation in specific_recommendations:
                rec_text = Paragraph(f"• {recommendation}", self.styles['Normal'])
                story.append(rec_text)
        else:
            none_text = Paragraph("No specific recommendations based on scan results.", self.styles['Normal'])
            story.append(none_text)
            
        story.append(Spacer(1, 0.25*inch))
        story.append(PageBreak())
    
    def add_appendices(self, story):
        """Add appendices
        
        Args:
            story: ReportLab story list
        """
        # Add appendices header
        appendices_title = Paragraph("Appendices", self.styles['Heading1'])
        story.append(appendices_title)
        
        # Add appendix for methodology
        methodology_title = Paragraph("Appendix A: Methodology", self.styles['Heading2'])
        story.append(methodology_title)
        
        methodology_text = """
        The wireless security assessment was conducted using industry standard tools and methodologies, including:
        
        • Passive scanning to identify wireless networks and their security configurations
        • Analysis of encryption methods and wireless security protocols
        • Evaluation of WPS implementation and security
        • Testing for common wireless vulnerabilities
        • Assessment of signal coverage and potential exposure outside the intended perimeter
        
        All testing was performed using specialized tools for wireless security assessment, with explicit authorization
        from the client organization. No active attacks were performed without prior approval.
        """
        
        methodology = Paragraph(methodology_text, self.styles['Normal'])
        story.append(methodology)
        
        story.append(Spacer(1, 0.25*inch))
        
        # Add appendix for tools used
        tools_title = Paragraph("Appendix B: Tools Used", self.styles['Heading2'])
        story.append(tools_title)
        
        tools_text = """
        The following tools were used during this assessment:
        
        • NetworkPentestPro: Advanced WiFi security assessment tool with real-time scanning
        • Aircrack-ng: Suite of tools for wireless network security assessment
        • Wireshark: Network protocol analyzer for traffic analysis
        • Kismet: Wireless network detector and sniffer
        • Reaver: WPS vulnerability assessment tool
        • Custom scripts for data analysis and reporting
        """
        
        tools = Paragraph(tools_text, self.styles['Normal'])
        story.append(tools)
        
        story.append(Spacer(1, 0.25*inch))
        
        # Add appendix for risk scoring
        scoring_title = Paragraph("Appendix C: Risk Scoring Methodology", self.styles['Heading2'])
        story.append(scoring_title)
        
        scoring_text = """
        Risk scores were calculated based on the following factors:
        
        • <b>Encryption Strength</b>: WPA3 (0 points), WPA2 (10 points), WPA (30 points), WEP (70 points), None (100 points)
        • <b>WPS Status</b>: Disabled (0 points), Enabled (30 points)
        • <b>Signal Strength</b>: Low (0 points), Medium (5 points), High outside perimeter (15 points)
        • <b>Default Credentials</b>: Changed (0 points), Default (50 points)
        • <b>Known Vulnerabilities</b>: None (0 points), Low (10 points), Medium (30 points), High (50 points)
        
        Risk scores are categorized as follows:
        • <b>Secure</b>: 0-25 points
        • <b>Low Risk</b>: 26-50 points
        • <b>Medium Risk</b>: 51-75 points
        • <b>High Risk</b>: 76-100 points
        """
        
        scoring = Paragraph(scoring_text, self.styles['Normal'])
        story.append(scoring)
        
        story.append(Spacer(1, 0.25*inch))