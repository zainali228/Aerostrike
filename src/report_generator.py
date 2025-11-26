#!/usr/bin/env python3
"""
Report Generator for Aero Strike (AI-Powered Wifi Penetration Testing Tool)
Generates PDF reports with network security findings
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
    print("ReportLab not available, PDF report generation will be disabled")

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
    """Report generator for wireless network security assessments"""
    
    def __init__(self, controller=None):
        """Initialize the report generator"""
        self.controller = controller
        self.company_name = "Client Organization"
        self.analyst_name = "Security Analyst"
        self.networks = []
        self.attacks = []
        self.traffic_data = {}
        self.vulnerabilities = []
        self.post_exploitation_data = {}
        
        # Initialize styles if ReportLab is available
        if REPORTLAB_AVAILABLE:
            self.styles = getSampleStyleSheet()
            # Modify existing styles
            self.styles['Heading1'].fontSize = 16
            self.styles['Heading1'].spaceAfter = 10
            
            self.styles['Heading2'].fontSize = 14
            self.styles['Heading2'].spaceAfter = 8
            
            self.styles['Heading3'].fontSize = 12
            self.styles['Heading3'].spaceAfter = 6
        
        # Ensure reports directory exists
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)
        
    def load_data_from_controller(self):
        """Load data from the main controller for the report
        
        This method fetches all necessary data from the controller
        including network scan results, attack data, and any other
        information needed for the report.
        """
        if not self.controller:
            # Don't add any sample data - only real results are shown
            return
            
        # Get networks from controller if available
        if hasattr(self.controller, 'networks') and self.controller.networks:
            self.networks = self.controller.networks
        elif hasattr(self.controller, 'scan_results') and self.controller.scan_results:
            # Alternative attribute name
            self.networks = self.controller.scan_results
        
        # Get attacks from controller's attack history if available
        if hasattr(self.controller, 'attack_history') and self.controller.attack_history:
            self.attacks = self.controller.attack_history
        elif hasattr(self.controller, 'attack_results') and self.controller.attack_results:
            # Alternative attribute name
            self.attacks = self.controller.attack_results
            
        # Get post exploitation data
        if hasattr(self.controller, 'post_exploitation_data') and self.controller.post_exploitation_data:
            self.post_exploitation_data = self.controller.post_exploitation_data
        elif hasattr(self.controller, 'post_exploitation') and self.controller.post_exploitation:
            # Try to get data from post_exploitation object
            post_exploit = self.controller.post_exploitation
            if hasattr(post_exploit, 'hosts') and post_exploit.hosts:
                self.post_exploitation_data = {'hosts': post_exploit.hosts}
            if hasattr(post_exploit, 'services') and post_exploit.services:
                if not self.post_exploitation_data:
                    self.post_exploitation_data = {}
                self.post_exploitation_data['services'] = post_exploit.services
            if hasattr(post_exploit, 'vulnerabilities') and post_exploit.vulnerabilities:
                if not self.post_exploitation_data:
                    self.post_exploitation_data = {}
                self.post_exploitation_data['vulnerabilities'] = post_exploit.vulnerabilities
                
        # Get network traffic data
        if hasattr(self.controller, 'traffic_data') and self.controller.traffic_data:
            self.traffic_data = self.controller.traffic_data
        elif hasattr(self.controller, 'traffic_monitor') and self.controller.traffic_monitor:
            # Try to get data directly from traffic monitor
            traffic_mon = self.controller.traffic_monitor
            self.traffic_data = {}
            if hasattr(traffic_mon, 'packet_count'):
                self.traffic_data['total_packets'] = traffic_mon.packet_count
            if hasattr(traffic_mon, 'protocol_stats'):
                self.traffic_data['protocols'] = traffic_mon.protocol_stats
            if hasattr(traffic_mon, 'sensitive_data_findings'):
                self.traffic_data['sensitive_data'] = traffic_mon.sensitive_data_findings
            
    # All sample data functions have been removed to ensure only real data is used in reports
    # No simulated or dummy data will be shown in any reports
        
    def set_company_info(self, company_name, analyst_name):
        """Set company and analyst information for the report"""
        self.company_name = company_name
        self.analyst_name = analyst_name
        
    def create_report_preview(self, parent_frame):
        """Create a preview of the report in the provided parent frame"""
        import tkinter as tk
        from tkinter import ttk
        
        # Create a simple preview label
        ttk.Label(
            parent_frame, 
            text="WiFi Security Assessment Report",
            font=("Helvetica", 14, "bold")
        ).pack(pady=10)
        
        # Client info
        info_frame = ttk.Frame(parent_frame)
        info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(info_frame, text=f"Client: {self.company_name}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Security Analyst: {self.analyst_name}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Date: {datetime.now().strftime('%Y-%m-%d')}").pack(anchor=tk.W)
        
        # Risk level calculation from real scan data
        risk_scores = {}
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        if self.networks:
            # Network section
            net_frame = ttk.LabelFrame(parent_frame, text="Networks Assessed")
            net_frame.pack(fill=tk.X, pady=10, padx=5)
            
            for i, net in enumerate(self.networks[:5]):  # Show up to 5 networks
                if isinstance(net, dict):
                    name = net.get("ssid", "Unknown")
                    bssid = net.get("bssid", "Unknown")
                    security = net.get("security", ["Unknown"])
                    if isinstance(security, list):
                        security = ", ".join(security)
                    
                    # Determine risk level based on security
                    risk = "High" if "Open" in security or "WEP" in security else \
                          "Medium" if "WPA" in security and "WPA2" not in security else "Low"
                    
                    # Count risk levels for visualization
                    if risk == "High":
                        high_risk += 1
                    elif risk == "Medium":
                        medium_risk += 1
                    else:
                        low_risk += 1
                        
                    risk_scores[name] = risk
                    
                    # Create network entry with risk level
                    ttk.Label(
                        net_frame,
                        text=f"{i+1}. {name} ({bssid[:10]}...) - Security: {security} - Risk: {risk}"
                    ).pack(anchor=tk.W, padx=10)
            
            # Add risk visualization if networks were found and matplotlib is available
            if risk_scores and MATPLOTLIB_AVAILABLE:
                try:
                    # Create risk visualization frame
                    risk_frame = ttk.LabelFrame(parent_frame, text="Security Risk Assessment")
                    risk_frame.pack(fill=tk.X, pady=10, padx=5)
                    
                    # Create matplotlib figure for risk visualization
                    import matplotlib.pyplot as plt
                    from matplotlib.figure import Figure
                    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
                    
                    # Create figure with two subplots
                    fig = Figure(figsize=(6, 3))
                    
                    # Risk distribution pie chart
                    ax1 = fig.add_subplot(121)
                    risk_data = [high_risk, medium_risk, low_risk]
                    labels = ['High', 'Medium', 'Low']
                    colors = ['#ff5252', '#ffb142', '#2ed573']
                    
                    # Only plot if we have data
                    if sum(risk_data) > 0:
                        ax1.pie(risk_data, labels=labels, colors=colors, autopct='%1.1f%%', 
                               shadow=True, startangle=90)
                        ax1.set_title('Network Risk Distribution')
                    else:
                        ax1.text(0.5, 0.5, 'No risk data available', 
                                horizontalalignment='center', verticalalignment='center')
                    
                    # Network security bar graph
                    ax2 = fig.add_subplot(122)
                    
                    # Count security types
                    security_types = {}
                    for net in self.networks:
                        if isinstance(net, dict):
                            sec = net.get("security", ["Unknown"])
                            if isinstance(sec, list):
                                sec = ", ".join(sec)
                            if sec in security_types:
                                security_types[sec] += 1
                            else:
                                security_types[sec] = 1
                    
                    # Plot security types if we have data
                    if security_types:
                        x = list(security_types.keys())
                        y = list(security_types.values())
                        ax2.bar(x, y, color='#9F44D3')
                        ax2.set_title('Security Types Found')
                        # Rotate x labels for better readability
                        ax2.set_xticklabels(x, rotation=45, ha='right')
                    else:
                        ax2.text(0.5, 0.5, 'No security data available',
                                horizontalalignment='center', verticalalignment='center')
                    
                    fig.tight_layout()
                    
                    # Embed the figure in the Tkinter window
                    canvas = FigureCanvasTkAgg(fig, master=risk_frame)
                    canvas.draw()
                    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=1)
                    
                except Exception as e:
                    # If visualization fails, just show a text message
                    ttk.Label(
                        parent_frame, 
                        text=f"Risk visualization error: {str(e)}", 
                        foreground="red"
                    ).pack(pady=5)
        else:
            ttk.Label(
                parent_frame,
                text="No networks have been scanned yet. Perform a scan to see network data."
            ).pack(pady=10)
        
        # Attack results section
        attack_frame = ttk.LabelFrame(parent_frame, text="Attack Results")
        attack_frame.pack(fill=tk.X, pady=10, padx=5)
        
        if self.attacks:
            for i, attack in enumerate(self.attacks[:5]):  # Show first 5 attacks
                if isinstance(attack, dict):
                    attack_type = attack.get("type", "Unknown")
                    target = attack.get("target", "Unknown")
                    result = attack.get("result", "Unknown")
                    
                    ttk.Label(
                        attack_frame,
                        text=f"{i+1}. {attack_type} against {target} - Result: {result}"
                    ).pack(anchor=tk.W, padx=10)
        else:
            ttk.Label(
                attack_frame,
                text="No attacks have been performed yet. Run attacks to see results here."
            ).pack(pady=5, padx=10)
        
        # Post-exploitation section
        post_frame = ttk.LabelFrame(parent_frame, text="Post-Exploitation Results")
        post_frame.pack(fill=tk.X, pady=10, padx=5)
        
        if hasattr(self, 'post_exploitation_data') and self.post_exploitation_data:
            # Count vulnerabilities by severity for visualization
            vuln_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            
            if 'vulnerabilities' in self.post_exploitation_data:
                for vuln in self.post_exploitation_data['vulnerabilities']:
                    if isinstance(vuln, dict):
                        severity = vuln.get('severity', 'Medium')
                        if severity in vuln_count:
                            vuln_count[severity] += 1
                        else:
                            vuln_count['Medium'] += 1  # Default if unknown
            
            # Show host count
            host_count = 0
            if 'hosts' in self.post_exploitation_data:
                host_count = len(self.post_exploitation_data['hosts'])
            
            ttk.Label(
                post_frame,
                text=f"Hosts discovered: {host_count}"
            ).pack(anchor=tk.W, padx=10)
            
            # Show vulnerability summary
            if sum(vuln_count.values()) > 0:
                ttk.Label(
                    post_frame,
                    text=f"Vulnerabilities found: {sum(vuln_count.values())}"
                ).pack(anchor=tk.W, padx=10)
                
                ttk.Label(
                    post_frame,
                    text=f"  - Critical: {vuln_count['Critical']}"
                ).pack(anchor=tk.W, padx=20)
                
                ttk.Label(
                    post_frame,
                    text=f"  - High: {vuln_count['High']}"
                ).pack(anchor=tk.W, padx=20)
                
                ttk.Label(
                    post_frame,
                    text=f"  - Medium: {vuln_count['Medium']}"
                ).pack(anchor=tk.W, padx=20)
                
                ttk.Label(
                    post_frame,
                    text=f"  - Low: {vuln_count['Low']}"
                ).pack(anchor=tk.W, padx=20)
        else:
            ttk.Label(
                post_frame,
                text="No post-exploitation data available. Connect to a network and run post-exploitation to see results."
            ).pack(pady=5, padx=10)
        
        # Network traffic section
        traffic_frame = ttk.LabelFrame(parent_frame, text="Network Traffic Analysis")
        traffic_frame.pack(fill=tk.X, pady=10, padx=5)
        
        if hasattr(self, 'traffic_data') and self.traffic_data:
            total_packets = self.traffic_data.get('total_packets', 0)
            protocols = self.traffic_data.get('protocols', {})
            sensitive_data = self.traffic_data.get('sensitive_data', [])
            
            ttk.Label(
                traffic_frame,
                text=f"Total packets captured: {total_packets}"
            ).pack(anchor=tk.W, padx=10)
            
            if protocols:
                protocol_text = "Top protocols: " + ", ".join([f"{p} ({c})" for p, c in sorted(protocols.items(), 
                                                                                      key=lambda x: x[1], 
                                                                                      reverse=True)[:3]])
                ttk.Label(
                    traffic_frame,
                    text=protocol_text
                ).pack(anchor=tk.W, padx=10)
            
            ttk.Label(
                traffic_frame,
                text=f"Sensitive data findings: {len(sensitive_data)}"
            ).pack(anchor=tk.W, padx=10)
        else:
            ttk.Label(
                traffic_frame,
                text="No traffic analysis data available. Run the Network Monitor to capture and analyze traffic."
            ).pack(pady=5, padx=10)
        
        # Preview note
        ttk.Label(
            parent_frame,
            text="Note: The full PDF report will include detailed findings, analysis, risk visualizations and recommendations.",
            font=("Helvetica", 9, "italic"),
            wraplength=500
        ).pack(pady=10)
        
    def generate_pdf_report(self, output_filename=None):
        """Generate a PDF report with all collected data
        
        Args:
            output_filename: Optional filename for the report
            
        Returns:
            str: Path to the generated PDF file
        """
        if not REPORTLAB_AVAILABLE:
            raise Exception("ReportLab is not available, PDF report generation is disabled")
            
        # Create reports directory if it doesn't exist
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Generate filename if not provided
        if not output_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = os.path.join(self.reports_dir, f"wifi_security_report_{timestamp}.pdf")
            
        # Helper function to limit text length for tables to avoid overwriting
        def limit_text(text, max_length=30):
            """Limit text to max_length, adding ellipsis if needed"""
            if not text:
                return ""
            text = str(text)
            # Remove any newlines to prevent text formatting issues
            text = text.replace("\n", " ").replace("\r", " ")
            if len(text) > max_length:
                return text[:max_length-2] + ".."
            return text
            
        # Basic implementation
        doc = SimpleDocTemplate(output_filename, pagesize=letter)
        elements = []
        
        # Title
        elements.append(Paragraph("WiFi Security Assessment Report", self.styles["Heading1"]))
        elements.append(Spacer(1, 0.25*inch))
        
        # Client info
        elements.append(Paragraph(f"Client: {self.company_name}", self.styles["Normal"]))
        elements.append(Paragraph(f"Security Analyst: {self.analyst_name}", self.styles["Normal"]))
        elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", self.styles["Normal"]))
        elements.append(Spacer(1, 0.25*inch))
        
        # Executive Summary
        elements.append(Paragraph("Executive Summary", self.styles["Heading2"]))
        elements.append(Paragraph(
            "This report presents the findings of a comprehensive wireless network security assessment. "
            "The assessment evaluated the security posture of the wireless networks, "
            "identified vulnerabilities, and provides recommendations for improvement. "
            "The assessment included network scanning, targeted attacks, post-exploitation analysis, "
            "network traffic monitoring, and AI-assisted security analysis.",
            self.styles["Normal"]
        ))
        elements.append(Spacer(1, 0.25*inch))
        
        # 1. Network Scanning Results
        elements.append(Paragraph("1. Network Scanning Results", self.styles["Heading2"]))
        elements.append(Paragraph(
            "The following wireless networks were discovered during the assessment. "
            "Each network's security configuration was evaluated for vulnerabilities.",
            self.styles["Normal"]
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        # Create a table for networks
        if self.networks:
            # Table data
            data = [["SSID", "BSSID", "Security", "Signal Strength", "Risk Level"]]
            
            # Add networks to table
            for net in self.networks:
                if isinstance(net, dict):
                    ssid = net.get("ssid", "Unknown")
                    bssid = net.get("bssid", "Unknown")
                    security = net.get("security", ["Unknown"])
                    if isinstance(security, list):
                        security = ", ".join(security)
                    signal = net.get("signal_strength", "Unknown")
                    
                    # Determine risk level based on security
                    risk = "High" if "Open" in security or "WEP" in security else \
                          "Medium" if "WPA" in security and "WPA2" not in security else "Low"
                    
                    data.append([ssid, bssid, security, f"{signal}%", risk])
                
            # Create table
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
            elements.append(Spacer(1, 0.2*inch))
        else:
            elements.append(Paragraph("No networks were discovered during the assessment.", self.styles["Normal"]))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # 2. Attack Results
        elements.append(Paragraph("2. Attack Results", self.styles["Heading2"]))
        elements.append(Paragraph(
            "The following attacks were performed during the assessment to evaluate the security "
            "of the identified wireless networks and connected devices.",
            self.styles["Normal"]
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        # Create a table for attacks
        if self.attacks:
            # Table data
            data = [["Attack Type", "Target", "Result", "Time Taken", "Notes"]]
            
            # Add attacks to table
            for attack in self.attacks:
                if isinstance(attack, dict):
                    attack_type = attack.get("type", "Unknown")
                    target = attack.get("target", "Unknown")
                    result = attack.get("result", "Unknown")
                    time_taken = attack.get("time_taken", "Unknown")
                    notes = attack.get("notes", "")
                    
                    data.append([attack_type, target, result, time_taken, notes])
                
            # Create table
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
            elements.append(Spacer(1, 0.2*inch))
        else:
            elements.append(Paragraph("No attacks were performed during the assessment.", self.styles["Normal"]))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # 3. Post-Exploitation Analysis
        elements.append(Paragraph("3. Post-Exploitation Analysis", self.styles["Heading2"]))
        elements.append(Paragraph(
            "After successful network access, the following post-exploitation analysis was performed "
            "to identify vulnerable hosts and services within the network.",
            self.styles["Normal"]
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        if self.post_exploitation_data:
            # Host Discovery
            elements.append(Paragraph("3.1 Host Discovery", self.styles["Heading3"]))
            hosts = self.post_exploitation_data.get("hosts", [])
            if hosts:
                # Create a table for hosts
                data = [["IP Address", "MAC Address", "Hostname", "Vendor"]]
                for host in hosts:
                    if isinstance(host, dict):
                        ip = limit_text(host.get("ip", "Unknown"), 15)
                        mac = limit_text(host.get("mac", "Unknown"), 18)
                        hostname = limit_text(host.get("hostname", "Unknown"), 15)
                        vendor = limit_text(host.get("vendor", "Unknown"), 15)
                        data.append([ip, mac, hostname, vendor])
                
                # Set specific column widths to prevent overflow
                table = Table(data, colWidths=[1.2*inch, 1.5*inch, 1.3*inch, 1.5*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # Vertical alignment
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),  # Smaller font for better fit
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 3),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('WORDWRAP', (0, 0), (-1, -1), True)  # Enable word wrapping
                ]))
                elements.append(table)
            else:
                elements.append(Paragraph("No hosts were discovered during post-exploitation.", self.styles["Normal"]))
            
            elements.append(Spacer(1, 0.2*inch))
            
            # Service Detection
            elements.append(Paragraph("3.2 Service Detection", self.styles["Heading3"]))
            services = self.post_exploitation_data.get("services", [])
            if services:
                # Create a table for services
                data = [["Host", "Port", "Service", "Version", "Risk Level"]]
                for service in services:
                    if isinstance(service, dict):
                        host = limit_text(service.get("host", "Unknown"), 15)
                        port = limit_text(service.get("port", "Unknown"), 8)
                        service_name = limit_text(service.get("service", "Unknown"), 12)
                        version = limit_text(service.get("version", "Unknown"), 15)
                        risk = limit_text(service.get("risk", "Medium"), 8)
                        data.append([host, port, service_name, version, risk])
                
                # Set specific column widths to prevent overflow
                table = Table(data, colWidths=[1.1*inch, 0.6*inch, 1.2*inch, 1.5*inch, 0.9*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # Vertical alignment
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),  # Smaller font for better fit
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 3),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('WORDWRAP', (0, 0), (-1, -1), True)  # Enable word wrapping
                ]))
                elements.append(table)
            else:
                elements.append(Paragraph("No services were detected during post-exploitation.", self.styles["Normal"]))
            
            elements.append(Spacer(1, 0.2*inch))
            
            # Vulnerabilities
            elements.append(Paragraph("3.3 Vulnerabilities", self.styles["Heading3"]))
            vulnerabilities = self.post_exploitation_data.get("vulnerabilities", [])
            if vulnerabilities:
                # Create a table for vulnerabilities
                data = [["Host", "Service", "Severity", "Description", "CVE"]]
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        host = limit_text(vuln.get("host", "Unknown"), 15)
                        service = limit_text(vuln.get("service", "Unknown"), 12)
                        severity = limit_text(vuln.get("severity", "Medium"), 8)
                        # Description field needs special treatment as it can be very long
                        description = vuln.get("description", "Unknown")
                        if len(description) > 40:
                            description = description[:37] + "..."
                        cve = limit_text(vuln.get("cve", "N/A"), 15)
                        data.append([host, service, severity, description, cve])
                
                # Set specific column widths with description column wider
                table = Table(data, colWidths=[1.0*inch, 1.0*inch, 0.7*inch, 2.5*inch, 1.0*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # Vertical alignment
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),  # Smaller font for better fit
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 3),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('WORDWRAP', (0, 0), (-1, -1), True),  # Enable word wrapping
                    ('ALIGN', (3, 1), (3, -1), 'LEFT')  # Left align description text
                ]))
                elements.append(table)
            else:
                elements.append(Paragraph("No vulnerabilities were detected during post-exploitation.", self.styles["Normal"]))
        else:
            elements.append(Paragraph("No post-exploitation data was collected during the assessment.", self.styles["Normal"]))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # 4. Network Traffic Analysis
        elements.append(Paragraph("4. Network Traffic Analysis", self.styles["Heading2"]))
        elements.append(Paragraph(
            "Network traffic was captured and analyzed to identify sensitive data transmission, "
            "unusual traffic patterns, and potential security issues.",
            self.styles["Normal"]
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        if self.traffic_data:
            # Traffic summary
            elements.append(Paragraph("4.1 Traffic Summary", self.styles["Heading3"]))
            total_packets = self.traffic_data.get("total_packets", 0)
            elements.append(Paragraph(f"Total Packets Captured: {total_packets}", self.styles["Normal"]))
            
            # Protocol distribution
            protocols = self.traffic_data.get("protocols", {})
            if protocols:
                elements.append(Paragraph("Protocol Distribution:", self.styles["Normal"]))
                
                protocol_data = []
                for protocol, count in protocols.items():
                    protocol_data.append([protocol, count])
                
                # Create a simple table for protocol distribution
                data = [["Protocol", "Packet Count"]] + protocol_data
                table = Table(data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(table)
            
            elements.append(Spacer(1, 0.2*inch))
            
            # Sensitive data
            elements.append(Paragraph("4.2 Sensitive Data Detection", self.styles["Heading3"]))
            sensitive_data = self.traffic_data.get("sensitive_data", [])
            if sensitive_data:
                elements.append(Paragraph(
                    "The following sensitive data was detected in network traffic. This represents "
                    "a potential security risk as sensitive information may be transmitted in "
                    "an insecure manner.",
                    self.styles["Normal"]
                ))
                
                # Create a table for sensitive data
                data = [["Type", "Protocol", "Source", "Destination"]]
                for item in sensitive_data:
                    if isinstance(item, dict):
                        data_type = item.get("type", "Unknown")
                        protocol = item.get("protocol", "Unknown")
                        source = item.get("source", "Unknown")
                        destination = item.get("destination", "Unknown")
                        data.append([data_type, protocol, source, destination])
                
                table = Table(data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(table)
            else:
                elements.append(Paragraph("No sensitive data was detected in network traffic.", self.styles["Normal"]))
        else:
            elements.append(Paragraph("No network traffic data was collected during the assessment.", self.styles["Normal"]))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # 5. AI-Assisted Security Analysis
        elements.append(Paragraph("5. AI-Assisted Security Analysis", self.styles["Heading2"]))
        
        # Try to get AI recommendations from various sources
        ai_recommendations = []
        
        # Check if we have AI data from the controller
        if self.controller and hasattr(self.controller, 'ai_recommendations'):
            ai_recommendations = self.controller.ai_recommendations
        
        # If we don't have AI recommendations, create some based on detected issues
        if not ai_recommendations:
            # Generate basic recommendations based on discovered vulnerabilities and networks
            if self.networks:
                for net in self.networks:
                    if isinstance(net, dict):
                        security = net.get("security", ["Unknown"])
                        if isinstance(security, list):
                            security = ", ".join(security)
                        
                        if "Open" in security:
                            ai_recommendations.append({
                                "title": "Implement Encryption on Open Networks",
                                "description": "Open networks transmit all data in plaintext, making it vulnerable to eavesdropping. "
                                             "Implement WPA2 or WPA3 encryption to protect data in transit.",
                                "severity": "Critical"
                            })
                        elif "WEP" in security:
                            ai_recommendations.append({
                                "title": "Replace WEP Encryption",
                                "description": "WEP encryption is cryptographically broken and can be cracked in minutes. "
                                             "Upgrade to WPA2 or WPA3 encryption immediately.",
                                "severity": "Critical"
                            })
                        elif "WPA" in security and "WPA2" not in security:
                            ai_recommendations.append({
                                "title": "Upgrade from WPA to WPA2/WPA3",
                                "description": "WPA has known vulnerabilities. Upgrade to WPA2 or preferably WPA3 "
                                             "to improve wireless network security.",
                                "severity": "High"
                            })
            
            # Add recommendations based on traffic analysis
            if self.traffic_data:
                sensitive_data = self.traffic_data.get("sensitive_data", [])
                if sensitive_data:
                    ai_recommendations.append({
                        "title": "Encrypt Sensitive Data Transmission",
                        "description": "Sensitive data was detected in unencrypted network traffic. "
                                     "Implement TLS/SSL for all sensitive data transmission.",
                        "severity": "Critical"
                    })
            
            # Add general security recommendations
            ai_recommendations.append({
                "title": "Implement Network Segmentation",
                "description": "Separate critical systems and data from the general network using VLANs or "
                             "physical network segmentation to reduce the impact of a breach.",
                "severity": "Medium"
            })
            
            ai_recommendations.append({
                "title": "Deploy Network Monitoring",
                "description": "Implement continuous network monitoring to detect unusual traffic patterns "
                             "and potential security incidents in real-time.",
                "severity": "Medium"
            })
            
            ai_recommendations.append({
                "title": "Regular Security Assessments",
                "description": "Conduct regular security assessments to identify and address new "
                             "vulnerabilities as they emerge.",
                "severity": "Medium"
            })
        
        # Add AI recommendations to report
        if ai_recommendations:
            elements.append(Paragraph(
                "Based on the assessment findings, the following security recommendations have been "
                "generated to address identified vulnerabilities and improve overall security posture.",
                self.styles["Normal"]
            ))
            elements.append(Spacer(1, 0.1*inch))
            
            # Create a table for AI recommendations
            data = [["Recommendation", "Description", "Severity"]]
            for rec in ai_recommendations:
                if isinstance(rec, dict):
                    title = rec.get("title", "Unknown")
                    description = rec.get("description", "Unknown")
                    severity = rec.get("severity", "Medium")
                    data.append([title, description, severity])
            
            table = Table(data, colWidths=[2*inch, 3*inch, 1*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph(
                "AI-assisted security analysis was not performed or did not generate any recommendations.",
                self.styles["Normal"]
            ))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # 6. Conclusion and Recommendations
        elements.append(Paragraph("6. Conclusion and Recommendations", self.styles["Heading2"]))
        elements.append(Paragraph(
            "Based on the assessment findings, the following key recommendations are provided to improve "
            "the security posture of the wireless network environment:",
            self.styles["Normal"]
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        recommendations = [
            "Implement strong encryption (WPA2/WPA3) on all wireless networks.",
            "Use complex, unique passwords for all wireless networks and network devices.",
            "Regularly update firmware on wireless access points and connected devices.",
            "Implement network segregation to isolate guest networks from corporate networks.",
            "Deploy a wireless intrusion detection system (WIDS) for continuous monitoring.",
            "Implement 802.1X authentication for enterprise environments.",
            "Conduct regular security assessments to identify and address new vulnerabilities.",
            "Develop and enforce a strong wireless security policy.",
            "Provide security awareness training to all users.",
            "Monitor network traffic for unusual patterns and potential security incidents."
        ]
        
        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec}", self.styles["Normal"]))
            elements.append(Spacer(1, 0.05*inch))
        
        # Generate the PDF
        doc.build(elements)
        
        return output_filename