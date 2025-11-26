#!/usr/bin/env python3
"""
Simple Report Generator for WiFi Penetration Testing Tool
Generates PDF reports without requiring complex dependencies
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
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("ReportLab not available, PDF report generation will be limited")

class SimpleReportGenerator:
    """Simple report generator for wireless network security assessments"""
    
    def __init__(self, controller=None):
        """Initialize the report generator"""
        self.controller = controller
        self.company_name = "Client Organization"
        self.tester_name = "Security Analyst"
        
        # Initialize styles if ReportLab is available
        if REPORTLAB_AVAILABLE:
            self.styles = getSampleStyleSheet()
            self.styles['Title'].fontSize = 16
            self.styles['Title'].spaceAfter = 10
            
            self.styles['Heading1'].fontSize = 14
            self.styles['Heading1'].spaceAfter = 8
            
            self.styles['Heading2'].fontSize = 12
            self.styles['Heading2'].spaceAfter = 6
            
            self.styles.add(ParagraphStyle(
                name='Normal_Justify', 
                parent=self.styles['Normal'],
                alignment=4,  # 4 is full justify
                spaceBefore=6,
                spaceAfter=6
            ))
            
            self.styles.add(ParagraphStyle(
                name='Bold',
                parent=self.styles['Normal'],
                fontName='Helvetica-Bold'
            ))
        
        # Ensure reports directory exists
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def generate_report(self, filename, data=None, client_info=None):
        """Generate simple security report
        
        Args:
            filename: Output PDF filename
            data: Network and scan data dictionary
            client_info: Optional client information
            
        Returns:
            Tuple[bool, str]: Success status and report path
        """
        if not REPORTLAB_AVAILABLE:
            return False, "ReportLab library not available for PDF generation"
            
        try:
            # Use provided filename or generate a default one
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = os.path.join(self.reports_dir, f"security_report_{timestamp}.pdf")
            
            # Create the PDF document
            doc = SimpleDocTemplate(filename, pagesize=letter)
            story = []
            
            # Get all real-time data from user's testing
            networks = data.get("networks", []) if data else []
            attack_results = data.get("attack_results", {}) if data else {}
            post_exploitation_data = data.get("post_exploitation_data", {}) if data else {}
            network_traffic = data.get("network_traffic", {}) if data else {}
            
            # Add report components with ALL real data from testing
            self.add_header(story, 
                          client_name=client_info.get("client_name", "Client Organization") if client_info else "Client Organization",
                          tester_name=client_info.get("tester_name", "Security Analyst") if client_info else "Security Analyst")
            
            self.add_executive_summary(story, networks, attack_results)
            self.add_network_details(story, networks)
            self.add_attack_results(story, attack_results)
            
            # Add real post-exploitation findings
            try:
                from src.simple_report_functions import add_post_exploitation_findings
                add_post_exploitation_findings(self, story, post_exploitation_data)
            except Exception as e:
                print(f"Error adding post-exploitation data: {e}")
                # Fallback to basic section
                post_title = Paragraph("4. Post-Exploitation Results", self.styles['Heading1'])
                story.append(post_title)
                if post_exploitation_data:
                    hosts = post_exploitation_data.get("hosts", [])
                    story.append(Paragraph(f"Hosts discovered: {len(hosts)}", self.styles['Normal']))
                    services = post_exploitation_data.get("services", [])
                    story.append(Paragraph(f"Services identified: {len(services)}", self.styles['Normal']))
                    vulns = post_exploitation_data.get("vulnerabilities", [])
                    story.append(Paragraph(f"Vulnerabilities detected: {len(vulns)}", self.styles['Normal']))
                else:
                    story.append(Paragraph("No post-exploitation data available", self.styles['Normal']))
            
            # Add real network traffic analysis
            try:
                from src.simple_report_functions import add_network_traffic_findings
                add_network_traffic_findings(self, story, network_traffic)
            except Exception as e:
                print(f"Error adding network traffic data: {e}")
                # Fallback to basic section
                traffic_title = Paragraph("5. Network Traffic Analysis", self.styles['Heading1'])
                story.append(traffic_title)
                if network_traffic:
                    packets = network_traffic.get('packets', [])
                    story.append(Paragraph(f"Total packets captured: {len(packets)}", self.styles['Normal']))
                    sensitive = network_traffic.get('sensitive_data', [])
                    story.append(Paragraph(f"Sensitive data detected: {len(sensitive)}", self.styles['Normal']))
                    alerts = network_traffic.get('alerts', [])
                    story.append(Paragraph(f"Security alerts: {len(alerts)}", self.styles['Normal']))
                else:
                    story.append(Paragraph("No network traffic data available", self.styles['Normal']))
            
            self.add_recommendations(story, networks)
            
            # Build the PDF
            doc.build(story)
            
            return True, filename
            
        except Exception as e:
            error_msg = f"Error generating report: {str(e)}"
            print(error_msg)
            return False, error_msg
    
    def add_header(self, story, client_name="Client Organization", tester_name="Security Analyst"):
        """Add report header
        
        Args:
            story: ReportLab story list
            client_name: Client organization name
            tester_name: Security tester name
        """
        # Title
        title = Paragraph("Wireless Network Security Assessment", self.styles['Title'])
        story.append(title)
        
        # Subtitle - Confidential
        subtitle = Paragraph("CONFIDENTIAL", self.styles['Title'])
        story.append(subtitle)
        
        # Date and client information
        date_text = Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", self.styles['Normal'])
        client_text = Paragraph(f"Client: {client_name}", self.styles['Normal'])
        tester_text = Paragraph(f"Security Analyst: {tester_name}", self.styles['Normal'])
        
        story.append(Spacer(1, 0.25*inch))
        story.append(date_text)
        story.append(client_text)
        story.append(tester_text)
        story.append(Spacer(1, 0.25*inch))
    
    def add_executive_summary(self, story, networks, attack_results):
        """Add executive summary
        
        Args:
            story: ReportLab story list
            networks: List of NetworkTarget objects
            attack_results: Dictionary of attack results
        """
        # Executive Summary header
        summary_title = Paragraph("Executive Summary", self.styles['Heading1'])
        story.append(summary_title)
        
        # Count networks by security type
        total_networks = len(networks)
        open_networks = sum(1 for n in networks if not getattr(n, 'security', True))
        wep_networks = sum(1 for n in networks if hasattr(n, 'security_type') and "WEP" in getattr(n, 'security_type', ''))
        wpa_networks = sum(1 for n in networks if hasattr(n, 'security_type') and "WPA" in getattr(n, 'security_type', ''))
        
        # Count successful attacks
        successful_attacks = 0
        for bssid, result in attack_results.items():
            results = result.get('results', {})
            if any(attack.get('success', False) for attack in results.values()):
                successful_attacks += 1
        
        # Write summary text
        summary_text = f"""
        This security assessment identified {total_networks} wireless networks in the target area. 
        Of these, {open_networks} networks were operating without encryption, {wep_networks} were using 
        obsolete WEP encryption, and {wpa_networks} were using WPA/WPA2.
        
        Security testing was conducted on selected networks, with {successful_attacks} networks 
        showing exploitable vulnerabilities. Key findings and recommendations are detailed in this report.
        """
        
        summary = Paragraph(summary_text, self.styles['Normal_Justify'])
        story.append(summary)
        story.append(Spacer(1, 0.25*inch))
        
        # Key findings
        findings_title = Paragraph("Key Findings:", self.styles['Heading2'])
        story.append(findings_title)
        
        findings = []
        
        if open_networks > 0:
            findings.append(f"• {open_networks} networks were found operating without encryption, posing an immediate security risk.")
        
        if wep_networks > 0:
            findings.append(f"• {wep_networks} networks were using obsolete WEP encryption that can be broken in minutes.")
        
        wps_enabled = sum(1 for n in networks if hasattr(n, 'wps_status') and getattr(n, 'wps_status', '') == "Enabled")
        if wps_enabled > 0:
            findings.append(f"• {wps_enabled} networks had WPS enabled, which may be vulnerable to PIN recovery attacks.")
        
        # Add findings to the story
        for finding in findings:
            finding_text = Paragraph(finding, self.styles['Normal'])
            story.append(finding_text)
        
        # If no specific findings, add a general statement
        if not findings:
            finding_text = Paragraph("• General security weaknesses were identified that should be addressed.", self.styles['Normal'])
            story.append(finding_text)
        
        story.append(Spacer(1, 0.25*inch))
        story.append(PageBreak())
    
    def add_network_details(self, story, networks):
        """Add detailed network list
        
        Args:
            story: ReportLab story list
            networks: List of NetworkTarget objects
        """
        # Network Details header
        networks_title = Paragraph("Network Details", self.styles['Heading1'])
        story.append(networks_title)
        
        if not networks:
            no_networks = Paragraph("No networks were identified during the scan.", self.styles['Normal'])
            story.append(no_networks)
            story.append(Spacer(1, 0.25*inch))
            return
        
        # Create a table of networks
        data = [["SSID", "BSSID", "Channel", "Security", "Signal"]]
        
        for network in networks:
            # Get network attributes (with fallbacks)
            ssid = getattr(network, 'ssid', 'Unknown')
            bssid = getattr(network, 'bssid', 'Unknown')
            channel = getattr(network, 'channel', 'Unknown')
            security = getattr(network, 'security_type', 'Unknown')
            signal = getattr(network, 'signal_strength', 'Unknown')
            
            # Add to table
            data.append([ssid, bssid, str(channel), security, str(signal)])
        
        # Create the table
        table = Table(data, colWidths=[1.5*inch, 1.5*inch, 0.75*inch, 1.25*inch, 0.75*inch])
        
        # Style the table
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (2, 1), (4, -1), 'CENTER'),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.25*inch))
        
        # Add details for each network
        for i, network in enumerate(networks):
            ssid = getattr(network, 'ssid', 'Unknown')
            bssid = getattr(network, 'bssid', 'Unknown')
            
            # Add network header
            if i > 0:  # Add space between networks
                story.append(Spacer(1, 0.25*inch))
                
            network_title = Paragraph(f"Network: {ssid} ({bssid})", self.styles['Heading2'])
            story.append(network_title)
            
            # Get additional details
            channel = getattr(network, 'channel', 'Unknown')
            security = getattr(network, 'security_type', 'Unknown')
            encryption = getattr(network, 'encryption', 'Unknown')
            signal = getattr(network, 'signal_strength', 'Unknown')
            wps = getattr(network, 'wps_status', 'Unknown')
            vendor = getattr(network, 'vendor', 'Unknown')
            
            # Create details paragraphs
            details = [
                f"• <b>Channel:</b> {channel}",
                f"• <b>Security:</b> {security}",
                f"• <b>Encryption:</b> {encryption}",
                f"• <b>Signal Strength:</b> {signal}",
                f"• <b>WPS Status:</b> {wps}",
                f"• <b>Vendor:</b> {vendor}"
            ]
            
            # Add details to story
            for detail in details:
                detail_text = Paragraph(detail, self.styles['Normal'])
                story.append(detail_text)
            
            # Add vulnerabilities if any
            if hasattr(network, 'vulnerabilities') and network.vulnerabilities:
                vuln_title = Paragraph("Identified Vulnerabilities:", self.styles['Bold'])
                story.append(Spacer(1, 0.1*inch))
                story.append(vuln_title)
                
                for vuln in network.vulnerabilities:
                    vuln_text = Paragraph(f"• {vuln}", self.styles['Normal'])
                    story.append(vuln_text)
        
        story.append(Spacer(1, 0.25*inch))
        story.append(PageBreak())
    
    def add_attack_results(self, story, attack_results):
        """Add attack results section
        
        Args:
            story: ReportLab story list
            attack_results: Dictionary of attack results
        """
        # Attack Results header
        results_title = Paragraph("Attack Results", self.styles['Heading1'])
        story.append(results_title)
        
        if not attack_results:
            no_results = Paragraph("No attacks were performed during this assessment.", self.styles['Normal'])
            story.append(no_results)
            story.append(Spacer(1, 0.25*inch))
            return
        
        # Add results for each target
        for bssid, results in attack_results.items():
            ssid = results.get('ssid', 'Unknown')
            
            # Target header
            target_title = Paragraph(f"Target: {ssid} ({bssid})", self.styles['Heading2'])
            story.append(target_title)
            
            # Attack results table
            attack_data = [["Attack Type", "Success", "Details"]]
            
            # Add each attack result
            attack_results_dict = results.get('results', {})
            if not attack_results_dict:
                no_attacks = Paragraph("No specific attacks were performed on this target.", self.styles['Normal'])
                story.append(no_attacks)
                continue
                
            for attack_type, attack_result in attack_results_dict.items():
                success = attack_result.get('success', False)
                details = attack_result.get('details', 'No details available')
                
                # Format attack type for display
                display_type = attack_type.replace('_', ' ').title()
                
                # Add to table
                attack_data.append([
                    display_type,
                    "Yes" if success else "No",
                    details
                ])
            
            # Create attack results table
            attack_table = Table(attack_data, colWidths=[1.5*inch, 0.75*inch, 3.5*inch])
            
            # Style the table
            attack_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            ]))
            
            # Add coloring for success/failure
            for i in range(1, len(attack_data)):
                if attack_data[i][1] == "Yes":  # Success
                    attack_table.setStyle(TableStyle([
                        ('BACKGROUND', (1, i), (1, i), colors.lightgreen)
                    ]))
                else:  # Failure
                    attack_table.setStyle(TableStyle([
                        ('BACKGROUND', (1, i), (1, i), colors.lightcoral)
                    ]))
            
            story.append(attack_table)
            story.append(Spacer(1, 0.25*inch))
        
        story.append(PageBreak())
    
    def add_recommendations(self, story, networks):
        """Add recommendations section
        
        Args:
            story: ReportLab story list
            networks: List of NetworkTarget objects
        """
        # Recommendations header
        recommendations_title = Paragraph("Security Recommendations", self.styles['Heading1'])
        story.append(recommendations_title)
        
        # General recommendations
        general_title = Paragraph("General Recommendations", self.styles['Heading2'])
        story.append(general_title)
        
        general_recommendations = [
            "• Use WPA2 or WPA3 encryption with a strong passphrase (minimum 12 characters).",
            "• Disable WPS on all access points to prevent PIN-based attacks.",
            "• Regularly update firmware on all wireless access points and routers.",
            "• Implement network segregation for guest and IoT devices.",
            "• Consider implementing 802.1X authentication for enterprise environments.",
            "• Conduct regular wireless security assessments.",
            "• Monitor for unauthorized access points in the network perimeter."
        ]
        
        for recommendation in general_recommendations:
            rec_text = Paragraph(recommendation, self.styles['Normal'])
            story.append(rec_text)
        
        story.append(Spacer(1, 0.25*inch))
        
        # Target-specific recommendations
        if networks:
            specific_title = Paragraph("Specific Recommendations", self.styles['Heading2'])
            story.append(specific_title)
            
            # Check for WEP networks
            wep_networks = [n for n in networks if hasattr(n, 'security_type') and "WEP" in getattr(n, 'security_type', '')]
            if wep_networks:
                wep_ssids = [getattr(n, 'ssid', 'Unknown') for n in wep_networks]
                wep_rec = Paragraph(
                    f"• <b>Replace WEP Encryption:</b> The following networks are using obsolete WEP encryption and should be reconfigured to use WPA2/WPA3 immediately: {', '.join(wep_ssids)}",
                    self.styles['Normal']
                )
                story.append(wep_rec)
            
            # Check for open networks
            open_networks = [n for n in networks if not getattr(n, 'security', True)]
            if open_networks:
                open_ssids = [getattr(n, 'ssid', 'Unknown') for n in open_networks]
                open_rec = Paragraph(
                    f"• <b>Secure Open Networks:</b> The following networks are operating without encryption and should be secured immediately: {', '.join(open_ssids)}",
                    self.styles['Normal']
                )
                story.append(open_rec)
            
            # Check for WPS enabled
            wps_networks = [n for n in networks if hasattr(n, 'wps_status') and getattr(n, 'wps_status', '') == "Enabled"]
            if wps_networks:
                wps_ssids = [getattr(n, 'ssid', 'Unknown') for n in wps_networks]
                wps_rec = Paragraph(
                    f"• <b>Disable WPS:</b> The following networks have WPS enabled, which may be vulnerable to attacks: {', '.join(wps_ssids)}",
                    self.styles['Normal']
                )
                story.append(wps_rec)
        
        story.append(Spacer(1, 0.25*inch))