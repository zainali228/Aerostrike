#!/usr/bin/env python3
"""
Additional functions for the Simple Report generator
Handles post-exploitation and network traffic data in reports
"""

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

def add_post_exploitation_findings(self, story, post_exploitation_data):
    """Add post-exploitation findings to the report
    
    Args:
        story: ReportLab story list
        post_exploitation_data: Dictionary with post-exploitation results
    """
    # Post-Exploitation Findings header
    findings_title = Paragraph("4. Post-Exploitation Findings", self.styles['Heading1'])
    story.append(findings_title)
    
    if not post_exploitation_data or not any([
        post_exploitation_data.get("hosts", []),
        post_exploitation_data.get("services", []),
        post_exploitation_data.get("vulnerabilities", [])
    ]):
        story.append(Paragraph("No post-exploitation data was collected during this assessment.", 
                             self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        return
    
    # Introduction text for real data only
    story.append(Paragraph(
        "After successfully gaining access to the network, the post-exploitation phase "
        "discovered the following genuine hosts, services, and vulnerabilities.",
        self.styles['Normal_Justify']
    ))
    story.append(Spacer(1, 0.15*inch))
    
    # Host Discovery Section
    story.append(Paragraph("4.1 Host Discovery", self.styles['Heading2']))
    
    hosts = post_exploitation_data.get("hosts", [])
    if hosts:
        # Create data for hosts table
        host_data = [["IP Address", "MAC Address", "Hostname", "Vendor"]]
        
        for host in hosts:
            if isinstance(host, dict):
                # Get host data with limited length to prevent overflow
                ip = host.get("ip", "Unknown")
                ip = str(ip).replace("\n", " ").replace("\r", " ")
                if len(ip) > 15: ip = ip[:13] + "..."
                
                mac = host.get("mac", "Unknown")
                mac = str(mac).replace("\n", " ").replace("\r", " ")
                if len(mac) > 17: mac = mac[:15] + "..."
                
                hostname = host.get("hostname", "Unknown")
                hostname = str(hostname).replace("\n", " ").replace("\r", " ")
                if len(hostname) > 20: hostname = hostname[:18] + "..."
                
                vendor = host.get("vendor", "Unknown")
                vendor = str(vendor).replace("\n", " ").replace("\r", " ")
                if len(vendor) > 20: vendor = vendor[:18] + "..."
                
                host_data.append([ip, mac, hostname, vendor])
        
        # Create and style the table
        host_table = Table(host_data, colWidths=[1.2*inch, 1.5*inch, 1.5*inch, 2.0*inch])
        host_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(host_table)
    else:
        story.append(Paragraph("No hosts were discovered during post-exploitation phase.", 
                             self.styles['Normal']))
    
    story.append(Spacer(1, 0.2*inch))
    
    # Service Detection Section
    story.append(Paragraph("4.2 Service Detection", self.styles['Heading2']))
    
    services = post_exploitation_data.get("services", [])
    if services:
        # Create data for services table
        service_data = [["Host", "Port", "Service", "Version", "Risk"]]
        
        for service in services:
            if isinstance(service, dict):
                # Get service data with limited length to prevent overflow
                host = service.get("host", "Unknown")
                if len(host) > 15: host = host[:13] + "..."
                
                port = service.get("port", "Unknown")
                
                service_name = service.get("service", "Unknown")
                if len(service_name) > 15: service_name = service_name[:13] + "..."
                
                version = service.get("version", "Unknown")
                if len(version) > 15: version = version[:13] + "..."
                
                risk = service.get("risk", "Medium")
                
                service_data.append([host, port, service_name, version, risk])
        
        # Create and style the table
        service_table = Table(service_data, colWidths=[1.1*inch, 0.7*inch, 1.2*inch, 1.7*inch, 0.8*inch])
        service_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(service_table)
    else:
        story.append(Paragraph("No services were detected during post-exploitation phase.", 
                             self.styles['Normal']))
    
    story.append(Spacer(1, 0.2*inch))
    
    # Vulnerabilities Section
    story.append(Paragraph("4.3 Vulnerabilities", self.styles['Heading2']))
    
    vulnerabilities = post_exploitation_data.get("vulnerabilities", [])
    if vulnerabilities:
        # Create data for vulnerabilities table
        vuln_data = [["Host", "Service", "Severity", "Description", "CVE"]]
        
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                # Get vulnerability data with limited length to prevent overflow
                host = vuln.get("host", "Unknown")
                if len(host) > 15: host = host[:13] + "..."
                
                service = vuln.get("service", "Unknown")
                if len(service) > 12: service = service[:10] + "..."
                
                severity = vuln.get("severity", "Medium")
                
                description = vuln.get("description", "Unknown")
                if len(description) > 30: description = description[:27] + "..."
                
                cve = vuln.get("cve", "N/A")
                if len(cve) > 15: cve = cve[:13] + "..."
                
                vuln_data.append([host, service, severity, description, cve])
        
        # Create and style the table
        vuln_table = Table(vuln_data, colWidths=[0.9*inch, 1.0*inch, 0.8*inch, 2.3*inch, 1.0*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (3, 1), (3, -1), 'LEFT')  # Left align description text
        ]))
        story.append(vuln_table)
    else:
        story.append(Paragraph("No vulnerabilities were detected during post-exploitation phase.", 
                             self.styles['Normal']))
    
    story.append(Spacer(1, 0.3*inch))

def add_network_traffic_findings(self, story, network_traffic):
    """Add network traffic analysis findings to the report
    
    Args:
        story: ReportLab story list
        network_traffic: Dictionary with network traffic data
    """
    # Network Traffic Analysis header
    traffic_title = Paragraph("5. Network Traffic Analysis", self.styles['Heading1'])
    story.append(traffic_title)
    
    if not network_traffic or not any([
        network_traffic.get("packets", []),
        network_traffic.get("sensitive_data", []),
        network_traffic.get("alerts", [])
    ]):
        story.append(Paragraph("No network traffic data was collected during this assessment.", 
                             self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        return
    
    # Introduction text for real data only
    story.append(Paragraph(
        "Real-time network traffic was monitored and analyzed to identify potential security "
        "concerns, sensitive data transmissions, and abnormal traffic patterns.",
        self.styles['Normal_Justify']
    ))
    story.append(Spacer(1, 0.15*inch))
    
    # Traffic Statistics Section
    story.append(Paragraph("5.1 Traffic Statistics", self.styles['Heading2']))
    
    packets = network_traffic.get('packets', [])
    packet_count = len(packets)
    
    # Count protocol distribution
    protocols = {}
    for packet in packets:
        if isinstance(packet, dict):
            protocol = packet.get('protocol', 'Unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
    
    # Create protocol statistics text
    protocols_text = "Protocol Distribution: "
    for protocol, count in protocols.items():
        percentage = 0
        if packet_count > 0:
            percentage = (count / packet_count) * 100
        protocols_text += f"{protocol}: {count} ({percentage:.1f}%), "
    
    # Remove trailing comma
    if protocols_text.endswith(", "):
        protocols_text = protocols_text[:-2]
    
    # Add statistics to report
    story.append(Paragraph(f"Total Packets Captured: {packet_count}", self.styles['Normal']))
    story.append(Paragraph(protocols_text, self.styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Sensitive Data Section
    story.append(Paragraph("5.2 Sensitive Data Detected", self.styles['Heading2']))
    
    sensitive_data = network_traffic.get('sensitive_data', [])
    if sensitive_data:
        # Create data for sensitive data table
        sensitive_data_table = [["Type", "Source", "Destination", "Protocol", "Details"]]
        
        for data in sensitive_data:
            if isinstance(data, dict):
                # Get sensitive data with limited length to prevent overflow
                data_type = data.get("type", "Unknown")
                if len(data_type) > 15: data_type = data_type[:13] + "..."
                
                source = data.get("source", "Unknown")
                if len(source) > 15: source = source[:13] + "..."
                
                destination = data.get("destination", "Unknown")
                if len(destination) > 15: destination = destination[:13] + "..."
                
                protocol = data.get("protocol", "Unknown")
                if len(protocol) > 10: protocol = protocol[:8] + "..."
                
                details = data.get("details", "Unknown")
                if len(details) > 30: details = details[:27] + "..."
                
                sensitive_data_table.append([data_type, source, destination, protocol, details])
        
        # Create and style the table
        table = Table(sensitive_data_table, colWidths=[1.0*inch, 1.1*inch, 1.1*inch, 0.8*inch, 2.0*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (4, 1), (4, -1), 'LEFT')  # Left align details text
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No sensitive data was detected in the network traffic.", 
                             self.styles['Normal']))
    
    story.append(Spacer(1, 0.2*inch))
    
    # Network Alerts Section
    story.append(Paragraph("5.3 Traffic Alerts", self.styles['Heading2']))
    
    alerts = network_traffic.get('alerts', [])
    if alerts:
        # Create data for alerts table
        alerts_table = [["Severity", "Source", "Destination", "Description", "Time"]]
        
        for alert in alerts:
            if isinstance(alert, dict):
                # Get alert data with limited length to prevent overflow
                severity = alert.get("severity", "Medium")
                if len(severity) > 10: severity = severity[:8] + "..."
                
                source = alert.get("source", "Unknown")
                if len(source) > 15: source = source[:13] + "..."
                
                destination = alert.get("destination", "Unknown")
                if len(destination) > 15: destination = destination[:13] + "..."
                
                description = alert.get("description", "Unknown")
                if len(description) > 30: description = description[:27] + "..."
                
                timestamp = alert.get("timestamp", "Unknown")
                if len(timestamp) > 15: timestamp = timestamp[:13] + "..."
                
                alerts_table.append([severity, source, destination, description, timestamp])
        
        # Create and style the table
        table = Table(alerts_table, colWidths=[0.8*inch, 1.1*inch, 1.1*inch, 2.4*inch, 0.9*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (3, 1), (3, -1), 'LEFT')  # Left align description text
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No security alerts were generated from the network traffic.", 
                             self.styles['Normal']))
    
    story.append(Spacer(1, 0.3*inch))