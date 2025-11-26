#!/usr/bin/env python3
"""
Comprehensive Advanced Report Generator
Integrates data from all security modules and generates detailed reports with visualizations
"""

import os
import time
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
import matplotlib
matplotlib.use('Agg')  # Use Agg backend to avoid display issues
import matplotlib.pyplot as plt
import numpy as np
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    Image, PageBreak, Flowable, ListFlowable, ListItem
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics.charts.textlabels import Label


class SecurityRiskScore:
    """Calculate and visualize security risk scores"""
    
    RISK_LEVELS = {
        "Critical": (9.0, 10.0, colors.red),
        "High": (7.0, 8.9, colors.orangered),
        "Medium": (4.0, 6.9, colors.orange),
        "Low": (1.0, 3.9, colors.green),
        "Info": (0.0, 0.9, colors.blue)
    }
    
    def __init__(self):
        self.risk_categories = {
            "network_exposure": 0.0,  # Open ports, services
            "authentication": 0.0,    # Password strength, auth mechanisms
            "encryption": 0.0,        # Encryption protocols, ciphers
            "vulnerabilities": 0.0,   # Known CVEs found
            "sensitive_data": 0.0,    # Exposed sensitive information
            "configuration": 0.0,     # Security misconfigurations
            "updates": 0.0,           # Missing patches, updates
            "defense_mechanisms": 0.0 # Firewalls, IDS, etc.
        }
        self.category_weights = {
            "network_exposure": 0.15,
            "authentication": 0.20,
            "encryption": 0.15,
            "vulnerabilities": 0.20,
            "sensitive_data": 0.10,
            "configuration": 0.10,
            "updates": 0.05,
            "defense_mechanisms": 0.05
        }
        self.findings = []
    
    def add_finding(self, category: str, description: str, score: float, evidence: str = None):
        """Add a security finding to the risk assessment
        
        Args:
            category: Risk category (must be one of the predefined categories)
            description: Description of the finding
            score: Risk score for this finding (0-10)
            evidence: Evidence supporting this finding (optional)
        """
        if category not in self.risk_categories:
            raise ValueError(f"Unknown category: {category}")
        
        if score < 0 or score > 10:
            raise ValueError("Score must be between 0 and 10")
        
        # Update the category score (take the highest score)
        self.risk_categories[category] = max(self.risk_categories[category], score)
        
        # Add to findings list
        self.findings.append({
            "category": category,
            "description": description,
            "score": score,
            "evidence": evidence,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    def calculate_overall_score(self) -> float:
        """Calculate overall weighted risk score
        
        Returns:
            float: Overall weighted risk score (0-10)
        """
        overall_score = 0.0
        
        for category, score in self.risk_categories.items():
            weight = self.category_weights[category]
            overall_score += score * weight
        
        return round(overall_score, 1)
    
    def get_risk_level(self, score: float = None) -> str:
        """Get the risk level label based on score
        
        Args:
            score: Score to get level for, or None to use overall score
            
        Returns:
            str: Risk level label ("Critical", "High", "Medium", "Low", "Info")
        """
        if score is None:
            score = self.calculate_overall_score()
        
        for level, (min_score, max_score, _) in self.RISK_LEVELS.items():
            if min_score <= score <= max_score:
                return level
        
        return "Unknown"
    
    def get_risk_color(self, level: str = None) -> colors.Color:
        """Get the color associated with a risk level
        
        Args:
            level: Risk level, or None to use calculated level
            
        Returns:
            colors.Color: Color for the risk level
        """
        if level is None:
            level = self.get_risk_level()
        
        for risk_level, (_, _, color) in self.RISK_LEVELS.items():
            if risk_level == level:
                return color
        
        return colors.black
    
    def generate_score_summary(self) -> Dict:
        """Generate a summary of the risk scores
        
        Returns:
            Dict: Risk score summary data
        """
        overall_score = self.calculate_overall_score()
        risk_level = self.get_risk_level(overall_score)
        category_scores = {}
        
        for category, score in self.risk_categories.items():
            if score > 0:  # Only include categories that have findings
                category_scores[category] = {
                    "score": score,
                    "level": self.get_risk_level(score),
                    "weight": self.category_weights[category]
                }
        
        return {
            "overall_score": overall_score,
            "risk_level": risk_level,
            "category_scores": category_scores,
            "findings_count": len(self.findings)
        }
    
    def create_risk_chart(self, output_path: str = None) -> str:
        """Create a risk radar chart visualization
        
        Args:
            output_path: Path to save the chart image, or None to create in temp dir
            
        Returns:
            str: Path to the saved chart image
        """
        # Create radar chart
        categories = []
        scores = []
        
        for category, score in self.risk_categories.items():
            if score > 0:  # Only include categories that have findings
                categories.append(category.replace('_', ' ').title())
                scores.append(score)
        
        if not categories:  # No data
            categories = ["No Data"]
            scores = [0]
        
        # Create the radar chart
        fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
        
        # Set max score to 10
        max_score = 10
        
        # Number of categories
        N = len(categories)
        
        # Compute angle for each category
        angles = [n / float(N) * 2 * np.pi for n in range(N)]
        angles += angles[:1]  # Close the loop
        
        # Add scores to the chart (repeat the first value to close the polygon)
        values = scores + [scores[0]]
        
        # Draw the risk polygon
        ax.plot(angles, values, linewidth=2, linestyle='solid', color='red')
        ax.fill(angles, values, color='red', alpha=0.4)
        
        # Set category labels
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, size=10)
        
        # Set radial ticks and grid
        ax.set_yticks(range(0, max_score + 1, 2))
        ax.set_rlabel_position(0)
        
        # Set chart title
        plt.title("Security Risk Assessment", size=15, color='black', y=1.1)
        
        # Determine output path
        if output_path is None:
            output_dir = os.path.join("reports", "images")
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"risk_radar_{int(time.time())}.png")
        
        # Save the figure
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def create_category_bar_chart(self, output_path: str = None) -> str:
        """Create a bar chart of category risk scores
        
        Args:
            output_path: Path to save the chart image, or None to create in temp dir
            
        Returns:
            str: Path to the saved chart image
        """
        # Extract categories and scores, sort by score
        items = sorted(self.risk_categories.items(), key=lambda x: x[1], reverse=True)
        categories = [item[0].replace('_', ' ').title() for item in items if item[1] > 0]
        scores = [item[1] for item in items if item[1] > 0]
        
        if not categories:  # No data
            categories = ["No Data"]
            scores = [0]
        
        # Create the bar chart
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Generate bars with color mapping according to risk level
        bars = ax.bar(categories, scores, width=0.6)
        
        # Color each bar based on its risk level
        for bar, score in zip(bars, scores):
            level = self.get_risk_level(score)
            color = self.RISK_LEVELS[level][2].hexrgb() if hasattr(self.RISK_LEVELS[level][2], 'hexrgb') else 'gray'
            bar.set_color(color)
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax.annotate(
                f'{height:.1f}',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),  # 3 points vertical offset
                textcoords="offset points",
                ha='center', va='bottom',
                fontsize=10
            )
        
        # Set labels and title
        ax.set_xlabel('Security Categories')
        ax.set_ylabel('Risk Score (0-10)')
        ax.set_title('Security Risk Scores by Category')
        
        # Set y-axis limit
        ax.set_ylim(0, 10.5)
        
        # Rotate x-axis labels for better readability
        plt.xticks(rotation=45, ha='right')
        
        # Add a horizontal line for average score
        if scores and sum(scores) > 0:
            avg_score = self.calculate_overall_score()
            ax.axhline(y=avg_score, color='r', linestyle='--', alpha=0.7)
            ax.annotate(
                f'Overall: {avg_score:.1f}',
                xy=(0, avg_score),
                xytext=(5, 0),
                textcoords="offset points",
                va='center',
                fontsize=10,
                color='darkred'
            )
        
        # Determine output path
        if output_path is None:
            output_dir = os.path.join("reports", "images")
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"risk_bars_{int(time.time())}.png")
        
        # Save the figure
        plt.tight_layout()
        plt.savefig(output_path, dpi=300)
        plt.close()
        
        return output_path


class ComprehensiveReport:
    """Generate comprehensive security reports with data from all modules"""
    
    def __init__(self):
        self.risk_calculator = SecurityRiskScore()
        self.report_sections = []
        self.charts = []
        self.metadata = {
            "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "company_name": "Client Organization",
            "report_title": "Comprehensive Security Assessment Report",
            "logo_path": None
        }
        self.data = {
            "network_scan": {},
            "attacks": [],
            "traffic_analysis": {},
            "post_exploitation": {},
            "vulnerabilities": [],
            "recommendations": []
        }
    
    def set_metadata(self, **kwargs):
        """Set report metadata
        
        Args:
            **kwargs: Metadata fields to set (company_name, report_title, logo_path)
        """
        for key, value in kwargs.items():
            if key in self.metadata and value:
                self.metadata[key] = value
    
    def add_network_scan_data(self, scan_data: Dict):
        """Add network scan results
        
        Args:
            scan_data: Dictionary containing network scan results
        """
        self.data["network_scan"] = scan_data
        
        # Process data for risk assessment
        if scan_data.get("access_points"):
            # Analyze WiFi security
            for ap in scan_data.get("access_points", []):
                if ap.get("encryption") == "Open" or ap.get("encryption") == "None":
                    self.risk_calculator.add_finding(
                        "encryption", 
                        f"Open WiFi network detected: {ap.get('ssid', 'Unknown')}",
                        9.5,
                        f"BSSID: {ap.get('bssid', 'Unknown')}"
                    )
                elif ap.get("encryption") == "WEP":
                    self.risk_calculator.add_finding(
                        "encryption", 
                        f"Insecure WEP encryption detected: {ap.get('ssid', 'Unknown')}",
                        8.5,
                        f"BSSID: {ap.get('bssid', 'Unknown')}"
                    )
                elif ap.get("encryption") == "WPA":
                    self.risk_calculator.add_finding(
                        "encryption", 
                        f"Outdated WPA encryption detected: {ap.get('ssid', 'Unknown')}",
                        6.5,
                        f"BSSID: {ap.get('bssid', 'Unknown')}"
                    )
                
                # Check for WPS
                if ap.get("wps_enabled"):
                    self.risk_calculator.add_finding(
                        "authentication", 
                        f"WPS enabled on access point: {ap.get('ssid', 'Unknown')}",
                        7.8,
                        f"BSSID: {ap.get('bssid', 'Unknown')}"
                    )
        
        if scan_data.get("hosts"):
            # Analyze host security
            for host in scan_data.get("hosts", []):
                # Check open ports
                open_ports = host.get("open_ports", [])
                if open_ports:
                    critical_ports = [p for p in open_ports if p.get("port") in [21, 22, 23, 3389, 445, 139, 135]]
                    high_risk_ports = [p for p in open_ports if p.get("port") in [80, 443, 8080, 8443, 1433, 3306, 5432]]
                    
                    if critical_ports:
                        self.risk_calculator.add_finding(
                            "network_exposure", 
                            f"Critical ports open on {host.get('ip', 'Unknown')}: {', '.join([str(p.get('port')) for p in critical_ports])}",
                            8.0,
                            f"Host: {host.get('hostname', host.get('ip', 'Unknown'))}"
                        )
                    elif high_risk_ports:
                        self.risk_calculator.add_finding(
                            "network_exposure", 
                            f"High-risk ports open on {host.get('ip', 'Unknown')}: {', '.join([str(p.get('port')) for p in high_risk_ports])}",
                            6.0,
                            f"Host: {host.get('hostname', host.get('ip', 'Unknown'))}"
                        )
    
    def add_attack_data(self, attack_data: Dict):
        """Add attack results
        
        Args:
            attack_data: Dictionary containing attack results
        """
        self.data["attacks"].append(attack_data)
        
        # Process data for risk assessment
        if attack_data.get("type") == "wpa_handshake":
            if attack_data.get("success", False):
                self.risk_calculator.add_finding(
                    "authentication", 
                    f"WPA password cracked for {attack_data.get('ssid', 'Unknown')}",
                    9.0,
                    f"Password found: {attack_data.get('password', 'Unknown')} | Time: {attack_data.get('time_taken', 'Unknown')}"
                )
        
        if attack_data.get("type") == "deauth":
            if attack_data.get("success", False):
                self.risk_calculator.add_finding(
                    "defense_mechanisms", 
                    f"Successful deauthentication attack against {attack_data.get('ssid', 'Unknown')}",
                    6.5,
                    f"Affected clients: {attack_data.get('affected_clients', 0)}"
                )
        
        if attack_data.get("type") == "wps_pin":
            if attack_data.get("success", False):
                self.risk_calculator.add_finding(
                    "authentication", 
                    f"WPS PIN cracked for {attack_data.get('ssid', 'Unknown')}",
                    8.5,
                    f"PIN found: {attack_data.get('pin', 'Unknown')} | Time: {attack_data.get('time_taken', 'Unknown')}"
                )
    
    def add_traffic_analysis_data(self, traffic_data: Dict):
        """Add traffic analysis results
        
        Args:
            traffic_data: Dictionary containing traffic analysis results
        """
        self.data["traffic_analysis"] = traffic_data
        
        # Process data for risk assessment
        if traffic_data.get("sensitive_data_found", []):
            for item in traffic_data.get("sensitive_data_found", []):
                self.risk_calculator.add_finding(
                    "sensitive_data", 
                    f"Sensitive data exposed: {item.get('type', 'Unknown')}",
                    8.8,
                    f"Source: {item.get('source', 'Unknown')} | Protocol: {item.get('protocol', 'Unknown')}"
                )
        
        if traffic_data.get("unencrypted_protocols", []):
            self.risk_calculator.add_finding(
                "encryption", 
                f"Unencrypted protocols in use: {', '.join(traffic_data.get('unencrypted_protocols', []))}",
                7.0,
                f"Count: {len(traffic_data.get('unencrypted_protocols', []))}"
            )
    
    def add_post_exploitation_data(self, post_data: Dict):
        """Add post-exploitation results
        
        Args:
            post_data: Dictionary containing post-exploitation results
        """
        self.data["post_exploitation"] = post_data
        
        # Process data for risk assessment
        if post_data.get("hosts", []):
            for host in post_data.get("hosts", []):
                if host.get("vulnerabilities", []):
                    for vuln in host.get("vulnerabilities", []):
                        severity = vuln.get("severity", "").lower()
                        score = 0.0
                        
                        if severity == "critical":
                            score = 9.5
                        elif severity == "high":
                            score = 8.0
                        elif severity == "medium":
                            score = 5.5
                        elif severity == "low":
                            score = 3.0
                        
                        if score > 0:
                            self.risk_calculator.add_finding(
                                "vulnerabilities", 
                                f"{vuln.get('name', 'Unknown vulnerability')} on {host.get('ip', 'Unknown')}",
                                score,
                                f"CVE: {vuln.get('cve', 'Unknown')} | Details: {vuln.get('description', 'No details')}"
                            )
                
                if host.get("default_credentials", False):
                    self.risk_calculator.add_finding(
                        "authentication", 
                        f"Default credentials on {host.get('ip', 'Unknown')}",
                        8.5,
                        f"Service: {host.get('service', 'Unknown')}"
                    )
    
    def add_vulnerability(self, vuln_data: Dict):
        """Add a vulnerability finding
        
        Args:
            vuln_data: Dictionary containing vulnerability details
        """
        self.data["vulnerabilities"].append(vuln_data)
        
        # Process data for risk assessment if not already done in other methods
        if not any(v.get("name") == vuln_data.get("name") for v in self.data.get("post_exploitation", {}).get("hosts", [])):
            severity = vuln_data.get("severity", "").lower()
            score = 0.0
            
            if severity == "critical":
                score = 9.5
            elif severity == "high":
                score = 8.0
            elif severity == "medium":
                score = 5.5
            elif severity == "low":
                score = 3.0
            
            if score > 0:
                self.risk_calculator.add_finding(
                    "vulnerabilities", 
                    f"{vuln_data.get('name', 'Unknown vulnerability')}",
                    score,
                    f"CVE: {vuln_data.get('cve', 'Unknown')} | Details: {vuln_data.get('description', 'No details')}"
                )
    
    def add_recommendation(self, recommendation: Dict):
        """Add a security recommendation
        
        Args:
            recommendation: Dictionary containing recommendation details
        """
        self.data["recommendations"].append(recommendation)
    
    def generate_recommendations(self, ai_assistant=None):
        """Generate security recommendations based on findings
        
        Args:
            ai_assistant: AI assistant instance for enhanced recommendations
        """
        # Generate standard recommendations based on findings
        high_risk_findings = []
        
        for finding in self.risk_calculator.findings:
            if finding["score"] >= 7.0:
                high_risk_findings.append(finding)
        
        # Generate basic recommendations
        basic_recommendations = []
        
        # WPA/WiFi recommendations
        if any(f["category"] == "encryption" and "WEP" in f["description"] for f in high_risk_findings):
            basic_recommendations.append({
                "title": "Replace WEP Encryption",
                "description": "Replace WEP with WPA2 or WPA3 encryption on all access points.",
                "priority": "Critical",
                "implementation": "Configure all access points to use WPA2-PSK with AES/CCMP or WPA3 encryption.",
                "references": ["https://www.wi-fi.org/discover-wi-fi/security"]
            })
        
        if any(f["category"] == "authentication" and "WPS" in f["description"] for f in high_risk_findings):
            basic_recommendations.append({
                "title": "Disable WPS on Access Points",
                "description": "Disable WPS on all access points as it contains vulnerabilities that can be exploited.",
                "priority": "High",
                "implementation": "Access the router administration interface and disable the WPS feature in wireless settings.",
                "references": ["https://www.kb.cert.org/vuls/id/723755"]
            })
        
        if any(f["category"] == "authentication" and "WPA password cracked" in f["description"] for f in high_risk_findings):
            basic_recommendations.append({
                "title": "Strengthen WiFi Passwords",
                "description": "Use strong, complex passwords for WiFi networks (minimum 12 characters with mixed case, numbers, and symbols).",
                "priority": "Critical",
                "implementation": "Change WiFi passwords immediately and implement a password policy that requires complex passwords.",
                "references": ["https://www.ncsc.gov.uk/collection/passwords"]
            })
        
        # Network exposure recommendations
        if any(f["category"] == "network_exposure" and "Critical ports open" in f["description"] for f in high_risk_findings):
            basic_recommendations.append({
                "title": "Secure Critical Network Services",
                "description": "Close or properly secure critical ports (21, 22, 23, 3389, 445, 139, 135) that are exposed.",
                "priority": "Critical",
                "implementation": "Implement a firewall, use VPN for remote access, disable unnecessary services, and use secure configurations for required services.",
                "references": ["https://www.cisa.gov/sites/default/files/publications/Securing_Network_Infrastructure_Devices_508_0.pdf"]
            })
        
        # Sensitive data recommendations
        if any(f["category"] == "sensitive_data" for f in high_risk_findings):
            basic_recommendations.append({
                "title": "Encrypt Sensitive Data Transmission",
                "description": "Ensure all sensitive data is encrypted during transmission using secure protocols (HTTPS, SSH, etc.).",
                "priority": "High",
                "implementation": "Implement TLS/SSL for all web services, use encrypted protocols, and avoid plain-text data transmission.",
                "references": ["https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data"]
            })
        
        # Add basic recommendations
        for rec in basic_recommendations:
            if rec not in self.data["recommendations"]:
                self.data["recommendations"].append(rec)
        
        # Use AI for enhanced recommendations if available
        if ai_assistant and hasattr(ai_assistant, 'generate_security_recommendations'):
            # Convert findings to format suitable for AI
            findings_for_ai = []
            for finding in self.risk_calculator.findings:
                findings_for_ai.append({
                    "category": finding["category"],
                    "description": finding["description"],
                    "score": finding["score"],
                    "evidence": finding["evidence"]
                })
            
            try:
                ai_recommendations = ai_assistant.generate_security_recommendations(findings_for_ai)
                
                # Add AI recommendations
                for rec in ai_recommendations:
                    if rec not in self.data["recommendations"]:
                        self.data["recommendations"].append(rec)
            except Exception as e:
                print(f"Error generating AI recommendations: {str(e)}")
        else:
            # Add additional standard recommendations when AI is not available
            additional_standard_recommendations = [
                {
                    "title": "Implement Network Segmentation",
                    "description": "Separate critical network assets from general-purpose networks to limit the impact of potential breaches.",
                    "priority": "High",
                    "implementation": "Use VLANs, firewalls, and access control lists to create network segments based on security requirements and functional roles.",
                    "references": ["https://www.nist.gov/publications/guide-industrial-control-systems-ics-security"]
                },
                {
                    "title": "Deploy Intrusion Detection Systems",
                    "description": "Monitor network traffic for suspicious activities and potential intrusion attempts.",
                    "priority": "Medium",
                    "implementation": "Install and configure network-based IDS/IPS solutions on critical network segments to detect and alert on suspicious activities.",
                    "references": ["https://csrc.nist.gov/publications/detail/sp/800-94/rev-1/draft"]
                },
                {
                    "title": "Implement Regular Security Audits",
                    "description": "Conduct periodic security assessments to identify and address vulnerabilities.",
                    "priority": "Medium",
                    "implementation": "Schedule quarterly internal security audits and annual external penetration testing to evaluate security posture.",
                    "references": ["https://www.sans.org/reading-room/whitepapers/auditing/"]
                },
                {
                    "title": "Deploy Multi-Factor Authentication",
                    "description": "Strengthen access controls by requiring multiple verification methods.",
                    "priority": "High",
                    "implementation": "Implement MFA for all administrative access, remote connections, and critical systems access.",
                    "references": ["https://pages.nist.gov/800-63-3/sp800-63b.html"]
                },
                {
                    "title": "Develop an Incident Response Plan",
                    "description": "Create a formal procedure for handling security incidents effectively.",
                    "priority": "High", 
                    "implementation": "Document incident response procedures, roles, and communication channels for different types of security incidents.",
                    "references": ["https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf"]
                }
            ]
            
            # Add additional recommendations
            for rec in additional_standard_recommendations:
                if rec not in self.data["recommendations"]:
                    self.data["recommendations"].append(rec)
    
    def generate_charts(self):
        """Generate charts for the report"""
        # Risk radar chart
        try:
            radar_chart_path = self.risk_calculator.create_risk_chart()
            self.charts.append({
                "type": "risk_radar",
                "path": radar_chart_path,
                "description": "Security Risk Assessment Radar Chart"
            })
        except Exception as e:
            print(f"Error generating risk radar chart: {str(e)}")
        
        # Category bar chart
        try:
            bar_chart_path = self.risk_calculator.create_category_bar_chart()
            self.charts.append({
                "type": "category_bars",
                "path": bar_chart_path,
                "description": "Security Risk Scores by Category"
            })
        except Exception as e:
            print(f"Error generating category bar chart: {str(e)}")
        
        # Network scan distribution
        try:
            if self.data["network_scan"].get("access_points"):
                # Create pie chart of encryption types
                encryption_types = {}
                for ap in self.data["network_scan"]["access_points"]:
                    enc_type = ap.get("encryption", "Unknown")
                    encryption_types[enc_type] = encryption_types.get(enc_type, 0) + 1
                
                if encryption_types:
                    fig, ax = plt.subplots(figsize=(8, 6))
                    labels = list(encryption_types.keys())
                    sizes = list(encryption_types.values())
                    
                    # Define colors for encryption types
                    colors_map = {
                        "WPA3": "green",
                        "WPA2": "lightgreen",
                        "WPA": "orange",
                        "WEP": "red",
                        "Open": "darkred",
                        "None": "darkred",
                        "Unknown": "gray"
                    }
                    
                    colors = [colors_map.get(label, "gray") for label in labels]
                    
                    # Create the pie chart
                    ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
                    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
                    
                    # Add title
                    plt.title("WiFi Encryption Distribution")
                    
                    # Save the chart
                    output_dir = os.path.join("reports", "images")
                    os.makedirs(output_dir, exist_ok=True)
                    output_path = os.path.join(output_dir, f"encryption_pie_{int(time.time())}.png")
                    plt.savefig(output_path, dpi=300, bbox_inches='tight')
                    plt.close()
                    
                    self.charts.append({
                        "type": "encryption_pie",
                        "path": output_path,
                        "description": "WiFi Encryption Distribution"
                    })
        except Exception as e:
            print(f"Error generating network scan charts: {str(e)}")
        
        # Traffic analysis charts
        try:
            if self.data["traffic_analysis"].get("protocol_stats"):
                # Create pie chart of protocol distribution
                fig, ax = plt.subplots(figsize=(8, 6))
                labels = list(self.data["traffic_analysis"]["protocol_stats"].keys())
                sizes = list(self.data["traffic_analysis"]["protocol_stats"].values())
                
                # Create the pie chart
                ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
                ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
                
                # Add title
                plt.title("Protocol Distribution")
                
                # Save the chart
                output_dir = os.path.join("reports", "images")
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, f"protocol_pie_{int(time.time())}.png")
                plt.savefig(output_path, dpi=300, bbox_inches='tight')
                plt.close()
                
                self.charts.append({
                    "type": "protocol_pie",
                    "path": output_path,
                    "description": "Network Protocol Distribution"
                })
        except Exception as e:
            print(f"Error generating traffic analysis charts: {str(e)}")
    
    def generate_pdf_report(self, output_path: str) -> str:
        """Generate PDF report
        
        Args:
            output_path: Path to save the PDF report
            
        Returns:
            str: Path to the generated PDF
        """
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Generate charts if not already done
        if not self.charts:
            self.generate_charts()
        
        # Create the PDF
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        
        # Get styles
        styles = getSampleStyleSheet()
        
        # Create custom styles
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Title'],
            fontSize=18,
            spaceAfter=12,
            textColor=colors.purple,
        )
        
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=10,
            textColor=colors.purple,
        )
        
        heading1_style = ParagraphStyle(
            'Heading1',
            parent=styles['Heading1'],
            fontSize=14,
            spaceAfter=10,
            textColor=colors.blue,
        )
        
        heading2_style = ParagraphStyle(
            'Heading2',
            parent=styles['Heading2'],
            fontSize=12,
            spaceAfter=8,
            textColor=colors.navy,
        )
        
        normal_style = styles['Normal']
        
        # Elements to add to the document
        elements = []
        
        # Title page
        elements.append(Paragraph(self.metadata['report_title'], title_style))
        elements.append(Spacer(1, 0.25*inch))
        
        elements.append(Paragraph(f"Prepared for: {self.metadata['company_name']}", styles['Heading2']))
        elements.append(Spacer(1, 0.1*inch))
        
        elements.append(Paragraph(f"Date: {self.metadata['report_date']}", normal_style))
        elements.append(Spacer(1, 0.5*inch))
        
        # Add company logo if available
        if self.metadata.get('logo_path') and os.path.exists(self.metadata['logo_path']):
            img = Image(self.metadata['logo_path'], width=2*inch, height=1*inch)
            elements.append(img)
            elements.append(Spacer(1, 0.5*inch))
        
        # Add executive summary
        elements.append(Paragraph("Executive Summary", subtitle_style))
        
        # Calculate overall risk score and level
        overall_score = self.risk_calculator.calculate_overall_score()
        risk_level = self.risk_calculator.get_risk_level(overall_score)
        
        summary_text = f"""
        This security assessment was conducted to evaluate the security posture of the network infrastructure and wireless systems. 
        The assessment identified various security issues and vulnerabilities with an overall risk score of {overall_score:.1f} out of 10.0, 
        indicating a <b>{risk_level} Risk</b> level. This report provides detailed findings and recommendations to address the identified issues.
        """
        elements.append(Paragraph(summary_text, normal_style))
        elements.append(Spacer(1, 0.25*inch))
        
        # Key Findings Summary
        elements.append(Paragraph("Key Findings", heading2_style))
        
        # Get high-risk findings (score >= 7.0)
        high_risk_findings = [f for f in self.risk_calculator.findings if f["score"] >= 7.0]
        
        if high_risk_findings:
            findings_list = []
            for finding in high_risk_findings[:5]:  # Show top 5 high-risk findings in summary
                findings_list.append(f"• {finding['description']} (Risk Score: {finding['score']:.1f})")
            
            elements.append(Paragraph("<br/>".join(findings_list), normal_style))
        else:
            elements.append(Paragraph("No high-risk findings were identified.", normal_style))
        
        elements.append(Spacer(1, 0.25*inch))
        
        # Recommendations Summary
        elements.append(Paragraph("Key Recommendations", heading2_style))
        
        if self.data["recommendations"]:
            rec_list = []
            for rec in self.data["recommendations"][:5]:  # Show top 5 recommendations in summary
                rec_list.append(f"• {rec.get('title')}: {rec.get('description')}")
            
            elements.append(Paragraph("<br/>".join(rec_list), normal_style))
        else:
            elements.append(Paragraph("No recommendations are available.", normal_style))
        
        elements.append(PageBreak())
        
        # Table of Contents
        elements.append(Paragraph("Table of Contents", subtitle_style))
        elements.append(Spacer(1, 0.25*inch))
        
        toc_data = [
            ["1. Executive Summary", "2"],
            ["2. Risk Assessment", "3"],
            ["3. Network Scan Results", "5"],
            ["4. Attack Results", "7"],
            ["5. Traffic Analysis", "9"],
            ["6. Post-Exploitation Findings", "11"],
            ["7. Detailed Vulnerabilities", "13"],
            ["8. Recommendations", "15"],
            ["9. Appendices", "17"]
        ]
        
        toc_table = Table(toc_data, colWidths=[4.5*inch, 0.5*inch])
        toc_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('LINEBELOW', (0, 0), (-1, -2), 1, colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(toc_table)
        elements.append(PageBreak())
        
        # Risk Assessment Section
        elements.append(Paragraph("2. Risk Assessment", subtitle_style))
        elements.append(Spacer(1, 0.25*inch))
        
        # Overall Risk Score
        elements.append(Paragraph("Overall Security Risk", heading1_style))
        
        risk_text = f"""
        Based on the assessment, the overall security risk score is <b>{overall_score:.1f} out of 10.0</b>, 
        indicating a <b>{risk_level} Risk</b> level. This score is calculated based on weighted assessments 
        of various security categories including network exposure, authentication mechanisms, 
        encryption protocols, vulnerabilities, sensitive data protection, configuration security, 
        and defense mechanisms.
        """
        elements.append(Paragraph(risk_text, normal_style))
        elements.append(Spacer(1, 0.25*inch))
        
        # Add risk radar chart
        radar_chart = next((c for c in self.charts if c["type"] == "risk_radar"), None)
        if radar_chart and os.path.exists(radar_chart["path"]):
            img = Image(radar_chart["path"], width=4*inch, height=4*inch)
            elements.append(img)
            elements.append(Paragraph(radar_chart["description"], styles['Caption']))
            elements.append(Spacer(1, 0.25*inch))
        
        # Add category bar chart
        bar_chart = next((c for c in self.charts if c["type"] == "category_bars"), None)
        if bar_chart and os.path.exists(bar_chart["path"]):
            img = Image(bar_chart["path"], width=6*inch, height=3.5*inch)
            elements.append(img)
            elements.append(Paragraph(bar_chart["description"], styles['Caption']))
            elements.append(Spacer(1, 0.25*inch))
        
        # Risk categories explanation
        elements.append(Paragraph("Risk Categories Explanation", heading2_style))
        
        # Create a table for risk categories
        category_data = [
            ["Category", "Score", "Risk Level", "Description"],
        ]
        
        for category, score in self.risk_calculator.risk_categories.items():
            if score > 0:  # Only include categories with findings
                risk_level = self.risk_calculator.get_risk_level(score)
                category_name = category.replace('_', ' ').title()
                
                # Add category description
                description = ""
                if category == "network_exposure":
                    description = "Risks related to open ports, services, and network accessibility."
                elif category == "authentication":
                    description = "Risks related to authentication mechanisms, password strength, and access controls."
                elif category == "encryption":
                    description = "Risks related to encryption protocols, cipher strength, and data protection."
                elif category == "vulnerabilities":
                    description = "Known security vulnerabilities and CVEs in systems and applications."
                elif category == "sensitive_data":
                    description = "Exposure of sensitive information such as credentials, personal data, or API keys."
                elif category == "configuration":
                    description = "Security issues related to system and application configurations."
                elif category == "updates":
                    description = "Risks related to missing security patches and software updates."
                elif category == "defense_mechanisms":
                    description = "Effectiveness of security controls such as firewalls, IDS/IPS, and access controls."
                
                category_data.append([category_name, f"{score:.1f}", risk_level, description])
        
        if len(category_data) > 1:  # If we have data besides the header
            category_table = Table(category_data, colWidths=[1.2*inch, 0.8*inch, 1*inch, 3.5*inch])
            category_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ]))
            
            # Add color to risk levels
            for i in range(1, len(category_data)):
                risk_level = category_data[i][2]
                if risk_level == "Critical":
                    category_table.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.red)]))
                elif risk_level == "High":
                    category_table.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.orangered)]))
                elif risk_level == "Medium":
                    category_table.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.orange)]))
                elif risk_level == "Low":
                    category_table.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.green)]))
            
            elements.append(category_table)
            elements.append(Spacer(1, 0.25*inch))
        
        # High-Risk Findings
        elements.append(Paragraph("High-Risk Findings", heading2_style))
        
        if high_risk_findings:
            # Create a table for high-risk findings
            findings_data = [
                ["Finding", "Category", "Score", "Evidence"],
            ]
            
            for finding in high_risk_findings:
                category = finding["category"].replace('_', ' ').title()
                findings_data.append([
                    finding["description"], 
                    category, 
                    f"{finding['score']:.1f}", 
                    finding["evidence"] or "N/A"
                ])
            
            findings_table = Table(findings_data, colWidths=[2.5*inch, 1*inch, 0.6*inch, 2.4*inch])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('WORDWRAP', (0, 1), (-1, -1), True),
            ]))
            
            elements.append(findings_table)
        else:
            elements.append(Paragraph("No high-risk findings were identified.", normal_style))
        
        elements.append(PageBreak())
        
        # Network Scan Results Section
        elements.append(Paragraph("3. Network Scan Results", subtitle_style))
        elements.append(Spacer(1, 0.25*inch))
        
        if self.data["network_scan"]:
            # WiFi Networks Section
            if self.data["network_scan"].get("access_points"):
                elements.append(Paragraph("Discovered WiFi Networks", heading1_style))
                
                # Add encryption distribution chart if available
                encryption_chart = next((c for c in self.charts if c["type"] == "encryption_pie"), None)
                if encryption_chart and os.path.exists(encryption_chart["path"]):
                    img = Image(encryption_chart["path"], width=4*inch, height=4*inch)
                    elements.append(img)
                    elements.append(Paragraph(encryption_chart["description"], styles['Caption']))
                    elements.append(Spacer(1, 0.25*inch))
                
                # Create a table for WiFi networks
                ap_data = [
                    ["SSID", "BSSID", "Channel", "Signal", "Encryption", "WPS", "Clients"],
                ]
                
                for ap in self.data["network_scan"]["access_points"]:
                    ap_data.append([
                        ap.get("ssid", "Hidden"),
                        ap.get("bssid", "Unknown"),
                        str(ap.get("channel", "N/A")),
                        f"{ap.get('signal', 0)}%",
                        ap.get("encryption", "Unknown"),
                        "Yes" if ap.get("wps_enabled", False) else "No",
                        str(ap.get("clients", 0))
                    ])
                
                ap_table = Table(ap_data, colWidths=[1.2*inch, 1.4*inch, 0.7*inch, 0.7*inch, 1*inch, 0.5*inch, 0.7*inch])
                ap_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                    ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                    ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                    ('ALIGN', (2, 1), (6, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ]))
                
                # Color code encryption types
                for i in range(1, len(ap_data)):
                    encryption = ap_data[i][4]
                    if encryption == "WPA3":
                        ap_table.setStyle(TableStyle([('TEXTCOLOR', (4, i), (4, i), colors.green)]))
                    elif encryption == "WPA2":
                        ap_table.setStyle(TableStyle([('TEXTCOLOR', (4, i), (4, i), colors.darkgreen)]))
                    elif encryption == "WPA":
                        ap_table.setStyle(TableStyle([('TEXTCOLOR', (4, i), (4, i), colors.orange)]))
                    elif encryption in ["WEP", "Open", "None"]:
                        ap_table.setStyle(TableStyle([('TEXTCOLOR', (4, i), (4, i), colors.red)]))
                    
                    # Highlight WPS enabled
                    if ap_data[i][5] == "Yes":
                        ap_table.setStyle(TableStyle([('TEXTCOLOR', (5, i), (5, i), colors.red)]))
                
                elements.append(ap_table)
                elements.append(Spacer(1, 0.25*inch))
                
                # WiFi security analysis
                elements.append(Paragraph("WiFi Security Analysis", heading2_style))
                
                wifi_sec_text = f"""
                The scan discovered {len(self.data["network_scan"]["access_points"])} WiFi networks in range. 
                """
                
                # Count encryption types
                encryption_counts = {}
                wps_enabled_count = 0
                for ap in self.data["network_scan"]["access_points"]:
                    enc_type = ap.get("encryption", "Unknown")
                    encryption_counts[enc_type] = encryption_counts.get(enc_type, 0) + 1
                    if ap.get("wps_enabled", False):
                        wps_enabled_count += 1
                
                # Add encryption breakdown
                enc_breakdown = []
                for enc_type, count in encryption_counts.items():
                    enc_breakdown.append(f"{enc_type}: {count}")
                
                wifi_sec_text += f"Encryption distribution: {', '.join(enc_breakdown)}. "
                
                if wps_enabled_count > 0:
                    wifi_sec_text += f"{wps_enabled_count} networks have WPS enabled, which poses a security risk."
                
                elements.append(Paragraph(wifi_sec_text, normal_style))
            else:
                elements.append(Paragraph("No WiFi networks were discovered during the scan.", normal_style))
            
            # Discovered Hosts Section
            if self.data["network_scan"].get("hosts"):
                elements.append(Paragraph("Discovered Network Hosts", heading1_style))
                
                # Create a table for hosts
                host_data = [
                    ["IP Address", "Hostname", "MAC Address", "Vendor", "Open Ports", "OS"],
                ]
                
                for host in self.data["network_scan"]["hosts"]:
                    open_ports_str = ", ".join([f"{p.get('port')}/{p.get('service', 'unknown')}" 
                                              for p in host.get("open_ports", [])[:5]])
                    if len(host.get("open_ports", [])) > 5:
                        open_ports_str += f" (+{len(host.get('open_ports', [])) - 5} more)"
                    
                    host_data.append([
                        host.get("ip", "Unknown"),
                        host.get("hostname", "N/A"),
                        host.get("mac", "Unknown"),
                        host.get("vendor", "Unknown"),
                        open_ports_str or "None",
                        host.get("os", "Unknown")
                    ])
                
                host_table = Table(host_data, colWidths=[1*inch, 1.5*inch, 1.2*inch, 1*inch, 1.5*inch, 1*inch])
                host_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                    ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ('WORDWRAP', (0, 1), (-1, -1), True),
                ]))
                
                elements.append(host_table)
                
                # Host security analysis
                elements.append(Spacer(1, 0.25*inch))
                elements.append(Paragraph("Network Security Analysis", heading2_style))
                
                host_sec_text = f"""
                The scan discovered {len(self.data["network_scan"]["hosts"])} active hosts on the network. 
                """
                
                # Count hosts with open ports
                hosts_with_ports = [h for h in self.data["network_scan"]["hosts"] if h.get("open_ports")]
                total_open_ports = sum(len(h.get("open_ports", [])) for h in self.data["network_scan"]["hosts"])
                
                if hosts_with_ports:
                    host_sec_text += f"{len(hosts_with_ports)} hosts have open ports exposed, with a total of {total_open_ports} open ports detected. "
                    
                    # List common services
                    services = {}
                    for host in hosts_with_ports:
                        for port in host.get("open_ports", []):
                            service = port.get("service", "unknown")
                            services[service] = services.get(service, 0) + 1
                    
                    if services:
                        top_services = sorted(services.items(), key=lambda x: x[1], reverse=True)[:5]
                        service_list = [f"{service} ({count})" for service, count in top_services]
                        host_sec_text += f"Common services: {', '.join(service_list)}."
                
                elements.append(Paragraph(host_sec_text, normal_style))
            else:
                elements.append(Paragraph("No network hosts were discovered during the scan.", normal_style))
        else:
            elements.append(Paragraph("No network scan data is available.", normal_style))
        
        # Add a page break
        elements.append(PageBreak())
        
        # Attack Results Section
        elements.append(Paragraph("4. Attack Results", subtitle_style))
        elements.append(Spacer(1, 0.25*inch))
        
        if self.data["attacks"]:
            elements.append(Paragraph("Conducted Security Tests", heading1_style))
            
            # Create a table for attack results
            attack_data = [
                ["Attack Type", "Target", "Result", "Details", "Time"],
            ]
            
            for attack in self.data["attacks"]:
                result = "Success" if attack.get("success", False) else "Failed"
                attack_data.append([
                    attack.get("type", "Unknown").replace("_", " ").title(),
                    attack.get("target", attack.get("ssid", "Unknown")),
                    result,
                    attack.get("details", "No details available"),
                    attack.get("time_taken", "N/A")
                ])
            
            attack_table = Table(attack_data, colWidths=[1.2*inch, 1.2*inch, 0.8*inch, 3*inch, 0.8*inch])
            attack_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                ('ALIGN', (2, 1), (2, -1), 'CENTER'),
                ('ALIGN', (4, 1), (4, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('WORDWRAP', (0, 1), (-1, -1), True),
            ]))
            
            # Color code results
            for i in range(1, len(attack_data)):
                result = attack_data[i][2]
                if result == "Success":
                    attack_table.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.red)]))
                else:
                    attack_table.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.green)]))
            
            elements.append(attack_table)
            elements.append(Spacer(1, 0.25*inch))
            
            # Attack analysis
            elements.append(Paragraph("Security Test Analysis", heading2_style))
            
            attack_analysis_text = f"""
            A total of {len(self.data["attacks"])} security tests were conducted to assess the vulnerability of the network systems. 
            """
            
            # Count successful attacks
            successful_attacks = [a for a in self.data["attacks"] if a.get("success", False)]
            
            if successful_attacks:
                attack_analysis_text += f"<b>{len(successful_attacks)} tests were successful</b>, indicating security vulnerabilities that need to be addressed. "
                
                # Group by attack type
                attack_types = {}
                for attack in successful_attacks:
                    attack_type = attack.get("type", "unknown").replace("_", " ").title()
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
                attack_list = [f"{attack_type} ({count})" for attack_type, count in attack_types.items()]
                attack_analysis_text += f"Successful attack types: {', '.join(attack_list)}."
            else:
                attack_analysis_text += "None of the security tests were successful, which is a positive indication of the network's security posture."
            
            elements.append(Paragraph(attack_analysis_text, normal_style))
            
            # WPA Password Analysis (if available)
            wpa_attacks = [a for a in self.data["attacks"] if a.get("type") == "wpa_handshake" and a.get("success", False)]
            if wpa_attacks:
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph("WPA Password Analysis", heading2_style))
                
                wpa_text = """
                <b>The following WiFi passwords were recovered during testing:</b>
                """
                elements.append(Paragraph(wpa_text, normal_style))
                
                # Create a table for cracked passwords
                pwd_data = [
                    ["SSID", "Password", "Cracking Time", "Complexity"],
                ]
                
                for attack in wpa_attacks:
                    # Determine password complexity
                    password = attack.get("password", "")
                    complexity = "N/A"
                    
                    if password:
                        has_lower = any(c.islower() for c in password)
                        has_upper = any(c.isupper() for c in password)
                        has_digit = any(c.isdigit() for c in password)
                        has_special = any(not c.isalnum() for c in password)
                        
                        if len(password) >= 12 and has_lower and has_upper and has_digit and has_special:
                            complexity = "Strong"
                        elif len(password) >= 8 and sum([has_lower, has_upper, has_digit, has_special]) >= 3:
                            complexity = "Medium"
                        else:
                            complexity = "Weak"
                    
                    pwd_data.append([
                        attack.get("ssid", "Unknown"),
                        password,
                        attack.get("time_taken", "N/A"),
                        complexity
                    ])
                
                pwd_table = Table(pwd_data, colWidths=[1.5*inch, 2*inch, 1.5*inch, 1*inch])
                pwd_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                    ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                    ('ALIGN', (2, 1), (3, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ]))
                
                # Color code complexity
                for i in range(1, len(pwd_data)):
                    complexity = pwd_data[i][3]
                    if complexity == "Strong":
                        pwd_table.setStyle(TableStyle([('TEXTCOLOR', (3, i), (3, i), colors.green)]))
                    elif complexity == "Medium":
                        pwd_table.setStyle(TableStyle([('TEXTCOLOR', (3, i), (3, i), colors.orange)]))
                    elif complexity == "Weak":
                        pwd_table.setStyle(TableStyle([('TEXTCOLOR', (3, i), (3, i), colors.red)]))
                
                elements.append(pwd_table)
                elements.append(Spacer(1, 0.1*inch))
                
                # Password security implications
                pwd_analysis = """
                The ability to recover WiFi passwords during testing indicates a significant security risk. 
                Weak passwords can be cracked quickly, while even moderately complex passwords may be susceptible to 
                determined attacks using modern hardware. It is recommended to update all WiFi passwords to use 
                strong, complex passphrases with a minimum of 12 characters, including uppercase and lowercase letters,
                numbers, and special characters.
                """
                elements.append(Paragraph(pwd_analysis, normal_style))
            
            # Deauthentication attacks (if any)
            deauth_attacks = [a for a in self.data["attacks"] if a.get("type") == "deauth" and a.get("success", False)]
            if deauth_attacks:
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph("Deauthentication Attack Analysis", heading2_style))
                
                deauth_text = f"""
                {len(deauth_attacks)} successful deauthentication attacks were performed during testing. 
                These attacks demonstrate the ability to disconnect legitimate clients from the WiFi network, 
                which can be used as a precursor to other attacks such as evil twin, handshake capture, 
                or general denial of service. The success of these attacks indicates that the network does not 
                have protection against management frame spoofing, a vulnerability that can be addressed with 
                802.11w Protected Management Frames.
                """
                elements.append(Paragraph(deauth_text, normal_style))
        else:
            elements.append(Paragraph("No attack data is available.", normal_style))
        
        # Add a page break
        elements.append(PageBreak())
        
        # Traffic Analysis Section
        elements.append(Paragraph("5. Traffic Analysis", subtitle_style))
        elements.append(Spacer(1, 0.25*inch))
        
        if self.data["traffic_analysis"]:
            elements.append(Paragraph("Network Traffic Overview", heading1_style))
            
            # Add protocol distribution chart if available
            protocol_chart = next((c for c in self.charts if c["type"] == "protocol_pie"), None)
            if protocol_chart and os.path.exists(protocol_chart["path"]):
                img = Image(protocol_chart["path"], width=4*inch, height=4*inch)
                elements.append(img)
                elements.append(Paragraph(protocol_chart["description"], styles['Caption']))
                elements.append(Spacer(1, 0.25*inch))
            
            # Traffic statistics
            if self.data["traffic_analysis"].get("stats"):
                stats = self.data["traffic_analysis"]["stats"]
                
                traffic_stats_text = f"""
                A total of {stats.get('total_packets', 0)} packets were captured during the traffic analysis, 
                comprising {self._format_bytes(stats.get('total_bytes', 0))} of data. The analysis revealed 
                {stats.get('total_hosts', 0)} active hosts communicating on the network.
                """
                elements.append(Paragraph(traffic_stats_text, normal_style))
            
            # Protocol Analysis
            if self.data["traffic_analysis"].get("protocol_stats"):
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph("Protocol Analysis", heading2_style))
                
                # Create a table for protocols
                protocol_data = [
                    ["Protocol", "Packets", "Percentage", "Security"],
                ]
                
                total_packets = sum(self.data["traffic_analysis"]["protocol_stats"].values())
                
                for protocol, count in sorted(self.data["traffic_analysis"]["protocol_stats"].items(), 
                                             key=lambda x: x[1], reverse=True):
                    percentage = (count / total_packets) * 100 if total_packets > 0 else 0
                    
                    # Determine protocol security
                    security = "Unknown"
                    if protocol in ["HTTPS", "SSH", "SSL", "TLS", "WPA2", "WPA3", "SFTP", "SCP", "FTPS"]:
                        security = "Secure"
                    elif protocol in ["HTTP", "FTP", "TELNET", "SMTP", "POP3", "IMAP", "SNMP", "WEP", "WPA"]:
                        security = "Insecure"
                    elif protocol in ["DNS", "DHCP", "NTP", "ICMP", "ARP"]:
                        security = "Neutral"
                    
                    protocol_data.append([
                        protocol,
                        str(count),
                        f"{percentage:.1f}%",
                        security
                    ])
                
                if len(protocol_data) > 1:  # If we have data besides the header
                    protocol_table = Table(protocol_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1.5*inch])
                    protocol_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                        ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                        ('ALIGN', (1, 1), (2, -1), 'CENTER'),
                        ('ALIGN', (3, 1), (3, -1), 'CENTER'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ]))
                    
                    # Color code security
                    for i in range(1, len(protocol_data)):
                        security = protocol_data[i][3]
                        if security == "Secure":
                            protocol_table.setStyle(TableStyle([('TEXTCOLOR', (3, i), (3, i), colors.green)]))
                        elif security == "Insecure":
                            protocol_table.setStyle(TableStyle([('TEXTCOLOR', (3, i), (3, i), colors.red)]))
                        elif security == "Neutral":
                            protocol_table.setStyle(TableStyle([('TEXTCOLOR', (3, i), (3, i), colors.orange)]))
                    
                    elements.append(protocol_table)
                    elements.append(Spacer(1, 0.1*inch))
            
            # Sensitive Data Findings
            if self.data["traffic_analysis"].get("sensitive_data_found"):
                elements.append(Paragraph("Sensitive Data Exposure", heading2_style))
                
                sensitive_data_text = f"""
                <b>The traffic analysis detected {len(self.data["traffic_analysis"]["sensitive_data_found"])} instances of 
                sensitive data exposure.</b> This indicates that confidential information is being transmitted over the 
                network, potentially in an insecure manner, which poses a significant security risk.
                """
                elements.append(Paragraph(sensitive_data_text, normal_style))
                
                # Create a table for sensitive data
                sensitive_data = [
                    ["Type", "Protocol", "Source", "Destination", "Details"],
                ]
                
                for item in self.data["traffic_analysis"]["sensitive_data_found"]:
                    # Sanitize details for display (remove actual sensitive data)
                    details = item.get("details", "")
                    if item.get("type") == "Password":
                        details = "Password exposed in plaintext"
                    elif item.get("type") == "API Key":
                        details = "API Key exposed in plaintext"
                    elif item.get("type") == "Credit Card":
                        details = "Credit card number exposed"
                    
                    sensitive_data.append([
                        item.get("type", "Unknown"),
                        item.get("protocol", "Unknown"),
                        item.get("source", "Unknown"),
                        item.get("destination", "Unknown"),
                        details
                    ])
                
                sensitive_table = Table(sensitive_data, colWidths=[1*inch, 0.8*inch, 1.2*inch, 1.2*inch, 2*inch])
                sensitive_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                    ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ('WORDWRAP', (0, 1), (-1, -1), True),
                ]))
                
                elements.append(sensitive_table)
                elements.append(Spacer(1, 0.1*inch))
                
                # Recommendations for sensitive data
                sensitive_rec_text = """
                <b>Sensitive data exposure presents a critical security risk</b>. It is strongly recommended to:
                
                • Ensure all sensitive data is transmitted over encrypted protocols (HTTPS, SSL/TLS)
                • Implement proper API key handling and token-based authentication
                • Enforce encrypted storage of all credentials
                • Consider implementing data loss prevention (DLP) solutions
                • Train users on the importance of not sending sensitive information over insecure channels
                """
                elements.append(Paragraph(sensitive_rec_text, normal_style))
            
            # Unusual Traffic Patterns
            if self.data["traffic_analysis"].get("unusual_traffic"):
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph("Unusual Traffic Patterns", heading2_style))
                
                unusual_text = f"""
                The traffic analysis detected {len(self.data["traffic_analysis"]["unusual_traffic"])} instances 
                of unusual network activity that could indicate security issues or misconfigurations:
                """
                elements.append(Paragraph(unusual_text, normal_style))
                
                # List unusual traffic
                unusual_list = []
                for item in self.data["traffic_analysis"]["unusual_traffic"]:
                    unusual_list.append(f"• <b>{item.get('type', 'Unknown activity')}:</b> {item.get('description', 'No details')}")
                
                elements.append(Paragraph("<br/>".join(unusual_list), normal_style))
            
            # Unencrypted protocols
            if self.data["traffic_analysis"].get("unencrypted_protocols"):
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph("Unencrypted Protocol Usage", heading2_style))
                
                unencrypted_text = f"""
                <b>The analysis identified {len(self.data["traffic_analysis"]["unencrypted_protocols"])} unencrypted 
                protocols</b> in use on the network: {', '.join(self.data["traffic_analysis"]["unencrypted_protocols"])}. 
                Unencrypted protocols transmit data in plaintext, allowing potential attackers to capture and read 
                sensitive information. It is recommended to transition to encrypted alternatives for all services.
                """
                elements.append(Paragraph(unencrypted_text, normal_style))
        else:
            elements.append(Paragraph("No traffic analysis data is available.", normal_style))
        
        # Add a page break
        elements.append(PageBreak())
        
        # Post-Exploitation Findings Section
        elements.append(Paragraph("6. Post-Exploitation Findings", subtitle_style))
        elements.append(Spacer(1, 0.25*inch))
        
        if self.data["post_exploitation"]:
            elements.append(Paragraph("Network Penetration Results", heading1_style))
            
            post_text = f"""
            Post-exploitation analysis was performed on systems that were successfully compromised during testing. 
            This phase involves examining the internal network to identify vulnerabilities, misconfigurations, 
            and potential attack vectors that could be exploited by an attacker who has gained initial access.
            """
            elements.append(Paragraph(post_text, normal_style))
            elements.append(Spacer(1, 0.1*inch))
            
            # Network Map / Structure
            if self.data["post_exploitation"].get("network_map"):
                elements.append(Paragraph("Network Structure", heading2_style))
                
                network_text = f"""
                The post-exploitation phase mapped a total of {len(self.data["post_exploitation"].get("hosts", []))} hosts 
                on the internal network. The network structure analysis revealed the following key information:
                """
                elements.append(Paragraph(network_text, normal_style))
                
                # List network info
                net_info_list = []
                
                net_info = self.data["post_exploitation"].get("network_map", {})
                if net_info.get("gateway"):
                    net_info_list.append(f"• <b>Network Gateway:</b> {net_info.get('gateway')}")
                if net_info.get("subnet"):
                    net_info_list.append(f"• <b>Subnet:</b> {net_info.get('subnet')}")
                if net_info.get("dhcp_server"):
                    net_info_list.append(f"• <b>DHCP Server:</b> {net_info.get('dhcp_server')}")
                if net_info.get("dns_servers"):
                    net_info_list.append(f"• <b>DNS Servers:</b> {', '.join(net_info.get('dns_servers', []))}")
                
                # Add host count by type
                host_types = {}
                for host in self.data["post_exploitation"].get("hosts", []):
                    host_type = host.get("type", "unknown")
                    host_types[host_type] = host_types.get(host_type, 0) + 1
                
                if host_types:
                    type_list = [f"{count} {host_type}" for host_type, count in host_types.items()]
                    net_info_list.append(f"• <b>Host Types:</b> {', '.join(type_list)}")
                
                elements.append(Paragraph("<br/>".join(net_info_list), normal_style))
                elements.append(Spacer(1, 0.1*inch))
            
            # Compromised Systems
            if self.data["post_exploitation"].get("hosts"):
                elements.append(Paragraph("Compromised Systems", heading2_style))
                
                # Create a table for compromised hosts
                host_data = [
                    ["IP Address", "Hostname", "OS / Version", "Access Level", "Vulnerabilities"],
                ]
                
                for host in self.data["post_exploitation"].get("hosts", []):
                    if host.get("compromised", False):
                        vulns_count = len(host.get("vulnerabilities", []))
                        vulns_str = f"{vulns_count} found"
                        if vulns_count > 0:
                            critical = sum(1 for v in host.get("vulnerabilities", []) if v.get("severity") == "Critical")
                            high = sum(1 for v in host.get("vulnerabilities", []) if v.get("severity") == "High")
                            if critical > 0:
                                vulns_str += f" ({critical} critical)"
                            elif high > 0:
                                vulns_str += f" ({high} high)"
                        
                        host_data.append([
                            host.get("ip", "Unknown"),
                            host.get("hostname", "N/A"),
                            host.get("os", "Unknown"),
                            host.get("access_level", "Unknown"),
                            vulns_str
                        ])
                
                if len(host_data) > 1:  # If we have data besides the header
                    host_table = Table(host_data, colWidths=[1*inch, 1.5*inch, 1.5*inch, 1*inch, 1.5*inch])
                    host_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                        ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                        ('WORDWRAP', (0, 1), (-1, -1), True),
                    ]))
                    
                    # Color code access level
                    for i in range(1, len(host_data)):
                        access = host_data[i][3]
                        if "root" in access.lower() or "admin" in access.lower() or "system" in access.lower():
                            host_table.setStyle(TableStyle([('TEXTCOLOR', (3, i), (3, i), colors.red)]))
                    
                    elements.append(host_table)
                    elements.append(Spacer(1, 0.1*inch))
            
            # Critical Findings
            critical_findings = []
            
            # Default credentials
            default_creds_hosts = [h for h in self.data["post_exploitation"].get("hosts", []) 
                                 if h.get("default_credentials", False)]
            if default_creds_hosts:
                critical_findings.append({
                    "title": "Default Credentials",
                    "description": f"Found {len(default_creds_hosts)} systems using default credentials",
                    "impact": "High",
                    "details": "Default credentials provide easy access for attackers"
                })
            
            # Sensitive files
            hosts_with_sensitive = [h for h in self.data["post_exploitation"].get("hosts", []) 
                                  if h.get("sensitive_files", [])]
            if hosts_with_sensitive:
                critical_findings.append({
                    "title": "Sensitive Files Exposed",
                    "description": f"Found {len(hosts_with_sensitive)} systems with exposed sensitive files",
                    "impact": "High",
                    "details": "Exposed sensitive files can lead to information disclosure"
                })
            
            # Missing patches
            hosts_missing_patches = [h for h in self.data["post_exploitation"].get("hosts", []) 
                                   if h.get("missing_patches", [])]
            if hosts_missing_patches:
                critical_findings.append({
                    "title": "Missing Security Patches",
                    "description": f"Found {len(hosts_missing_patches)} systems missing critical security patches",
                    "impact": "Critical",
                    "details": "Missing patches expose systems to known vulnerabilities"
                })
            
            # Lateral movement
            if self.data["post_exploitation"].get("lateral_movement", {}).get("successful", False):
                critical_findings.append({
                    "title": "Lateral Movement Success",
                    "description": "Successfully moved between systems after initial compromise",
                    "impact": "Critical",
                    "details": "Attacker can access multiple systems once inside the network"
                })
            
            # Privilege escalation
            hosts_with_privesc = [h for h in self.data["post_exploitation"].get("hosts", []) 
                                if h.get("privilege_escalation", {}).get("successful", False)]
            if hosts_with_privesc:
                critical_findings.append({
                    "title": "Privilege Escalation",
                    "description": f"Successfully escalated privileges on {len(hosts_with_privesc)} systems",
                    "impact": "Critical",
                    "details": "Attacker can gain administrative control after initial access"
                })
            
            if critical_findings:
                elements.append(Paragraph("Critical Security Findings", heading2_style))
                
                # Create a table for critical findings
                findings_data = [
                    ["Finding", "Description", "Impact", "Details"],
                ]
                
                for finding in critical_findings:
                    findings_data.append([
                        finding["title"],
                        finding["description"],
                        finding["impact"],
                        finding["details"]
                    ])
                
                findings_table = Table(findings_data, colWidths=[1.2*inch, 1.8*inch, 0.8*inch, 2.5*inch])
                findings_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                    ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                    ('ALIGN', (2, 1), (2, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ('WORDWRAP', (0, 1), (-1, -1), True),
                ]))
                
                # Color code impact
                for i in range(1, len(findings_data)):
                    impact = findings_data[i][2]
                    if impact == "Critical":
                        findings_table.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.red)]))
                    elif impact == "High":
                        findings_table.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), colors.orangered)]))
                
                elements.append(findings_table)
                elements.append(Spacer(1, 0.2*inch))
            
            # Post-Exploitation Summary
            elements.append(Paragraph("Post-Exploitation Summary", heading2_style))
            
            summary_text = """
            The post-exploitation findings reveal the potential damage that could occur if an attacker gains initial access to the network. 
            These results highlight the importance of defense-in-depth strategies that go beyond perimeter security to protect against 
            lateral movement and privilege escalation once an attacker has established a foothold.
            """
            
            # Add specific summary points based on findings
            if default_creds_hosts:
                summary_text += f"""
                <br/><br/>The presence of default credentials on {len(default_creds_hosts)} systems is particularly concerning, 
                as it provides an easy entry point for attackers and indicates poor credential management practices.
                """
            
            if hosts_missing_patches:
                summary_text += f"""
                <br/><br/>Missing security patches on {len(hosts_missing_patches)} systems exposes the network to known vulnerabilities 
                that can be easily exploited using publicly available tools and exploit code.
                """
            
            if self.data["post_exploitation"].get("lateral_movement", {}).get("successful", False):
                summary_text += """
                <br/><br/>The successful lateral movement during testing demonstrates that once an attacker compromises one system, 
                they can potentially access other systems and sensitive data across the network.
                """
            
            elements.append(Paragraph(summary_text, normal_style))
        else:
            elements.append(Paragraph("No post-exploitation data is available.", normal_style))
        
        # Add a page break
        elements.append(PageBreak())
        
        # Detailed Vulnerabilities Section
        elements.append(Paragraph("7. Detailed Vulnerabilities", subtitle_style))
        elements.append(Spacer(1, 0.25*inch))
        
        all_vulnerabilities = []
        
        # Collect vulnerabilities from post-exploitation
        for host in self.data["post_exploitation"].get("hosts", []):
            for vuln in host.get("vulnerabilities", []):
                vuln["host"] = host.get("ip", "Unknown")
                vuln["hostname"] = host.get("hostname", "N/A")
                all_vulnerabilities.append(vuln)
        
        # Add standalone vulnerabilities
        for vuln in self.data["vulnerabilities"]:
            if vuln not in all_vulnerabilities:
                all_vulnerabilities.append(vuln)
        
        if all_vulnerabilities:
            elements.append(Paragraph("Vulnerability Summary", heading1_style))
            
            # Group vulnerabilities by severity
            vuln_by_severity = {
                "Critical": [],
                "High": [],
                "Medium": [],
                "Low": [],
                "Info": []
            }
            
            for vuln in all_vulnerabilities:
                severity = vuln.get("severity", "Info")
                vuln_by_severity[severity].append(vuln)
            
            # Create summary text
            summary_text = """
            The security assessment identified the following vulnerabilities across the systems tested:
            """
            elements.append(Paragraph(summary_text, normal_style))
            
            # Create a summary table
            summary_data = [
                ["Severity", "Count", "Risk Level"],
            ]
            
            for severity, vulns in vuln_by_severity.items():
                if vulns:  # Only add if we have vulnerabilities of this severity
                    risk_level = ""
                    if severity == "Critical":
                        risk_level = "Immediate action required"
                    elif severity == "High":
                        risk_level = "Urgent action needed"
                    elif severity == "Medium":
                        risk_level = "Plan for remediation"
                    elif severity == "Low":
                        risk_level = "Address as resources permit"
                    else:
                        risk_level = "For information only"
                    
                    summary_data.append([
                        severity,
                        str(len(vulns)),
                        risk_level
                    ])
            
            summary_table = Table(summary_data, colWidths=[1*inch, 0.8*inch, 3.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ]))
            
            # Color code severity
            for i, (severity, vulns) in enumerate(vuln_by_severity.items()):
                if vulns:  # Only process if we have vulnerabilities of this severity
                    row = summary_data.index([severity, str(len(vulns)), summary_data[summary_data.index([severity, str(len(vulns)), summary_data[summary_data.index([severity, str(len(vulns))])][2]])][2]])
                    if severity == "Critical":
                        summary_table.setStyle(TableStyle([('TEXTCOLOR', (0, row), (0, row), colors.red)]))
                    elif severity == "High":
                        summary_table.setStyle(TableStyle([('TEXTCOLOR', (0, row), (0, row), colors.orangered)]))
                    elif severity == "Medium":
                        summary_table.setStyle(TableStyle([('TEXTCOLOR', (0, row), (0, row), colors.orange)]))
                    elif severity == "Low":
                        summary_table.setStyle(TableStyle([('TEXTCOLOR', (0, row), (0, row), colors.green)]))
            
            elements.append(summary_table)
            elements.append(Spacer(1, 0.25*inch))
            
            # Detailed vulnerabilities (Critical and High only to keep the report manageable)
            critical_high_vulns = vuln_by_severity["Critical"] + vuln_by_severity["High"]
            
            if critical_high_vulns:
                elements.append(Paragraph("Critical & High Severity Vulnerabilities", heading2_style))
                
                # Add each vulnerability as a detailed item
                for i, vuln in enumerate(critical_high_vulns):
                    elements.append(Paragraph(f"{i+1}. {vuln.get('name', 'Unknown Vulnerability')}", heading2_style))
                    
                    # Create a table with vulnerability details
                    vuln_details = [
                        ["Attribute", "Value"],
                        ["Severity", vuln.get("severity", "Unknown")],
                        ["CVSS Score", str(vuln.get("cvss", "N/A"))],
                        ["Affected System", f"{vuln.get('hostname', 'N/A')} ({vuln.get('host', 'Unknown')})"],
                        ["CVE ID", vuln.get("cve", "N/A")],
                        ["Affected Component", vuln.get("affected_component", "Unknown")],
                        ["Exploit Available", "Yes" if vuln.get("exploit_available", False) else "No"]
                    ]
                    
                    vuln_table = Table(vuln_details, colWidths=[1.5*inch, 4*inch])
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 9),
                        ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ]))
                    
                    # Color code severity
                    severity_row = 1  # "Severity" is the first row after the header
                    if vuln.get("severity") == "Critical":
                        vuln_table.setStyle(TableStyle([('TEXTCOLOR', (1, severity_row), (1, severity_row), colors.red)]))
                    elif vuln.get("severity") == "High":
                        vuln_table.setStyle(TableStyle([('TEXTCOLOR', (1, severity_row), (1, severity_row), colors.orangered)]))
                    
                    elements.append(vuln_table)
                    elements.append(Spacer(1, 0.1*inch))
                    
                    # Description, impact, remediation
                    if vuln.get("description"):
                        elements.append(Paragraph("<b>Description:</b>", normal_style))
                        elements.append(Paragraph(vuln.get("description"), normal_style))
                        elements.append(Spacer(1, 0.05*inch))
                    
                    if vuln.get("impact"):
                        elements.append(Paragraph("<b>Impact:</b>", normal_style))
                        elements.append(Paragraph(vuln.get("impact"), normal_style))
                        elements.append(Spacer(1, 0.05*inch))
                    
                    if vuln.get("remediation"):
                        elements.append(Paragraph("<b>Remediation:</b>", normal_style))
                        elements.append(Paragraph(vuln.get("remediation"), normal_style))
                        elements.append(Spacer(1, 0.05*inch))
                    
                    # Add references if available
                    if vuln.get("references", []):
                        elements.append(Paragraph("<b>References:</b>", normal_style))
                        ref_list = []
                        for ref in vuln.get("references", []):
                            ref_list.append(f"• {ref}")
                        elements.append(Paragraph("<br/>".join(ref_list), normal_style))
                    
                    # Add a spacer before the next vulnerability
                    elements.append(Spacer(1, 0.2*inch))
            
            # Medium vulnerabilities summary (just a table)
            if vuln_by_severity["Medium"]:
                elements.append(Paragraph("Medium Severity Vulnerabilities", heading2_style))
                
                # Create a table for medium vulnerabilities
                medium_data = [
                    ["Vulnerability", "CVE", "Affected System", "CVSS", "Remediation Available"],
                ]
                
                for vuln in vuln_by_severity["Medium"]:
                    medium_data.append([
                        vuln.get("name", "Unknown"),
                        vuln.get("cve", "N/A"),
                        f"{vuln.get('hostname', 'N/A')} ({vuln.get('host', 'Unknown')})",
                        str(vuln.get("cvss", "N/A")),
                        "Yes" if vuln.get("remediation") else "No"
                    ])
                
                medium_table = Table(medium_data, colWidths=[2*inch, 0.8*inch, 1.5*inch, 0.6*inch, 1.2*inch])
                medium_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lavender),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                    ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                    ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                    ('ALIGN', (3, 1), (4, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ('WORDWRAP', (0, 1), (-1, -1), True),
                ]))
                
                elements.append(medium_table)
        else:
            elements.append(Paragraph("No vulnerability data is available.", normal_style))
        
        # Add a page break
        elements.append(PageBreak())
        
        # Recommendations Section
        elements.append(Paragraph("8. Recommendations", subtitle_style))
        elements.append(Spacer(1, 0.25*inch))
        
        if self.data["recommendations"]:
            elements.append(Paragraph("Security Recommendations", heading1_style))
            
            # Prioritized Recommendations
            elements.append(Paragraph("Prioritized Action Items", heading2_style))
            
            priority_text = """
            Based on the security assessment findings, the following recommendations are provided in order of priority 
            to address the identified vulnerabilities and security issues:
            """
            elements.append(Paragraph(priority_text, normal_style))
            elements.append(Spacer(1, 0.1*inch))
            
            # Group recommendations by priority
            recommendations_by_priority = {
                "Critical": [],
                "High": [],
                "Medium": [],
                "Low": []
            }
            
            for rec in self.data["recommendations"]:
                priority = rec.get("priority", "Medium")
                recommendations_by_priority[priority].append(rec)
            
            # Flatten the recommendations in priority order
            all_recommendations = []
            for priority in ["Critical", "High", "Medium", "Low"]:
                all_recommendations.extend(recommendations_by_priority[priority])
            
            # Create a table for recommendations
            rec_data = []
            
            for i, rec in enumerate(all_recommendations):
                # Create a nested table for each recommendation
                title_data = [[f"{i+1}. {rec.get('title')}"]]
                title_table = Table(title_data, colWidths=[6.5*inch])
                title_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, 0), self._get_priority_color(rec.get("priority", "Medium"))),
                    ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
                    ('ALIGN', (0, 0), (0, 0), 'LEFT'),
                    ('FONT', (0, 0), (0, 0), 'Helvetica-Bold', 10),
                    ('VALIGN', (0, 0), (0, 0), 'MIDDLE'),
                ]))
                
                # Create content table
                content_data = []
                
                # Description
                content_data.append(["Description:", rec.get("description", "No description available")])
                
                # Risk Level
                content_data.append(["Priority:", rec.get("priority", "Medium")])
                
                # Implementation details if available
                if rec.get("implementation"):
                    content_data.append(["Implementation:", rec.get("implementation")])
                
                # References if available
                if rec.get("references"):
                    refs = rec.get("references", [])
                    if isinstance(refs, list):
                        refs = ", ".join(refs)
                    content_data.append(["References:", refs])
                
                content_table = Table(content_data, colWidths=[1.2*inch, 5.3*inch])
                content_table.setStyle(TableStyle([
                    ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 9),
                    ('FONT', (1, 0), (1, -1), 'Helvetica', 9),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('WORDWRAP', (0, 0), (-1, -1), True),
                ]))
                
                rec_data.append([title_table])
                rec_data.append([content_table])
                rec_data.append([Spacer(1, 0.1*inch)])
            
            if rec_data:
                rec_table = Table(rec_data, colWidths=[6.5*inch])
                rec_table.setStyle(TableStyle([
                    ('LEFTPADDING', (0, 0), (-1, -1), 0),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                    ('TOPPADDING', (0, 0), (-1, -1), 0),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                ]))
                
                elements.append(rec_table)
                
                # Implementation Roadmap
                elements.append(Paragraph("Implementation Roadmap", heading2_style))
                
                roadmap_text = """
                To effectively address the identified security issues, the following implementation roadmap is proposed:
                
                <b>Short-term (0-30 days):</b>
                • Address all Critical priority items immediately
                • Apply available security patches for all systems
                • Change default credentials and implement strong password policies
                • Disable unnecessary services and protocols
                • Configure firewalls to restrict access to critical systems
                
                <b>Medium-term (30-90 days):</b>
                • Address High and Medium priority recommendations
                • Implement network segmentation to separate critical systems
                • Deploy multi-factor authentication for sensitive systems
                • Enhance monitoring and logging capabilities
                • Conduct security awareness training for all users
                
                <b>Long-term (90+ days):</b>
                • Address remaining Low priority recommendations
                • Implement a formal vulnerability management program
                • Establish a security policy framework
                • Develop an incident response plan
                • Conduct regular security assessments
                """
                
                elements.append(Paragraph(roadmap_text, normal_style))
        else:
            elements.append(Paragraph("No recommendations are available.", normal_style))
        
        # Add a page break
        elements.append(PageBreak())
        
        # Appendices Section
        elements.append(Paragraph("9. Appendices", subtitle_style))
        elements.append(Spacer(1, 0.25*inch))
        
        # Testing methodology
        elements.append(Paragraph("A. Testing Methodology", heading1_style))
        
        methodology_text = """
        The security assessment was conducted using a comprehensive approach that includes the following phases:
        
        <b>1. Reconnaissance and Information Gathering</b>
        • Network discovery and enumeration
        • Wireless network scanning
        • Service and version identification
        • Open-source intelligence gathering
        
        <b>2. Vulnerability Assessment</b>
        • Automated vulnerability scanning
        • Manual security testing
        • Configuration review
        • Password strength analysis
        
        <b>3. Exploitation Testing</b>
        • WiFi security testing (WPA handshake capture, password cracking)
        • Exploitation of identified vulnerabilities
        • Access control bypass attempts
        • Default credential testing
        
        <b>4. Post-Exploitation Assessment</b>
        • Lateral movement testing
        • Privilege escalation attempts
        • Data access and exfiltration testing
        • Persistence mechanism identification
        
        <b>5. Analysis and Reporting</b>
        • Vulnerability analysis and risk assessment
        • Root cause analysis
        • Remediation recommendations
        • Detailed technical reporting
        """
        
        elements.append(Paragraph(methodology_text, normal_style))
        elements.append(Spacer(1, 0.25*inch))
        
        # Tools used
        elements.append(Paragraph("B. Tools Used", heading1_style))
        
        tools_text = """
        The following tools were used during the security assessment:
        
        <b>Network Scanning and Enumeration:</b>
        • Nmap - Network discovery and service detection
        • Netdiscover - Active/passive ARP reconnaissance
        • Wireshark - Protocol analyzer
        
        <b>Wireless Testing:</b>
        • Aircrack-ng suite - Wireless network security assessment
        • Hashcat - Password recovery
        • Reaver - WPS PIN recovery
        
        <b>Vulnerability Assessment:</b>
        • OpenVAS - Vulnerability scanning
        • Searchsploit - Exploit database search utility
        • Nessus - Vulnerability scanner
        
        <b>Exploitation Tools:</b>
        • Metasploit Framework - Exploitation and post-exploitation
        • Hydra - Login brute-forcer
        • John the Ripper - Password cracker
        
        <b>Post-Exploitation:</b>
        • Mimikatz - Credential dumping
        • Empire - Post-exploitation framework
        • Bloodhound - Active Directory reconnaissance
        
        <b>Reporting and Analysis:</b>
        • Custom report generation tools
        • Data visualization libraries
        • Risk assessment frameworks
        """
        
        elements.append(Paragraph(tools_text, normal_style))
        elements.append(Spacer(1, 0.25*inch))
        
        # Risk scoring methodology
        elements.append(Paragraph("C. Risk Scoring Methodology", heading1_style))
        
        risk_methodology_text = """
        The risk scoring methodology used in this report follows industry standards for security risk assessment:
        
        <b>Risk Score Scale:</b>
        • 0-10 scale with decimal precision
        • 0.0-0.9: Information/Minimal Risk
        • 1.0-3.9: Low Risk
        • 4.0-6.9: Medium Risk
        • 7.0-8.9: High Risk
        • 9.0-10.0: Critical Risk
        
        <b>Risk Category Weightings:</b>
        • Network Exposure: 15%
        • Authentication: 20%
        • Encryption: 15%
        • Vulnerabilities: 20%
        • Sensitive Data: 10%
        • Configuration: 10%
        • Updates: 5%
        • Defense Mechanisms: 5%
        
        <b>Risk Factors Considered:</b>
        • Exploitability: How easily the issue can be exploited
        • Impact: Potential damage if exploited
        • Exposure: Level of exposure to potential attackers
        • Data Sensitivity: Sensitivity of potentially affected data
        • Mitigation Difficulty: Complexity of implementing fixes
        
        The final risk score represents the weighted combination of these factors, providing a comprehensive assessment of the security posture.
        """
        
        elements.append(Paragraph(risk_methodology_text, normal_style))
        
        # Build the PDF
        doc.build(elements)
        
        return output_path
    
    def _get_priority_color(self, priority: str) -> colors.Color:
        """Get color based on recommendation priority
        
        Args:
            priority: Priority level string
            
        Returns:
            colors.Color: Color for the priority level
        """
        if priority == "Critical":
            return colors.red
        elif priority == "High":
            return colors.orangered
        elif priority == "Medium":
            return colors.orange
        elif priority == "Low":
            return colors.green
        else:
            return colors.blue
    
    def _format_bytes(self, size: int) -> str:
        """Format bytes to human-readable format
        
        Args:
            size: Size in bytes
            
        Returns:
            str: Human-readable size string
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024 or unit == 'TB':
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"  # Should never reach here, but just in case


# Test function to create a sample report
def create_sample_report():
    """Create a sample comprehensive report for testing"""
    report_gen = ComprehensiveReport()
    
    # Set metadata
    report_gen.set_metadata(
        company_name="ACME Corporation",
        report_title="Comprehensive Security Assessment Report"
    )
    
    # Add sample network scan data
    network_scan = {
        "access_points": [
            {"ssid": "ACME-Corp", "bssid": "00:11:22:33:44:55", "channel": 6, "signal": 90, "encryption": "WPA2", "clients": 5},
            {"ssid": "ACME-Guest", "bssid": "00:11:22:33:44:56", "channel": 11, "signal": 85, "encryption": "WPA2", "clients": 3},
            {"ssid": "Legacy-Printer", "bssid": "00:11:22:33:44:57", "channel": 1, "signal": 60, "encryption": "WEP", "clients": 1, "wps_enabled": True}
        ],
        "hosts": [
            {"ip": "192.168.1.1", "hostname": "gateway.local", "mac": "00:11:22:33:44:55", "vendor": "Cisco", "os": "Cisco IOS", 
             "open_ports": [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}, {"port": 22, "service": "SSH"}]},
            {"ip": "192.168.1.10", "hostname": "server01.local", "mac": "00:11:22:33:44:56", "vendor": "Dell", "os": "Windows Server 2019", 
             "open_ports": [{"port": 445, "service": "SMB"}, {"port": 3389, "service": "RDP"}]},
            {"ip": "192.168.1.20", "hostname": "workstation01.local", "mac": "00:11:22:33:44:57", "vendor": "HP", "os": "Windows 10", 
             "open_ports": [{"port": 139, "service": "NetBIOS"}, {"port": 445, "service": "SMB"}]}
        ]
    }
    report_gen.add_network_scan_data(network_scan)
    
    # Add sample attack data
    attack_data = [
        {"type": "wpa_handshake", "ssid": "Legacy-Printer", "target": "00:11:22:33:44:57", "success": True, 
         "password": "printer123", "time_taken": "2m 15s", "details": "Default password for printer network"},
        {"type": "deauth", "ssid": "ACME-Corp", "target": "00:11:22:33:44:55", "success": True, 
         "affected_clients": 3, "time_taken": "30s", "details": "Successfully deauthenticated 3 clients"}
    ]
    for attack in attack_data:
        report_gen.add_attack_data(attack)
    
    # Add sample traffic analysis data
    traffic_data = {
        "stats": {"total_packets": 5263, "total_bytes": 3524680, "total_hosts": 15},
        "protocol_stats": {"HTTP": 1250, "HTTPS": 2500, "DNS": 450, "SMB": 150, "ICMP": 120, "SSH": 100, "FTP": 80},
        "sensitive_data_found": [
            {"type": "Password", "protocol": "HTTP", "source": "192.168.1.50", "destination": "203.0.113.10", "details": "Login password sent in plaintext"},
            {"type": "API Key", "protocol": "HTTP", "source": "192.168.1.55", "destination": "203.0.113.20", "details": "API key exposed in URL parameter"}
        ],
        "unencrypted_protocols": ["HTTP", "FTP", "Telnet"],
        "unusual_traffic": [
            {"type": "Port Scan", "description": "Detected internal port scan from 192.168.1.100 targeting multiple hosts"},
            {"type": "Unusual Data Transfer", "description": "Large outbound data transfer to external IP 203.0.113.50 at unusual hours"}
        ]
    }
    report_gen.add_traffic_analysis_data(traffic_data)
    
    # Add sample post-exploitation data
    post_data = {
        "network_map": {
            "gateway": "192.168.1.1",
            "subnet": "192.168.1.0/24",
            "dhcp_server": "192.168.1.1",
            "dns_servers": ["192.168.1.1", "8.8.8.8"]
        },
        "hosts": [
            {
                "ip": "192.168.1.10", 
                "hostname": "server01.local", 
                "os": "Windows Server 2019", 
                "type": "server",
                "access_level": "Administrator",
                "compromised": True,
                "default_credentials": True,
                "vulnerabilities": [
                    {
                        "name": "SMB Remote Code Execution Vulnerability",
                        "cve": "CVE-2020-0796",
                        "severity": "Critical",
                        "cvss": 10.0,
                        "description": "Remote code execution vulnerability in SMBv3 protocol.",
                        "affected_component": "SMB Service",
                        "exploit_available": True,
                        "impact": "An attacker could gain full control of the affected system.",
                        "remediation": "Apply the latest security updates from Microsoft.",
                        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796"]
                    }
                ],
                "missing_patches": ["KB4541505", "KB4571756"]
            },
            {
                "ip": "192.168.1.20", 
                "hostname": "workstation01.local", 
                "os": "Windows 10", 
                "type": "workstation",
                "access_level": "User",
                "compromised": True,
                "privilege_escalation": {
                    "successful": True,
                    "method": "Unquoted Service Path",
                    "details": "Escalated to SYSTEM privileges using unquoted service path vulnerability"
                },
                "vulnerabilities": [
                    {
                        "name": "Print Spooler Remote Code Execution Vulnerability",
                        "cve": "CVE-2021-34527",
                        "severity": "High",
                        "cvss": 8.8,
                        "description": "Remote code execution vulnerability in the Windows Print Spooler service.",
                        "affected_component": "Print Spooler Service",
                        "exploit_available": True,
                        "impact": "Attackers could run arbitrary code with SYSTEM privileges.",
                        "remediation": "Disable the Print Spooler service or apply Microsoft security updates.",
                        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"]
                    }
                ]
            }
        ],
        "lateral_movement": {
            "successful": True,
            "methods": ["Pass-the-Hash", "RDP", "Admin Shares"],
            "details": "Successfully moved from workstation01 to server01 using harvested NTLM hashes."
        }
    }
    report_gen.add_post_exploitation_data(post_data)
    
    # Add vulnerabilities
    vuln_data = {
        "name": "Weak SSH Algorithms Enabled",
        "severity": "Medium",
        "cvss": 5.9,
        "cve": "CVE-2019-14889",
        "affected_component": "SSH Server",
        "description": "The SSH server is configured to allow weak algorithms that are susceptible to brute-force attacks.",
        "impact": "An attacker could potentially decrypt captured SSH traffic or brute-force SSH credentials.",
        "remediation": "Reconfigure SSH server to disable weak algorithms and ciphers.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-14889"]
    }
    report_gen.add_vulnerability(vuln_data)
    
    # Add recommendations
    recommendations = [
        {
            "title": "Replace WEP Encryption",
            "description": "Replace WEP with WPA2 or WPA3 encryption on all access points.",
            "priority": "Critical",
            "implementation": "Configure Legacy-Printer access point to use WPA2-PSK with AES/CCMP encryption.",
            "references": ["https://www.wi-fi.org/discover-wi-fi/security"]
        },
        {
            "title": "Patch SMB Vulnerability",
            "description": "Apply security patches to address the SMB Remote Code Execution Vulnerability (CVE-2020-0796).",
            "priority": "Critical",
            "implementation": "Apply Microsoft security update KB4541505 to server01.",
            "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796"]
        },
        {
            "title": "Implement Strong Password Policy",
            "description": "Enforce a strong password policy for all systems and services.",
            "priority": "High",
            "implementation": "Configure password policy to require minimum 12 characters with complexity requirements.",
            "references": ["https://www.ncsc.gov.uk/collection/passwords/updating-your-approach"]
        }
    ]
    for rec in recommendations:
        report_gen.add_recommendation(rec)
    
    # Generate recommendations using findings
    report_gen.generate_recommendations()
    
    # Generate charts
    report_gen.generate_charts()
    
    # Generate the PDF report
    output_path = os.path.join("reports", "comprehensive_security_report.pdf")
    report_gen.generate_pdf_report(output_path)
    
    print(f"Sample report generated at: {output_path}")
    return output_path


if __name__ == "__main__":
    create_sample_report()