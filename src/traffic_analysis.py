#!/usr/bin/env python3
"""
Wireless Traffic Analysis Module for the WiFi Penetration Testing Tool
Real-time packet capture and analysis with protocol dissection, sensitive data detection,
and automatic CVE identification using machine learning techniques
"""

import os
import re
import json
import time
import tempfile
import threading
import subprocess
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional, Union, Callable
from scapy.all import (
    sniff, rdpcap, wrpcap, Packet, TCP, UDP, IP, Raw, 
    ARP, ICMP, DNS, Ether
)
from scapy.layers.http import HTTP
from scapy.layers.inet import ICMP
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
import joblib
import warnings

# Suppress warnings to keep output clean
warnings.filterwarnings("ignore")

class TrafficAnalysisModule:
    """Advanced Wireless Traffic Analysis Module
    
    Features:
    - Live capture of wireless traffic from any network (encrypted or unencrypted)
    - Protocol dissection to identify sensitive data (passwords, keys, etc)
    - Traffic pattern visualization
    - Machine learning for anomaly detection
    - Automatic CVE detection for discovered services
    """
    
    def __init__(self, controller=None, log_callback=None, dev_mode=False):
        """Initialize the traffic analysis module
        
        Args:
            controller: Reference to the main application controller
            log_callback: Callback function to log messages
            dev_mode: Run in development mode (simulation)
        """
        self.controller = controller
        self.log_callback = log_callback
        self.dev_mode = dev_mode
        
        # State variables
        self.interface = None
        self.capture_thread = None
        self.analyzing = False
        self.capture_running = False
        self.stop_event = threading.Event()
        
        # Data storage
        self.packets = []  # Captured packets
        self.packet_stats = {
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "arp": 0,
            "dns": 0,
            "http": 0,
            "https": 0,
            "dhcp": 0,
            "other": 0,
            "total": 0
        }
        self.sensitive_data_findings = []
        self.latest_traffic_data = []
        self.detected_vulnerabilities = []
        self.device_fingerprints = {}
        self.cve_database = self.load_cve_database()
        
        # Initialize working directory
        self.working_dir = tempfile.mkdtemp(prefix="traffic_analysis_")
        self.current_pcap = None
        
        # Initialize ML models
        self.anomaly_detector = None
        self.protocol_classifier = None
        self.initialize_ml_models()
    
    def log(self, message, error=False, warning=False, success=False):
        """Log a message using the provided callback"""
        if self.log_callback:
            self.log_callback(message, error=error, warning=warning, success=success)
        else:
            status = ""
            if error:
                status = "[ERROR] "
            elif warning:
                status = "[WARNING] "
            elif success:
                status = "[SUCCESS] "
            print(f"{status}{message}")
    
    def initialize_ml_models(self):
        """Initialize machine learning models for traffic analysis"""
        try:
            # Only initialize ML in real mode for performance
            if not self.dev_mode:
                # Anomaly detection model
                self.anomaly_detector = IsolationForest(
                    n_estimators=100,
                    contamination=0.05,
                    random_state=42
                )
                
                # Protocol classification model
                self.protocol_classifier = RandomForestClassifier(
                    n_estimators=50,
                    max_depth=10,
                    random_state=42
                )
                
                self.log("Machine learning models initialized", success=True)
        except Exception as e:
            self.log(f"Failed to initialize ML models: {str(e)}", error=True)
    
    def load_cve_database(self) -> Dict:
        """Load CVE database from file or build a new one"""
        cve_db = {}
        
        try:
            # Look for local CVE database first
            cve_db_file = os.path.join(os.path.dirname(__file__), "..", "data", "cve_database.json")
            if os.path.exists(cve_db_file):
                with open(cve_db_file, 'r') as f:
                    cve_db = json.load(f)
                    self.log(f"Loaded {len(cve_db)} CVE entries", success=True)
                    return cve_db
                    
            # If in real mode (Kali Linux), fetch CVEs from searchsploit
            if not self.dev_mode:
                # This will run in a real Kali Linux environment
                self.log("Building CVE database from searchsploit...", warning=True)
                cve_db = self._build_cve_database_from_searchsploit()
                
                # Save for future use
                os.makedirs(os.path.dirname(cve_db_file), exist_ok=True)
                with open(cve_db_file, 'w') as f:
                    json.dump(cve_db, f)
                
                self.log(f"Built CVE database with {len(cve_db)} entries", success=True)
                return cve_db
        
        except Exception as e:
            self.log(f"Error loading CVE database: {str(e)}", error=True)
        
        # Return empty database if all else fails
        return {}
    
    def _build_cve_database_from_searchsploit(self) -> Dict:
        """Build CVE database using searchsploit in Kali Linux
        
        Returns:
            Dict: CVE database mapping services to vulnerabilities
        """
        cve_db = {}
        
        try:
            # Use searchsploit to get exploits (if available)
            cmd = ["searchsploit", "--json", "all"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    
                    # Process exploits into a service-based dictionary
                    for exploit in exploits:
                        title = exploit.get("Title", "").lower()
                        path = exploit.get("Path", "")
                        eid = exploit.get("EDB-ID", "")
                        
                        # Extract CVE if present
                        cve_match = re.search(r'CVE-\d{4}-\d+', title)
                        cve_id = cve_match.group(0) if cve_match else None
                        
                        # Extract service names and versions
                        services = []
                        for service in ["http", "ftp", "ssh", "telnet", "smtp", "dns", "smb"]:
                            if service in title:
                                services.append(service)
                        
                        if not services:
                            continue
                            
                        # Add to database
                        for service in services:
                            if service not in cve_db:
                                cve_db[service] = []
                                
                            cve_entry = {
                                "title": exploit.get("Title", ""),
                                "path": path,
                                "edb_id": eid, 
                                "cve_id": cve_id
                            }
                            
                            # Parse version info where possible
                            version_match = re.search(r'\d+\.\d+(\.\d+)?', title)
                            if version_match:
                                cve_entry["version"] = version_match.group(0)
                                
                            cve_db[service].append(cve_entry)
            except (subprocess.SubprocessError, json.JSONDecodeError) as e:
                self.log(f"Error building CVE database: {str(e)}", error=True)
                
            # Fall back to CVE-Search API if available and searchsploit fails
            if not cve_db:
                self.log("Trying alternative CVE sources...", warning=True)
                # Implementation for CVE-Search would go here
        
        except Exception as e:
            self.log(f"Error in CVE database construction: {str(e)}", error=True)
        
        return cve_db
    
    def set_interface(self, interface: str) -> bool:
        """Set the interface to use for packet capture
        
        Args:
            interface: Name of network interface
            
        Returns:
            bool: True if interface was set successfully
        """
        if not interface:
            self.log("No interface specified", error=True)
            return False
            
        self.interface = interface
        self.log(f"Set capture interface to {interface}", success=True)
        
        # Check if interface is in monitor mode, and enable if needed
        if not self.dev_mode:
            is_monitor = self._check_monitor_mode(interface)
            if not is_monitor:
                self.log(f"Interface {interface} is not in monitor mode. Enabling...", warning=True)
                if self._enable_monitor_mode(interface):
                    self.log(f"Enabled monitor mode on {interface}", success=True)
                else:
                    self.log(f"Failed to enable monitor mode on {interface}", error=True)
        
        return True
    
    def _check_monitor_mode(self, interface: str) -> bool:
        """Check if interface is in monitor mode
        
        Args:
            interface: Network interface name
            
        Returns:
            bool: True if interface is in monitor mode
        """
        try:
            cmd = ["iwconfig", interface]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return "Mode:Monitor" in result.stdout
        except:
            return False
    
    def _enable_monitor_mode(self, interface: str) -> bool:
        """Enable monitor mode on interface
        
        Args:
            interface: Network interface name
            
        Returns:
            bool: True if monitor mode was enabled successfully
        """
        try:
            # First, stop NetworkManager if it's managing this interface
            try:
                cmd = ["sudo", "systemctl", "stop", "NetworkManager"]
                subprocess.run(cmd, capture_output=True, check=False, timeout=5)
            except:
                pass
                
            # Enable monitor mode
            cmds = [
                ["sudo", "ip", "link", "set", interface, "down"],
                ["sudo", "iw", "dev", interface, "set", "type", "monitor"],
                ["sudo", "ip", "link", "set", interface, "up"]
            ]
            
            for cmd in cmds:
                result = subprocess.run(cmd, capture_output=True, check=False)
                if result.returncode != 0:
                    self.log(f"Command failed: {' '.join(cmd)}", error=True)
                    return False
                    
            # Verify monitor mode is enabled
            return self._check_monitor_mode(interface)
            
        except Exception as e:
            self.log(f"Error enabling monitor mode: {str(e)}", error=True)
            return False
    
    def start_capture(self, bpf_filter: str = None, duration: int = None) -> bool:
        """Start capturing packets on the set interface
        
        Args:
            bpf_filter: Berkeley Packet Filter string
            duration: Duration to capture in seconds (None = until stopped)
            
        Returns:
            bool: True if capture started successfully
        """
        if self.capture_running:
            self.log("Packet capture already running", warning=True)
            return False
            
        if not self.interface:
            self.log("No interface set for packet capture", error=True)
            return False
            
        # Reset stats and clear packets
        self.packets = []
        self.packet_stats = {k: 0 for k in self.packet_stats}
        self.sensitive_data_findings = []
        self.latest_traffic_data = []
        self.detected_vulnerabilities = []
        self.stop_event.clear()
        
        # Create pcap file for this capture
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_pcap = os.path.join(self.working_dir, f"capture_{timestamp}.pcap")
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(bpf_filter, duration),
            daemon=True
        )
        self.capture_thread.start()
        self.capture_running = True
        
        self.log(f"Started packet capture on {self.interface}", success=True)
        return True
    
    def stop_capture(self) -> bool:
        """Stop the current packet capture
        
        Returns:
            bool: True if capture was stopped
        """
        if not self.capture_running:
            return False
            
        self.stop_event.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
            
        self.capture_running = False
        self.log("Stopped packet capture", success=True)
        
        # Save captured packets to pcap file
        if self.packets and self.current_pcap:
            try:
                wrpcap(self.current_pcap, self.packets)
                self.log(f"Saved {len(self.packets)} packets to {os.path.basename(self.current_pcap)}", success=True)
            except Exception as e:
                self.log(f"Error saving pcap: {str(e)}", error=True)
        
        return True
    
    def _capture_packets(self, bpf_filter: str = None, duration: int = None):
        """Background thread for packet capture
        
        Args:
            bpf_filter: Berkeley Packet Filter string
            duration: Duration in seconds
        """
        end_time = None
        if duration:
            end_time = time.time() + duration
            
        try:
            # Configure sniff parameters
            kwargs = {
                "iface": self.interface,
                "prn": self._process_packet,
                "store": False,  # Don't store in memory, we do it manually
                "stop_filter": lambda _: self.stop_event.is_set()
            }
            
            if bpf_filter:
                kwargs["filter"] = bpf_filter
                
            if duration:
                # Need to modify the stop filter to check both time and event
                original_stop = kwargs["stop_filter"]
                kwargs["stop_filter"] = lambda p: original_stop(p) or time.time() > end_time
                
            # Start sniffing - this blocks until stop_filter returns True
            sniff(**kwargs)
            
        except Exception as e:
            self.log(f"Error in packet capture: {str(e)}", error=True)
            
        finally:
            self.capture_running = False
    
    def _process_packet(self, packet: Packet):
        """Process a single captured packet
        
        This is called for each packet by scapy's sniff function
        
        Args:
            packet: Scapy packet object
        """
        # Store packet
        self.packets.append(packet)
        
        # Update overall stats
        self.packet_stats["total"] += 1
        
        # Update protocol stats
        if TCP in packet:
            self.packet_stats["tcp"] += 1
            
            # Check for HTTP
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                self.packet_stats["http"] += 1
                # Process for sensitive data
                self._process_http_packet(packet)
                
            # Check for HTTPS (port 443)
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                self.packet_stats["https"] += 1
                
        elif UDP in packet:
            self.packet_stats["udp"] += 1
            
            # Check for DNS
            if packet.haslayer(DNS):
                self.packet_stats["dns"] += 1
                # Process DNS for domain intel
                self._process_dns_packet(packet)
                
            # Check for DHCP
            elif packet.haslayer(DHCP) or packet.haslayer(BOOTP):
                self.packet_stats["dhcp"] += 1
                
        elif ICMP in packet:
            self.packet_stats["icmp"] += 1
            
        elif ARP in packet:
            self.packet_stats["arp"] += 1
            # Process ARP for spoofing detection
            self._process_arp_packet(packet)
            
        else:
            self.packet_stats["other"] += 1
        
        # Check for 802.11 (WiFi) specific traffic
        if Dot11 in packet:
            self._process_wifi_packet(packet)
            
        # Store recent traffic for visualization (IP only)
        if IP in packet:
            self._add_traffic_data_point(packet)
            
        # Run anomaly detection periodically (every 100 packets)
        if len(self.packets) % 100 == 0 and self.anomaly_detector and not self.dev_mode:
            self._detect_anomalies()
    
    def _process_http_packet(self, packet: Packet):
        """Process HTTP packet for sensitive data
        
        Args:
            packet: Scapy packet with HTTP layer
        """
        # Don't process non-HTTP packets
        if not (TCP in packet and (HTTPRequest in packet or HTTPResponse in packet)):
            return
            
        # Try to get raw payload
        try:
            payload = bytes(packet[TCP].payload)
            
            # Check for sensitive patterns
            patterns = {
                "Password": rb'(?i)password["\s:=]+([^&"\s]+)',
                "Username": rb'(?i)username["\s:=]+([^&"\s]+)',
                "Email": rb'(?i)[\w\.-]+@[\w\.-]+\.\w+',
                "Credit Card": rb'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})',
                "Social Security Number": rb'\b(?!000|666|9)[0-8][0-9]{2}[- ](?!00)[0-9]{2}[- ](?!0000)[0-9]{4}\b',
                "API Key": rb'(?i)([\"]?(?:api[_-]?key|access[_-]?key|secret[_-]?key|app[_-]?key)[\"]?[\\]?\s*[:]?[\\]?\s*[\"])([^"\s]+)',
                "Authentication Token": rb'(?i)(auth(?:entication|orization)?[_-]?token|bearer)(?:[\s:=]+)([^&\s]+)',
                "Private Key": rb'-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----',
                "AWS Key": rb'AKIA[0-9A-Z]{16}',
                "Google API Key": rb'(?i)(AIza[0-9A-Za-z\-_]{35})'
            }
            
            # Source and destination
            src = None
            dst = None
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
            
            # Check each pattern
            for data_type, pattern in patterns.items():
                matches = re.findall(pattern, payload)
                if matches:
                    for match in matches:
                        # If match is a tuple, get the captured group
                        if isinstance(match, tuple):
                            match = match[1] if len(match) > 1 else match[0]
                            
                        # Add to findings
                        finding = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": data_type,
                            "src": src,
                            "dst": dst,
                            "value": match.decode('utf-8', errors='replace'),
                            "protocol": "HTTP",
                            "packet_num": len(self.packets) - 1  # Link to packet for reference
                        }
                        
                        self.sensitive_data_findings.append(finding)
                        self.log(f"Found sensitive data: {data_type} from {src} to {dst}", warning=True)
                        
            # Look for services and versions for CVE matching
            if HTTPRequest in packet:
                host = None
                if hasattr(packet[HTTPRequest], 'Host'):
                    host = packet[HTTPRequest].Host.decode('utf-8', errors='replace')
                    
                # Look for User-Agent with version info
                if hasattr(packet[HTTPRequest], 'User_Agent'):
                    ua = packet[HTTPRequest].User_Agent.decode('utf-8', errors='replace')
                    self._check_ua_for_vulnerabilities(ua, host, dst)
                    
            elif HTTPResponse in packet:
                # Check for Server header with version info
                if hasattr(packet[HTTPResponse], 'Server'):
                    server = packet[HTTPResponse].Server.decode('utf-8', errors='replace')
                    self._check_server_for_vulnerabilities(server, src)
                    
        except Exception as e:
            # Silently fail on parsing errors
            pass
    
    def _process_dns_packet(self, packet: Packet):
        """Process DNS packet for domain intelligence
        
        Args:
            packet: Scapy packet with DNS layer
        """
        if not packet.haslayer(DNS):
            return
            
        try:
            dns = packet[DNS]
            
            # Process DNS queries
            if dns.qr == 0:  # Query
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')
                    
                    # Check for suspicious domains (C2 servers, etc)
                    suspicious_tlds = ['.top', '.xyz', '.club', '.cc', '.pw']
                    suspicious = any(qname.endswith(tld) for tld in suspicious_tlds)
                    
                    if suspicious or (len(qname) > 30 and qname.count('.') > 3):
                        finding = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "Suspicious DNS Query",
                            "value": qname,
                            "protocol": "DNS",
                            "packet_num": len(self.packets) - 1
                        }
                        self.sensitive_data_findings.append(finding)
                        self.log(f"Suspicious DNS query: {qname}", warning=True)
                        
            # Process DNS responses
            elif dns.qr == 1:  # Response
                if packet.haslayer(DNSRR):
                    for i in range(dns.ancount):
                        rr = dns.an[i]
                        rrname = rr.rrname.decode('utf-8', errors='replace').rstrip('.')
                        
                        # Record if it's an A or AAAA record
                        if rr.type in (1, 28):  # A or AAAA record
                            if hasattr(rr, 'rdata'):
                                ip = rr.rdata
                                if isinstance(ip, bytes):
                                    ip = ip.decode('utf-8', errors='replace')
                                
                                # Map domain to IP
                                finding = {
                                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "type": "DNS Resolution",
                                    "domain": rrname,
                                    "ip": ip,
                                    "protocol": "DNS",
                                    "packet_num": len(self.packets) - 1
                                }
                                
                                # Add to findings if this is a suspicious domain
                                suspicious_tlds = ['.top', '.xyz', '.club', '.cc', '.pw']
                                suspicious = any(rrname.endswith(tld) for tld in suspicious_tlds)
                                
                                if suspicious or (len(rrname) > 30 and rrname.count('.') > 3):
                                    self.sensitive_data_findings.append(finding)
                                    self.log(f"Suspicious domain resolved: {rrname} → {ip}", warning=True)
                                
        except Exception as e:
            # Silently fail on parsing errors
            pass
    
    def _process_arp_packet(self, packet: Packet):
        """Process ARP packet for spoofing detection
        
        Args:
            packet: Scapy packet with ARP layer
        """
        if not packet.haslayer(ARP):
            return
            
        try:
            arp = packet[ARP]
            
            # Store MAC to IP mappings
            if arp.op == 1:  # who-has (request)
                pass
            elif arp.op == 2:  # is-at (response)
                # Check for ARP spoofing (same IP, different MAC)
                ip = arp.psrc
                mac = arp.hwsrc
                
                # Basic ARP spoofing detection
                # For real implementation, we'd need to maintain an IP/MAC mapping table
                # and check for conflicts
                
        except Exception as e:
            # Silently fail on parsing errors
            pass
    
    def _process_wifi_packet(self, packet: Packet):
        """Process WiFi packet for wireless specific analysis
        
        Args:
            packet: Scapy packet with Dot11 (WiFi) layer
        """
        if not packet.haslayer(Dot11):
            return
            
        try:
            dot11 = packet[Dot11]
            
            # Extract MAC addresses
            src = dot11.addr2
            dst = dot11.addr1
            bssid = dot11.addr3
            
            # Process different WiFi packet types
            if packet.haslayer(Dot11Beacon):
                # Beacon frames contain network info
                self._process_beacon_frame(packet)
                
            elif packet.haslayer(Dot11Auth):
                # Authentication frames
                self._process_auth_frame(packet)
                
            elif packet.haslayer(Dot11AssoReq) or packet.haslayer(Dot11AssoResp):
                # Association frames
                self._process_assoc_frame(packet)
                
        except Exception as e:
            # Silently fail on parsing errors
            pass
    
    def _process_beacon_frame(self, packet: Packet):
        """Process WiFi beacon frame for network info
        
        Args:
            packet: Scapy packet with Dot11Beacon layer
        """
        try:
            # Get the SSID
            essid = None
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
                essid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
                
            # Get BSSID (MAC)
            bssid = packet[Dot11].addr3
            
            # Only process if we have both
            if essid and bssid:
                # This would be part of a more complete wireless analysis feature
                pass
                
        except Exception as e:
            # Silently fail on parsing errors
            pass
    
    def _process_auth_frame(self, packet: Packet):
        """Process WiFi authentication frame
        
        Args:
            packet: Scapy packet with Dot11Auth layer
        """
        try:
            auth = packet[Dot11Auth]
            
            # Detect deauthentication attacks
            if auth.status == 0:  # Successful auth
                pass
            else:
                # Auth failure - could be normal or part of an attack
                pass
                
        except Exception as e:
            # Silently fail on parsing errors
            pass
    
    def _process_assoc_frame(self, packet: Packet):
        """Process WiFi association frame
        
        Args:
            packet: Scapy packet with Dot11AssoReq or Dot11AssoResp layer
        """
        try:
            # Could be used to track client associations with networks
            pass
                
        except Exception as e:
            # Silently fail on parsing errors
            pass
    
    def _add_traffic_data_point(self, packet: Packet):
        """Add a data point for traffic visualization
        
        Args:
            packet: Scapy packet with IP layer
        """
        if not IP in packet:
            return
            
        try:
            # Basic data point with timestamp
            data_point = {
                "timestamp": datetime.now(),
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "proto": packet[IP].proto,
                "size": len(packet),
            }
            
            # Add layer-specific info
            if TCP in packet:
                data_point["sport"] = packet[TCP].sport
                data_point["dport"] = packet[TCP].dport
                
                # Detect service
                service = "unknown"
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    service = "http"
                elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    service = "https"
                elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                    service = "ssh"
                elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    service = "ftp"
                    
                data_point["service"] = service
                
            elif UDP in packet:
                data_point["sport"] = packet[UDP].sport
                data_point["dport"] = packet[UDP].dport
                
                # Detect service
                service = "unknown"
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    service = "dns"
                elif packet[UDP].dport == 67 or packet[UDP].dport == 68:
                    service = "dhcp"
                    
                data_point["service"] = service
                
            # Keep only recent traffic (last 500 packets)
            self.latest_traffic_data.append(data_point)
            if len(self.latest_traffic_data) > 500:
                self.latest_traffic_data.pop(0)
                
        except Exception as e:
            # Silently fail
            pass
    
    def _detect_anomalies(self):
        """Use machine learning to detect traffic anomalies"""
        if not self.anomaly_detector or len(self.latest_traffic_data) < 50:
            return
            
        try:
            # Extract features for anomaly detection
            features = []
            
            # Group by source/destination pairs
            flow_data = {}
            for dp in self.latest_traffic_data:
                flow_key = f"{dp['src']}:{dp['dst']}"
                if flow_key not in flow_data:
                    flow_data[flow_key] = []
                flow_data[flow_key].append(dp)
                
            # Extract features for each flow
            for flow_key, flow in flow_data.items():
                if len(flow) < 3:
                    continue
                    
                # Calculate features
                sizes = [dp["size"] for dp in flow]
                times = [(dp["timestamp"] - flow[0]["timestamp"]).total_seconds() for dp in flow]
                
                # Skip if timeline is too short
                if max(times) < 0.1:
                    continue
                    
                # Statistical features
                avg_size = np.mean(sizes)
                std_size = np.std(sizes)
                max_size = max(sizes)
                min_size = min(sizes)
                avg_interval = np.mean(np.diff(times))
                std_interval = np.std(np.diff(times))
                pkt_rate = len(flow) / max(times)
                
                # Create feature vector
                feature = [
                    avg_size, std_size, max_size, min_size,
                    avg_interval, std_interval, pkt_rate
                ]
                
                features.append((flow_key, feature))
                
            # Run anomaly detection if we have enough flows
            if len(features) > 5:
                # Extract feature matrix
                X = np.array([f[1] for f in features])
                
                # Fit and predict
                self.anomaly_detector.fit(X)
                y_pred = self.anomaly_detector.predict(X)
                
                # Find anomalies
                for i, pred in enumerate(y_pred):
                    if pred == -1:  # Anomaly
                        flow_key = features[i][0]
                        src, dst = flow_key.split(':')
                        
                        finding = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "Traffic Anomaly",
                            "src": src,
                            "dst": dst,
                            "details": "Unusual traffic pattern detected",
                            "severity": "Medium"
                        }
                        
                        # Add to findings
                        self.sensitive_data_findings.append(finding)
                        self.log(f"Anomaly detected in traffic flow {src} → {dst}", warning=True)
                
        except Exception as e:
            # ML errors should not crash the capture
            self.log(f"Error in anomaly detection: {str(e)}", error=True)
    
    def _check_ua_for_vulnerabilities(self, user_agent: str, host: str, dst: str):
        """Check User-Agent for potential vulnerabilities
        
        Args:
            user_agent: User-Agent string
            host: HTTP Host header
            dst: Destination IP
        """
        if not self.cve_database:
            return
            
        try:
            # Extract browser/software info from User-Agent
            browser_match = re.search(r'(Chrome|Firefox|Safari|Edge|MSIE|Trident)/(\d+\.\d+)', user_agent)
            if browser_match:
                browser = browser_match.group(1).lower()
                version = browser_match.group(2)
                
                # Check for CVEs related to this browser/version
                cves = []
                for service, vulns in self.cve_database.items():
                    if browser in service.lower():
                        for vuln in vulns:
                            if 'version' in vuln and version.startswith(vuln['version']):
                                cves.append(vuln)
                
                # Report any findings
                if cves:
                    for cve in cves:
                        vulnerability = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "Client Vulnerability",
                            "ip": dst,
                            "service": browser,
                            "version": version,
                            "cve_id": cve.get("cve_id", "Unknown"),
                            "title": cve.get("title", "Unknown vulnerability"),
                            "severity": "Medium"  # Could compute based on CVSS
                        }
                        
                        self.detected_vulnerabilities.append(vulnerability)
                        self.log(f"Potential client vulnerability: {browser} {version} - {cve.get('title')}", warning=True)
                        
        except Exception as e:
            # Silently fail on parsing errors
            pass
    
    def _check_server_for_vulnerabilities(self, server: str, src: str):
        """Check Server header for potential vulnerabilities
        
        Args:
            server: Server header string
            src: Source IP
        """
        if not self.cve_database:
            return
            
        try:
            # Extract server software info
            server_match = re.search(r'([a-zA-Z0-9_-]+)/(\d+\.\d+\.?\d*)', server)
            if server_match:
                software = server_match.group(1).lower()
                version = server_match.group(2)
                
                # Check for CVEs related to this server/version
                cves = []
                for service, vulns in self.cve_database.items():
                    if software in service.lower():
                        for vuln in vulns:
                            if 'version' in vuln and version.startswith(vuln['version']):
                                cves.append(vuln)
                
                # Report any findings
                if cves:
                    for cve in cves:
                        vulnerability = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "Server Vulnerability",
                            "ip": src,
                            "service": software,
                            "version": version,
                            "cve_id": cve.get("cve_id", "Unknown"),
                            "title": cve.get("title", "Unknown vulnerability"),
                            "severity": "High"  # Server vulns are typically more severe
                        }
                        
                        self.detected_vulnerabilities.append(vulnerability)
                        self.log(f"Potential server vulnerability: {software} {version} - {cve.get('title')}", error=True)
                        
        except Exception as e:
            # Silently fail on parsing errors
            pass
    
    def analyze_pcap(self, pcap_file: str = None) -> Dict:
        """Analyze a pcap file and generate statistics
        
        Args:
            pcap_file: Path to pcap file (or use the last captured file)
            
        Returns:
            Dict: Analysis results
        """
        if not pcap_file and not self.current_pcap:
            self.log("No pcap file specified and no capture has been performed", error=True)
            return {}
            
        pcap_file = pcap_file or self.current_pcap
        
        if not os.path.exists(pcap_file):
            self.log(f"PCAP file not found: {pcap_file}", error=True)
            return {}
            
        try:
            self.analyzing = True
            self.log(f"Analyzing pcap file: {os.path.basename(pcap_file)}", success=True)
            
            # Reset state for analysis
            self.packets = []
            self.packet_stats = {k: 0 for k in self.packet_stats}
            self.sensitive_data_findings = []
            self.latest_traffic_data = []
            self.detected_vulnerabilities = []
            
            # Load packets
            try:
                # Read from pcap
                self.log("Loading packets from pcap file...", warning=True)
                packets = rdpcap(pcap_file)
                
                # Process each packet
                for i, packet in enumerate(packets):
                    if i % 1000 == 0:
                        self.log(f"Processed {i} packets...", success=True)
                    self._process_packet(packet)
                    
                self.log(f"Completed analysis of {len(packets)} packets", success=True)
                
            except Exception as e:
                self.log(f"Error reading pcap file: {str(e)}", error=True)
                
            # Generate summary report
            summary = {
                "packet_count": len(self.packets),
                "protocol_stats": self.packet_stats,
                "sensitive_data_count": len(self.sensitive_data_findings),
                "vulnerability_count": len(self.detected_vulnerabilities),
                "analyzed_file": os.path.basename(pcap_file),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            return summary
            
        except Exception as e:
            self.log(f"Error in pcap analysis: {str(e)}", error=True)
            return {}
        finally:
            self.analyzing = False
    
    def generate_traffic_graph(self, canvas=None, graph_type="timeline"):
        """Generate and display traffic visualization
        
        Args:
            canvas: Matplotlib canvas for embedding in tkinter
            graph_type: Type of graph to generate (timeline, flows, protocols)
            
        Returns:
            matplotlib.figure.Figure or None
        """
        if not self.latest_traffic_data:
            return None
            
        try:
            # Create figure
            fig = plt.figure(figsize=(10, 5))
            ax = fig.add_subplot(111)
            
            if graph_type == "timeline":
                # Timeline graph showing packet sizes over time
                timestamps = [dp["timestamp"] for dp in self.latest_traffic_data]
                sizes = [dp["size"] for dp in self.latest_traffic_data]
                
                # Convert to relative timestamps for easier readability
                base_time = min(timestamps)
                rel_times = [(t - base_time).total_seconds() for t in timestamps]
                
                # Create scatter plot
                ax.scatter(rel_times, sizes, alpha=0.6, s=10)
                ax.set_xlabel("Time (seconds)")
                ax.set_ylabel("Packet Size (bytes)")
                ax.set_title("Packet Size Timeline")
                
                # Add grid and tight layout
                ax.grid(True, linestyle="--", alpha=0.6)
                fig.tight_layout()
                
            elif graph_type == "protocols":
                # Protocol distribution
                if len(self.packet_stats) > 0:
                    # Get protocols and counts, skip 'total'
                    protocols = [k for k in self.packet_stats.keys() if k != "total"]
                    counts = [self.packet_stats[k] for k in protocols]
                    
                    # Create bar chart
                    ax.bar(protocols, counts)
                    ax.set_xlabel("Protocol")
                    ax.set_ylabel("Packet Count")
                    ax.set_title("Protocol Distribution")
                    
                    # Add value labels above bars
                    for i, count in enumerate(counts):
                        ax.text(i, count + 0.5, str(count), ha='center')
                        
                    # Adjust layout
                    fig.tight_layout()
                    
            elif graph_type == "flows":
                # Flow graph showing connections between hosts
                if len(self.latest_traffic_data) > 0:
                    # Extract unique source-destination pairs
                    flows = {}
                    for dp in self.latest_traffic_data:
                        key = f"{dp['src']}_{dp['dst']}"
                        if key not in flows:
                            flows[key] = {
                                "src": dp["src"],
                                "dst": dp["dst"],
                                "count": 0,
                                "bytes": 0
                            }
                        flows[key]["count"] += 1
                        flows[key]["bytes"] += dp["size"]
                    
                    # Get top 10 flows by byte count
                    top_flows = sorted(flows.values(), key=lambda x: x["bytes"], reverse=True)[:10]
                    
                    # Create bar chart for top flows
                    labels = [f"{f['src']}\n↓\n{f['dst']}" for f in top_flows]
                    values = [f["bytes"] for f in top_flows]
                    
                    ax.bar(labels, values)
                    ax.set_xlabel("Communication Flow")
                    ax.set_ylabel("Bytes Transferred")
                    ax.set_title("Top Traffic Flows (Bytes)")
                    
                    # Rotate labels for better readability
                    plt.xticks(rotation=90)
                    
                    # Adjust layout
                    fig.tight_layout()
                
            # Display on the provided canvas
            if canvas:
                canvas.figure = fig
                canvas.draw()
                
            return fig
            
        except Exception as e:
            self.log(f"Error generating traffic graph: {str(e)}", error=True)
            return None
    
    def export_findings(self, filename: str) -> bool:
        """Export findings to a JSON file
        
        Args:
            filename: Output filename
            
        Returns:
            bool: True if export was successful
        """
        try:
            # Prepare data for export
            export_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "packet_stats": self.packet_stats,
                "sensitive_data": self.sensitive_data_findings,
                "vulnerabilities": self.detected_vulnerabilities,
                "pcap_file": os.path.basename(self.current_pcap) if self.current_pcap else None
            }
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            
            # Write to file
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
                
            self.log(f"Exported findings to {filename}", success=True)
            return True
            
        except Exception as e:
            self.log(f"Error exporting findings: {str(e)}", error=True)
            return False
    
    def get_network_interfaces(self) -> List[str]:
        """Get list of available network interfaces
        
        Returns:
            List[str]: Network interfaces
        """
        interfaces = []
        
        try:
            if self.dev_mode:
                # In development mode, return sample interfaces
                interfaces = ["wlan0", "wlan1", "eth0", "mon0"]
            else:
                # In real mode, use actual system interfaces
                try:
                    # Use ip command to get interfaces
                    result = subprocess.run(
                        ["ip", "-o", "link", "show"],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    
                    # Parse output
                    for line in result.stdout.splitlines():
                        parts = line.strip().split(":", 2)
                        if len(parts) >= 2:
                            iface = parts[1].strip()
                            # Skip loopback
                            if iface != "lo" and not iface.startswith("docker") and not iface.startswith("br-"):
                                interfaces.append(iface)
                                
                except Exception:
                    # Fall back to iwconfig
                    try:
                        result = subprocess.run(
                            ["iwconfig"],
                            capture_output=True,
                            text=True,
                            check=False
                        )
                        
                        # Parse output - iwconfig will show wireless interfaces
                        current_iface = None
                        for line in result.stdout.splitlines():
                            if not line.startswith(" "):
                                current_iface = line.split()[0]
                                if current_iface not in interfaces:
                                    interfaces.append(current_iface)
                    except:
                        # Last resort - try some common interfaces
                        interfaces = ["wlan0", "wlan1", "eth0", "mon0"]
        
        except Exception as e:
            self.log(f"Error getting network interfaces: {str(e)}", error=True)
            # Return some defaults
            interfaces = ["wlan0", "eth0"]
            
        return interfaces
    
    def cleanup(self):
        """Clean up resources on exit"""
        # Stop any running capture
        if self.capture_running:
            self.stop_capture()
            
        # Cleanup any temp files
        try:
            if os.path.exists(self.working_dir):
                shutil.rmtree(self.working_dir)
        except:
            pass