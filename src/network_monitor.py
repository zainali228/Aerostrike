#!/usr/bin/env python3
"""
Network Traffic Monitor - Simplified
A streamlined interface for monitoring network traffic and detecting sensitive data
"""

import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime
import subprocess
import tempfile
from typing import Dict, List, Any, Optional

# Try to import optional dependencies with graceful fallbacks
try:
    from scapy.all import sniff, wrpcap, rdpcap, Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.l2 import ARP
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available, packet analysis will be limited")

import re  # Required for sensitive data detection

class NetworkMonitor:
    """Simplified Network Traffic Monitor focused on security alerts"""
    
    def __init__(self, parent, dark_mode=True, controller=None):
        """Initialize the simplified network monitor
        
        Args:
            parent: Parent frame/widget
            dark_mode: Whether to use dark mode
            controller: Reference to the main application controller
        """
        self.parent = parent
        self.dark_mode = dark_mode
        self.controller = controller
        
        # Get the root window from the parent widget
        try:
            self.root = parent.winfo_toplevel()
        except:
            self.root = None
        
        # Configure basic styles
        self.bg_color = "#2d2d2d" if dark_mode else "#f0f0f0"
        self.fg_color = "#ffffff" if dark_mode else "#000000"
        self.accent_color = "#9F44D3"  # Purple accent
        self.highlight_color = "#480B86" if dark_mode else "#c880ff"
        self.warning_color = "#ffb142"
        self.error_color = "#ff5252"
        self.success_color = "#2ed573"
        
        # Initialize state variables
        self.current_packets = []
        self.packet_count = 0
        self.interface_var = tk.StringVar()
        self.monitor_mode = tk.BooleanVar(value=False)
        self.is_capturing = False
        self.capture_thread = None
        self.stop_event = threading.Event()
        self.sensitive_data_findings = []
        
        # Setup UI
        self.setup_ui()
    
    def setup_ui(self):
        """Create all UI elements"""
        try:
            self.parent["bg"] = self.bg_color  # More compatible approach
        except:
            pass  # Ignore if this fails
        
        # Create header frame
        self.create_header()
        
        # Create main content
        self.create_main_content()
        
        # Create status bar
        self.create_status_bar()
        
        # Set initial status
        if SCAPY_AVAILABLE:
            self.log("Ready to start network traffic monitoring.", success=True)
        else:
            self.log("Limited functionality: Scapy not available.", warning=True)
    
    def create_header(self):
        """Create simplified header with essential controls"""
        header_frame = ttk.Frame(self.parent)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Title
        title_label = ttk.Label(
            header_frame,
            text="Network Traffic Monitor",
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(side=tk.LEFT, padx=5)
        
        # Controls frame on right
        controls_frame = ttk.Frame(header_frame)
        controls_frame.pack(side=tk.RIGHT, padx=5)
        
        # Interface selection
        ttk.Label(controls_frame, text="Interface:").pack(side=tk.LEFT, padx=(10, 5))
        self.interface_combo = ttk.Combobox(
            controls_frame, 
            textvariable=self.interface_var,
            width=12
        )
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        # Populate interfaces
        self._refresh_interfaces()
        
        # Monitor mode checkbox 
        monitor_check = ttk.Checkbutton(
            controls_frame,
            text="Monitor Mode",
            variable=self.monitor_mode
        )
        monitor_check.pack(side=tk.LEFT, padx=5)
        
        # Start/Stop button
        self.capture_btn = ttk.Button(
            controls_frame,
            text="Start Capture",
            command=self.toggle_capture,
            width=15
        )
        self.capture_btn.pack(side=tk.LEFT, padx=10)
        
        # Simple Import button (like Export button)
        self.import_btn = ttk.Button(
            controls_frame,
            text="Import",
            command=self.import_capture_file,
            width=10
        )
        self.import_btn.pack(side=tk.LEFT, padx=5)
    
    def create_main_content(self):
        """Create simplified main content with essentials only"""
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Sensitive Data Alerts Section (Top Priority)
        alerts_frame = ttk.LabelFrame(main_frame, text="🔴 SENSITIVE DATA ALERTS")
        alerts_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create scrollable alert display
        self.alerts_text = scrolledtext.ScrolledText(
            alerts_frame,
            wrap=tk.WORD,
            width=60,
            height=6,
            font=("Consolas", 10),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground="#ff5252"  # Always red for sensitive data
        )
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.alerts_text.insert(tk.END, "No sensitive data detected yet. Start capturing to monitor for passwords, API keys, and tokens.\n")
        self.alerts_text.config(state=tk.DISABLED)
        
        # Network Traffic
        packets_frame = ttk.LabelFrame(main_frame, text="Network Traffic")
        packets_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create simplified packet tree
        columns = ("No", "Time", "Source", "Destination", "Protocol", "Info")
        self.packet_tree = ttk.Treeview(
            packets_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns - simplified
        self.packet_tree.heading("No", text="#")
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.heading("Source", text="Source")
        self.packet_tree.heading("Destination", text="Destination")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Info", text="Important Info")
        
        self.packet_tree.column("No", width=50, stretch=False)
        self.packet_tree.column("Time", width=80, stretch=False)
        self.packet_tree.column("Source", width=150)
        self.packet_tree.column("Destination", width=150)
        self.packet_tree.column("Protocol", width=80, stretch=False)
        self.packet_tree.column("Info", width=300)
        
        # Add scrollbar
        packet_scroll = ttk.Scrollbar(packets_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scroll.set)
        
        # Pack tree and scrollbar
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        packet_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Set up event handlers
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        
        # Packet Details (Simple Version)
        details_frame = ttk.LabelFrame(main_frame, text="Packet Details")
        details_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            width=60,
            height=8,
            font=("Consolas", 10),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground="#cccccc" if self.dark_mode else "#000000"
        )
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.details_text.insert(tk.END, "Select a packet to view details\n")
        self.details_text.config(state=tk.DISABLED)
    
    def create_status_bar(self):
        """Create status bar at the bottom"""
        status_frame = ttk.Frame(self.parent)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(
            status_frame, 
            textvariable=self.status_var,
            anchor=tk.W
        )
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Packet count label
        self.count_var = tk.StringVar(value="Packets: 0")
        count_label = ttk.Label(
            status_frame,
            textvariable=self.count_var
        )
        count_label.pack(side=tk.RIGHT)
    
    def _refresh_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        
        try:
            if os.name == 'posix':  # Linux/Mac
                # Use ip link show
                output = subprocess.check_output(['ip', 'link', 'show'], universal_newlines=True)
                for line in output.splitlines():
                    if ': ' in line:
                        iface = line.split(': ')[1]
                        interfaces.append(iface)
            else:  # Windows
                if SCAPY_AVAILABLE:
                    try:
                        from scapy.arch import get_windows_if_list
                        win_interfaces = get_windows_if_list()
                        for iface in win_interfaces:
                            if 'name' in iface:
                                interfaces.append(iface['name'])
                    except ImportError:
                        # Fallback to basic interfaces on Windows
                        interfaces = ["Ethernet", "Wi-Fi"]
        except Exception as e:
            print(f"Error getting interfaces: {str(e)}")
            interfaces = ["eth0", "wlan0"]  # Fallback
        
        # Update the combobox
        self.interface_combo['values'] = interfaces
        if interfaces and not self.interface_var.get():
            self.interface_var.set(interfaces[0])
    
    def log(self, message, error=False, warning=False, success=False):
        """Log message to status bar"""
        color = self.fg_color
        if error:
            color = self.error_color
        elif warning:
            color = self.warning_color
        elif success:
            color = self.success_color
            
        self.status_var.set(message)
        
        # Log to console for debugging
        print(f"[NetworkMonitor] {message}")
    
    def toggle_capture(self):
        """Start or stop packet capture"""
        if self.is_capturing:
            self.stop_capture()
        else:
            self.start_capture()
    
    def start_capture(self):
        """Start capturing packets on selected interface"""
        if self.is_capturing:
            return
            
        # Check if scapy is available
        if not SCAPY_AVAILABLE:
            self.log("Cannot start capture: Scapy not available", error=True)
            messagebox.showerror("Error", "Scapy is required for packet capture but is not installed.")
            return
            
        interface = self.interface_var.get()
        if not interface:
            self.log("No interface selected", error=True)
            return
            
        # Set monitor mode if requested
        if self.monitor_mode.get():
            self._set_monitor_mode(interface, True)
        
        # Clear existing packets
        self.current_packets = []
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
            
        # Clear alerts
        self.sensitive_data_findings = []
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        self.alerts_text.insert(tk.END, "Monitoring for sensitive data...\n")
        self.alerts_text.config(state=tk.DISABLED)
        
        # Reset packet counter
        self.packet_count = 0
        self.count_var.set("Packets: 0")
        
        # Update UI state
        self.is_capturing = True
        self.capture_btn.config(text="Stop Capture")
        
        # Reset stop event
        self.stop_event.clear()
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface,)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        self.log(f"Started capture on {interface}", success=True)
    
    def stop_capture(self):
        """Stop the packet capture"""
        if not self.is_capturing:
            return
            
        self.log("Stopping capture...")
        self.stop_event.set()
        
        # Wait for thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)
        
        # Update UI state
        self.is_capturing = False
        self.capture_btn.config(text="Start Capture")
        
        # Disable monitor mode if it was enabled
        if self.monitor_mode.get():
            interface = self.interface_var.get()
            self._set_monitor_mode(interface, False)
            
        self.log("Capture stopped", success=True)
    
    def _capture_packets(self, interface):
        """Thread for capturing packets"""
        try:
            def packet_callback(packet):
                if self.stop_event.is_set():
                    return True  # Stop sniffing
                
                # Process packet
                self._process_packet(packet)
                return False  # Continue sniffing
            
            # Start sniffing
            sniff(
                iface=interface,
                prn=packet_callback,
                store=False,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            if self.root:
                self.root.after(0, lambda: self.log(f"Capture error: {str(e)}", error=True))
            else:
                print(f"Capture error: {str(e)}")
    
    def _process_packet(self, packet):
        """Process a single packet"""
        # Add to packet list
        self.current_packets.append(packet)
        self.packet_count += 1
        
        # Extract packet info
        packet_info = self._extract_packet_info(packet)
        
        # Add to tree
        if self.root:
            self.root.after(0, lambda: self._add_packet_to_tree(packet_info))
            
            # Update counter
            self.root.after(0, lambda: self.count_var.set(f"Packets: {self.packet_count}"))
            
            # Check for sensitive data
            self._check_for_sensitive_data(packet, packet_info)
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        packet_time = datetime.now().strftime("%H:%M:%S")
        src = "Unknown"
        dst = "Unknown"
        proto = "Unknown"
        info = "Unknown"
        
        # Get main IP details if present
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            
            # Determine protocol
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                info = f"{sport} → {dport}"
                
                # Attempt to identify service
                if dport == 80 or sport == 80:
                    proto = "HTTP"
                    # Check for HTTP data
                    if Raw in packet:
                        try:
                            http_data = packet[Raw].load.decode('utf-8', errors='ignore')
                            if "GET" in http_data or "POST" in http_data:
                                first_line = http_data.split('\r\n')[0]
                                info = first_line[:50]
                        except:
                            pass
                elif dport == 443 or sport == 443:
                    proto = "HTTPS"
                elif dport == 23 or sport == 23:
                    proto = "Telnet"
                elif dport == 22 or sport == 22:
                    proto = "SSH"
                elif dport == 21 or sport == 21:
                    proto = "FTP"
                
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                info = f"{sport} → {dport}"
                
                # Check for common UDP protocols
                if dport == 53 or sport == 53:
                    proto = "DNS"
                    if DNS in packet:
                        if packet.haslayer(DNS) and packet[DNS].qr == 0:
                            if hasattr(packet[DNS], 'qd') and packet[DNS].qd:
                                try:
                                    info = f"Query: {packet[DNS].qd.qname.decode('utf-8', errors='ignore')}"
                                except:
                                    info = "DNS Query"
                        elif packet.haslayer(DNS) and packet[DNS].qr == 1:
                            info = "DNS Response"
            
            elif ICMP in packet:
                proto = "ICMP"
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                if icmp_type == 8:
                    info = "Echo request (ping)"
                elif icmp_type == 0:
                    info = "Echo reply (ping)"
                else:
                    info = f"Type: {icmp_type}, Code: {icmp_code}"
        
        # Check for ARP
        elif ARP in packet:
            proto = "ARP"
            if packet[ARP].op == 1:
                info = f"Who has {packet[ARP].pdst}?"
                src = packet[ARP].psrc
                dst = "Broadcast"
            elif packet[ARP].op == 2:
                info = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
                src = packet[ARP].psrc
                dst = packet[ARP].pdst
        
        return {
            "no": self.packet_count,
            "time": packet_time,
            "src": src,
            "dst": dst,
            "proto": proto,
            "info": info,
            "packet": packet  # Store reference to original packet
        }
    
    def _add_packet_to_tree(self, packet_info):
        """Add packet to the treeview"""
        try:
            self.packet_tree.insert(
                "",
                "end",
                values=(
                    packet_info["no"],
                    packet_info["time"],
                    packet_info["src"],
                    packet_info["dst"],
                    packet_info["proto"],
                    packet_info["info"]
                )
            )
            
            # Auto-scroll to bottom
            children = self.packet_tree.get_children()
            if children:
                self.packet_tree.see(children[-1])
                
            # Limit displayed packets to prevent UI slowdown
            if len(children) > 1000:
                # Remove oldest packets from display (not from memory)
                self.packet_tree.delete(children[0])
        except Exception as e:
            print(f"Error adding packet to tree: {str(e)}")
    
    def _check_for_sensitive_data(self, packet, packet_info):
        """Check packet for sensitive information"""
        if not Raw in packet:
            return
            
        # Convert packet payload to string for regex matching
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
        except:
            return
            
        # Setup patterns for sensitive data
        patterns = {
            "Password": [
                r'(?i)password["\s:=]+\s*([^"\s&]+)',
                r'(?i)pass["\s:=]+\s*([^"\s&]+)',
                r'(?i)pwd["\s:=]+\s*([^"\s&]+)'
            ],
            "API Key": [
                r'(?i)api[_-]?key["\s:=]+\s*([^"\s&]+)',
                r'(?i)apikey["\s:=]+\s*([^"\s&]+)',
                r'(?i)api[_-]?token["\s:=]+\s*([^"\s&]+)',
                r'(?i)access[_-]?token["\s:=]+\s*([^"\s&]+)',
                r'(?i)auth[_-]?token["\s:=]+\s*([^"\s&]+)',
                r'(?i)client[_-]?secret["\s:=]+\s*([^"\s&]+)'
            ],
            "Credit Card": [
                r'(?i)(?:\d{4}[- ]?){3}\d{4}',  # 16-digit card
                r'(?i)(?:\d{4}[- ]?){2}\d{4}'  # shortened for expiry or just last digits
            ],
            "Authentication": [
                r'(?i)bearer\s+([a-zA-Z0-9\._\-]+)',  # Bearer token
                r'(?i)basic\s+([a-zA-Z0-9+/=]+)'  # Basic auth
            ],
            "Personal Info": [
                r'(?i)ssn["\s:=]+\s*([^"\s&]+)',  # Social Security Number
                r'(?i)social["\s:=]+\s*([^"\s&]+)'  # Social Security
            ]
        }
        
        # Check all patterns for matches
        found_sensitive = False
        
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, payload)
                
                if matches:
                    found_sensitive = True
                    match_text = matches[0] if isinstance(matches[0], str) else matches[0][0]
                    
                    # Create alert info
                    alert_info = {
                        "category": category,
                        "data": match_text[:20] + "..." if len(match_text) > 20 else match_text,
                        "protocol": packet_info["proto"],
                        "src": packet_info["src"],
                        "dst": packet_info["dst"],
                        "time": packet_info["time"]
                    }
                    
                    # Add to findings
                    self.sensitive_data_findings.append(alert_info)
                    
                    # Update UI with alert
                    if self.root:
                        self.root.after(0, lambda a=alert_info: self._add_alert_to_ui(a))
                    
                    # Try to send desktop notification
                    try:
                        # Only on Linux/Mac
                        if os.name == 'posix':
                            subprocess.run([
                                'notify-send',
                                f'SECURITY ALERT: {category} Detected',
                                f'Source: {packet_info["src"]}\nDestination: {packet_info["dst"]}'
                            ], timeout=1, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    except:
                        pass
    
    def _add_alert_to_ui(self, alert):
        """Add sensitive data alert to the UI"""
        try:
            # Enable text widget
            self.alerts_text.config(state=tk.NORMAL)
            
            # Clear "no alerts" message if this is the first alert
            if len(self.sensitive_data_findings) == 1:
                self.alerts_text.delete(1.0, tk.END)
                
            # Format message
            alert_msg = f"[{alert['time']}] {alert['category']} detected: {alert['data']} ({alert['src']} → {alert['dst']})\n"
            
            # Add to text widget
            self.alerts_text.insert(tk.END, alert_msg)
            
            # Auto-scroll to bottom
            self.alerts_text.see(tk.END)
            
            # Disable text widget
            self.alerts_text.config(state=tk.DISABLED)
            
            # Show alert in status bar too
            self.log(f"ALERT: {alert['category']} detected from {alert['src']}", warning=True)
        except Exception as e:
            print(f"Error updating alert UI: {str(e)}")
    
    def on_packet_select(self, event):
        """Handle packet selection in treeview"""
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        # Get selected item
        item_id = selection[0]
        values = self.packet_tree.item(item_id, "values")
        
        if not values:
            return
            
        # Find corresponding packet
        try:
            packet_no = int(values[0])
            if 0 <= packet_no - 1 < len(self.current_packets):
                packet = self.current_packets[packet_no - 1]
                self._show_packet_details(packet)
        except (ValueError, IndexError) as e:
            print(f"Error selecting packet: {str(e)}")
    
    def _show_packet_details(self, packet):
        """Show detailed packet information"""
        if not packet:
            return
            
        # Format packet details as text
        packet_text = self._format_packet_details(packet)
        
        # Update text widget
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, packet_text)
        self.details_text.config(state=tk.DISABLED)
    
    def _format_packet_details(self, packet):
        """Format packet details as human-readable text"""
        details = []
        
        try:
            # Layer by layer breakdown
            for layer in packet.layers():
                layer_name = layer.__name__
                details.append(f"=== {layer_name} ===")
                
                # Get layer fields
                layer_instance = packet.getlayer(layer)
                layer_fields = layer_instance.fields
                
                for field, value in layer_fields.items():
                    if field != "load":  # Skip binary data
                        details.append(f"{field}: {value}")
                
                details.append("")  # Empty line between layers
            
            # Add payload if present
            if Raw in packet:
                details.append("=== Payload ===")
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    # Truncate if too long
                    if len(payload) > 500:
                        payload = payload[:500] + "... [truncated]"
                    details.append(payload)
                except:
                    details.append("[Binary data]")
        except Exception as e:
            details.append(f"Error formatting packet: {str(e)}")
        
        return "\n".join(details)
    
    def _set_monitor_mode(self, interface, enable):
        """Enable or disable monitor mode on interface"""
        if os.name != 'posix':
            self.log("Monitor mode only supported on Linux", warning=True)
            return False
            
        try:
            # Try to set monitor mode
            if enable:
                # Disable the interface first
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], 
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Set monitor mode
                subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'monitor', 'none'],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Re-enable interface
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.log(f"Monitor mode enabled on {interface}", success=True)
                return True
            else:
                # Disable the interface first
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Set managed mode
                subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'managed'],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Re-enable interface
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.log(f"Monitor mode disabled on {interface}", success=True)
                return True
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to set monitor mode: {e.stderr.decode() if e.stderr else str(e)}"
            self.log(error_msg, error=True)
            return False
        except Exception as e:
            self.log(f"Error setting monitor mode: {str(e)}", error=True)
            return False
    
    def cleanup(self):
        """Clean up resources when closing"""
        self.stop_capture()

# Standalone test
    def import_capture_file(self):
        """Simple import function - select file and analyze immediately"""
        try:
            from tkinter import filedialog
            
            # File types for capture files
            filetypes = [
                ("Capture Files", "*.pcap *.pcapng *.cap"),
                ("PCAP Files", "*.pcap"),
                ("PCAPNG Files", "*.pcapng"), 
                ("CAP Files", "*.cap"),
                ("All Files", "*.*")
            ]
            
            # Open file dialog
            filename = filedialog.askopenfilename(
                title="Select Capture File to Import and Analyze",
                filetypes=filetypes
            )
            
            if not filename:
                return
                
            self.log(f"Importing and analyzing: {os.path.basename(filename)}", success=True)
            
            # Clear existing data  
            self._clear_display_data()
            
            # Process file in background thread
            import_thread = threading.Thread(target=self._process_imported_file, args=(filename,))
            import_thread.daemon = True
            import_thread.start()
            
        except Exception as e:
            self.log(f"Error importing file: {e}", warning=True)
    
    def _clear_display_data(self):
        """Clear existing display data"""
        try:
            # Clear packet tree
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
                
            # Clear alerts
            self.alerts_text.config(state=tk.NORMAL)
            self.alerts_text.delete(1.0, tk.END)
            self.alerts_text.insert(tk.END, "Analyzing imported file for sensitive data...\n")
            self.alerts_text.config(state=tk.DISABLED)
            
            # Reset counters
            self.packet_count = 0
            self.sensitive_data_findings = []
            
        except Exception as e:
            self.log(f"Error clearing data: {e}", warning=True)
    
    def _process_imported_file(self, filename):
        """Process imported capture file and analyze for sensitive data"""
        try:
            if not SCAPY_AVAILABLE:
                self.log("Cannot process file: Scapy not available", warning=True)
                return
                
            self.log("Analyzing capture file for sensitive data...", success=True)
            
            # Read packets from file
            from scapy.all import rdpcap
            packets = rdpcap(filename)
            
            total_packets = len(packets)
            self.log(f"Loaded {total_packets} packets from file", success=True)
            
            # Reset counters
            self.packet_count = 0
            self.sensitive_data_findings = []
            
            # Process each packet
            for i, packet in enumerate(packets):
                try:
                    # Update progress every 100 packets
                    if i % 100 == 0:
                        progress = (i / total_packets) * 100
                        self.log(f"Processing... {progress:.1f}% complete", success=True)
                    
                    # Process packet for sensitive data
                    self._process_packet_for_sensitive_data(packet)
                    
                    # Add to packet display (limit to last 1000 for performance)
                    if self.packet_count < 1000:
                        packet_info = self._extract_packet_info(packet)
                        if self.root:
                            self.root.after(0, lambda p=packet_info: self._add_packet_to_display(p))
                    
                    self.packet_count += 1
                    
                except Exception as e:
                    continue  # Skip problematic packets
            
            # Final summary
            sensitive_count = len(self.sensitive_data_findings)
            self.log(f"Analysis complete: {total_packets} packets processed", success=True)
            self.log(f"Found {sensitive_count} sensitive data alerts", 
                    warning=True if sensitive_count > 0 else False)
            
            # Update graphs and statistics
            if self.root:
                self.root.after(0, self._update_imported_file_stats)
            
            # Analysis complete
            self.log("Import analysis completed successfully!", success=True)
                
        except Exception as e:
            self.log(f"Error processing imported file: {e}", warning=True)
    
    def _update_imported_file_stats(self):
        """Update statistics and graphs after importing file"""
        try:
            # Update protocol statistics
            self._update_protocol_stats()
            
            # Create summary of findings
            if self.sensitive_data_findings:
                summary = {}
                for finding in self.sensitive_data_findings:
                    category = finding['category']
                    summary[category] = summary.get(category, 0) + 1
                
                # Log summary
                self.log("=== SENSITIVE DATA SUMMARY ===", success=True)
                for category, count in summary.items():
                    self.log(f"{category}: {count} instances detected", warning=True)
                
                # Save findings to file for reports
                self._save_imported_findings()
            else:
                self.log("No sensitive data detected in imported file", success=True)
                
        except Exception as e:
            self.log(f"Error updating stats: {e}", warning=True)
    
    def _save_imported_findings(self):
        """Save imported file findings for report generation"""
        try:
            import json
            
            # Prepare data structure
            import_data = {
                "source": "imported_file",
                "timestamp": datetime.now().isoformat(),
                "packets": [],
                "sensitive_data": [],
                "alerts": []
            }
            
            # Add sensitive data findings
            for finding in self.sensitive_data_findings:
                import_data["sensitive_data"].append({
                    "type": finding["category"],
                    "source": finding["src"],
                    "destination": finding["dst"],
                    "protocol": finding["protocol"],
                    "details": f"Detected in imported capture file: {finding['data']}",
                    "timestamp": finding["time"]
                })
                
                # Also add as alert
                import_data["alerts"].append({
                    "severity": "High" if finding["category"] in ["PASSWORD", "API_KEY", "TOKEN"] else "Medium",
                    "source": finding["src"],
                    "destination": finding["dst"],
                    "description": f"{finding['category']} detected in network traffic",
                    "timestamp": finding["time"]
                })
            
            # Create directory if needed
            os.makedirs("data/network_traffic", exist_ok=True)
            
            # Save to file
            with open("data/network_traffic/latest_results.json", "w") as f:
                json.dump(import_data, f, indent=2)
                
            self.log("Findings saved for report generation", success=True)
            
        except Exception as e:
            self.log(f"Error saving findings: {e}", warning=True)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Network Traffic Monitor")
    root.geometry("1024x768")
    
    frame = ttk.Frame(root)
    frame.pack(fill=tk.BOTH, expand=True)
    
    app = NetworkMonitor(frame)
    
    root.mainloop()