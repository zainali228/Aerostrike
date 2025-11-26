#!/usr/bin/env python3
"""
Enhanced Network Traffic Monitor
Provides real-time network traffic analysis with visual graphs and sensitive data detection
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime
import subprocess
import tempfile
from typing import Dict, List, Any, Optional, Tuple
import json
import re
import socket
import webbrowser
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from io import BytesIO
import base64

# For data visualization
try:
    import matplotlib
    matplotlib.use('TkAgg')  # Use TkAgg backend for embedding in tkinter
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Matplotlib not available, visualization will be limited")

# For numerical operations
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("NumPy not available, data processing will be limited")

# For packet capture
try:
    from scapy.all import sniff, wrpcap, rdpcap, Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw
    from scapy.utils import hexdump
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available, packet analysis will be limited")

class EnhancedNetworkMonitor:
    """Enhanced Network Traffic Monitor with visual graphs and sensitive data detection"""
    
    def __init__(self, parent, dark_mode=True, controller=None):
        """Initialize the enhanced network monitor
        
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
        
        # Create reports directory if it doesn't exist
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        
        # Data storage for stats
        self.protocol_stats = {}  # Protocol -> count
        self.ip_stats = {}        # IP -> count
        self.data_volume = {}     # IP -> bytes
        self.port_stats = {}      # Port -> count
        
        # Initialize visualization update interval (ms)
        self.update_interval = 1000  # 1 second
        
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
        
        # Import File button
        self.import_btn = ttk.Button(
            controls_frame,
            text="Import File",
            command=self.import_capture_file,
            width=12,
            style="AI.TButton"  # Use AI style for purple color
        )
        self.import_btn.pack(side=tk.LEFT, padx=5)
        
        # Export Report button
        self.export_report_btn = ttk.Button(
            controls_frame,
            text="Export Report",
            command=self.export_report,
            width=15,
            style="Report.TButton"  # Use Report style for green color
        )
        self.export_report_btn.pack(side=tk.LEFT, padx=10)
    
    def create_main_content(self):
        """Create enhanced main content with visual elements"""
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create top frame for alerts and key information
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create left and right frames in top frame
        top_left_frame = ttk.Frame(top_frame)
        top_left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        top_right_frame = ttk.Frame(top_frame)
        top_right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Sensitive Data Alerts Section (Top Priority)
        alerts_frame = ttk.LabelFrame(top_left_frame, text="🔴 SENSITIVE DATA ALERTS")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create scrollable alert display
        self.alerts_text = scrolledtext.ScrolledText(
            alerts_frame,
            wrap=tk.WORD,
            width=40,
            height=6,
            font=("Consolas", 10),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground="#ff5252"  # Always red for sensitive data
        )
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.alerts_text.insert(tk.END, "No sensitive data detected yet. Start capturing to monitor for passwords, API keys, and tokens.\n")
        self.alerts_text.config(state=tk.DISABLED)
        
        # Traffic Summary (Top Right)
        summary_frame = ttk.LabelFrame(top_right_frame, text="Traffic Summary")
        summary_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create stats display
        self.stats_text = scrolledtext.ScrolledText(
            summary_frame,
            wrap=tk.WORD,
            width=40,
            height=6,
            font=("Consolas", 10),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground=self.fg_color
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.stats_text.insert(tk.END, "No traffic captured yet. Start capturing to view statistics.\n")
        self.stats_text.config(state=tk.DISABLED)
        
        # Create middle frame for visualization
        self.middle_frame = ttk.Frame(main_frame)
        self.middle_frame.pack(fill=tk.X, expand=False, padx=5, pady=5)
        
        # We'll fill this with graphs when starting capture
        self.create_visualization_area()
        
        # Network Traffic (Bottom)
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
        
        # Create tags for sensitive data highlighting
        self.packet_tree.tag_configure("sensitive", background="#ff5252", foreground="#ffffff")
        
        # Add scrollbar
        packet_scroll = ttk.Scrollbar(packets_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scroll.set)
        
        # Pack tree and scrollbar
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        packet_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Set up event handlers
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        
        # Packet Details (Bottom Frame, below packet tree)
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
    
    def create_visualization_area(self):
        """Create the visualization area with graphs"""
        # Clear existing widgets
        for widget in self.middle_frame.winfo_children():
            widget.destroy()
        
        if not MATPLOTLIB_AVAILABLE or not NUMPY_AVAILABLE:
            # Show message if visualization libraries not available
            msg_label = ttk.Label(
                self.middle_frame,
                text="Visualization requires matplotlib and numpy libraries",
                font=("Helvetica", 10),
                foreground=self.warning_color
            )
            msg_label.pack(fill=tk.X, padx=5, pady=20)
            return
        
        # Create frames for charts
        left_chart_frame = ttk.LabelFrame(self.middle_frame, text="Protocol Distribution")
        left_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5), pady=5)
        
        right_chart_frame = ttk.LabelFrame(self.middle_frame, text="Top Talkers (IPs)")
        right_chart_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        
        # Create protocol chart on the left
        protocol_fig = Figure(figsize=(4, 3), dpi=100)
        protocol_fig.patch.set_facecolor('#333333' if self.dark_mode else '#f5f5f5')
        # Add more bottom padding to prevent text cutoff
        protocol_fig.subplots_adjust(bottom=0.2, left=0.1, right=0.9, top=0.85)
        self.protocol_ax = protocol_fig.add_subplot(111)
        self.protocol_ax.set_title('Protocol Distribution', color=self.fg_color)
        self.protocol_ax.text(0.5, 0.5, 'No data yet', 
                            horizontalalignment='center',
                            verticalalignment='center',
                            transform=self.protocol_ax.transAxes,
                            color=self.fg_color)
        
        # Remove axis ticks for pie chart
        self.protocol_ax.set_xticks([])
        self.protocol_ax.set_yticks([])
        
        # Set text color for dark mode
        if self.dark_mode:
            self.protocol_ax.tick_params(colors=self.fg_color)
            self.protocol_ax.xaxis.label.set_color(self.fg_color)
            self.protocol_ax.yaxis.label.set_color(self.fg_color)
            self.protocol_ax.title.set_color(self.fg_color)
        
        self.protocol_canvas = FigureCanvasTkAgg(protocol_fig, left_chart_frame)
        self.protocol_canvas.draw()
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create top talkers chart on the right
        talkers_fig = Figure(figsize=(4, 3), dpi=100)
        talkers_fig.patch.set_facecolor('#333333' if self.dark_mode else '#f5f5f5')
        # Add more spacing to prevent text cutoff
        talkers_fig.subplots_adjust(bottom=0.2, left=0.15, right=0.9, top=0.85)
        self.talkers_ax = talkers_fig.add_subplot(111)
        self.talkers_ax.set_title('Top Talkers', color=self.fg_color)
        self.talkers_ax.text(0.5, 0.5, 'No data yet', 
                           horizontalalignment='center',
                           verticalalignment='center',
                           transform=self.talkers_ax.transAxes,
                           color=self.fg_color)
        
        # Set text color for dark mode
        if self.dark_mode:
            self.talkers_ax.tick_params(colors=self.fg_color)
            self.talkers_ax.xaxis.label.set_color(self.fg_color)
            self.talkers_ax.yaxis.label.set_color(self.fg_color)
            self.talkers_ax.title.set_color(self.fg_color)
        
        self.talkers_canvas = FigureCanvasTkAgg(talkers_fig, right_chart_frame)
        self.talkers_canvas.draw()
        self.talkers_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
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
    
    def log(self, message, error=False, warning=False, success=False, phase=None):
        """Log message to status bar with optional phase indicator"""
        color = self.fg_color
        if error:
            color = self.error_color
        elif warning:
            color = self.warning_color
        elif success:
            color = self.success_color
        
        # Format message with phase if provided
        display_msg = message
        if phase:
            display_msg = f"[{phase}] {message}"
            
        self.status_var.set(display_msg)
        
        # Also update the status text widget if available
        if hasattr(self, 'status_text'):
            try:
                timestamp = datetime.now().strftime("[%H:%M:%S] ")
                self.status_text.config(state=tk.NORMAL)
                self.status_text.insert(tk.END, timestamp + display_msg + "\n")
                self.status_text.see(tk.END)
                self.status_text.config(state=tk.DISABLED)
            except Exception:
                pass
        
        # Log to console for debugging
        print(f"[Network Monitor] {display_msg}")
    
    def export_report(self):
        """Generate a professional PDF report with all network traffic analysis results"""
        if not hasattr(self, 'current_packets') or not self.current_packets:
            messagebox.showwarning("No Data Available", 
                                  "No network traffic data available to export. Start capturing first.")
            return

        try:
            # Import all required modules
            import os
            import sys
            from datetime import datetime
            import subprocess
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.graphics.shapes import Drawing
            from reportlab.graphics.charts.piecharts import Pie
            from reportlab.graphics.charts.barcharts import VerticalBarChart
                
            # Define reports directory if not already set
            if not hasattr(self, 'reports_dir'):
                self.reports_dir = os.path.join(os.getcwd(), "reports")
                
            # Create reports directory if it doesn't exist
            if not os.path.exists(self.reports_dir):
                os.makedirs(self.reports_dir)
                
            # Create a unique filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.reports_dir, f"network_traffic_report_{timestamp}.pdf")
            
            # Setup the document
            doc = SimpleDocTemplate(filename, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []
            
            # Create custom styles
            title_style = ParagraphStyle(
                'Title',
                parent=styles['Title'],
                fontSize=18,
                spaceAfter=12,
                textColor=colors.purple,
            )
            
            heading_style = ParagraphStyle(
                'Heading1',
                parent=styles['Heading1'],
                fontSize=14,
                spaceAfter=10,
                textColor=colors.blue,
            )
            
            normal_style = styles['Normal']
            
            # Add title and timestamp
            elements.append(Paragraph("Network Traffic Analysis Report", title_style))
            elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
            elements.append(Spacer(1, 0.25*inch))
            
            # Add summary statistics
            elements.append(Paragraph("Summary Statistics", heading_style))
            
            # Create summary table
            summary_data = [
                ["Total Packets Captured", str(self.packet_count)],
                ["Capture Interface", self.interface_var.get() or "Not specified"]
            ]
            
            if hasattr(self, 'start_time'):
                duration = time.time() - self.start_time
                summary_data.append(["Capture Duration", f"{duration:.2f} seconds"])
            
            if self.protocol_stats:
                protocol_str = ", ".join([f"{k}: {v}" for k, v in sorted(self.protocol_stats.items(), 
                                                                         key=lambda x: x[1], 
                                                                         reverse=True)[:5]])
                summary_data.append(["Protocol Distribution", protocol_str])
            
            if self.sensitive_data_findings:
                summary_data.append(["Sensitive Data Findings", f"{len(self.sensitive_data_findings)} potential sensitive data items found"])
            
            summary_table = Table(summary_data, colWidths=[2*inch, 3.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(summary_table)
            elements.append(Spacer(1, 0.25*inch))
            
            # Protocol distribution chart as pie chart
            if self.protocol_stats:
                elements.append(Paragraph("Protocol Distribution", heading_style))
                
                # Create protocol distribution pie chart
                drawing = Drawing(400, 200)
                
                # Create pie chart
                pie = Pie()
                pie.x = 100
                pie.y = 0
                pie.width = 150
                pie.height = 150
                
                # Get protocol data - safely handle potentially empty data
                try:
                    if hasattr(self, 'protocol_stats') and self.protocol_stats:
                        # Check if protocol_stats has items
                        if len(self.protocol_stats) > 0:
                            top_protocols = sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:6]  # Limit to top 6
                            protocols = [k for k, v in top_protocols]
                            values = [self.protocol_stats.get(p, 0) for p in protocols]
                            
                            # Only setup the pie if we have data
                            if protocols and values:
                                pie.data = values
                                pie.labels = [f"{p} ({v})" for p, v in zip(protocols, values)]
                            else:
                                # Add a placeholder if no data
                                pie.data = [1]
                                pie.labels = ["No protocol data"]
                        else:
                            # Add a placeholder if no data
                            pie.data = [1]
                            pie.labels = ["No protocol data"]
                    else:
                        # Add a placeholder if no data
                        pie.data = [1]
                        pie.labels = ["No protocol data"]
                except Exception as pie_error:
                    # Handle any exceptions
                    self.log(f"Error creating protocol chart: {str(pie_error)}", error=True)
                    # Use placeholder data
                    pie.data = [1]
                    pie.labels = ["Error: Could not load data"]
                
                # Add to drawing
                drawing.add(pie)
                elements.append(drawing)
                elements.append(Spacer(1, 0.25*inch))
            
            # Top Talkers section (IP addresses)
            if hasattr(self, 'ip_stats') and self.ip_stats:
                elements.append(Paragraph("Top IP Addresses (Talkers)", heading_style))
                
                # Sort by count (descending)
                sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]
                
                if sorted_ips:
                    # Create a bar chart for top talkers
                    drawing = Drawing(400, 200)
                    
                    # Create bar chart
                    chart = VerticalBarChart()
                    chart.x = 50
                    chart.y = 50
                    chart.height = 125
                    chart.width = 300
                    
                    # Add data safely
                    chart.data = [[count for _, count in sorted_ips]]
                    
                    # Truncate long IP addresses to prevent label overlap
                    chart.categoryAxis.categoryNames = []
                    for ip, _ in sorted_ips:
                        # Truncate or format long IP addresses if needed
                        if len(ip) > 15:
                            ip_parts = ip.split('.')
                            if len(ip_parts) == 4:  # IPv4
                                ip = f"{ip_parts[0]}.{ip_parts[1]}..."
                        chart.categoryAxis.categoryNames.append(ip)
                    
                    chart.categoryAxis.labels.boxAnchor = 'ne'
                    chart.categoryAxis.labels.angle = 30
                    chart.categoryAxis.labels.dx = -8
                    chart.categoryAxis.labels.dy = -2
                    
                    # Style the chart
                    try:
                        chart.bars[0].fillColor = colors.purple
                        
                        # Add to drawing
                        drawing.add(chart)
                        elements.append(drawing)
                    except IndexError:
                        # Handle case where the chart data might be empty
                        elements.append(Paragraph("Chart could not be generated due to insufficient data", normal_style))
                else:
                    # Add text if no data
                    elements.append(Paragraph("No IP address statistics available", normal_style))
                    
                elements.append(Spacer(1, 0.25*inch))
            
            # Sensitive Data Findings
            try:
                if hasattr(self, 'sensitive_data_findings') and self.sensitive_data_findings:
                    elements.append(Paragraph("Sensitive Data Findings", heading_style))
                    elements.append(Paragraph("The following potentially sensitive data was detected in network traffic:", normal_style))
                    elements.append(Spacer(1, 0.1*inch))
                    
                    # Create table for sensitive data
                    sensitive_data = []
                    sensitive_data.append(["Type", "Value", "Source", "Destination", "Timestamp"])
                    
                    # Safety check - ensure we have items to process
                    if len(self.sensitive_data_findings) > 0:
                        # Add sensitive data findings (up to 20)
                        limit = min(20, len(self.sensitive_data_findings))
                        for i in range(limit):
                            try:
                                if i >= len(self.sensitive_data_findings):
                                    break
                                    
                                finding = self.sensitive_data_findings[i]
                                if not isinstance(finding, dict):
                                    continue
                                    
                                # Mask sensitive values (show only first and last 2 chars)
                                masked_value = finding.get("value", "")
                                if not isinstance(masked_value, str):
                                    masked_value = str(masked_value)
                                    
                                if len(masked_value) > 6:
                                    masked_value = masked_value[:2] + "*" * (len(masked_value) - 4) + masked_value[-2:]
                                else:
                                    masked_value = "*" * len(masked_value)
                                
                                sensitive_data.append([
                                    str(finding.get("type", "Unknown")),
                                    masked_value,
                                    str(finding.get("src", "Unknown")),
                                    str(finding.get("dst", "Unknown")),
                                    str(finding.get("timestamp", "Unknown"))
                                ])
                            except Exception as item_err:
                                # Skip problematic items
                                continue
                    
                    # If we have no valid items to show (or none at all), add a placeholder row
                    if len(sensitive_data) == 1:  # Only header row
                        sensitive_data.append(["No data", "-", "-", "-", "-"])
            except Exception as sensitive_err:
                # Handle any exception in sensitive data processing
                self.log(f"Error processing sensitive data for report: {str(sensitive_err)}", error=True)
                
                # Add a basic table with error information
                sensitive_data = []
                sensitive_data.append(["Type", "Value", "Source", "Destination", "Timestamp"])
                sensitive_data.append(["Error", "Could not process sensitive data", "-", "-", "-"])
                
                # Limit text length to prevent overflow in each cell
                for i in range(1, len(sensitive_data)):
                    for j in range(len(sensitive_data[i])):
                        if sensitive_data[i][j] and len(str(sensitive_data[i][j])) > 18:
                            sensitive_data[i][j] = str(sensitive_data[i][j])[:16] + ".."
                
                # Adjusted column widths to prevent overflow
                sensitive_table = Table(sensitive_data, colWidths=[0.7*inch, 1.2*inch, 1.0*inch, 1.0*inch, 0.9*inch])
                sensitive_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.purple),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),  # Smaller font for better fit
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 3),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('WORDWRAP', (0, 0), (-1, -1), True)  # Enable word wrapping
                ]))
                
                elements.append(sensitive_table)
                
                if len(self.sensitive_data_findings) > 20:
                    elements.append(Paragraph(f"Note: {len(self.sensitive_data_findings) - 20} additional findings are not shown.", normal_style))
                
                elements.append(Spacer(1, 0.25*inch))
            
            # Add packet details (top 50)
            elements.append(Paragraph("Packet Details (Top 50)", heading_style))
            
            packet_data = []
            packet_data.append(["#", "Time", "Source", "Destination", "Protocol", "Length"])
            
            # Safely add packet details for first 50 packets
            if hasattr(self, 'current_packets') and self.current_packets:
                # Get up to 50 packets
                packets_to_show = self.current_packets[:50] if len(self.current_packets) >= 1 else []
                
                for i, packet in enumerate(packets_to_show):
                    try:
                        # Handle different packet types (dict or Scapy packet)
                        if isinstance(packet, dict):
                            # If it's a dictionary, use normal get
                            src = str(packet.get("src", "Unknown"))
                            dst = str(packet.get("dst", "Unknown"))
                            protocol = str(packet.get("protocol", "Unknown"))
                            
                            # Try different field names for length/size
                            if "length" in packet:
                                length = str(packet.get("length", 0))
                            elif "size" in packet:
                                length = str(packet.get("size", 0))
                            else:
                                length = "0"
                                
                            # Try different field names for timestamp/time
                            if "timestamp" in packet:
                                timestamp = str(packet.get("timestamp", "Unknown"))
                            elif "time" in packet:
                                timestamp = str(packet.get("time", "Unknown"))
                            else:
                                timestamp = "Unknown"
                        else:
                            # This is likely a Scapy packet object
                            # Extract information directly from Scapy packet attributes
                            try:
                                # Try to get source and destination from IP or other headers
                                if hasattr(packet, 'src') and packet.src:
                                    src = str(packet.src)[:15]  # Limit length to prevent overflow
                                elif hasattr(packet, 'psrc') and packet.psrc:
                                    src = str(packet.psrc)[:15]
                                else:
                                    src = "Unknown"
                                
                                if hasattr(packet, 'dst') and packet.dst:
                                    dst = str(packet.dst)[:15]
                                elif hasattr(packet, 'pdst') and packet.pdst:
                                    dst = str(packet.pdst)[:15]
                                else:
                                    dst = "Unknown"
                                
                                # Try to determine packet protocol
                                if hasattr(packet, 'name'):
                                    protocol = str(packet.name)[:10]  # Limit protocol name length
                                elif 'TCP' in packet:
                                    protocol = "TCP"
                                elif 'UDP' in packet:
                                    protocol = "UDP"
                                elif 'ICMP' in packet:
                                    protocol = "ICMP"
                                elif 'ARP' in packet:
                                    protocol = "ARP"
                                elif 'DNS' in packet:
                                    protocol = "DNS"
                                else:
                                    protocol = "Unknown"
                                
                                # Get packet length
                                if hasattr(packet, 'len'):
                                    length = str(packet.len)[:8]  # Limit length
                                else:
                                    length = str(len(packet))[:8]
                                
                                # Get timestamp if available - limit length to prevent overwriting
                                if hasattr(packet, 'time'):
                                    time_str = str(packet.time)
                                    # Format timestamp nicely to avoid overflow
                                    if len(time_str) > 10:
                                        # Try to format as a readable time
                                        try:
                                            from datetime import datetime
                                            time_val = float(time_str)
                                            # Format as hour:minute:second
                                            timestamp = datetime.fromtimestamp(time_val).strftime("%H:%M:%S")
                                        except:
                                            # If conversion fails, truncate
                                            timestamp = time_str[:10] + "..."
                                    else:
                                        timestamp = time_str
                                else:
                                    timestamp = "Unknown"
                            except Exception as inner_ex:
                                # If extracting fields fails, set generic values
                                src = "Unknown"
                                dst = "Unknown"
                                protocol = "Unknown"
                                length = "0"
                                timestamp = "Unknown"
                        
                        packet_data.append([
                            str(i+1),
                            timestamp,
                            src,
                            dst,
                            protocol,
                            length
                        ])
                    except Exception as packet_err:
                        # Skip problematic packets
                        continue
            else:
                # Add empty row if no packets
                packet_data.append(["", "No packet data available", "", "", "", ""])
            
            # Limit text length to prevent overflow
            for i in range(1, len(packet_data)):
                for j in range(len(packet_data[i])):
                    if packet_data[i][j] and len(str(packet_data[i][j])) > 20:
                        packet_data[i][j] = str(packet_data[i][j])[:18] + ".."
            
            # Set column widths to prevent text overflowing
            packet_table = Table(packet_data, colWidths=[0.3*inch, 0.9*inch, 1.2*inch, 1.2*inch, 0.7*inch, 0.5*inch])
            packet_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),  # Smaller font for better fit
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
                ('RIGHTPADDING', (0, 0), (-1, -1), 3),
                ('LEFTPADDING', (0, 0), (-1, -1), 3),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('WORDWRAP', (0, 0), (-1, -1), True)  # Enable word wrapping
            ]))
            
            elements.append(packet_table)
            
            # Add disclaimer/footer
            elements.append(Spacer(1, 0.5*inch))
            elements.append(Paragraph("This report was generated for security analysis purposes only. Handle with appropriate confidentiality.", 
                                     ParagraphStyle("Footer", parent=styles['Normal'], fontSize=8, textColor=colors.grey)))
            
            # Build the document
            doc.build(elements)
            
            # Show success message and offer to open the report
            self.log(f"Report saved to {filename}", success=True)
            if messagebox.askyesno("Report Generated", 
                                  f"Network traffic report was successfully generated and saved to:\n{filename}\n\nWould you like to open it now?"):
                try:
                    if sys.platform == 'win32':
                        os.startfile(filename)
                    elif sys.platform == 'darwin':  # macOS
                        subprocess.run(['open', filename], check=True)
                    else:  # Linux
                        subprocess.run(['xdg-open', filename], check=True)
                except Exception as open_err:
                    self.log(f"Could not automatically open report: {str(open_err)}", warning=True)
                    messagebox.showinfo("Report Generated", f"Report saved to:\n{filename}")
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            self.log(f"Error generating report: {str(e)}", error=True)
            self.log(f"Error details: {error_details}", error=True)
            messagebox.showerror("Report Error", f"Failed to generate report: {str(e)}\n\nPlease check that all required libraries are installed.")
    
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
        
        # Reset packet counter and stats
        self.packet_count = 0
        self.count_var.set("Packets: 0")
        self.protocol_stats = {}
        self.ip_stats = {}
        self.data_volume = {}
        self.port_stats = {}
        
        # Reset stats text
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, "Starting capture...\n")
        self.stats_text.config(state=tk.DISABLED)
        
        # Update UI state
        self.is_capturing = True
        self.capture_btn.config(text="Stop Capture")
        
        # Reset stop event
        self.stop_event.clear()
        
        # Recreate visualization area
        self.create_visualization_area()
        
        # Start visualization update timer
        self._schedule_visualization_update()
        
        # Set up automated analysis timer
        self.last_alert_timestamps = {}  # Track when alerts were last shown
        self.known_sensitive_hashes = set()  # Track already seen sensitive data
        
        # Only capture real network traffic - no test data generation
        self.log("Ready to capture real network traffic on selected interface", success=True)
            
        # Start capture thread with automatic analysis
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface,)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Start automated traffic analysis timer
        if self.root:
            self.root.after(5000, self._automated_traffic_analysis)
        
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
    
    def _schedule_visualization_update(self):
        """Schedule the visualization update"""
        if self.is_capturing and self.root:
            self._update_visualizations()
            # Schedule next update
            self.root.after(self.update_interval, self._schedule_visualization_update)
    
    def _update_visualizations(self):
        """Update the visualization charts and statistics"""
        if not MATPLOTLIB_AVAILABLE or not NUMPY_AVAILABLE:
            return
        
        # Update the protocol distribution chart
        self._update_protocol_chart()
        
        # Update top talkers chart
        self._update_top_hosts_chart()
        
        # Update stats text
        self._update_stats_text()
    
    def _update_protocol_chart(self):
        """Update the protocol distribution pie chart"""
        # Skip if no data
        if not self.protocol_stats:
            return
        
        try:
            # Clear the current chart
            self.protocol_ax.clear()
            
            # Get labels and sizes from protocol stats
            labels = []
            sizes = []
            others = 0
            other_count = 0
            
            # Sort protocols by count
            sorted_protocols = sorted(self.protocol_stats.items(), 
                                      key=lambda x: x[1], reverse=True)
            
            # Use top 5 protocols individually and group the rest
            for i, (protocol, count) in enumerate(sorted_protocols):
                if i < 5:  # Top 5 protocols
                    labels.append(protocol)
                    sizes.append(count)
                else:  # Group the rest as "Others"
                    others += count
                    other_count += 1
            
            # Add the "Others" category if there are any
            if others > 0:
                labels.append(f"Others ({other_count})")
                sizes.append(others)
            
            # Create pie chart with improved label positioning
            colors = plt.cm.tab10(range(len(labels)))
            
            # Create pie with no direct labels to prevent overlap
            wedges, texts, autotexts = self.protocol_ax.pie(
                sizes, 
                labels=None,  # Remove direct labels to prevent overlap
                autopct='%1.1f%%', 
                startangle=90, 
                colors=colors,
                pctdistance=0.85
            )
            
            # Add legend instead of direct labels to prevent overlap and text cutoff
            self.protocol_ax.legend(
                wedges, 
                [f"{label} ({size})" for label, size in zip(labels, sizes)],
                loc="center left",
                bbox_to_anchor=(0.9, 0, 0.5, 1),
                fontsize=8
            )
            
            self.protocol_ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            
            # Set title
            self.protocol_ax.set_title('Protocol Distribution', color=self.fg_color)
            
            # Update the canvas
            self.protocol_canvas.draw()
            
        except Exception as e:
            print(f"Error updating protocol chart: {str(e)}")
    
    def _update_top_hosts_chart(self):
        """Update the top talkers bar chart"""
        # Skip if no data
        if not self.ip_stats:
            return
            
        try:
            # Clear the current chart
            self.talkers_ax.clear()
            
            # Get top 10 talkers by packet count
            top_talkers = sorted(self.ip_stats.items(), 
                               key=lambda x: x[1], reverse=True)[:10]
            
            if not top_talkers:
                return
                
            # Extract IPs and counts
            ips = [self._resolve_hostname(ip) for ip, _ in top_talkers]
            counts = [count for _, count in top_talkers]
            
            # Shorten IP labels if too long
            shortened_ips = []
            for ip in ips:
                if len(ip) > 15:
                    # For long hostnames, keep first and last part
                    parts = ip.split('.')
                    if len(parts) > 2:
                        shortened_ips.append(f"{parts[0]}...{parts[-1]}")
                    else:
                        shortened_ips.append(ip[:13] + "...")
                else:
                    shortened_ips.append(ip)
            
            # Create bar chart
            bars = self.talkers_ax.barh(range(len(shortened_ips)), counts, 
                                       align='center', color=self.accent_color)
            
            # Set y-axis ticks and labels
            self.talkers_ax.set_yticks(range(len(shortened_ips)))
            self.talkers_ax.set_yticklabels(shortened_ips)
            
            # Add count values at the end of each bar for better readability
            for i, (bar, count) in enumerate(zip(bars, counts)):
                self.talkers_ax.text(
                    count + (max(counts) * 0.02),  # Position slightly to the right of the bar
                    bar.get_y() + bar.get_height()/2,
                    str(count),
                    va='center',
                    fontsize=8,
                    color=self.fg_color
                )
            
            # Adjust x-axis limit to make room for count labels
            self.talkers_ax.set_xlim(0, max(counts) * 1.15)  # Add 15% margin on right
            
            # Set title and labels
            self.talkers_ax.set_title('Top Talkers (by packets)', color=self.fg_color)
            self.talkers_ax.set_xlabel('Packet Count', color=self.fg_color)
            
            # Set tick colors for dark mode
            if self.dark_mode:
                self.talkers_ax.tick_params(colors=self.fg_color)
                self.talkers_ax.xaxis.label.set_color(self.fg_color)
                self.talkers_ax.yaxis.label.set_color(self.fg_color)
                self.talkers_ax.title.set_color(self.fg_color)
            
            # Update the canvas
            self.talkers_canvas.draw()
            
        except Exception as e:
            print(f"Error updating talkers chart: {str(e)}")
    
    def _resolve_hostname(self, ip):
        """Try to resolve an IP to a hostname
        
        Returns shortened hostname or IP if resolution fails
        """
        try:
            # Skip common special IPs
            if ip == "127.0.0.1" or ip == "0.0.0.0" or ip == "255.255.255.255":
                return ip
                
            # Attempt resolution with timeout
            hostname, _, _ = socket.gethostbyaddr(ip)
            
            # Get just the first part of the hostname
            if hostname and hostname != ip:
                parts = hostname.split('.')
                return parts[0]  # Return just the hostname part
                
        except (socket.herror, socket.timeout, socket.gaierror):
            pass  # Resolution failed, return IP
            
        return ip
    
    def _update_stats_text(self):
        """Update the statistics text area"""
        if not self.current_packets:
            return
            
        # Calculate statistics
        total_packets = len(self.current_packets)
        total_bytes = sum(len(p) for p in self.current_packets)
        active_ips = len(self.ip_stats)
        unique_protocols = len(self.protocol_stats)
        
        # Format statistics text
        stats_text = f"Packets Captured: {total_packets}\n"
        stats_text += f"Data Volume: {self._format_bytes(total_bytes)}\n"
        stats_text += f"Active IPs: {active_ips}\n"
        stats_text += f"Protocols Detected: {unique_protocols}\n\n"
        
        # Add top protocols
        top_protocols = sorted(self.protocol_stats.items(), 
                              key=lambda x: x[1], reverse=True)[:3]
        if top_protocols:
            stats_text += "Top Protocols:\n"
            for proto, count in top_protocols:
                percentage = (count / total_packets) * 100
                stats_text += f"- {proto}: {count} ({percentage:.1f}%)\n"
        
        # Update the stats text
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text)
        self.stats_text.config(state=tk.DISABLED)
    
    def _format_bytes(self, size):
        """Format bytes into human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def _capture_packets(self, interface):
        """Thread for capturing packets"""
        try:
            def packet_callback(packet):
                if self.stop_event.is_set():
                    return True  # Stop sniffing
                
                # Process packet immediately for real-time analysis
                self._process_packet(packet)
                return False  # Continue sniffing
            
            # Using standard mode for reliable packet capture
            self.log(f"Using standard capture mode on {interface}", phase="INIT")
            
            # Start capturing all traffic on the interface
            self.log(f"Starting real-time packet capture on {interface}", phase="CAPTURE")
            
            # Create a temporary loopback packet to ensure the capture system is working
            try:
                # Create a test packet to localhost to verify packet processing
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_socket.sendto(b"Traffic monitor test packet", ("127.0.0.1", 9999))
                test_socket.close()
                self.log("Sent test packet to validate capture system", success=True)
            except Exception as e:
                self.log(f"Note: Test packet sending failed: {e}", warning=True)
            
            # Start sniffing with a filter to ensure we see traffic
            # Include filter to capture common protocols but exclude excessive noise
            try:
                # First try with standard capture - most reliable for normal traffic
                self.log("Starting packet capture with standard settings", phase="CAPTURE")
                sniff(
                    iface=interface,
                    prn=packet_callback,
                    store=False,
                    filter="tcp or udp or icmp or arp",  # Focus on most relevant protocols
                    stop_filter=lambda p: self.stop_event.is_set()
                )
            except Exception as e:
                self.log(f"Standard capture failed: {e}", error=True)
                # Fallback to basic capture with minimal filtering
                self.log("Trying fallback capture method", warning=True)
                try:
                    sniff(
                        iface=interface,
                        prn=packet_callback,
                        store=False,
                        stop_filter=lambda p: self.stop_event.is_set()
                    )
                except Exception as e2:
                    self.log(f"Fallback capture also failed: {e2}", error=True)
                    # Try to capture on the loopback interface as last resort
                    self.log("Attempting capture on loopback interface", warning=True)
                    sniff(
                        iface="lo",
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
        try:
            # Add to packet list
            self.current_packets.append(packet)
            self.packet_count += 1
            
            # Extract packet info for real traffic
            packet_info = self._extract_packet_info(packet)
            packet_data = packet_info.get("data", "")
            
            # Only show real traffic - no simulated data
            if self.packet_count == 1 and not packet_info.get("src") and not packet_info.get("dst"):
                # Only show this message once to avoid flooding the UI
                self.log("No real traffic detected. Please check network adapter settings and permissions.", warning=True)
            
            # Check if contains sensitive data
            contains_sensitive = self._check_for_sensitive_data(packet, packet_info)
        except Exception as e:
            self.log(f"Error processing packet: {str(e)}", error=True)
            # Create basic packet info for failed parsing
            packet_info = {
                "no": self.packet_count,
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src": "Unknown",
                "dst": "Unknown",
                "proto": "Unknown",
                "info": f"Error: {str(e)}",
                "data": ""
            }
            contains_sensitive = False
        
        # Add to tree
        if self.root:
            self.root.after(0, lambda: self._add_packet_to_tree(packet_info, contains_sensitive))
            
            # Update counter
            self.root.after(0, lambda: self.count_var.set(f"Packets: {self.packet_count}"))
        
        # Update statistics
        self._update_statistics(packet, packet_info)
    
    def _update_statistics(self, packet, packet_info):
        """Update packet statistics"""
        # Update protocol stats
        proto = packet_info["proto"]
        if proto in self.protocol_stats:
            self.protocol_stats[proto] += 1
        else:
            self.protocol_stats[proto] = 1
            
        # Update IP stats (source and destination)
        src_ip = packet_info["src"]
        dst_ip = packet_info["dst"]
        
        # Count source IPs
        if src_ip in self.ip_stats:
            self.ip_stats[src_ip] += 1
        else:
            self.ip_stats[src_ip] = 1
            
        # Count destination IPs
        if dst_ip in self.ip_stats:
            self.ip_stats[dst_ip] += 1
        else:
            self.ip_stats[dst_ip] = 1
            
        # Update data volume stats
        packet_len = len(packet)
        
        # Add to source IP data volume
        if src_ip in self.data_volume:
            self.data_volume[src_ip] += packet_len
        else:
            self.data_volume[src_ip] = packet_len
            
        # Add to destination IP data volume
        if dst_ip in self.data_volume:
            self.data_volume[dst_ip] += packet_len
        else:
            self.data_volume[dst_ip] = packet_len
            
        # Update port stats if TCP or UDP
        if TCP in packet and packet[TCP].dport:
            port = packet[TCP].dport
            if port in self.port_stats:
                self.port_stats[port] += 1
            else:
                self.port_stats[port] = 1
        elif UDP in packet and packet[UDP].dport:
            port = packet[UDP].dport
            if port in self.port_stats:
                self.port_stats[port] += 1
            else:
                self.port_stats[port] = 1
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        packet_time = datetime.now().strftime("%H:%M:%S")
        src = "Unknown"
        dst = "Unknown"
        proto = "Unknown"
        info = "Unknown"
        raw_data = ""
        
        # Get main IP details if present
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            
            # Enhanced protocol detection for ALL packet types
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                info = f"{sport} → {dport}"
                
                # Enhanced service identification
                if dport == 80 or sport == 80:
                    proto = "HTTP"
                elif dport == 443 or sport == 443:
                    proto = "HTTPS/TLS"
                elif dport == 53 or sport == 53:
                    proto = "DNS over TCP"
                elif dport == 21 or sport == 21:
                    proto = "FTP"
                elif dport == 22 or sport == 22:
                    proto = "SSH"
                elif dport == 23 or sport == 23:
                    proto = "Telnet"
                elif dport == 25 or sport == 25:
                    proto = "SMTP"
                elif dport == 110 or sport == 110:
                    proto = "POP3"
                elif dport == 143 or sport == 143:
                    proto = "IMAP"
                elif dport == 993 or sport == 993:
                    proto = "IMAPS"
                elif dport == 995 or sport == 995:
                    proto = "POP3S"
                else:
                    proto = "TCP"
                
                # Check for TLS/SSL patterns in TCP payload
                if Raw in packet:
                    try:
                        raw_data = packet[Raw].load
                        # Check for TLS handshake patterns
                        if len(raw_data) > 5:
                            # TLS record header: content type (1 byte) + version (2 bytes) + length (2 bytes)
                            if raw_data[0] in [0x16, 0x14, 0x15, 0x17]:  # TLS record types
                                if raw_data[1:3] in [b'\x03\x01', b'\x03\x02', b'\x03\x03', b'\x03\x04']:  # TLS versions
                                    proto = "TLSv1.2/1.3"
                                    info = f"TLS {sport} → {dport}"
                        
                        # Try to decode for text protocols
                        try:
                            decoded_data = raw_data.decode('utf-8', errors='ignore')
                            raw_data = decoded_data
                            
                            if "GET" in decoded_data or "POST" in decoded_data:
                                proto = "HTTP"
                                first_line = decoded_data.split('\r\n')[0]
                                info = first_line[:50]
                            elif "220" in decoded_data or "EHLO" in decoded_data:
                                proto = "SMTP"
                            elif "SSH-" in decoded_data:
                                proto = "SSH"
                        except:
                            pass
                    except:
                        pass
                
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
        
        # Extract any raw data from packet
        if Raw in packet:
            try:
                raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            except:
                raw_data = str(packet[Raw].load)
        
        return {
            "no": self.packet_count,
            "time": packet_time,
            "src": src,
            "dst": dst,
            "proto": proto,
            "info": info,
            "data": raw_data,
            "packet": packet  # Store reference to original packet
        }
    
    def _add_packet_to_tree(self, packet_info, is_sensitive=False):
        """Add packet to the treeview with optional highlighting"""
        try:
            item_id = self.packet_tree.insert(
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
            
            # Apply sensitive tag if needed
            if is_sensitive:
                self.packet_tree.item(item_id, tags=("sensitive",))
            
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
    
    def _check_for_sensitive_data(self, packet, packet_info=None):
        """Check packet for sensitive information - Enhanced for real capture files
        
        Returns True if sensitive data found, False otherwise
        """
        is_sensitive = False
        
        # Get raw payload from various sources to maximize detection
        payloads = []
        
        # Try to get raw payload if available
        if hasattr(packet, 'haslayer') and packet.haslayer('Raw'):
            try:
                raw_payload = packet.getlayer('Raw').load.decode('utf-8', errors='ignore')
                payloads.append(raw_payload)
            except Exception:
                pass
                
        # Add processed payload from packet_info if available
        if packet_info and "data" in packet_info and packet_info["data"]:
            payloads.append(packet_info["data"])
            
        # If we have no payload data at all, return False
        if not payloads:
            return False
            
        # Combine all payloads to ensure we don't miss anything
        combined_payload = " ".join(payloads)
            
        # Enhanced patterns for more accurate detection of real sensitive data
        patterns = {
            "Password": [
                # Form-based login patterns (more flexible)
                r'(?i)password["\s:=]*([^\s&;"\'<>\n\r]{3,})',
                r'(?i)pass["\s:=]*([^\s&;"\'<>\n\r]{3,})',
                r'(?i)pwd["\s:=]*([^\s&;"\'<>\n\r]{3,})',
                r'(?i)passwd["\s:=]*([^\s&;"\'<>\n\r]{3,})',
                # URL-encoded form data
                r'(?i)password=([^&\s\n\r]{3,})',
                r'(?i)passwd=([^&\s\n\r]{3,})',
                r'(?i)pass=([^&\s\n\r]{3,})',
                r'(?i)pwd=([^&\s\n\r]{3,})',
                # JSON format
                r'(?i)"password"\s*:\s*"([^"]{3,})"',
                r'(?i)"passwd"\s*:\s*"([^"]{3,})"',
                r'(?i)"pass"\s*:\s*"([^"]{3,})"',
                r'(?i)"pwd"\s*:\s*"([^"]{3,})"',
                # Any password-like field
                r'(?i)\bpassword\b[^a-zA-Z0-9]*([a-zA-Z0-9@#$%^&*!]{3,})',
                r'(?i)\bpass\b[^a-zA-Z0-9]*([a-zA-Z0-9@#$%^&*!]{3,})'
            ],
            "Username": [
                # Username patterns
                r'(?i)username["\s:=]*([^\s&;"\'<>\n\r]{3,})',
                r'(?i)user["\s:=]*([^\s&;"\'<>\n\r]{3,})',
                r'(?i)login["\s:=]*([^\s&;"\'<>\n\r]{3,})',
                r'(?i)email["\s:=]*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                # URL parameters
                r'(?i)username=([^&\s\n\r]{3,})',
                r'(?i)user=([^&\s\n\r]{3,})',
                r'(?i)login=([^&\s\n\r]{3,})',
                # JSON format
                r'(?i)"username"\s*:\s*"([^"]{3,})"',
                r'(?i)"user"\s*:\s*"([^"]{3,})"',
                r'(?i)"login"\s*:\s*"([^"]{3,})"'
            ],
            "API Key": [
                # Various API key formats
                r'(?i)api[_-]?key["\s:=]+\s*([^"\s&;]+)',
                r'(?i)apikey["\s:=]+\s*([^"\s&;]+)',
                r'(?i)api[_-]?token["\s:=]+\s*([^"\s&;]+)',
                r'(?i)access[_-]?token["\s:=]+\s*([^"\s&;]+)',
                r'(?i)auth[_-]?token["\s:=]+\s*([^"\s&;]+)',
                r'(?i)client[_-]?secret["\s:=]+\s*([^"\s&;]+)',
                # URL parameters
                r'(?i)[?&]api[_-]?key=([^&\s]+)',
                r'(?i)[?&]key=([^&\s]+)',
                r'(?i)[?&]token=([^&\s]+)',
                # Headers
                r'(?i)x-api-key:\s*([^\r\n]+)',
                r'(?i)authorization:\s*([^\r\n]+)'
            ],
            "Credit Card": [
                # Card number patterns
                r'(?i)(?:\d{4}[- ]?){3}\d{4}',  # 16-digit card
                r'(?i)card[_-]?number["\s:=]+\s*([^"\s&;]+)',
                r'(?i)ccnumber["\s:=]+\s*([^"\s&;]+)',
                r'(?i)cc[_-]?num["\s:=]+\s*([^"\s&;]+)',
                # Form data
                r'(?i)card_number=([^&\s]+)',
                r'(?i)ccnumber=([^&\s]+)',
                r'(?i)cc_num=([^&\s]+)'
            ],
            "Authentication": [
                # HTTP Auth headers
                r'(?i)bearer\s+([a-zA-Z0-9\._\-]+)',  # Bearer token
                r'(?i)basic\s+([a-zA-Z0-9+/=]+)',  # Basic auth
                r'(?i)digest\s+([a-zA-Z0-9+/=\s,]+)',  # Digest auth
                # Cookie auth
                r'(?i)auth_token=([^;\s]+)',
                r'(?i)session=([^;\s]+)',
                r'(?i)sid=([^;\s]+)'
            ],
            "Personal Info": [
                # PII data patterns
                r'(?i)ssn["\s:=]+\s*([^"\s&;]+)',  # Social Security Number
                r'(?i)social["\s:=]+\s*([^"\s&;]+)',  # Social Security
                r'(?i)tax[_-]?id["\s:=]+\s*([^"\s&;]+)',
                # Email addresses
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ],
            "JWT Token": [
                # JWT token format - three base64 sections with periods
                r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
            ],
            "Private Key": [
                # Key patterns
                r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----',
                r'(?i)private[_-]?key["\s:=]+\s*([^"\s&;]+)'
            ]
        }
        
        # Check all patterns for matches
        found_sensitive = False
        
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                # Use the combined payload to ensure we catch all sensitive data
                matches = re.findall(pattern, combined_payload)
                
                if matches:
                    match_text = matches[0] if isinstance(matches[0], str) else matches[0][0]
                    
                    # Calculate hash of finding to avoid duplicates
                    # Use source + destination + category + data to identify unique findings
                    finding_key = f"{packet_info['src']}_{packet_info['dst']}_{category}_{match_text}"
                    finding_hash = hash(finding_key)
                    
                    # Check if we've seen this exact sensitive data before
                    if finding_hash in self.known_sensitive_hashes:
                        continue  # Skip if already seen
                        
                    # Mark as found and remember for future
                    found_sensitive = True
                    self.known_sensitive_hashes.add(finding_hash)
                    
                    # Create alert info
                    alert_info = {
                        "category": category,
                        "data": match_text[:20] + "..." if len(match_text) > 20 else match_text,
                        "protocol": packet_info["proto"],
                        "src": packet_info["src"],
                        "dst": packet_info["dst"],
                        "time": packet_info["time"],
                        "hash": finding_hash
                    }
                    
                    # Add to findings
                    self.sensitive_data_findings.append(alert_info)
                    
                    # Update UI with alert (only for new discoveries)
                    if self.root:
                        self.root.after(0, lambda a=alert_info: self._add_alert_to_ui(a))
                    
                    # Only notify for first 5 findings to avoid overwhelming the user
                    if len(self.sensitive_data_findings) <= 5:
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
        
        return found_sensitive
    
    def _add_alert_to_ui(self, alert):
        """Add sensitive data alert to the UI"""
        try:
            # Show messagebox alert for sensitive data
            messagebox.showwarning(
                f"Sensitive Data Detected: {alert['category']}",
                f"Found {alert['category']} in traffic from {alert['src']} to {alert['dst']}\n\n"
                f"Data: {alert['data']}\n"
                f"Protocol: {alert['protocol']}"
            )
            
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
                    # Check for sensitive data in payload
                    payload = self._highlight_sensitive_data(payload)
                    
                    # Truncate if too long
                    if len(payload) > 500:
                        payload = payload[:500] + "... [truncated]"
                    details.append(payload)
                except:
                    details.append("[Binary data]")
        except Exception as e:
            details.append(f"Error formatting packet: {str(e)}")
        
        return "\n".join(details)
    
    def _highlight_sensitive_data(self, text):
        """Highlight sensitive data in text with markers"""
        patterns = [
            # Passwords
            (r'(?i)password["\s:=]+\s*([^"\s&]+)', r'password: ***SENSITIVE***'),
            (r'(?i)pass["\s:=]+\s*([^"\s&]+)', r'pass: ***SENSITIVE***'),
            # API Keys
            (r'(?i)api[_-]?key["\s:=]+\s*([^"\s&;]+)', r'api_key: ***SENSITIVE***'),
            # Credit cards - mask all but last 4 digits
            (r'(\d{4})[- ]?(\d{4})[- ]?(\d{4})[- ]?(\d{4})', r'****-****-****-\4'),
            # Tokens
            (r'(?i)token["\s:=]+\s*([^"\s&;]+)', r'token: ***SENSITIVE***'),
            # Authentication headers
            (r'(?i)(authorization:\s*bearer\s+)([a-zA-Z0-9\._\-]+)', r'\1***SENSITIVE***'),
            (r'(?i)(authorization:\s*basic\s+)([a-zA-Z0-9+/=]+)', r'\1***SENSITIVE***'),
        ]
        
        # Apply each pattern
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text)
            
        return text
    
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
    
    def _automated_traffic_analysis(self):
        """Automatically analyze traffic patterns and alert on unusual activity"""
        if not self.is_capturing or not self.root:
            return
        
        # Continue analyzing while capturing
        if self.is_capturing:
            # Detect unusual traffic patterns
            unusual_traffic = self._detect_unusual_traffic()
            for alert in unusual_traffic:
                self._add_traffic_alert(alert)
            
            # Schedule next analysis
            self.root.after(10000, self._automated_traffic_analysis)  # Check every 10 seconds
    
    def _detect_unusual_traffic(self):
        """Detect unusual traffic patterns that might indicate security issues"""
        alerts = []
        
        # Skip if not enough data yet
        if len(self.current_packets) < 20:
            return alerts
        
        # Check for common security and unusual patterns
        try:
            # 1. Check for port scanning behavior
            # If a single IP is connecting to many different ports in short time
            port_scan_threshold = 10  # Consider it a scan if connecting to many ports
            potential_scanners = {}
            
            for ip, ips_data in self.ip_stats.items():
                ports_accessed = set()
                # Check TCP packets for this IP
                for packet in self.current_packets[-100:]:  # Check last 100 packets
                    if IP in packet and TCP in packet:
                        if packet[IP].src == ip:
                            ports_accessed.add(packet[TCP].dport)
                
                if len(ports_accessed) > port_scan_threshold:
                    potential_scanners[ip] = len(ports_accessed)
            
            # Alert for port scanning
            for ip, port_count in potential_scanners.items():
                # Only alert if we haven't alerted about this IP in last 30 seconds
                if ip not in self.last_alert_timestamps or \
                   (time.time() - self.last_alert_timestamps.get(ip, 0) > 30):
                    alert = {
                        "type": "Port Scanning",
                        "src": ip,
                        "info": f"Potential port scanning detected: {ip} accessed {port_count} different ports",
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "severity": "high"
                    }
                    alerts.append(alert)
                    self.last_alert_timestamps[ip] = time.time()
            
            # 2. Check for unusually high traffic volume from a single IP
            # Calculate average packets per IP
            avg_packets_per_ip = sum(self.ip_stats.values()) / max(1, len(self.ip_stats))
            high_traffic_threshold = avg_packets_per_ip * 3  # 3x average
            
            for ip, count in self.ip_stats.items():
                if count > high_traffic_threshold and count > 50:  # Minimum threshold
                    # Only alert if we haven't alerted about this IP in last 60 seconds
                    if ip not in self.last_alert_timestamps or \
                       (time.time() - self.last_alert_timestamps.get(ip, 0) > 60):
                        alert = {
                            "type": "High Traffic",
                            "src": ip,
                            "info": f"Unusually high traffic from {ip}: {count} packets",
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "severity": "medium"
                        }
                        alerts.append(alert)
                        self.last_alert_timestamps[ip] = time.time()
            
            # 3. Check for unknown/suspicious protocols
            unusual_protocols = set()
            for proto, count in self.protocol_stats.items():
                # Consider unusual if not common protocol and has more than a few packets
                if proto not in ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP", "ARP"] and count > 5:
                    unusual_protocols.add(proto)
            
            if unusual_protocols:
                proto_str = ", ".join(unusual_protocols)
                alert = {
                    "type": "Unusual Protocol",
                    "src": "Multiple",
                    "info": f"Unusual protocols detected: {proto_str}",
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "severity": "low"
                }
                alerts.append(alert)
        
        except Exception as e:
            print(f"Error in traffic analysis: {str(e)}")
        
        return alerts
    
    def _add_traffic_alert(self, alert):
        """Add automatic traffic analysis alert to UI"""
        try:
            # Determine alert color based on severity
            color = self.warning_color  # Default yellow
            if alert["severity"] == "high":
                color = self.error_color  # Red for high severity
            elif alert["severity"] == "low":
                color = self.accent_color  # Purple for low severity
            
            # Show popup for high severity alerts
            if alert["severity"] == "high":
                messagebox.showwarning(
                    f"Security Alert: {alert['type']}",
                    f"{alert['info']}\n\nTime: {alert['time']}"
                )
                
            # Add to alerts text
            self.alerts_text.config(state=tk.NORMAL)
            
            # Format message (emoji based on severity)
            if alert["severity"] == "high":
                emoji = "⚠️"
            elif alert["severity"] == "medium":
                emoji = "⚡"
            else:
                emoji = "ℹ️"
                
            alert_msg = f"[{alert['time']}] {emoji} {alert['type']}: {alert['info']}\n"
            
            self.alerts_text.insert(tk.END, alert_msg)
            
            # Scroll to bottom
            self.alerts_text.see(tk.END)
            self.alerts_text.config(state=tk.DISABLED)
            
            # Show in status bar too
            self.log(f"ALERT: {alert['type']} - {alert['info']}", warning=True)
        except Exception as e:
            print(f"Error adding traffic alert: {str(e)}")
    
    def import_capture_file(self):
        """Import and analyze a capture file"""
        try:
            from tkinter import filedialog
            
            # File dialog for capture files
            filetypes = [
                ("Capture Files", "*.pcap *.pcapng *.cap"),
                ("PCAP Files", "*.pcap"),
                ("PCAPNG Files", "*.pcapng"), 
                ("CAP Files", "*.cap"),
                ("All Files", "*.*")
            ]
            
            filename = filedialog.askopenfilename(
                title="Select Capture File to Import and Analyze",
                filetypes=filetypes
            )
            
            if not filename:
                return
                
            self.log(f"Importing capture file: {os.path.basename(filename)}", success=True)
            
            # Clear existing data
            self._clear_analysis_data()
            
            # Start analysis in background
            import_thread = threading.Thread(target=self._analyze_imported_file, args=(filename,))
            import_thread.daemon = True
            import_thread.start()
            
        except Exception as e:
            self.log(f"Error importing file: {e}", error=True)
    
    def _clear_analysis_data(self):
        """Clear existing analysis data"""
        try:
            # Clear packet display
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
                
            # Clear alerts
            self.alerts_text.config(state=tk.NORMAL)
            self.alerts_text.delete(1.0, tk.END)
            self.alerts_text.insert(tk.END, "Analyzing imported file for sensitive data...\n")
            self.alerts_text.config(state=tk.DISABLED)
            
            # Reset counters
            self.packet_count = 0
            self.sensitive_findings = []
            self.current_packets = []
            self.protocol_stats = {}
            self.ip_stats = {}
            
        except Exception as e:
            self.log(f"Error clearing data: {e}", error=True)
    
    def _analyze_imported_file(self, filename):
        """Analyze imported capture file for sensitive data"""
        try:
            if not SCAPY_AVAILABLE:
                self.log("Cannot analyze file: Scapy not available", error=True)
                return
                
            # Read packets from file
            from scapy.all import rdpcap
            packets = rdpcap(filename)
            
            total_packets = len(packets)
            self.log(f"Loaded {total_packets} packets from file", success=True)
            
            # Process each packet
            for i, packet in enumerate(packets):
                try:
                    # Show progress
                    if i % 100 == 0:
                        progress = (i / total_packets) * 100
                        self.log(f"Analyzing... {progress:.1f}% complete", success=True)
                    
                    # Process packet for sensitive data using proper method
                    self._check_for_sensitive_data(packet)
                    
                    # Extract packet info and update stats
                    packet_info = self._extract_packet_info(packet)
                    self.current_packets.append(packet)
                    
                    # Update protocol stats
                    proto = packet_info.get("proto", "Unknown")
                    self.protocol_stats[proto] = self.protocol_stats.get(proto, 0) + 1
                    
                    # Update IP stats
                    src_ip = packet_info.get("src", "Unknown")
                    if src_ip != "Unknown":
                        self.ip_stats[src_ip] = self.ip_stats.get(src_ip, 0) + 1
                    
                    # Add to display (limit for performance)
                    if self.packet_count < 1000:
                        if self.root:
                            self.root.after(0, lambda p=packet_info: self._add_packet_to_tree(p))
                    
                    self.packet_count += 1
                    
                    # Update charts every 100 packets for real-time feedback
                    if i % 100 == 0 and self.root:
                        self.root.after(0, self._update_charts_immediately)
                    
                except Exception:
                    continue  # Skip problematic packets
            
            # Analysis complete - update everything immediately
            sensitive_count = len(self.sensitive_findings)
            self.log(f"Analysis complete: {total_packets} packets processed", success=True)
            self.log(f"Found {sensitive_count} sensitive data instances", 
                    warning=True if sensitive_count > 0 else False)
            
            # Update all charts and displays immediately
            if self.root:
                self.root.after(0, self._update_all_displays_final)
            
            # Save findings for reports
            self._save_analysis_results()
                
        except Exception as e:
            self.log(f"Error analyzing imported file: {e}", error=True)
    
    def _save_analysis_results(self):
        """Save analysis results for report generation"""
        try:
            import json
            
            # Prepare findings data
            analysis_data = {
                "source": "imported_file",
                "timestamp": datetime.now().isoformat(),
                "packets": [],
                "sensitive_data": [],
                "alerts": []
            }
            
            # Add sensitive data findings
            for finding in self.sensitive_findings:
                analysis_data["sensitive_data"].append({
                    "type": finding["category"],
                    "source": finding["src"],
                    "destination": finding["dst"],
                    "protocol": finding["protocol"],
                    "details": f"Found in imported capture: {finding['data']}",
                    "timestamp": finding["time"]
                })
                
                # Add as alert too
                analysis_data["alerts"].append({
                    "severity": "High" if finding["category"] in ["PASSWORD", "API_KEY", "TOKEN"] else "Medium",
                    "source": finding["src"],
                    "destination": finding["dst"],
                    "description": f"{finding['category']} detected in traffic",
                    "timestamp": finding["time"]
                })
            
            # Create directory and save
            os.makedirs("data/network_traffic", exist_ok=True)
            with open("data/network_traffic/latest_results.json", "w") as f:
                json.dump(analysis_data, f, indent=2)
                
            self.log("Analysis results saved for reports", success=True)
            
        except Exception as e:
            self.log(f"Error saving results: {e}", error=True)
    
    def _update_charts_immediately(self):
        """Update charts immediately during import"""
        try:
            # Update protocol chart
            self._update_protocol_chart()
            # Update top talkers chart (using correct method name)
            self._update_top_hosts_chart()
        except Exception as e:
            print(f"Error updating charts: {e}")
    
    def _update_all_displays_final(self):
        """Final update of all displays after import complete"""
        try:
            # Update all charts
            self._update_protocol_chart()
            self._update_top_hosts_chart()
            
            # Show summary of findings
            if self.sensitive_findings:
                summary_msg = f"\n=== IMPORT ANALYSIS COMPLETE ===\n"
                summary_msg += f"Total Packets: {self.packet_count}\n"
                summary_msg += f"Protocols Found: {len(self.protocol_stats)}\n"
                summary_msg += f"Unique IPs: {len(self.ip_stats)}\n"
                summary_msg += f"Sensitive Data Found: {len(self.sensitive_findings)}\n\n"
                
                # Add sensitive data summary
                categories = {}
                for finding in self.sensitive_findings:
                    cat = finding['category']
                    categories[cat] = categories.get(cat, 0) + 1
                
                for category, count in categories.items():
                    summary_msg += f"• {category}: {count} instances\n"
                
                # Add to alerts display
                self.alerts_text.config(state=tk.NORMAL)
                self.alerts_text.insert(tk.END, summary_msg)
                self.alerts_text.see(tk.END)
                self.alerts_text.config(state=tk.DISABLED)
                
                # Show popup for critical findings
                if any(f['category'] in ['PASSWORD', 'API_KEY', 'TOKEN'] for f in self.sensitive_findings):
                    critical_count = len([f for f in self.sensitive_findings if f['category'] in ['PASSWORD', 'API_KEY', 'TOKEN']])
                    messagebox.showwarning(
                        "Critical Sensitive Data Found!", 
                        f"Found {critical_count} critical sensitive data items in your capture file!\n\nCheck the alerts panel for details."
                    )
            
        except Exception as e:
            print(f"Error in final display update: {e}")

    def cleanup(self):
        """Clean up resources when closing"""
        self.stop_capture()
        
        # Close matplotlib figures if any
        if MATPLOTLIB_AVAILABLE:
            try:
                plt.close('all')
            except:
                pass

# Standalone test
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Enhanced Network Traffic Monitor")
    root.geometry("1024x768")
    
    frame = ttk.Frame(root)
    frame.pack(fill=tk.BOTH, expand=True)
    
    app = EnhancedNetworkMonitor(frame)
    
    root.mainloop()