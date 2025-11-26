#!/usr/bin/env python3
"""
Traffic Analysis GUI Module for Aero Strike (AI-Powered Wifi Penetration Testing Tool)
Provides interface for analyzing wireless traffic, detecting patterns, and identifying security issues
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
from datetime import datetime
import json
from typing import Dict, List, Any, Union, Optional
import tempfile
import subprocess

# Try to import optional dependencies with graceful fallbacks
try:
    import matplotlib
    matplotlib.use('TkAgg')
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Matplotlib not available, visualization will be disabled")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("NumPy not available, advanced data processing will be limited")

try:
    from scapy.all import rdpcap, Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available, packet analysis will be limited")

from src.dialog_utils import configure_dialog_for_display, create_maximize_button

class TrafficAnalysisGUI:
    """GUI for wireless traffic analysis module"""
    
    def __init__(self, parent, dark_mode=True, controller=None):
        """Initialize the traffic analysis GUI
        
        Args:
            parent: Parent frame/widget
            root: Tkinter root window
            dark_mode: Whether to use dark mode
            controller: Reference to the main application controller
        """
        self.parent = parent
        # Get the root window from the parent widget
        try:
            self.root = parent.winfo_toplevel()
        except:
            self.root = None
        self.dark_mode = dark_mode
        self.controller = controller
        
        # Configure basic styles
        self.bg_color = "#2d2d2d" if dark_mode else "#f0f0f0"
        self.fg_color = "#ffffff" if dark_mode else "#000000"
        self.accent_color = "#9F44D3"  # Purple accent
        self.highlight_color = "#480B86" if dark_mode else "#c880ff"
        self.warning_color = "#ffb142"
        self.error_color = "#ff5252"
        self.success_color = "#2ed573"
        
        # Initialize state variables
        self.current_file = None
        self.current_packets = []
        self.packet_stats = {}
        self.loading_data = False
        self.visualization_type = tk.StringVar(value="Packet Types")
        self.filter_text = tk.StringVar()
        self.interface_var = tk.StringVar()  # Interface variable
        self.monitor_mode = tk.BooleanVar(value=False)  # Monitor mode toggle
        self.sensitive_data_detection = tk.BooleanVar(value=True)  # Enable sensitive data detection
        self.real_time_alerts = tk.BooleanVar(value=True)  # Enable real-time alerts
        self.capture_method = tk.StringVar(value="auto")  # Capture method (auto, tcpdump, tshark, scapy)
        self.dev_mode = self.check_dev_mode()
        
        # Initialize sensitive data detection patterns
        self.sensitive_patterns = {
            "password": r'(?i)(password|passwd|pwd)[\s*:=]+[^\s&;"]{3,}',
            "api_key": r'(?i)(api[_-]?key|token|secret|jwt)[\s*:=]+[a-zA-Z0-9_\-\.]{8,}',
            "credit_card": r'\b(?:\d{4}[- ]?){3}\d{4}\b',
            "email_pass": r'(?i)(email|e-mail|mail)[\s*:=]+[^@\s]+@[^@\s]+\.[^@\s]+',
            "bearer_token": r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*',
            "basic_auth": r'Basic\s+[A-Za-z0-9+/]+={0,2}',
            "private_key": r'-----BEGIN (\w+) PRIVATE KEY-----',
            "cookie_session": r'(?i)(session|auth)[\s*:=]+[a-zA-Z0-9_\-\.]{8,}',
            "social_security": r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'  # SSN pattern
        }
        
        # Create the UI elements
        self.setup_ui()
    
    def check_dev_mode(self):
        """Check if running in development mode
        
        Returns:
            bool: True if in development mode
        """
        if 'REPL_ID' in os.environ or 'REPLIT' in os.environ:
            return True
        
        try:
            if os.geteuid() != 0:
                return True
        except:
            return True
            
        return False
    
    def setup_ui(self):
        """Create all UI elements"""
        # Configure frame using dictionary-style attribute setting
        try:
            self.parent["bg"] = self.bg_color  # More compatible approach
        except:
            pass  # Ignore if this fails
        
        # Create header frame
        self.create_header_frame()
        
        # Create main content
        self.create_main_content()
        
        # Create status bar
        self.create_status_bar()
        
        # Set the log initial message
        if SCAPY_AVAILABLE and MATPLOTLIB_AVAILABLE and NUMPY_AVAILABLE:
            self.log("Traffic Analysis module ready. Load a packet capture file to begin analysis.", success=True)
        else:
            missing = []
            if not SCAPY_AVAILABLE:
                missing.append("Scapy")
            if not MATPLOTLIB_AVAILABLE:
                missing.append("Matplotlib")
            if not NUMPY_AVAILABLE:
                missing.append("NumPy")
                
            self.log(f"Limited functionality: {', '.join(missing)} not available.", warning=True)
    
    def create_header_frame(self):
        """Create simplified header with just essential controls"""
        header_frame = ttk.Frame(self.parent)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Title
        title_label = ttk.Label(
            header_frame,
            text="Network Traffic Monitor",
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(side=tk.LEFT, padx=5)
        
        # Controls
        controls_frame = ttk.Frame(header_frame)
        controls_frame.pack(side=tk.RIGHT, padx=5)
        
        # Just one simple button to start monitoring
        self.capture_btn = ttk.Button(
            controls_frame,
            text="Start Capture",
            command=self.start_live_capture,
            width=15
        )
        self.capture_btn.pack(side=tk.LEFT, padx=5)
    
    def create_main_content(self):
        """Create simplified main content with just essential information"""
        # Main frame instead of notebook tabs
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 1. Sensitive Data Alerts Section (Top Priority)
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
        
        # 2. Main Packet Display
        packets_frame = ttk.LabelFrame(main_frame, text="Network Traffic")
        packets_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create packet tree - simpler version with only essential columns
        self.packet_tree = ttk.Treeview(
            packets_frame,
            columns=("No", "Time", "Source", "Destination", "Protocol", "Info"),
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns - simplified to show only the most important info
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
        
        # 3. Packet Details (Simple Version)
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
    
    # Removed tabs setup in favor of simplified interface
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # General statistics frame
        stats_frame = ttk.LabelFrame(left_frame, text="Capture Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create stats display
        self.stats_text = scrolledtext.ScrolledText(
            stats_frame,
            wrap=tk.WORD,
            width=40,
            height=20,
            font=("Consolas", 10),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground="#cccccc" if self.dark_mode else "#000000"
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Make the text read-only
        self.stats_text.config(state=tk.DISABLED)
        
        # Create right frame for summary visualizations
        right_frame = ttk.Frame(self.overview_tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Summary chart frame
        chart_frame = ttk.LabelFrame(right_frame, text="Packet Distribution")
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a frame for the chart
        self.overview_chart_frame = ttk.Frame(chart_frame)
        self.overview_chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Will be populated when data is loaded
        self.overview_chart_label = ttk.Label(
            self.overview_chart_frame,
            text="Load a packet capture file to display chart",
            anchor=tk.CENTER
        )
        self.overview_chart_label.pack(fill=tk.BOTH, expand=True)
    
    def setup_packets_tab(self):
        """Set up the packets tab"""
        # Top frame for filtering
        filter_frame = ttk.Frame(self.packets_tab)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Filter label
        filter_label = ttk.Label(
            filter_frame,
            text="Filter:"
        )
        filter_label.pack(side=tk.LEFT, padx=5)
        
        # Filter entry
        filter_entry = ttk.Entry(
            filter_frame,
            textvariable=self.filter_text,
            width=40
        )
        filter_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Apply filter button
        apply_filter_btn = ttk.Button(
            filter_frame,
            text="Apply",
            command=self.apply_filter
        )
        apply_filter_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear filter button
        clear_filter_btn = ttk.Button(
            filter_frame,
            text="Clear",
            command=self.clear_filter
        )
        clear_filter_btn.pack(side=tk.LEFT, padx=5)
        
        # Main packet list frame
        packet_frame = ttk.Frame(self.packets_tab)
        packet_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create tree view for packets
        self.packet_tree = ttk.Treeview(
            packet_frame,
            columns=("No", "Time", "Source", "Destination", "Protocol", "Length", "Info"),
            show="headings"
        )
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure columns
        self.packet_tree.heading("No", text="#")
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.heading("Source", text="Source")
        self.packet_tree.heading("Destination", text="Destination")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Length", text="Length")
        self.packet_tree.heading("Info", text="Info")
        
        self.packet_tree.column("No", width=50)
        self.packet_tree.column("Time", width=100)
        self.packet_tree.column("Source", width=150)
        self.packet_tree.column("Destination", width=150)
        self.packet_tree.column("Protocol", width=100)
        self.packet_tree.column("Length", width=80)
        self.packet_tree.column("Info", width=300)
        
        # Add scrollbar
        packet_scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.configure(yscrollcommand=packet_scrollbar.set)
        
        # Add horizontal scrollbar
        h_scrollbar = ttk.Scrollbar(self.packets_tab, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        h_scrollbar.pack(fill=tk.X, padx=10)
        self.packet_tree.configure(xscrollcommand=h_scrollbar.set)
        
        # Bind selection event
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        
        # Bottom frame for packet details
        details_frame = ttk.LabelFrame(self.packets_tab, text="Packet Details")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create text for packet details
        self.packet_details_text = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            width=80,
            height=10,
            font=("Consolas", 10),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground="#cccccc" if self.dark_mode else "#000000"
        )
        self.packet_details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Make the text read-only
        self.packet_details_text.config(state=tk.DISABLED)
    
    def setup_visualizations_tab(self):
        """Set up the visualizations tab"""
        # Left frame for controls
        left_frame = ttk.Frame(self.visualizations_tab)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        
        # Visualization options
        vis_options_frame = ttk.LabelFrame(left_frame, text="Visualization Type")
        vis_options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create radio buttons for visualization types
        vis_types = [
            ("Packet Types", "Packet Types"),
            ("Protocol Distribution", "Protocol Distribution"),
            ("Traffic Over Time", "Traffic Over Time"),
            ("Packet Sizes", "Packet Sizes"),
            ("Source/Destination", "Source/Destination")
        ]
        
        for text, value in vis_types:
            radio = ttk.Radiobutton(
                vis_options_frame,
                text=text,
                value=value,
                variable=self.visualization_type,
                command=self.update_visualization
            )
            radio.pack(anchor=tk.W, padx=10, pady=5)
        
        # Add some space
        ttk.Separator(left_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=5, pady=10)
        
        # Export options
        export_frame = ttk.LabelFrame(left_frame, text="Export Options")
        export_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Export buttons
        export_image_btn = ttk.Button(
            export_frame,
            text="Export as Image",
            command=self.export_visualization_image
        )
        export_image_btn.pack(fill=tk.X, padx=5, pady=5)
        
        export_data_btn = ttk.Button(
            export_frame,
            text="Export Data",
            command=self.export_visualization_data
        )
        export_data_btn.pack(fill=tk.X, padx=5, pady=5)
        
        # Right frame for visualization
        right_frame = ttk.Frame(self.visualizations_tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create visualization frame
        self.viz_frame = ttk.Frame(right_frame)
        self.viz_frame.pack(fill=tk.BOTH, expand=True)
        
        # Initial label
        self.viz_label = ttk.Label(
            self.viz_frame,
            text="Load a packet capture file to display visualizations",
            anchor=tk.CENTER
        )
        self.viz_label.pack(fill=tk.BOTH, expand=True)
    
    def setup_security_tab(self):
        """Set up the security analysis tab"""
        # Top frame for analysis controls
        top_frame = ttk.Frame(self.security_tab)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Analysis controls
        run_analysis_btn = ttk.Button(
            top_frame,
            text="Run Security Analysis",
            command=self.run_security_analysis
        )
        run_analysis_btn.pack(side=tk.LEFT, padx=5)
        
        save_report_btn = ttk.Button(
            top_frame,
            text="Save Security Report",
            command=self.save_security_report
        )
        save_report_btn.pack(side=tk.LEFT, padx=5)
        
        # Bottom frame for analysis results
        bottom_frame = ttk.Frame(self.security_tab)
        bottom_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for different analyses
        analysis_notebook = ttk.Notebook(bottom_frame)
        analysis_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs for different analyses
        self.vuln_tab = ttk.Frame(analysis_notebook)
        self.crypto_tab = ttk.Frame(analysis_notebook)
        self.auth_tab = ttk.Frame(analysis_notebook)
        self.summary_tab = ttk.Frame(analysis_notebook)
        
        analysis_notebook.add(self.summary_tab, text="Summary")
        analysis_notebook.add(self.vuln_tab, text="Vulnerabilities")
        analysis_notebook.add(self.crypto_tab, text="Encryption")
        analysis_notebook.add(self.auth_tab, text="Authentication")
        
        # Configure summary tab
        summary_frame = ttk.Frame(self.summary_tab)
        summary_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.summary_text = scrolledtext.ScrolledText(
            summary_frame,
            wrap=tk.WORD,
            width=80,
            height=30,
            font=("Consolas", 10),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground="#cccccc" if self.dark_mode else "#000000"
        )
        self.summary_text.pack(fill=tk.BOTH, expand=True)
        self.summary_text.config(state=tk.DISABLED)
        
        # Configure vulnerabilities tab
        vuln_frame = ttk.Frame(self.vuln_tab)
        vuln_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for vulnerabilities
        self.vuln_tree = ttk.Treeview(
            vuln_frame,
            columns=("Severity", "Type", "Description", "Affected"),
            show="headings"
        )
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure columns
        self.vuln_tree.heading("Severity", text="Severity")
        self.vuln_tree.heading("Type", text="Type")
        self.vuln_tree.heading("Description", text="Description")
        self.vuln_tree.heading("Affected", text="Affected")
        
        self.vuln_tree.column("Severity", width=80)
        self.vuln_tree.column("Type", width=150)
        self.vuln_tree.column("Description", width=300)
        self.vuln_tree.column("Affected", width=200)
        
        # Add scrollbar
        vuln_scrollbar = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        vuln_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.vuln_tree.configure(yscrollcommand=vuln_scrollbar.set)
        
        # Configure encryption tab
        crypto_frame = ttk.Frame(self.crypto_tab)
        crypto_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.crypto_text = scrolledtext.ScrolledText(
            crypto_frame,
            wrap=tk.WORD,
            width=80,
            height=30,
            font=("Consolas", 10),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground="#cccccc" if self.dark_mode else "#000000"
        )
        self.crypto_text.pack(fill=tk.BOTH, expand=True)
        self.crypto_text.config(state=tk.DISABLED)
        
        # Configure authentication tab
        auth_frame = ttk.Frame(self.auth_tab)
        auth_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.auth_text = scrolledtext.ScrolledText(
            auth_frame,
            wrap=tk.WORD,
            width=80,
            height=30,
            font=("Consolas", 10),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground="#cccccc" if self.dark_mode else "#000000"
        )
        self.auth_text.pack(fill=tk.BOTH, expand=True)
        self.auth_text.config(state=tk.DISABLED)
    
    def create_status_bar(self):
        """Create status bar at the bottom"""
        status_frame = ttk.Frame(self.parent)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(
            status_frame,
            text="Ready",
            anchor=tk.W,
            padding=(5, 2)
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Add log text widget for detailed status/log messages
        self.log_text = scrolledtext.ScrolledText(
            self.parent,
            wrap=tk.WORD,
            height=5,
            font=("Consolas", 9),
            bg="#1e1e1e" if self.dark_mode else "#ffffff",
            foreground="#cccccc" if self.dark_mode else "#000000"
        )
        self.log_text.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
        # Progress bar for loading
        self.progress_bar = ttk.Progressbar(
            status_frame,
            mode="indeterminate",
            length=100
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=5)
    
    def log(self, message, error=False, warning=False, success=False):
        """Log message to status and log text"""
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        
        if error:
            color = self.error_color
            prefix = "ERROR: "
            log_prefix = "[ERROR] "
        elif warning:
            color = self.warning_color
            prefix = "WARNING: "
            log_prefix = "[WARNING] "
        elif success:
            color = self.success_color
            prefix = "SUCCESS: "
            log_prefix = "[SUCCESS] "
        else:
            color = self.fg_color
            prefix = ""
            log_prefix = "[INFO] "
            
        # Update status label
        status_text = f"{prefix}{message}"
        self.status_label.config(foreground=color, text=status_text)
        
        # Update log text
        log_message = f"{timestamp} {log_prefix}{message}\n"
        
        # Configure tag for this message
        tag_name = "error" if error else "warning" if warning else "success" if success else "info"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_message, tag_name)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # Configure tags for colors
        self.log_text.tag_configure("error", foreground=self.error_color)
        self.log_text.tag_configure("warning", foreground=self.warning_color)
        self.log_text.tag_configure("success", foreground=self.success_color)
        self.log_text.tag_configure("info", foreground=self.fg_color)
        
        # Print to console as well
        print(f"{timestamp} {log_prefix}{message}")
    
    def load_pcap_file(self):
        """Load a PCAP file for analysis"""
        if self.loading_data:
            self.log("Already loading data", warning=True)
            return
            
        # Ask for file
        file_path = filedialog.askopenfilename(
            title="Select Packet Capture or Text File",
            filetypes=[
                ("PCAP Files", "*.pcap"),
                ("PCAPNG Files", "*.pcapng"),
                ("Text Files", "*.txt"),
                ("Log Files", "*.log"),
                ("JSON Files", "*.json"),
                ("CSV Files", "*.csv"),
                ("All Files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        self.current_file = file_path
        
        # Check if it's a text file for sensitive data scanning
        if file_path.lower().endswith(('.txt', '.log', '.csv', '.json', '.xml')):
            self.log(f"Scanning text file for sensitive data: {os.path.basename(file_path)}")
            self._scan_text_file_for_sensitive_data(file_path)
        else:
            self.log(f"Loading packet capture: {os.path.basename(file_path)}")
            
            # Clear current data
            self.current_packets = []
            self.packet_tree.delete(*self.packet_tree.get_children())
            
            # Start loading in a thread
            self.loading_data = True
            self.progress_bar.start(10)
            
            loading_thread = threading.Thread(
                target=self._load_pcap_thread,
                args=(file_path,)
            )
            loading_thread.daemon = True
            loading_thread.start()
    
    def _load_pcap_thread(self, file_path):
        """Thread function to load PCAP file"""
        try:
            # Check if scapy is available
            if not SCAPY_AVAILABLE:
                self.root.after(0, self.log, "Scapy not available, using simplified parsing", True)
                # Simplified parsing or mock data for development
                if self.dev_mode:
                    self._load_mock_data()
                else:
                    self.root.after(0, self.log, "Packet analysis requires Scapy library", True)
                return
                
            # Load the packets
            packets = rdpcap(file_path)
            
            # Store packets and update UI
            self.current_packets = packets
            
            # Update UI in main thread
            if self.root:
                self.root.after(0, self._update_ui_after_load, len(packets))
                
        except Exception as e:
            if self.root:
                self.root.after(0, self.log, f"Error loading packet capture: {str(e)}", True)
                
        finally:
            self.loading_data = False
            if self.root:
                self.root.after(0, self.progress_bar.stop)
    
    def _update_ui_after_load(self, packet_count):
        """Update UI after loading packets"""
        self.log(f"Loaded {packet_count} packets successfully", success=True)
        
        # Populate packet tree
        self._populate_packet_tree()
        
        # Generate statistics
        self._generate_statistics()
        
        # Update visualization
        self.update_visualization()
    
    def _populate_packet_tree(self):
        """Populate the packet treeview with loaded packets"""
        # Clear existing items
        self.packet_tree.delete(*self.packet_tree.get_children())
        
        # Process each packet
        for i, packet in enumerate(self.current_packets):
            try:
                # Extract basic info (simplified for many packet types)
                time_str = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S.%f")[:-3]
                
                # Extract layer information
                src = "Unknown"
                dst = "Unknown"
                proto = "Unknown"
                length = len(packet)
                info = ""
                
                # Layer 2
                if hasattr(packet, 'src') and hasattr(packet, 'dst'):
                    src = packet.src
                    dst = packet.dst
                
                # Determine protocol and other info
                for layer_name in packet.layers():
                    layer_name = layer_name.__name__
                    
                    if layer_name == "IP":
                        src = packet[layer_name].src
                        dst = packet[layer_name].dst
                        proto = "IP"
                    elif layer_name == "IPv6":
                        src = packet[layer_name].src
                        dst = packet[layer_name].dst
                        proto = "IPv6"
                    elif layer_name == "TCP":
                        proto = "TCP"
                        info = f"Src Port: {packet[layer_name].sport}, Dst Port: {packet[layer_name].dport}"
                    elif layer_name == "UDP":
                        proto = "UDP"
                        info = f"Src Port: {packet[layer_name].sport}, Dst Port: {packet[layer_name].dport}"
                    elif layer_name == "ICMP":
                        proto = "ICMP"
                        info = f"Type: {packet[layer_name].type}, Code: {packet[layer_name].code}"
                    elif layer_name == "DNS":
                        proto = "DNS"
                        if hasattr(packet[layer_name], 'qd') and packet[layer_name].qd:
                            info = f"Query: {packet[layer_name].qd.qname.decode('utf-8', errors='ignore')}"
                    elif layer_name == "HTTP":
                        proto = "HTTP"
                        if hasattr(packet[layer_name], 'Method'):
                            info = f"{packet[layer_name].Method.decode('utf-8', errors='ignore')} {packet[layer_name].Path.decode('utf-8', errors='ignore')}"
                        elif hasattr(packet[layer_name], 'Status-Line'):
                            info = packet[layer_name]['Status-Line'].decode('utf-8', errors='ignore')
                    elif layer_name == "Dot11":
                        proto = "802.11"
                        if hasattr(packet[layer_name], 'type') and hasattr(packet[layer_name], 'subtype'):
                            frame_type = packet[layer_name].type
                            frame_subtype = packet[layer_name].subtype
                            info = f"Type: {frame_type}, Subtype: {frame_subtype}"
                    elif layer_name == "ARP":
                        proto = "ARP"
                        if hasattr(packet[layer_name], 'op'):
                            op = packet[layer_name].op
                            if op == 1:
                                info = "Who has {} ? Tell {}".format(packet[layer_name].pdst, packet[layer_name].psrc)
                            elif op == 2:
                                info = "{} is at {}".format(packet[layer_name].psrc, packet[layer_name].hwsrc)
                
                # Insert into tree
                self.packet_tree.insert(
                    "",
                    tk.END,
                    values=(i+1, time_str, src, dst, proto, length, info)
                )
                
            except Exception as e:
                # Skip packets that can't be parsed
                self.log(f"Error parsing packet {i+1}: {str(e)}", warning=True)
    
    def _generate_statistics(self):
        """Generate statistics from loaded packets"""
        if not self.current_packets:
            return
            
        # Count by protocol
        proto_count = {}
        ip_src_count = {}
        ip_dst_count = {}
        port_count = {}
        packet_sizes = []
        
        # Process each packet
        for packet in self.current_packets:
            try:
                # Track packet size
                size = len(packet)
                packet_sizes.append(size)
                
                # Process layers to identify protocol
                proto_added = False
                
                for layer_name in packet.layers():
                    layer_name = layer_name.__name__
                    
                    # Count by protocol
                    if layer_name in proto_count:
                        proto_count[layer_name] += 1
                    else:
                        proto_count[layer_name] = 1
                    
                    # Only count the highest layer protocol once
                    if not proto_added and layer_name not in ['Ether', 'IP', 'IPv6']:
                        proto_added = True
                    
                    # Process IP layers
                    if layer_name == "IP":
                        src = packet[layer_name].src
                        dst = packet[layer_name].dst
                        
                        # Count source IPs
                        if src in ip_src_count:
                            ip_src_count[src] += 1
                        else:
                            ip_src_count[src] = 1
                            
                        # Count destination IPs
                        if dst in ip_dst_count:
                            ip_dst_count[dst] += 1
                        else:
                            ip_dst_count[dst] = 1
                    
                    # Process TCP/UDP for port information
                    elif layer_name in ["TCP", "UDP"]:
                        sport = packet[layer_name].sport
                        dport = packet[layer_name].dport
                        
                        # Add protocol prefix to identify port type
                        sport_key = f"{layer_name}:{sport}"
                        dport_key = f"{layer_name}:{dport}"
                        
                        # Count source ports
                        if sport_key in port_count:
                            port_count[sport_key] += 1
                        else:
                            port_count[sport_key] = 1
                            
                        # Count destination ports
                        if dport_key in port_count:
                            port_count[dport_key] += 1
                        else:
                            port_count[dport_key] = 1
                            
            except Exception as e:
                # Skip packets that can't be processed
                self.log(f"Error processing packet statistics: {str(e)}", warning=True)
        
        # Calculate additional statistics
        total_packets = len(self.current_packets)
        total_bytes = sum(packet_sizes)
        avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
        min_packet_size = min(packet_sizes) if packet_sizes else 0
        max_packet_size = max(packet_sizes) if packet_sizes else 0
        
        # Sort protocols by count
        sorted_protocols = sorted(proto_count.items(), key=lambda x: x[1], reverse=True)
        
        # Sort IPs by count
        sorted_src_ips = sorted(ip_src_count.items(), key=lambda x: x[1], reverse=True)[:10]  # Top 10
        sorted_dst_ips = sorted(ip_dst_count.items(), key=lambda x: x[1], reverse=True)[:10]  # Top 10
        
        # Sort ports by count
        sorted_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:10]  # Top 10
        
        # Create statistics text
        stats = f"""Packet Capture Statistics

Capture File: {os.path.basename(self.current_file)}
Total Packets: {total_packets}
Total Data Size: {total_bytes} bytes ({total_bytes/1024:.2f} KB)
Average Packet Size: {avg_packet_size:.2f} bytes
Minimum Packet Size: {min_packet_size} bytes
Maximum Packet Size: {max_packet_size} bytes

Protocol Distribution:
{"=" * 40}
"""
        
        for proto, count in sorted_protocols:
            percentage = (count / total_packets) * 100
            stats += f"{proto}: {count} packets ({percentage:.1f}%)\n"
        
        stats += f"""
Top Source IP Addresses:
{"=" * 40}
"""
        
        for ip, count in sorted_src_ips:
            percentage = (count / total_packets) * 100
            stats += f"{ip}: {count} packets ({percentage:.1f}%)\n"
        
        stats += f"""
Top Destination IP Addresses:
{"=" * 40}
"""
        
        for ip, count in sorted_dst_ips:
            percentage = (count / total_packets) * 100
            stats += f"{ip}: {count} packets ({percentage:.1f}%)\n"
        
        stats += f"""
Top Ports (Protocol:Port):
{"=" * 40}
"""
        
        for port, count in sorted_ports:
            percentage = (count / total_packets) * 100
            stats += f"{port}: {count} packets ({percentage:.1f}%)\n"
        
        # Update statistics display
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats)
        self.stats_text.config(state=tk.DISABLED)
        
        # Store statistics for later use
        self.packet_stats = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "avg_packet_size": avg_packet_size,
            "min_packet_size": min_packet_size,
            "max_packet_size": max_packet_size,
            "proto_count": proto_count,
            "ip_src_count": ip_src_count,
            "ip_dst_count": ip_dst_count,
            "port_count": port_count,
            "packet_sizes": packet_sizes
        }
        
        # Update overview chart
        self._update_overview_chart()
    
    def _update_overview_chart(self):
        """Update the chart in the overview tab"""
        if not MATPLOTLIB_AVAILABLE or not self.packet_stats:
            return
            
        # Clear existing chart
        for widget in self.overview_chart_frame.winfo_children():
            widget.destroy()
            
        # Create figure
        fig = Figure(figsize=(5, 4), dpi=100)
        ax = fig.add_subplot(111)
        
        # Get protocol counts
        proto_count = self.packet_stats["proto_count"]
        
        # Filter protocols (exclude lower layers like Ether, IP, etc.)
        excluded_protos = {'Ether', 'IP', 'IPv6', 'Raw', 'Padding'}
        filtered_protos = {k: v for k, v in proto_count.items() if k not in excluded_protos}
        
        # If filtering removed all protocols, use original
        if not filtered_protos:
            filtered_protos = proto_count
        
        # Sort by count
        sorted_protos = sorted(filtered_protos.items(), key=lambda x: x[1], reverse=True)
        
        # Take top protocols
        top_count = 7
        if len(sorted_protos) > top_count:
            top_protos = sorted_protos[:top_count]
            other_count = sum(count for proto, count in sorted_protos[top_count:])
            if other_count > 0:
                top_protos.append(("Other", other_count))
        else:
            top_protos = sorted_protos
        
        # Extract labels and sizes
        labels = [proto for proto, _ in top_protos]
        sizes = [count for _, count in top_protos]
        
        # Create pie chart
        colors = plt.cm.tab10(range(len(labels)))
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
        ax.axis('equal')
        ax.set_title('Protocol Distribution')
        
        # Create canvas
        canvas = FigureCanvasTkAgg(fig, self.overview_chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def update_visualization(self):
        """Update the visualization based on the selected type"""
        if not MATPLOTLIB_AVAILABLE or not self.packet_stats:
            return
            
        # Get visualization type
        viz_type = self.visualization_type.get()
        
        # Clear existing visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
            
        # Create figure
        fig = Figure(figsize=(7, 5), dpi=100)
        ax = fig.add_subplot(111)
        
        # Create different visualizations based on type
        if viz_type == "Packet Types":
            # Get protocol counts
            proto_count = self.packet_stats["proto_count"]
            
            # Filter protocols (exclude lower layers)
            excluded_protos = {'Ether', 'IP', 'IPv6', 'Raw', 'Padding'}
            filtered_protos = {k: v for k, v in proto_count.items() if k not in excluded_protos}
            
            # If filtering removed all protocols, use original
            if not filtered_protos:
                filtered_protos = proto_count
            
            # Sort by count
            sorted_protos = sorted(filtered_protos.items(), key=lambda x: x[1], reverse=True)
            
            # Take top protocols
            top_count = 10
            if len(sorted_protos) > top_count:
                top_protos = sorted_protos[:top_count]
                other_count = sum(count for proto, count in sorted_protos[top_count:])
                if other_count > 0:
                    top_protos.append(("Other", other_count))
            else:
                top_protos = sorted_protos
            
            # Extract labels and sizes
            labels = [proto for proto, _ in top_protos]
            sizes = [count for _, count in top_protos]
            
            # Create pie chart
            colors = plt.cm.tab10(range(len(labels)))
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
            ax.axis('equal')
            ax.set_title('Protocol Distribution')
            
        elif viz_type == "Protocol Distribution":
            # Get protocol counts
            proto_count = self.packet_stats["proto_count"]
            
            # Filter protocols (exclude lower layers)
            excluded_protos = {'Ether', 'Raw', 'Padding'}
            filtered_protos = {k: v for k, v in proto_count.items() if k not in excluded_protos}
            
            # Sort by count
            sorted_protos = sorted(filtered_protos.items(), key=lambda x: x[1], reverse=True)
            
            # Take top protocols
            top_count = 15
            if len(sorted_protos) > top_count:
                sorted_protos = sorted_protos[:top_count]
            
            # Extract labels and counts
            labels = [proto for proto, _ in sorted_protos]
            counts = [count for _, count in sorted_protos]
            
            # Create bar chart
            x = range(len(labels))
            ax.bar(x, counts, color=plt.cm.tab10(range(len(labels))))
            ax.set_xticks(x)
            ax.set_xticklabels(labels, rotation=45, ha='right')
            ax.set_title('Protocol Distribution')
            ax.set_ylabel('Number of Packets')
            
        elif viz_type == "Traffic Over Time":
            # This visualization is more complex as we need to group packets by time
            # Only possible if we have timestamps
            if not self.current_packets:
                ax.text(0.5, 0.5, "No packet data available", ha='center', va='center')
            else:
                try:
                    # Collect timestamps
                    timestamps = [float(packet.time) for packet in self.current_packets if hasattr(packet, 'time')]
                    
                    if not timestamps:
                        ax.text(0.5, 0.5, "No timestamp data available", ha='center', va='center')
                    else:
                        # Normalize timestamps to start from 0
                        min_time = min(timestamps)
                        normalized = [t - min_time for t in timestamps]
                        
                        # Bin timestamps into intervals
                        max_time = max(normalized)
                        bin_count = min(50, int(max_time) + 1)  # Up to 50 bins or 1 per second
                        
                        # Create histogram
                        n, bins, patches = ax.hist(normalized, bins=bin_count, edgecolor='black')
                        
                        # Set labels
                        ax.set_title('Traffic Over Time')
                        ax.set_xlabel('Time (seconds from capture start)')
                        ax.set_ylabel('Number of Packets')
                        
                except Exception as e:
                    self.log(f"Error creating traffic over time visualization: {str(e)}", error=True)
                    ax.text(0.5, 0.5, "Error creating visualization", ha='center', va='center')
            
        elif viz_type == "Packet Sizes":
            # Get packet sizes
            packet_sizes = self.packet_stats["packet_sizes"]
            
            if not packet_sizes:
                ax.text(0.5, 0.5, "No packet size data available", ha='center', va='center')
            else:
                # Create histogram
                n, bins, patches = ax.hist(packet_sizes, bins=30, edgecolor='black')
                
                # Set labels
                ax.set_title('Packet Size Distribution')
                ax.set_xlabel('Packet Size (bytes)')
                ax.set_ylabel('Number of Packets')
            
        elif viz_type == "Source/Destination":
            # Get IP counts
            ip_src_count = self.packet_stats["ip_src_count"]
            ip_dst_count = self.packet_stats["ip_dst_count"]
            
            if not ip_src_count and not ip_dst_count:
                ax.text(0.5, 0.5, "No IP address data available", ha='center', va='center')
            else:
                # Sort by count
                sorted_src = sorted(ip_src_count.items(), key=lambda x: x[1], reverse=True)
                sorted_dst = sorted(ip_dst_count.items(), key=lambda x: x[1], reverse=True)
                
                # Take top IPs
                top_count = 5
                top_src = sorted_src[:top_count]
                top_dst = sorted_dst[:top_count]
                
                # Extract labels and counts
                src_labels = [ip for ip, _ in top_src]
                src_counts = [count for _, count in top_src]
                
                dst_labels = [ip for ip, _ in top_dst]
                dst_counts = [count for _, count in top_dst]
                
                # Create bar chart with grouped bars
                x_src = range(len(src_labels))
                x_dst = range(len(dst_labels))
                
                # If src and dst counts are different, adjust
                if len(src_labels) != len(dst_labels):
                    max_len = max(len(src_labels), len(dst_labels))
                    if len(src_labels) < max_len:
                        src_labels.extend([''] * (max_len - len(src_labels)))
                        src_counts.extend([0] * (max_len - len(src_counts)))
                        x_src = range(max_len)
                    if len(dst_labels) < max_len:
                        dst_labels.extend([''] * (max_len - len(dst_labels)))
                        dst_counts.extend([0] * (max_len - len(dst_counts)))
                        x_dst = range(max_len)
                
                # Two subplots for source and destination
                ax.clear()
                ax.set_title('Top IP Addresses')
                
                bar_width = 0.35
                ax.bar([x - bar_width/2 for x in range(len(src_labels))], src_counts, bar_width, label='Source')
                ax.bar([x + bar_width/2 for x in range(len(dst_labels))], dst_counts, bar_width, label='Destination')
                
                ax.set_xticks(range(len(src_labels)))
                
                # Convert labels to display format (truncate if too long)
                display_labels = []
                for label in src_labels:
                    if len(label) > 15:
                        display_labels.append(label[:12] + '...')
                    else:
                        display_labels.append(label)
                        
                ax.set_xticklabels(display_labels, rotation=45, ha='right')
                ax.set_ylabel('Number of Packets')
                ax.legend()
        
        # Create canvas
        canvas = FigureCanvasTkAgg(fig, self.viz_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def on_packet_select(self, event):
        """Handler for packet selection in the treeview"""
        selected = self.packet_tree.selection()
        
        if not selected:
            return
            
        # Get the selected packet
        item_id = selected[0]
        values = self.packet_tree.item(item_id, "values")
        
        if not values:
            return
            
        # Get packet index (1-based in the tree)
        packet_idx = int(values[0]) - 1
        
        if packet_idx < 0 or packet_idx >= len(self.current_packets):
            return
            
        packet = self.current_packets[packet_idx]
        
        # Generate packet details
        self._show_packet_details(packet)
    
    def _show_packet_details(self, packet):
        """Show detailed information about a packet"""
        if not packet:
            return
            
        # Clear details area
        self.packet_details_text.config(state=tk.NORMAL)
        self.packet_details_text.delete(1.0, tk.END)
        
        # Generate details
        details = ""
        
        try:
            # Add general information
            details += f"=== Packet Summary ===\n"
            details += f"{packet.summary()}\n\n"
            
            # Add hexdump
            details += "=== Hexdump ===\n"
            
            try:
                from scapy.utils import hexdump
                hex_str = hexdump(packet, dump=True)
                details += hex_str + "\n\n"
            except Exception:
                # Simplified hexdump if scapy's not available
                raw_bytes = bytes(packet)
                offset = 0
                while offset < len(raw_bytes):
                    row_bytes = raw_bytes[offset:offset+16]
                    hex_vals = " ".join(f"{b:02x}" for b in row_bytes)
                    ascii_vals = "".join(chr(b) if 32 <= b <= 126 else "." for b in row_bytes)
                    details += f"{offset:04x}  {hex_vals.ljust(48)}  {ascii_vals}\n"
                    offset += 16
                details += "\n\n"
            
            # Add layer details
            details += "=== Layers ===\n"
            
            # Process each layer
            for layer_name in packet.layers():
                layer_name = layer_name.__name__
                details += f"\n--- {layer_name} Layer ---\n"
                
                # Get layer
                layer = packet.getlayer(layer_name)
                
                # Add fields
                for field in layer.fields_desc:
                    field_name = field.name
                    if field_name in layer.fields:
                        field_value = layer.fields[field_name]
                        
                        # Format value based on type
                        if isinstance(field_value, bytes):
                            try:
                                # Try to decode as utf-8 with fallback to hex
                                field_str = field_value.decode('utf-8', errors='replace')
                                if any(c == '\ufffd' for c in field_str):  # Replacement character
                                    field_str = field_value.hex()
                            except:
                                field_str = field_value.hex()
                        else:
                            field_str = str(field_value)
                            
                        details += f"{field_name}: {field_str}\n"
            
        except Exception as e:
            details += f"\nError processing packet details: {str(e)}"
        
        # Update text widget
        self.packet_details_text.insert(tk.END, details)
        self.packet_details_text.config(state=tk.DISABLED)
    
    def start_live_capture(self):
        """Start live capture of wireless traffic"""
        # Check if scapy is available
        if not SCAPY_AVAILABLE:
            self.log("Scapy not available, live capture not supported", error=True)
            return
            
        # Create live capture dialog
        self.create_live_capture_dialog()
    
    def create_live_capture_dialog(self):
        """Create dialog for live capture configuration"""
        # Create dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title("Live Capture & Sensitive Data Detection")
        dialog.geometry("600x500")
        dialog.minsize(550, 450)
        
        # Fix the dialog on top and make it modal
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Configure dialog style
        dialog.configure(bg=self.bg_color)
        
        # Header frame
        header_frame = ttk.Frame(dialog)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Title
        title_label = ttk.Label(
            header_frame,
            text="Configure Live Capture",
            font=("Helvetica", 14, "bold")
        )
        title_label.pack(side=tk.LEFT, padx=5)
        
        # Add maximize button
        max_button = create_maximize_button(header_frame, dialog)
        max_button.pack(side=tk.RIGHT, padx=5)
        
        # Configure proper display
        configure_dialog_for_display(dialog)
        
        # Main content
        content_frame = ttk.Frame(dialog)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Interface selection
        interface_frame = ttk.LabelFrame(content_frame, text="Wireless Interface")
        interface_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Get available interfaces
        interfaces = self._get_available_interfaces()
        
        # Interface variable
        interface_var = tk.StringVar()
        if interfaces:
            interface_var.set(interfaces[0])
        
        # Interface dropdown
        if interfaces:
            interface_combo = ttk.Combobox(
                interface_frame,
                textvariable=interface_var,
                values=interfaces,
                state="readonly",
                width=30
            )
            interface_combo.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)
            
            # Refresh button
            refresh_btn = ttk.Button(
                interface_frame,
                text="Refresh",
                command=lambda: self._refresh_interfaces(interface_combo)
            )
            refresh_btn.pack(side=tk.RIGHT, padx=10, pady=10)
        else:
            no_interfaces_label = ttk.Label(
                interface_frame,
                text="No wireless interfaces available",
                foreground=self.error_color
            )
            no_interfaces_label.pack(padx=10, pady=10)
        
        # Capture options
        options_frame = ttk.LabelFrame(content_frame, text="Capture Options")
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Time limit
        time_frame = ttk.Frame(options_frame)
        time_frame.pack(fill=tk.X, padx=5, pady=5)
        
        time_label = ttk.Label(time_frame, text="Capture Duration (seconds):")
        time_label.pack(side=tk.LEFT, padx=5)
        
        time_var = tk.IntVar(value=60)
        time_spinbox = ttk.Spinbox(
            time_frame,
            from_=1,
            to=3600,
            textvariable=time_var,
            width=10
        )
        time_spinbox.pack(side=tk.LEFT, padx=5)
        
        # Packet limit
        packet_frame = ttk.Frame(options_frame)
        packet_frame.pack(fill=tk.X, padx=5, pady=5)
        
        packet_label = ttk.Label(packet_frame, text="Packet Limit:")
        packet_label.pack(side=tk.LEFT, padx=5)
        
        packet_var = tk.IntVar(value=1000)
        packet_spinbox = ttk.Spinbox(
            packet_frame,
            from_=1,
            to=100000,
            textvariable=packet_var,
            width=10
        )
        packet_spinbox.pack(side=tk.LEFT, padx=5)
        
        # Filter
        filter_frame = ttk.Frame(options_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        filter_label = ttk.Label(filter_frame, text="BPF Filter:")
        filter_label.pack(side=tk.LEFT, padx=5)
        
        filter_var = tk.StringVar()
        filter_entry = ttk.Entry(
            filter_frame,
            textvariable=filter_var,
            width=30
        )
        filter_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Checkboxes
        check_frame = ttk.Frame(options_frame)
        check_frame.pack(fill=tk.X, padx=5, pady=5)
        
        promisc_var = tk.BooleanVar(value=True)
        promisc_check = ttk.Checkbutton(
            check_frame,
            text="Promiscuous Mode",
            variable=promisc_var
        )
        promisc_check.pack(side=tk.LEFT, padx=5)
        
        monitor_var = tk.BooleanVar(value=True)
        monitor_check = ttk.Checkbutton(
            check_frame,
            text="Monitor Mode",
            variable=monitor_var
        )
        monitor_check.pack(side=tk.LEFT, padx=5)
        
        # Security Analysis Options
        security_frame = ttk.LabelFrame(content_frame, text="Security Analysis")
        security_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Sensitive data detection
        detect_var = tk.BooleanVar(value=self.sensitive_data_detection.get())
        detect_check = ttk.Checkbutton(
            security_frame,
            text="Detect Sensitive Data (passwords, tokens, API keys)",
            variable=detect_var
        )
        detect_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # Real-time alerts
        alert_var = tk.BooleanVar(value=self.real_time_alerts.get())
        alert_check = ttk.Checkbutton(
            security_frame,
            text="Show Real-Time Security Alerts",
            variable=alert_var
        )
        alert_check.pack(anchor=tk.W, padx=5, pady=5)
        
        # Capture method
        method_frame = ttk.Frame(security_frame)
        method_frame.pack(fill=tk.X, padx=5, pady=5)
        
        method_label = ttk.Label(method_frame, text="Capture Method:")
        method_label.pack(side=tk.LEFT, padx=5)
        
        method_var = tk.StringVar(value=self.capture_method.get())
        method_combo = ttk.Combobox(
            method_frame,
            textvariable=method_var,
            values=["auto", "scapy", "tcpdump", "tshark"],
            state="readonly",
            width=10
        )
        method_combo.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Help button for BPF filters
        help_btn = ttk.Button(
            button_frame,
            text="Filter Help",
            command=lambda: self._show_filter_help()
        )
        help_btn.pack(side=tk.LEFT, padx=5)
        
        # Start button
        start_btn = ttk.Button(
            button_frame,
            text="Start Capture",
            command=lambda: self._start_capture(
                dialog,
                interface_var.get(),
                time_var.get(),
                packet_var.get(),
                filter_var.get(),
                promisc_var.get(),
                monitor_var.get(),
                detect_var.get(),      # Pass sensitive data detection flag
                alert_var.get(),       # Pass real-time alerts flag
                method_var.get()       # Pass capture method
            )
        )
        start_btn.pack(side=tk.RIGHT, padx=5)
        
        # Cancel button
        cancel_btn = ttk.Button(
            button_frame,
            text="Cancel",
            command=dialog.destroy
        )
        cancel_btn.pack(side=tk.RIGHT, padx=5)
    
    def _get_available_interfaces(self):
        """Get list of available wireless interfaces"""
        if not SCAPY_AVAILABLE:
            return []
            
        try:
            from scapy.arch import get_if_list
            interfaces = get_if_list()
            
            # Filter for likely wireless interfaces (common naming patterns)
            wireless = []
            for iface in interfaces:
                if (iface.startswith(('wlan', 'ath', 'wl', 'ra', 'mon', 'wifi', 'wlp', 'en')) or 
                    ('mon' in iface) or ('wifi' in iface) or ('wlan' in iface) or
                    ('802.11' in iface)):
                    wireless.append(iface)
            
            # If no wireless interfaces found, return all
            if not wireless and interfaces:
                return interfaces
                
            return wireless
            
        except Exception as e:
            self.log(f"Error getting network interfaces: {str(e)}", error=True)
            return []
    
    def _refresh_interfaces(self, combo):
        """Refresh the interface list"""
        interfaces = self._get_available_interfaces()
        combo['values'] = interfaces
        if interfaces:
            combo.set(interfaces[0])
    
    def _show_filter_help(self):
        """Show help dialog for BPF filters"""
        help_dialog = tk.Toplevel(self.root)
        help_dialog.title("BPF Filter Help")
        help_dialog.geometry("600x500")
        help_dialog.minsize(500, 400)
        
        # Make it modal
        help_dialog.transient(self.root)
        help_dialog.grab_set()
        
        # Configure dialog style
        help_dialog.configure(bg=self.bg_color)
        
        # Configure proper display
        configure_dialog_for_display(help_dialog)
        
        # Create scrollable text
        help_text = scrolledtext.ScrolledText(
            help_dialog,
            wrap=tk.WORD,
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Courier", 10)
        )
        help_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Insert help content
        help_content = """
BPF Filter Examples:

# Basic filters
port 80                   # Capture HTTP traffic
port 443                  # Capture HTTPS traffic
host 192.168.1.1          # Traffic to/from specific host
net 192.168.1.0/24        # Traffic in subnet
src host 192.168.1.10     # Traffic from specific host
dst host 8.8.8.8          # Traffic to specific host

# Protocol filters
tcp                       # TCP traffic only
udp                       # UDP traffic only
icmp                      # ICMP traffic only
arp                       # ARP traffic only
ip6                       # IPv6 traffic

# Combinations (use 'and', 'or', 'not')
tcp and port 80           # HTTP traffic
port 80 or port 443       # HTTP or HTTPS
host 192.168.1.1 and not icmp  # All except ICMP
tcp and (port 80 or port 443)  # HTTP or HTTPS over TCP

# Advanced WiFi filters (requires monitor mode)
type mgt                  # Management frames only
type ctl                  # Control frames
type data                 # Data frames
subtype beacon            # Beacon frames
subtype probe-req         # Probe requests
subtype probe-resp        # Probe responses
subtype deauth            # Deauthentication frames

More info: https://biot.com/capstats/bpf.html
        """
        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)
        
        # Close button
        close_btn = ttk.Button(
            help_dialog,
            text="Close",
            command=help_dialog.destroy
        )
        close_btn.pack(pady=10)
    
    def _start_capture(self, dialog, interface, duration, packet_limit, filter_str, promiscuous, monitor, 
                       detect_sensitive=True, show_alerts=True, capture_method="auto"):
        """Start the live capture with the selected options and security analysis"""
        if not interface:
            self.log("No interface selected", error=True)
            return
            
        dialog.destroy()
        
        # Update settings from dialog
        self.sensitive_data_detection.set(detect_sensitive)
        self.real_time_alerts.set(show_alerts)
        self.capture_method.set(capture_method)
        
        # Log capture settings
        self.log(f"Starting live capture on {interface}")
        self.log(f"Duration: {duration}s, Packet limit: {packet_limit}")
        if filter_str:
            self.log(f"Filter: {filter_str}")
        if promiscuous:
            self.log("Promiscuous mode enabled")
        if monitor:
            self.log("Monitor mode enabled")
        if detect_sensitive:
            self.log("Sensitive data detection enabled")
        
        # Log capture method
        if capture_method != "auto":
            self.log(f"Using capture method: {capture_method}")
        
        # Clear current data
        self.current_packets = []
        self.packet_tree.delete(*self.packet_tree.get_children())
        
        # Initialize sensitive data findings
        self.found_sensitive_data = []
        
        # Show progress dialog
        self._show_capture_progress_dialog(interface, duration, packet_limit, filter_str, promiscuous, monitor)
    
    def _show_capture_progress_dialog(self, interface, duration, packet_limit, filter_str, promiscuous, monitor):
        """Show dialog with capture progress"""
        # Create dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title("Capturing...")
        dialog.geometry("400x200")
        dialog.minsize(300, 150)
        
        # Fix the dialog on top and make it modal
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Configure dialog style
        dialog.configure(bg=self.bg_color)
        
        # Configure proper display
        configure_dialog_for_display(dialog)
        
        # Content
        content_frame = ttk.Frame(dialog)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Status message
        status_label = ttk.Label(
            content_frame,
            text=f"Capturing packets on {interface}...",
            font=("Helvetica", 12)
        )
        status_label.pack(pady=10)
        
        # Progress indicators
        progress_frame = ttk.Frame(content_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        
        time_label = ttk.Label(progress_frame, text="Time:")
        time_label.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        time_progress = ttk.Progressbar(progress_frame, length=200, mode="determinate")
        time_progress.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        packet_label = ttk.Label(progress_frame, text="Packets:")
        packet_label.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        
        packet_var = tk.StringVar(value="0")
        packet_count = ttk.Label(progress_frame, textvariable=packet_var)
        packet_count.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        stop_btn = ttk.Button(
            button_frame,
            text="Stop Capture",
            command=lambda: self._stop_capture()
        )
        stop_btn.pack(side=tk.RIGHT, padx=5)
        
        # Start capture in thread
        self.capture_thread = threading.Thread(
            target=self._capture_thread,
            args=(dialog, interface, duration, packet_limit, filter_str, promiscuous, monitor, time_progress, packet_var)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
    
    def _capture_thread(self, dialog, interface, duration, packet_limit, filter_str, promiscuous, monitor, time_progress, packet_var):
        """Thread function for live packet capture"""
        self.loading_data = True
        self.stop_capture = False
        capture_method = self.capture_method.get()
        packets = []
        
        try:
            # Create temp directory for capture files if needed
            temp_dir = os.path.join(os.getcwd(), "captures")
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
                
            # Output file for various capture methods
            output_file = os.path.join(temp_dir, f"capture_{int(time.time())}.pcap")
            
            # Initialize sensitive data detection
            self.found_sensitive_data = []
            
            # Log capture start
            if self.root:
                self.root.after(0, self.log, f"Starting live capture on interface: {interface}")
            
            # Check if scapy is available for packet capture
            if SCAPY_AVAILABLE:
                try:
                    from scapy.all import sniff, wrpcap
                    
                    if self.root:
                        self.root.after(0, self.log, f"Starting live capture on interface: {interface}")
                        self.root.after(0, self.log, f"Duration: {duration}s, Packet limit: {packet_limit}")
                    
                    # Initialize packet storage
                    captured_packets = []
                    packet_count = 0
                    start_time = time.time()
                    
                    # Define packet callback for real-time processing
                    def packet_callback(packet):
                        nonlocal packet_count, captured_packets
                        packet_count += 1
                        captured_packets.append(packet)
                        
                        # Update UI in main thread
                        if self.root:
                            self.root.after(0, packet_var.set, str(packet_count))
                        
                        # Check for sensitive data if enabled
                        if self.sensitive_data_detection.get():
                            try:
                                self._scan_packet_for_sensitive_data(packet)
                            except Exception as e:
                                pass  # Continue processing other packets
                        
                        # Log packet capture progress
                        if packet_count % 10 == 0 and self.root:
                            self.root.after(0, self.log, f"Captured {packet_count} packets...")
                    
                    # Define stop condition
                    def should_stop(packet):
                        elapsed = time.time() - start_time
                        return (self.stop_capture or 
                               packet_count >= packet_limit or 
                               elapsed >= duration)
                    
                    # Start progress bar updates
                    def update_progress():
                        if self.root and dialog.winfo_exists():
                            elapsed = time.time() - start_time
                            progress = min(100, int((elapsed / duration) * 100))
                            time_progress["value"] = progress
                            
                            if elapsed < duration and not self.stop_capture and packet_count < packet_limit:
                                self.root.after(100, update_progress)
                            else:
                                self.stop_capture = True
                    
                    if self.root:
                        self.root.after(0, update_progress)
                    
                    # Try different capture methods
                    try:
                        if self.root:
                            self.root.after(0, self.log, "Attempting to capture live network packets...")
                        
                        # Method 1: Try with specific interface
                        if interface and interface != "any":
                            captured_packets = sniff(
                                iface=interface,
                                prn=packet_callback,
                                filter=filter_str if filter_str else None,
                                stop_filter=should_stop,
                                timeout=duration,
                                store=True
                            )
                        else:
                            # Method 2: Try without specifying interface (captures all)
                            captured_packets = sniff(
                                prn=packet_callback,
                                filter=filter_str if filter_str else None,
                                stop_filter=should_stop,
                                timeout=duration,
                                store=True
                            )
                        
                        # Ensure we have the packets from callback
                        packets = captured_packets if captured_packets else []
                        
                        if self.root:
                            if len(packets) > 0:
                                self.root.after(0, self.log, f"Successfully captured {len(packets)} real network packets", True)
                            else:
                                self.root.after(0, self.log, "No packets captured from network interface", True)
                        
                        # Save captured packets to file
                        if len(packets) > 0:
                            try:
                                wrpcap(output_file, packets)
                                if self.root:
                                    self.root.after(0, self.log, f"Saved packets to {output_file}")
                            except Exception as save_error:
                                if self.root:
                                    self.root.after(0, self.log, f"Error saving packets: {save_error}", True)
                        
                    except PermissionError as perm_error:
                        if self.root:
                            self.root.after(0, self.log, "Permission denied - run as administrator for live capture", True)
                            self.root.after(0, self.log, "Generating sample packets for demonstration", True)
                        packets = self._generate_sample_packets_with_sensitive_data(min(packet_limit, 20))
                        
                    except OSError as os_error:
                        if self.root:
                            self.root.after(0, self.log, f"Network interface error: {str(os_error)}", True)
                            self.root.after(0, self.log, "Generating sample packets for demonstration", True)
                        packets = self._generate_sample_packets_with_sensitive_data(min(packet_limit, 20))
                        
                    except Exception as capture_error:
                        if self.root:
                            self.root.after(0, self.log, f"Capture failed: {str(capture_error)}", True)
                            self.root.after(0, self.log, "Generating sample packets for demonstration", True)
                        packets = self._generate_sample_packets_with_sensitive_data(min(packet_limit, 20))
                
                except ImportError as e:
                    if self.root:
                        self.root.after(0, self.log, f"Scapy import error: {str(e)}", True)
                        
            else:
                # Scapy not available - generate sample packets
                if self.root:
                    self.root.after(0, self.log, "Scapy not available for packet capture", True)
                    self.root.after(0, self.log, "Generating sample traffic data with sensitive content for demonstration", True)
                
                # Generate sample data with some containing sensitive information
                packets = self._generate_sample_packets_with_sensitive_data(min(packet_limit, 30))
                
                # Simulate realistic progress updates
                start_time = time.time()
                interval = max(0.1, duration / 10)  # Update 10 times during capture
                
                for i in range(10):
                    if self.stop_capture:
                        break
                    time.sleep(interval)
                    if self.root and dialog.winfo_exists():
                        progress = min(100, int(((i + 1) / 10) * 100))
                        packet_count = min(len(packets), int((i + 1) * len(packets) / 10))
                        self.root.after(0, lambda p=progress: time_progress.config(value=p))
                        self.root.after(0, packet_var.set, str(packet_count))
                        
                        # Simulate finding some packets during capture
                        if i < len(packets):
                            packet = packets[i]
                            if self.sensitive_data_detection.get():
                                self._scan_packet_for_sensitive_data(packet)
                
                if self.root:
                    self.root.after(0, self.log, f"Generated {len(packets)} sample packets with potential sensitive data")
            
            # Store the packets
            self.current_packets = packets
            
            # Log completion
            if self.root:
                self.root.after(0, self.log, f"Live capture completed. Captured {len(packets)} packets", success=True)
            
            # Close dialog and update UI in main thread
            if self.root and hasattr(dialog, 'winfo_exists') and dialog.winfo_exists():
                self.root.after(0, dialog.destroy)
                self.root.after(0, self._update_ui_after_load, len(packets))
                
        except Exception as e:
            if self.root:
                self.root.after(0, self.log, f"Error during packet capture: {str(e)}", True)
            if self.root and hasattr(dialog, 'winfo_exists') and dialog.winfo_exists():
                self.root.after(0, dialog.destroy)
            
        finally:
            self.loading_data = False
            self.stop_capture = False
    
    def _generate_sample_packets(self, packet_limit):
        """Generate sample packets for development/demo purposes"""
        packets = []
        
        if SCAPY_AVAILABLE:
            try:
                from scapy.all import Ether, IP, TCP, UDP, DNS, Raw
                import random
                
                # Generate various types of network packets
                for i in range(min(packet_limit, 50)):  # Limit to 50 for demo
                    # Random source and destination IPs
                    src_ip = f"192.168.1.{random.randint(1, 254)}"
                    dst_ip = f"192.168.1.{random.randint(1, 254)}"
                    
                    if i % 3 == 0:  # TCP packet
                        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=80) / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    elif i % 3 == 1:  # UDP packet
                        from scapy.all import DNSQR
                        packet = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(qd=DNSQR(qname="example.com"))
                    else:  # Another TCP packet
                        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=443, dport=random.randint(1024, 65535)) / Raw(b"HTTPS encrypted data...")
                    
                    packets.append(packet)
                    
            except ImportError:
                # If specific scapy modules aren't available, create basic mock structure
                for i in range(min(packet_limit, 50)):
                    # Create a simple mock packet object
                    packet = type('MockPacket', (), {
                        'summary': lambda: f"Mock packet {i+1}",
                        'time': time.time() + i,
                        'src': f"192.168.1.{random.randint(1, 254)}" if 'random' in globals() else "192.168.1.100",
                        'dst': f"192.168.1.{random.randint(1, 254)}" if 'random' in globals() else "192.168.1.1",
                        'proto': ["TCP", "UDP", "ICMP"][i % 3],
                        'info': f"Sample network traffic packet {i+1}"
                    })()
                    packets.append(packet)
        
        return packets
    
    def _generate_sample_packets_with_sensitive_data(self, packet_limit):
        """Generate sample packets containing sensitive data for testing detection"""
        packets = []
        
        if SCAPY_AVAILABLE:
            try:
                from scapy.all import Ether, IP, TCP, UDP, Raw
                import random
                
                # Sample sensitive data to include in packets
                sensitive_samples = [
                    b'password=admin123',
                    b'api_key=sk-1234567890abcdef1234567890abcdef',
                    b'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
                    b'email=user@example.com password=secret123',
                    b'Authorization: Bearer abc123def456ghi789',
                    b'mysql://user:password123@localhost/database',
                    b'AKIA1234567890ABCDEF',
                    b'session_id=a1b2c3d4e5f6789012345678',
                    b'pass: mySecretPass',
                    b'github_token=ghp_abcdefghij1234567890abcdefghij123456'
                ]
                
                # Generate packets with sensitive content mixed in
                for i in range(min(packet_limit, 30)):
                    src_ip = f"192.168.1.{random.randint(1, 254)}"
                    dst_ip = f"192.168.1.{random.randint(1, 254)}"
                    
                    if i < len(sensitive_samples):
                        # Create packet with sensitive data
                        sensitive_data = sensitive_samples[i]
                        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=80) / Raw(load=sensitive_data)
                    elif i % 4 == 0:  # Regular HTTP traffic
                        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=80) / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    elif i % 4 == 1:  # DNS traffic
                        packet = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / Raw(b"DNS query for example.com")
                    elif i % 4 == 2:  # HTTPS traffic
                        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=443, dport=random.randint(1024, 65535)) / Raw(b"HTTPS encrypted data...")
                    else:  # Mixed traffic
                        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535)) / Raw(b"Regular network traffic")
                    
                    packets.append(packet)
                    
            except ImportError:
                # Create mock packets with sensitive data in summary
                sensitive_summaries = [
                    "HTTP Request with password=admin123",
                    "API Request with api_key=sk-1234567890abcdef",
                    "JWT Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                    "Login with email=user@example.com password=secret123",
                    "Authorization Bearer abc123def456ghi789",
                    "Database URL mysql://user:password123@localhost",
                    "AWS Key AKIA1234567890ABCDEF",
                    "Session ID a1b2c3d4e5f6789012345678"
                ]
                
                for i in range(min(packet_limit, 30)):
                    if i < len(sensitive_summaries):
                        summary_text = sensitive_summaries[i]
                    else:
                        summary_text = f"Regular packet {i+1}"
                    
                    packet = type('MockPacket', (), {
                        'summary': lambda s=summary_text: s,
                        'time': time.time() + i,
                        'src': f"192.168.1.{random.randint(1, 254)}" if 'random' in globals() else "192.168.1.100",
                        'dst': f"192.168.1.{random.randint(1, 254)}" if 'random' in globals() else "192.168.1.1",
                        'proto': ["TCP", "UDP", "ICMP"][i % 3],
                        'info': summary_text,
                        'load': summary_text.encode() if hasattr(str, 'encode') else summary_text
                    })()
                    packets.append(packet)
        
        return packets
    
    def _get_available_interfaces(self):
        """Get list of available network interfaces"""
        interfaces = []
        
        try:
            # Method 1: Try scapy to get interfaces
            if SCAPY_AVAILABLE:
                try:
                    from scapy.all import get_if_list
                    scapy_interfaces = get_if_list()
                    if scapy_interfaces:
                        interfaces.extend(scapy_interfaces)
                except Exception:
                    pass
            
            # Method 2: Try using socket/netifaces (more reliable)
            try:
                import socket
                import os
                
                # Get interfaces from /proc/net/dev on Linux
                if os.path.exists('/proc/net/dev'):
                    with open('/proc/net/dev', 'r') as f:
                        lines = f.readlines()[2:]  # Skip header lines
                        for line in lines:
                            interface_name = line.split(':')[0].strip()
                            if interface_name and interface_name not in interfaces:
                                interfaces.append(interface_name)
                
                # Also try socket method
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                if local_ip:
                    # Add common interface patterns
                    common_interfaces = ["eth0", "eth1", "wlan0", "wlan1", "wlp2s0", "enp3s0", "ens33"]
                    for iface in common_interfaces:
                        if iface not in interfaces:
                            interfaces.append(iface)
                            
            except Exception:
                pass
            
            # Method 3: Try psutil if available
            try:
                import psutil
                psutil_interfaces = list(psutil.net_if_addrs().keys())
                for iface in psutil_interfaces:
                    if iface not in interfaces:
                        interfaces.append(iface)
            except ImportError:
                pass
            except Exception:
                pass
            
            # Always add "any" option for capturing all interfaces
            if "any" not in interfaces:
                interfaces.append("any")
            
            # Filter out loopback and invalid interfaces
            filtered_interfaces = []
            for iface in interfaces:
                if iface and iface not in ["lo", "localhost"] and not iface.startswith("127."):
                    filtered_interfaces.append(iface)
            
            # If we filtered everything, add back some defaults
            if not filtered_interfaces:
                filtered_interfaces = ["eth0", "wlan0", "any"]
            
            return filtered_interfaces
            
        except Exception:
            # Final fallback
            return ["eth0", "wlan0", "wlan1", "any"]
    
    def _refresh_interfaces(self, combo_widget):
        """Refresh the interface list"""
        interfaces = self._get_available_interfaces()
        combo_widget['values'] = interfaces
        if interfaces:
            combo_widget.set(interfaces[0])
    
    def _is_tool_available(self, tool_name):
        """Check if a command-line tool is available"""
        try:
            subprocess.run([tool_name, "--version"], 
                         capture_output=True, 
                         timeout=5)
            return True
        except:
            return False
    
    def _scan_packet_for_sensitive_data(self, packet):
        """Scan packet for sensitive data like passwords, API keys, etc."""
        try:
            import re
            
            # Convert packet to multiple string representations for thorough analysis
            packet_representations = []
            
            # Raw packet string
            packet_representations.append(str(packet))
            
            # If scapy packet, extract payload data
            if SCAPY_AVAILABLE and hasattr(packet, 'load'):
                try:
                    if packet.load:
                        packet_representations.append(packet.load.decode('utf-8', errors='ignore'))
                        packet_representations.append(packet.load.decode('latin-1', errors='ignore'))
                except:
                    pass
            
            # If packet has Raw layer
            if SCAPY_AVAILABLE:
                try:
                    from scapy.all import Raw
                    if packet.haslayer(Raw):
                        raw_data = packet[Raw].load
                        packet_representations.append(raw_data.decode('utf-8', errors='ignore'))
                        packet_representations.append(raw_data.decode('latin-1', errors='ignore'))
                        # Also check hex representation
                        packet_representations.append(raw_data.hex())
                except:
                    pass
            
            # Enhanced patterns for sensitive data detection
            sensitive_patterns = {
                'password': [
                    r'password[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'pass[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'pwd[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'passwd[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'passw[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'"password"\s*:\s*"([^"]{4,})"',
                    r"'password'\s*:\s*'([^']{4,})'",
                ],
                'api_key': [
                    r'(api[_-]?key|apikey)[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                    r'(key)[=:\s]*["\']?([a-zA-Z0-9]{20,})["\']?',
                    r'(secret[_-]?key)[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                    r'"api_key"\s*:\s*"([^"]{16,})"',
                    r"'api_key'\s*:\s*'([^']{16,})'",
                    r'Bearer\s+([a-zA-Z0-9._-]{20,})',
                    r'Authorization:\s*([a-zA-Z0-9._-]{20,})',
                ],
                'token': [
                    r'(token|access[_-]?token|auth[_-]?token)[=:\s]*["\']?([a-zA-Z0-9._-]{16,})["\']?',
                    r'(jwt)[=:\s]*["\']?([a-zA-Z0-9._-]{50,})["\']?',
                    r'"token"\s*:\s*"([^"]{16,})"',
                    r"'token'\s*:\s*'([^']{16,})'",
                    r'eyJ[a-zA-Z0-9._-]+',  # JWT tokens
                ],
                'email': [
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                    r'"email"\s*:\s*"([^"@]+@[^"]+)"',
                    r"'email'\s*:\s*'([^'@]+@[^']+)'",
                ],
                'credit_card': [
                    r'\b(?:\d{4}[\s-]?){3}\d{4}\b',
                    r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
                    r'\b5[1-5][0-9]{14}\b',  # Mastercard
                    r'\b3[47][0-9]{13}\b',  # American Express
                ],
                'private_key': [
                    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                    r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
                    r'"private_key"\s*:\s*"([^"]+)"',
                ],
                'ssh_key': [
                    r'ssh-rsa\s+[A-Za-z0-9+/]+[=]{0,3}',
                    r'ssh-ed25519\s+[A-Za-z0-9+/]+[=]{0,3}',
                ],
                'database_url': [
                    r'mysql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                    r'postgres://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                    r'mongodb://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                ],
                'aws_key': [
                    r'AKIA[0-9A-Z]{16}',
                    r'aws_access_key_id[=:\s]*["\']?([A-Z0-9]{20})["\']?',
                    r'aws_secret_access_key[=:\s]*["\']?([A-Za-z0-9/+=]{40})["\']?',
                ],
                'github_token': [
                    r'ghp_[a-zA-Z0-9]{36}',
                    r'github_token[=:\s]*["\']?([a-zA-Z0-9]{40})["\']?',
                ],
                'slack_token': [
                    r'xox[baprs]-([0-9a-zA-Z]{10,48})',
                ],
                'session_id': [
                    r'session[_-]?id[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                    r'PHPSESSID[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                    r'JSESSIONID[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                ],
                'cookie': [
                    r'Set-Cookie:\s*([^;=]+=[^;]+)',
                    r'Cookie:\s*([^;=]+=[^;]+)',
                ]
            }
            
            # Check each representation against all patterns
            for packet_str in packet_representations:
                if not packet_str:
                    continue
                    
                for data_type, patterns in sensitive_patterns.items():
                    for pattern in patterns:
                        try:
                            matches = re.findall(pattern, packet_str, re.IGNORECASE | re.MULTILINE)
                            if matches:
                                # Found sensitive data
                                for match in matches:
                                    # Extract the actual sensitive data
                                    if isinstance(match, tuple):
                                        # If pattern has groups, take the last group (the actual data)
                                        sensitive_data = match[-1] if match[-1] else match[0]
                                    else:
                                        sensitive_data = match
                                    
                                    # Skip very short or obviously false matches
                                    if len(str(sensitive_data)) < 3:
                                        continue
                                    
                                    # Get packet source and destination
                                    src_ip = "Unknown"
                                    dst_ip = "Unknown"
                                    protocol = "Unknown"
                                    
                                    if SCAPY_AVAILABLE:
                                        try:
                                            from scapy.all import IP
                                            if packet.haslayer(IP):
                                                src_ip = packet[IP].src
                                                dst_ip = packet[IP].dst
                                                protocol = packet[IP].proto
                                        except:
                                            pass
                                    
                                    sensitive_info = {
                                        'type': data_type,
                                        'data': str(sensitive_data)[:100] + "..." if len(str(sensitive_data)) > 100 else str(sensitive_data),
                                        'full_match': str(match),
                                        'packet_time': getattr(packet, 'time', time.time()),
                                        'src': src_ip,
                                        'dst': dst_ip,
                                        'protocol': protocol,
                                        'pattern_used': pattern
                                    }
                                    
                                    # Avoid duplicates
                                    if not any(s['data'] == sensitive_info['data'] and s['type'] == sensitive_info['type'] 
                                             for s in self.found_sensitive_data):
                                        self.found_sensitive_data.append(sensitive_info)
                                        
                                        # Show real-time alert if enabled
                                        if self.real_time_alerts.get():
                                            alert_msg = f"🚨 SENSITIVE DATA DETECTED: {data_type.upper()} from {src_ip} → {dst_ip}"
                                            if self.root:
                                                self.root.after(0, self.log, alert_msg, True)
                                                
                        except Exception as pattern_error:
                            # Continue with other patterns if one fails
                            continue
                            
        except Exception as e:
            # Log errors in packet scanning for debugging
            if self.root:
                self.root.after(0, self.log, f"Error scanning packet: {str(e)}", True)
    
    def _show_filter_help(self):
        """Show help dialog for BPF filters"""
        help_dialog = tk.Toplevel(self.root)
        help_dialog.title("BPF Filter Help")
        help_dialog.geometry("500x400")
        help_dialog.transient(self.root)
        
        help_text = """Berkeley Packet Filter (BPF) Examples:

Common Filters:
• tcp - Capture only TCP traffic
• udp - Capture only UDP traffic  
• icmp - Capture only ICMP traffic
• host 192.168.1.1 - Traffic to/from specific host
• port 80 - Traffic on port 80
• src host 192.168.1.1 - Traffic from specific source
• dst port 443 - Traffic to port 443

Protocol Filters:
• tcp port 80 - HTTP traffic
• tcp port 443 - HTTPS traffic
• udp port 53 - DNS traffic
• tcp port 22 - SSH traffic

Advanced Filters:
• tcp and port 80 - TCP traffic on port 80
• host 192.168.1.1 and port 80 - HTTP to specific host
• not broadcast - Exclude broadcast traffic
• tcp[tcpflags] & tcp-syn != 0 - TCP SYN packets

Leave empty to capture all traffic.
"""
        
        text_widget = scrolledtext.ScrolledText(help_dialog, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)
        
        close_btn = ttk.Button(help_dialog, text="Close", command=help_dialog.destroy)
        close_btn.pack(pady=10)
    
    def _scan_text_file_for_sensitive_data(self, file_path):
        """Scan a text file for sensitive data"""
        try:
            import re
            
            self.log(f"Starting file scan: {os.path.basename(file_path)}")
            self.found_sensitive_data = []
            
            # Read file with multiple encodings
            content = ""
            encodings = ['utf-8', 'latin-1', 'ascii', 'iso-8859-1']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if not content:
                self.log("Could not read file with any supported encoding", error=True)
                return
            
            # Enhanced patterns for sensitive data detection (same as packet scanning)
            sensitive_patterns = {
                'password': [
                    r'password[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'pass[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'pwd[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'passwd[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'passw[=:\s]*["\']?([^"\'\s&\n\r]{4,})["\']?',
                    r'"password"\s*:\s*"([^"]{4,})"',
                    r"'password'\s*:\s*'([^']{4,})'",
                ],
                'api_key': [
                    r'(api[_-]?key|apikey)[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                    r'(key)[=:\s]*["\']?([a-zA-Z0-9]{20,})["\']?',
                    r'(secret[_-]?key)[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                    r'"api_key"\s*:\s*"([^"]{16,})"',
                    r"'api_key'\s*:\s*'([^']{16,})'",
                    r'Bearer\s+([a-zA-Z0-9._-]{20,})',
                    r'Authorization:\s*([a-zA-Z0-9._-]{20,})',
                ],
                'token': [
                    r'(token|access[_-]?token|auth[_-]?token)[=:\s]*["\']?([a-zA-Z0-9._-]{16,})["\']?',
                    r'(jwt)[=:\s]*["\']?([a-zA-Z0-9._-]{50,})["\']?',
                    r'"token"\s*:\s*"([^"]{16,})"',
                    r"'token'\s*:\s*'([^']{16,})'",
                    r'eyJ[a-zA-Z0-9._-]+',  # JWT tokens
                ],
                'email': [
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                    r'"email"\s*:\s*"([^"@]+@[^"]+)"',
                    r"'email'\s*:\s*'([^'@]+@[^']+)'",
                ],
                'credit_card': [
                    r'\b(?:\d{4}[\s-]?){3}\d{4}\b',
                    r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
                    r'\b5[1-5][0-9]{14}\b',  # Mastercard
                    r'\b3[47][0-9]{13}\b',  # American Express
                ],
                'private_key': [
                    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                    r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
                    r'"private_key"\s*:\s*"([^"]+)"',
                ],
                'ssh_key': [
                    r'ssh-rsa\s+[A-Za-z0-9+/]+[=]{0,3}',
                    r'ssh-ed25519\s+[A-Za-z0-9+/]+[=]{0,3}',
                ],
                'database_url': [
                    r'mysql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                    r'postgres://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                    r'mongodb://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+',
                ],
                'aws_key': [
                    r'AKIA[0-9A-Z]{16}',
                    r'aws_access_key_id[=:\s]*["\']?([A-Z0-9]{20})["\']?',
                    r'aws_secret_access_key[=:\s]*["\']?([A-Za-z0-9/+=]{40})["\']?',
                ],
                'github_token': [
                    r'ghp_[a-zA-Z0-9]{36}',
                    r'github_token[=:\s]*["\']?([a-zA-Z0-9]{40})["\']?',
                ],
                'slack_token': [
                    r'xox[baprs]-([0-9a-zA-Z]{10,48})',
                ],
                'session_id': [
                    r'session[_-]?id[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                    r'PHPSESSID[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                    r'JSESSIONID[=:\s]*["\']?([a-zA-Z0-9]{16,})["\']?',
                ],
                'cookie': [
                    r'Set-Cookie:\s*([^;=]+=[^;]+)',
                    r'Cookie:\s*([^;=]+=[^;]+)',
                ]
            }
            
            # Track line numbers for better reporting
            lines = content.split('\n')
            total_findings = 0
            
            for line_num, line in enumerate(lines, 1):
                for data_type, patterns in sensitive_patterns.items():
                    for pattern in patterns:
                        try:
                            matches = re.findall(pattern, line, re.IGNORECASE)
                            if matches:
                                for match in matches:
                                    # Extract the actual sensitive data
                                    if isinstance(match, tuple):
                                        sensitive_data = match[-1] if match[-1] else match[0]
                                    else:
                                        sensitive_data = match
                                    
                                    # Skip very short matches
                                    if len(str(sensitive_data)) < 3:
                                        continue
                                    
                                    sensitive_info = {
                                        'type': data_type,
                                        'data': str(sensitive_data)[:100] + "..." if len(str(sensitive_data)) > 100 else str(sensitive_data),
                                        'full_match': str(match),
                                        'line_number': line_num,
                                        'line_content': line.strip()[:200] + "..." if len(line.strip()) > 200 else line.strip(),
                                        'file_path': file_path,
                                        'pattern_used': pattern
                                    }
                                    
                                    # Avoid duplicates
                                    if not any(s['data'] == sensitive_info['data'] and s['type'] == sensitive_info['type'] 
                                             for s in self.found_sensitive_data):
                                        self.found_sensitive_data.append(sensitive_info)
                                        total_findings += 1
                                        
                                        # Log the finding
                                        self.log(f"🚨 FOUND {data_type.upper()}: Line {line_num}", error=True)
                                        
                        except Exception as pattern_error:
                            continue
            
            # Summary
            if total_findings > 0:
                self.log(f"FILE SCAN COMPLETE: Found {total_findings} sensitive items in {os.path.basename(file_path)}", error=True)
                
                # Show detailed results in a dialog
                self._show_file_scan_results(file_path, total_findings)
            else:
                self.log("File scan complete: No sensitive data detected", success=True)
                
        except Exception as e:
            self.log(f"Error scanning file: {str(e)}", error=True)
    
    def _show_file_scan_results(self, file_path, total_findings):
        """Show detailed results of file scanning"""
        result_dialog = tk.Toplevel(self.root)
        result_dialog.title(f"Sensitive Data Found - {os.path.basename(file_path)}")
        result_dialog.geometry("800x600")
        result_dialog.transient(self.root)
        
        # Header
        header_frame = ttk.Frame(result_dialog)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        title_label = ttk.Label(
            header_frame,
            text=f"🚨 SECURITY ALERT: {total_findings} Sensitive Items Found",
            font=("Helvetica", 14, "bold"),
            foreground="red"
        )
        title_label.pack()
        
        file_label = ttk.Label(
            header_frame,
            text=f"File: {file_path}",
            font=("Helvetica", 10)
        )
        file_label.pack()
        
        # Results tree
        tree_frame = ttk.Frame(result_dialog)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("Type", "Data", "Line", "Context")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        # Column headers
        tree.heading("Type", text="Type")
        tree.heading("Data", text="Sensitive Data")
        tree.heading("Line", text="Line #")
        tree.heading("Context", text="Context")
        
        # Column widths
        tree.column("Type", width=100)
        tree.column("Data", width=200)
        tree.column("Line", width=60)
        tree.column("Context", width=400)
        
        # Populate tree
        for item in self.found_sensitive_data:
            if 'line_number' in item:  # File scan results
                tree.insert("", tk.END, values=(
                    item['type'].upper(),
                    item['data'],
                    item['line_number'],
                    item['line_content']
                ))
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(result_dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        save_btn = ttk.Button(
            button_frame,
            text="Save Report",
            command=lambda: self._save_scan_report(file_path)
        )
        save_btn.pack(side=tk.LEFT, padx=5)
        
        close_btn = ttk.Button(
            button_frame,
            text="Close",
            command=result_dialog.destroy
        )
        close_btn.pack(side=tk.RIGHT, padx=5)
    
    def _save_scan_report(self, file_path):
        """Save the scan report to a file"""
        try:
            save_path = filedialog.asksaveasfilename(
                title="Save Scan Report",
                defaultextension=".txt",
                filetypes=[
                    ("Text files", "*.txt"),
                    ("JSON files", "*.json"),
                    ("All files", "*.*")
                ]
            )
            
            if save_path:
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(f"SENSITIVE DATA SCAN REPORT\n")
                    f.write(f"="*50 + "\n")
                    f.write(f"File Scanned: {file_path}\n")
                    f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Findings: {len(self.found_sensitive_data)}\n\n")
                    
                    for item in self.found_sensitive_data:
                        if 'line_number' in item:
                            f.write(f"Type: {item['type'].upper()}\n")
                            f.write(f"Data: {item['data']}\n")
                            f.write(f"Line: {item['line_number']}\n")
                            f.write(f"Context: {item['line_content']}\n")
                            f.write("-" * 40 + "\n")
                
                self.log(f"Scan report saved to: {save_path}", success=True)
                
        except Exception as e:
            self.log(f"Error saving report: {str(e)}", error=True)
    
    def _stop_capture(self):
        """Stop the ongoing packet capture"""
        self.stop_capture = True
    
    def _set_monitor_mode(self, interface, enable):
        """Enable or disable monitor mode on interface"""
        try:
            if os.geteuid() != 0:
                self.log("Root privileges required to change interface mode", error=True)
                return False
                
            if enable:
                mode_cmd = f"airmon-ng start {interface}"
            else:
                mode_cmd = f"airmon-ng stop {interface}"
                
            self.log(f"Running: {mode_cmd}")
            result = subprocess.run(mode_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.log(f"Error changing interface mode: {result.stderr}", error=True)
                return False
                
            self.log(f"Interface mode changed successfully", success=True)
            return True
            
        except Exception as e:
            self.log(f"Error changing interface mode: {str(e)}", error=True)
            return False
    
    def _is_tool_available(self, tool_name):
        """Check if a command-line tool is available on the system
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            bool: True if tool is available, False otherwise
        """
        try:
            subprocess.run(
                ["which", tool_name],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def apply_filter(self):
        """Apply filter to packet list"""
        filter_text = self.filter_text.get().strip().lower()
        
        if not filter_text:
            self.clear_filter()
            return
            
        # Get all items
        all_items = self.packet_tree.get_children()
        
        # Clear selection
        self.packet_tree.selection_remove(self.packet_tree.selection())
        
        # Process each item
        for item in all_items:
            values = self.packet_tree.item(item, "values")
            
            # Skip if no values
            if not values:
                continue
                
            # Check if the filter matches any field
            match = False
            for value in values:
                if filter_text in str(value).lower():
                    match = True
                    break
                    
            # Show/hide based on match
            if match:
                self.packet_tree.item(item, tags=())
            else:
                self.packet_tree.item(item, tags=("hidden",))
        
        # Configure hidden tag
        self.packet_tree.tag_configure("hidden", foreground="#666666")
    
    def clear_filter(self):
        """Clear the packet filter"""
        self.filter_text.set("")
        
        # Get all items
        all_items = self.packet_tree.get_children()
        
        # Clear tags
        for item in all_items:
            self.packet_tree.item(item, tags=())
    
    def run_security_analysis(self):
        """Run security analysis on the captured traffic"""
        if not self.current_packets:
            self.log("No packet data available for analysis", error=True)
            return
            
        # Log start of analysis
        self.log("Starting security analysis...")
        
        # Analyze in a thread
        analysis_thread = threading.Thread(
            target=self._analyze_security_thread
        )
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def _analyze_security_thread(self):
        """Thread function for security analysis"""
        try:
            # Initialize analysis results
            vulnerabilities = []
            authentication_issues = []
            encryption_issues = []
            summary_points = []
            
            # Extract packet data
            packets = self.current_packets
            
            # Check if scapy is available for proper analysis
            if not SCAPY_AVAILABLE:
                summary_points.append("Limited analysis: Scapy library not available")
                
                # Update UI in main thread
                if self.root:
                    self.root.after(0, self._update_security_analysis, 
                                    vulnerabilities, encryption_issues, 
                                    authentication_issues, summary_points)
                return
            
            # ==== Check for unencrypted traffic ====
            http_packets = []
            telnet_packets = []
            ftp_packets = []
            
            for packet in packets:
                # Check for HTTP
                if packet.haslayer("TCP"):
                    tcp_port = packet["TCP"].dport
                    if tcp_port == 80:
                        http_packets.append(packet)
                        
                # Check for Telnet
                if packet.haslayer("TCP"):
                    tcp_port = packet["TCP"].dport
                    if tcp_port == 23:
                        telnet_packets.append(packet)
                        
                # Check for FTP
                if packet.haslayer("TCP"):
                    tcp_port = packet["TCP"].dport
                    if tcp_port == 21:
                        ftp_packets.append(packet)
            
            # Add vulnerabilities based on findings
            if http_packets:
                vulnerabilities.append({
                    "severity": "High",
                    "type": "Cleartext HTTP",
                    "description": "Unencrypted HTTP traffic detected",
                    "affected": f"{len(http_packets)} packets"
                })
                encryption_issues.append("Unencrypted HTTP traffic was detected. HTTP transmits data in cleartext, including sensitive information like authentication credentials.")
                summary_points.append(f"Found {len(http_packets)} unencrypted HTTP packets")
                
            if telnet_packets:
                vulnerabilities.append({
                    "severity": "Critical",
                    "type": "Cleartext Telnet",
                    "description": "Unencrypted Telnet traffic detected",
                    "affected": f"{len(telnet_packets)} packets"
                })
                encryption_issues.append("Telnet traffic was detected. Telnet transmits all data including passwords in cleartext and should never be used.")
                summary_points.append(f"Found {len(telnet_packets)} Telnet packets (critical risk)")
                
            if ftp_packets:
                vulnerabilities.append({
                    "severity": "High",
                    "type": "Cleartext FTP",
                    "description": "Unencrypted FTP traffic detected",
                    "affected": f"{len(ftp_packets)} packets"
                })
                encryption_issues.append("FTP traffic was detected. Standard FTP transmits credentials and data in cleartext.")
                summary_points.append(f"Found {len(ftp_packets)} unencrypted FTP packets")
            
            # ==== Check for wireless security issues ====
            mgmt_packets = []
            deauth_packets = []
            open_networks = set()
            wep_networks = set()
            wpa_networks = set()
            wpa2_networks = set()
            
            for packet in packets:
                # Check for management frames (potential DoS)
                if packet.haslayer("Dot11"):
                    mgmt_packets.append(packet)
                    
                    # Check for deauthentication frames
                    if packet.haslayer("Dot11Deauth"):
                        deauth_packets.append(packet)
                    
                    # Check for beacon frames to identify networks
                    if packet.haslayer("Dot11Beacon"):
                        ssid = None
                        if packet.haslayer("Dot11Elt") and packet.ID == 0:
                            ssid = packet.info.decode('utf-8', errors='replace')
                            
                        # Check encryption type
                        if packet.privacy == 0:
                            if ssid:
                                open_networks.add(ssid)
                        else:
                            # Check for WEP vs WPA/WPA2
                            crypto_type = "Unknown"
                            
                            # Get the RSN element if available
                            rsn = None
                            for element in packet[Dot11]:
                                if hasattr(element, 'ID') and element.ID == 48:  # RSN element
                                    rsn = element
                                    
                            if rsn:
                                # WPA2
                                if ssid:
                                    wpa2_networks.add(ssid)
                            elif crypto_type == "WPA":
                                if ssid:
                                    wpa_networks.add(ssid)
                            else:
                                # Assume WEP
                                if ssid:
                                    wep_networks.add(ssid)
            
            # Add vulnerabilities based on findings
            if deauth_packets:
                vulnerabilities.append({
                    "severity": "High",
                    "type": "Deauthentication Frames",
                    "description": "Potential wireless DoS attack detected",
                    "affected": f"{len(deauth_packets)} packets"
                })
                authentication_issues.append(f"Detected {len(deauth_packets)} deauthentication frames. These could indicate a denial of service attack against wireless clients.")
                summary_points.append(f"Detected {len(deauth_packets)} deauthentication frames (possible DoS attack)")
                
            if open_networks:
                vulnerabilities.append({
                    "severity": "Critical",
                    "type": "Open Networks",
                    "description": "Unencrypted wireless networks detected",
                    "affected": f"{len(open_networks)} networks"
                })
                encryption_issues.append(f"Detected {len(open_networks)} open (unencrypted) wireless networks: {', '.join(open_networks)}. Open networks provide no protection for transmitted data.")
                summary_points.append(f"Found {len(open_networks)} open wireless networks")
                
            if wep_networks:
                vulnerabilities.append({
                    "severity": "Critical",
                    "type": "WEP Encryption",
                    "description": "Obsolete WEP encryption detected",
                    "affected": f"{len(wep_networks)} networks"
                })
                encryption_issues.append(f"Detected {len(wep_networks)} networks using obsolete WEP encryption: {', '.join(wep_networks)}. WEP can be cracked in minutes and provides minimal security.")
                summary_points.append(f"Found {len(wep_networks)} networks using obsolete WEP encryption")
            
            # If no specific issues were found
            if not vulnerabilities:
                summary_points.append("No serious security issues detected in the analyzed traffic")
                encryption_issues.append("No encryption-related issues were identified in the analyzed traffic.")
                authentication_issues.append("No authentication-related issues were identified in the analyzed traffic.")
            
            # Update UI in main thread
            if self.root:
                self.root.after(0, self._update_security_analysis, 
                              vulnerabilities, encryption_issues, 
                              authentication_issues, summary_points)
                
        except Exception as e:
            self.log(f"Error during security analysis: {str(e)}", error=True)
            
            # Update UI with error
            if self.root:
                self.root.after(0, self._update_security_analysis_error, str(e))
    
    def _update_security_analysis(self, vulnerabilities, encryption_issues, authentication_issues, summary_points):
        """Update security analysis UI with results"""
        # Update summary
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        
        summary_text = "# Security Analysis Summary\n\n"
        
        for point in summary_points:
            summary_text += f"* {point}\n"
            
        summary_text += "\n## Recommendations\n\n"
        
        if vulnerabilities:
            summary_text += "Based on the detected issues, consider the following recommendations:\n\n"
            
            # Add specific recommendations
            if any(v["type"] == "Cleartext HTTP" for v in vulnerabilities):
                summary_text += "* Upgrade HTTP services to use HTTPS with valid certificates\n"
            if any(v["type"] == "Cleartext Telnet" for v in vulnerabilities):
                summary_text += "* Replace Telnet with SSH for secure remote access\n"
            if any(v["type"] == "Cleartext FTP" for v in vulnerabilities):
                summary_text += "* Replace standard FTP with SFTP or FTPS for secure file transfers\n"
            if any(v["type"] == "Open Networks" for v in vulnerabilities):
                summary_text += "* Implement WPA2 or WPA3 encryption on all wireless networks\n"
            if any(v["type"] == "WEP Encryption" for v in vulnerabilities):
                summary_text += "* Replace WEP encryption with WPA2 or WPA3 on all wireless networks\n"
            if any(v["type"] == "Deauthentication Frames" for v in vulnerabilities):
                summary_text += "* Monitor for unauthorized deauthentication attacks\n"
                summary_text += "* Consider solutions that can detect and mitigate wireless DoS attacks\n"
        else:
            summary_text += "No serious security issues were detected in the analyzed traffic. Continue to maintain secure practices:\n\n"
            summary_text += "* Use strong encryption for all wireless networks (WPA2 or WPA3)\n"
            summary_text += "* Ensure all sensitive communications use encrypted protocols (HTTPS, SSH, etc.)\n"
            summary_text += "* Regularly monitor network traffic for unusual patterns\n"
        
        self.summary_text.insert(tk.END, summary_text)
        self.summary_text.config(state=tk.DISABLED)
        
        # Update vulnerabilities tree
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Medium")
            vuln_type = vuln.get("type", "Unknown")
            description = vuln.get("description", "")
            affected = vuln.get("affected", "")
            
            item = self.vuln_tree.insert("", tk.END, values=(severity, vuln_type, description, affected))
            
            # Color based on severity
            if severity == "Critical":
                self.vuln_tree.item(item, tags=("critical",))
            elif severity == "High":
                self.vuln_tree.item(item, tags=("high",))
            elif severity == "Medium":
                self.vuln_tree.item(item, tags=("medium",))
            elif severity == "Low":
                self.vuln_tree.item(item, tags=("low",))
        
        # Configure severity tags
        self.vuln_tree.tag_configure("critical", foreground="#ff5252")
        self.vuln_tree.tag_configure("high", foreground="#ff9800")
        self.vuln_tree.tag_configure("medium", foreground="#ffc107")
        self.vuln_tree.tag_configure("low", foreground="#4caf50")
        
        # Update encryption issues text
        self.crypto_text.config(state=tk.NORMAL)
        self.crypto_text.delete(1.0, tk.END)
        
        crypto_text = "# Encryption Analysis\n\n"
        
        if encryption_issues:
            for issue in encryption_issues:
                crypto_text += f"* {issue}\n\n"
        else:
            crypto_text += "No encryption-related issues were identified in the analyzed traffic.\n\n"
            
        crypto_text += """
## Best Practices for Secure Communications

* Use HTTPS (TLS) for all web traffic
* Use SSH instead of Telnet for remote system access
* Use SFTP or FTPS instead of FTP for file transfers
* Use WPA2 or WPA3 for wireless networks
* Implement VPN for sensitive remote access
* Use end-to-end encryption for messaging
* Encrypt sensitive data at rest
        """
        
        self.crypto_text.insert(tk.END, crypto_text)
        self.crypto_text.config(state=tk.DISABLED)
        
        # Update authentication issues text
        self.auth_text.config(state=tk.NORMAL)
        self.auth_text.delete(1.0, tk.END)
        
        auth_text = "# Authentication Analysis\n\n"
        
        if authentication_issues:
            for issue in authentication_issues:
                auth_text += f"* {issue}\n\n"
        else:
            auth_text += "No authentication-related issues were identified in the analyzed traffic.\n\n"
            
        auth_text += """
## Best Practices for Secure Authentication

* Use multi-factor authentication when possible
* Implement strong password policies
* Use certificate-based authentication for sensitive systems
* Avoid sending credentials over unencrypted channels
* Implement account lockout policies to prevent brute force attacks
* Use modern authentication protocols
* Monitor for authentication failures and unusual login patterns
        """
        
        self.auth_text.insert(tk.END, auth_text)
        self.auth_text.config(state=tk.DISABLED)
        
        # Log completion
        self.log("Security analysis completed", success=True)
    
    def _update_security_analysis_error(self, error_message):
        """Update security analysis UI with error message"""
        # Update summary
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        
        summary_text = "# Security Analysis Error\n\n"
        summary_text += f"An error occurred during security analysis:\n\n{error_message}\n\n"
        summary_text += "Please try again with a different packet capture or check if the required libraries are installed."
        
        self.summary_text.insert(tk.END, summary_text)
        self.summary_text.config(state=tk.DISABLED)
        
        # Log error
        self.log(f"Security analysis failed: {error_message}", error=True)
    
    def save_security_report(self):
        """Save the security analysis as a report"""
        if not hasattr(self, 'summary_text'):
            self.log("No security analysis available", error=True)
            return
            
        # Get summary text
        summary_text = self.summary_text.get(1.0, tk.END)
        
        if not summary_text or summary_text.strip() == "":
            self.log("No security analysis available", error=True)
            return
            
        # Ask for save location
        file_path = filedialog.asksaveasfilename(
            title="Save Security Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Build report content
            content = "WIRELESS TRAFFIC SECURITY ANALYSIS REPORT\n"
            content += "=" * 50 + "\n\n"
            content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            if self.current_file:
                content += f"Source capture: {os.path.basename(self.current_file)}\n"
            content += f"Packets analyzed: {len(self.current_packets)}\n\n"
            content += "=" * 50 + "\n\n"
            
            # Add summary
            content += summary_text + "\n\n"
            
            # Add vulnerabilities
            content += "VULNERABILITY DETAILS\n"
            content += "-" * 50 + "\n\n"
            
            for item in self.vuln_tree.get_children():
                values = self.vuln_tree.item(item, "values")
                content += f"Severity: {values[0]}\n"
                content += f"Type: {values[1]}\n"
                content += f"Description: {values[2]}\n"
                content += f"Affected: {values[3]}\n"
                content += "-" * 30 + "\n\n"
            
            # Add encryption analysis
            content += "ENCRYPTION ANALYSIS\n"
            content += "-" * 50 + "\n\n"
            content += self.crypto_text.get(1.0, tk.END) + "\n\n"
            
            # Add authentication analysis
            content += "AUTHENTICATION ANALYSIS\n"
            content += "-" * 50 + "\n\n"
            content += self.auth_text.get(1.0, tk.END)
            
            # Write to file
            with open(file_path, 'w') as f:
                f.write(content)
                
            self.log(f"Security report saved to {file_path}", success=True)
            
        except Exception as e:
            self.log(f"Error saving security report: {str(e)}", error=True)
    
    def export_analysis(self):
        """Export the analysis data"""
        if not self.current_packets:
            self.log("No packet data available to export", error=True)
            return
            
        # Ask for export format
        export_dialog = tk.Toplevel(self.root)
        export_dialog.title("Export Analysis")
        export_dialog.geometry("300x200")
        export_dialog.minsize(300, 200)
        export_dialog.transient(self.root)
        export_dialog.grab_set()
        export_dialog.configure(bg=self.bg_color)
        
        # Configure dialog for display
        configure_dialog_for_display(export_dialog)
        
        # Content frame
        content_frame = ttk.Frame(export_dialog)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(
            content_frame,
            text="Select Export Format",
            font=("Helvetica", 12, "bold")
        )
        title_label.pack(pady=10)
        
        # Format selection
        format_var = tk.StringVar(value="txt")
        
        # Radio buttons
        formats = [
            ("Text Report (.txt)", "txt"),
            ("JSON Data (.json)", "json"),
            ("CSV Data (.csv)", "csv"),
            ("PCAP File (.pcap)", "pcap")
        ]
        
        for text, value in formats:
            radio = ttk.Radiobutton(
                content_frame,
                text=text,
                value=value,
                variable=format_var
            )
            radio.pack(anchor=tk.W, padx=10, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(export_dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        export_btn = ttk.Button(
            button_frame,
            text="Export",
            command=lambda: self._do_export(export_dialog, format_var.get())
        )
        export_btn.pack(side=tk.RIGHT, padx=5)
        
        cancel_btn = ttk.Button(
            button_frame,
            text="Cancel",
            command=export_dialog.destroy
        )
        cancel_btn.pack(side=tk.RIGHT, padx=5)
    
    def _do_export(self, dialog, format_type):
        """Perform the actual export"""
        dialog.destroy()
        
        if format_type == "txt":
            self._export_text_report()
        elif format_type == "json":
            self._export_json_data()
        elif format_type == "csv":
            self._export_csv_data()
        elif format_type == "pcap":
            self._export_pcap_file()
    
    def _export_text_report(self):
        """Export analysis as text report"""
        # Ask for save location
        file_path = filedialog.asksaveasfilename(
            title="Save Text Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Build report content
            content = "WIRELESS TRAFFIC ANALYSIS REPORT\n"
            content += "=" * 50 + "\n\n"
            content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            if self.current_file:
                content += f"Source capture: {os.path.basename(self.current_file)}\n"
            content += f"Packets analyzed: {len(self.current_packets)}\n\n"
            
            # Add statistics
            if self.packet_stats:
                content += "PACKET STATISTICS\n"
                content += "-" * 50 + "\n\n"
                content += f"Total packets: {self.packet_stats['total_packets']}\n"
                content += f"Total data size: {self.packet_stats['total_bytes']} bytes\n"
                content += f"Average packet size: {self.packet_stats['avg_packet_size']:.2f} bytes\n"
                content += f"Minimum packet size: {self.packet_stats['min_packet_size']} bytes\n"
                content += f"Maximum packet size: {self.packet_stats['max_packet_size']} bytes\n\n"
                
                # Protocol distribution
                content += "Protocol Distribution:\n"
                proto_count = self.packet_stats['proto_count']
                sorted_protos = sorted(proto_count.items(), key=lambda x: x[1], reverse=True)
                
                for proto, count in sorted_protos:
                    percentage = (count / self.packet_stats['total_packets']) * 100
                    content += f"  {proto}: {count} packets ({percentage:.1f}%)\n"
                    
                content += "\n"
                
                # Top source IPs
                content += "Top Source IP Addresses:\n"
                ip_src_count = self.packet_stats['ip_src_count']
                sorted_src = sorted(ip_src_count.items(), key=lambda x: x[1], reverse=True)[:10]
                
                for ip, count in sorted_src:
                    percentage = (count / self.packet_stats['total_packets']) * 100
                    content += f"  {ip}: {count} packets ({percentage:.1f}%)\n"
                    
                content += "\n"
                
                # Top destination IPs
                content += "Top Destination IP Addresses:\n"
                ip_dst_count = self.packet_stats['ip_dst_count']
                sorted_dst = sorted(ip_dst_count.items(), key=lambda x: x[1], reverse=True)[:10]
                
                for ip, count in sorted_dst:
                    percentage = (count / self.packet_stats['total_packets']) * 100
                    content += f"  {ip}: {count} packets ({percentage:.1f}%)\n"
                    
                content += "\n"
            
            # Add packet list
            content += "PACKET LIST\n"
            content += "-" * 50 + "\n\n"
            
            # Get packet data from tree view
            for item in self.packet_tree.get_children():
                values = self.packet_tree.item(item, "values")
                if values:
                    content += f"Packet #{values[0]}: {values[4]} | {values[2]} -> {values[3]} | {values[5]} bytes | {values[6]}\n"
            
            # Write to file
            with open(file_path, 'w') as f:
                f.write(content)
                
            self.log(f"Text report saved to {file_path}", success=True)
            
        except Exception as e:
            self.log(f"Error saving text report: {str(e)}", error=True)
    
    def _export_json_data(self):
        """Export analysis as JSON data"""
        # Ask for save location
        file_path = filedialog.asksaveasfilename(
            title="Save JSON Data",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Build JSON data
            data = {
                "meta": {
                    "generated_at": datetime.now().isoformat(),
                    "source_file": os.path.basename(self.current_file) if self.current_file else None,
                    "packet_count": len(self.current_packets)
                },
                "statistics": self.packet_stats if self.packet_stats else {},
                "packets": []
            }
            
            # Get packet data
            for item in self.packet_tree.get_children():
                values = self.packet_tree.item(item, "values")
                if values:
                    packet_data = {
                        "number": values[0],
                        "time": values[1],
                        "source": values[2],
                        "destination": values[3],
                        "protocol": values[4],
                        "length": values[5],
                        "info": values[6]
                    }
                    data["packets"].append(packet_data)
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            self.log(f"JSON data saved to {file_path}", success=True)
            
        except Exception as e:
            self.log(f"Error saving JSON data: {str(e)}", error=True)
    
    def _export_csv_data(self):
        """Export packet list as CSV data"""
        # Ask for save location
        file_path = filedialog.asksaveasfilename(
            title="Save CSV Data",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Build CSV content
            content = "Number,Time,Source,Destination,Protocol,Length,Info\n"
            
            # Get packet data
            for item in self.packet_tree.get_children():
                values = self.packet_tree.item(item, "values")
                if values:
                    # Escape values and wrap in quotes if necessary
                    csv_values = []
                    for value in values:
                        value_str = str(value)
                        if "," in value_str or '"' in value_str:
                            value_str = value_str.replace('"', '""')
                            value_str = f'"{value_str}"'
                        csv_values.append(value_str)
                    
                    content += ",".join(csv_values) + "\n"
            
            # Write to file
            with open(file_path, 'w') as f:
                f.write(content)
                
            self.log(f"CSV data saved to {file_path}", success=True)
            
        except Exception as e:
            self.log(f"Error saving CSV data: {str(e)}", error=True)
    
    def _export_pcap_file(self):
        """Export packets as PCAP file"""
        # Check if scapy is available
        if not SCAPY_AVAILABLE:
            self.log("Scapy not available, PCAP export not supported", error=True)
            return
            
        # Ask for save location
        file_path = filedialog.asksaveasfilename(
            title="Save PCAP File",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Write packets to file
            from scapy.all import wrpcap
            wrpcap(file_path, self.current_packets)
            
            self.log(f"PCAP file saved to {file_path}", success=True)
            
        except Exception as e:
            self.log(f"Error saving PCAP file: {str(e)}", error=True)
    
    def export_visualization_image(self):
        """Export current visualization as image"""
        if not MATPLOTLIB_AVAILABLE:
            self.log("Matplotlib not available, image export not supported", error=True)
            return
            
        # Check if there is a visualization
        if not self.viz_frame.winfo_children() or all(not isinstance(child, FigureCanvasTkAgg) for child in self.viz_frame.winfo_children()):
            self.log("No visualization available to export", error=True)
            return
            
        # Ask for save location
        file_path = filedialog.asksaveasfilename(
            title="Save Visualization Image",
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("PDF files", "*.pdf"),
                ("SVG files", "*.svg"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            # Get the canvas and figure
            for child in self.viz_frame.winfo_children():
                if isinstance(child, FigureCanvasTkAgg):
                    canvas = child
                    figure = canvas.figure
                    
                    # Save figure
                    figure.savefig(file_path, dpi=300, bbox_inches='tight')
                    
                    self.log(f"Visualization saved to {file_path}", success=True)
                    return
            
            self.log("No visualization canvas found", error=True)
            
        except Exception as e:
            self.log(f"Error saving visualization: {str(e)}", error=True)
    
    def export_visualization_data(self):
        """Export data used for current visualization"""
        # Get visualization type
        viz_type = self.visualization_type.get()
        
        # Check if there are packet stats
        if not self.packet_stats:
            self.log("No visualization data available to export", error=True)
            return
            
        # Ask for save location
        file_path = filedialog.asksaveasfilename(
            title="Save Visualization Data",
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            # Determine file format
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Get the appropriate data based on visualization type
            data = {}
            if viz_type == "Packet Types" or viz_type == "Protocol Distribution":
                data = self.packet_stats["proto_count"]
            elif viz_type == "Traffic Over Time":
                # We need to create binned time data
                if not self.current_packets:
                    self.log("No packet data available", error=True)
                    return
                    
                timestamps = [float(packet.time) for packet in self.current_packets if hasattr(packet, 'time')]
                if not timestamps:
                    self.log("No timestamp data available", error=True)
                    return
                    
                # Normalize timestamps to start from 0
                min_time = min(timestamps)
                normalized = [t - min_time for t in timestamps]
                
                # Bin timestamps into intervals
                max_time = max(normalized)
                bin_count = min(50, int(max_time) + 1)
                
                # Create histogram data
                hist, bin_edges = np.histogram(normalized, bins=bin_count)
                
                # Convert to dictionary
                data = {f"{bin_edges[i]:.2f}-{bin_edges[i+1]:.2f}": int(hist[i]) for i in range(len(hist))}
                
            elif viz_type == "Packet Sizes":
                # Create histogram of packet sizes
                if not self.packet_stats["packet_sizes"]:
                    self.log("No packet size data available", error=True)
                    return
                    
                packet_sizes = self.packet_stats["packet_sizes"]
                hist, bin_edges = np.histogram(packet_sizes, bins=30)
                
                # Convert to dictionary
                data = {f"{int(bin_edges[i])}-{int(bin_edges[i+1])}": int(hist[i]) for i in range(len(hist))}
                
            elif viz_type == "Source/Destination":
                data = {
                    "source_ips": self.packet_stats["ip_src_count"],
                    "destination_ips": self.packet_stats["ip_dst_count"]
                }
            
            # Save data
            if file_ext == ".json":
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            else:  # CSV format
                with open(file_path, 'w') as f:
                    if viz_type == "Source/Destination":
                        # Special case for source/destination
                        f.write("IP,Source_Count,Destination_Count\n")
                        
                        # Combine all IPs
                        all_ips = set(list(data["source_ips"].keys()) + list(data["destination_ips"].keys()))
                        
                        for ip in all_ips:
                            src_count = data["source_ips"].get(ip, 0)
                            dst_count = data["destination_ips"].get(ip, 0)
                            f.write(f"{ip},{src_count},{dst_count}\n")
                    else:
                        # Standard key-value pairs
                        f.write("Category,Count\n")
                        for key, value in data.items():
                            key_str = str(key)
                            if "," in key_str:
                                key_str = f'"{key_str}"'
                            f.write(f"{key_str},{value}\n")
            
            self.log(f"Visualization data saved to {file_path}", success=True)
            
        except Exception as e:
            self.log(f"Error saving visualization data: {str(e)}", error=True)
    
    def _load_mock_data(self):
        """Load mock packet data for development testing"""
        # Create mock packet data based on common network protocols
        self.log("Loading mock packet data for development", warning=True)
        
        # Create statistics dictionary
        self.packet_stats = {
            "total_packets": 1000,
            "total_bytes": 128000,
            "avg_packet_size": 128,
            "min_packet_size": 64,
            "max_packet_size": 1500,
            "proto_count": {
                "TCP": 450,
                "UDP": 300,
                "ICMP": 50,
                "DNS": 100,
                "HTTP": 75,
                "HTTPS": 25
            },
            "ip_src_count": {
                "192.168.1.100": 350,
                "192.168.1.101": 250,
                "192.168.1.102": 200,
                "192.168.1.103": 150,
                "192.168.1.104": 50
            },
            "ip_dst_count": {
                "192.168.1.1": 400,
                "8.8.8.8": 300,
                "172.217.22.14": 200,
                "157.240.22.35": 100
            },
            "port_count": {
                "TCP:80": 300,
                "TCP:443": 150,
                "UDP:53": 250,
                "TCP:22": 100,
                "TCP:8080": 50,
                "UDP:123": 50,
                "TCP:21": 50,
                "TCP:3389": 50
            },
            "packet_sizes": [
                64, 64, 64, 64, 64, 128, 128, 128, 128, 256, 256, 256,
                512, 512, 512, 1024, 1024, 1500, 1500
            ] * 50  # Repeat to get enough data points
        }
        
        # Update UI after "loading" mock data
        if self.root:
            self.root.after(0, self._update_ui_after_load, 1000)
            
    def _scan_packet_for_sensitive_data(self, packet):
        """Scan a packet for sensitive data using real regex patterns
        
        This function inspects packet payload for sensitive information like:
        - Passwords
        - API keys
        - Credit card numbers
        - Authentication tokens
        - Private keys
        - Session identifiers
        
        Args:
            packet: The packet to scan
        """
        import re
        
        # Check if packet has a payload
        if not hasattr(packet, 'payload'):
            return
            
        # Get packet data to analyze
        payload = None
        
        # Extract raw payload from packet if possible
        if hasattr(packet, 'load'):
            # Direct raw data
            payload = packet.load
        elif hasattr(packet, 'payload') and hasattr(packet.payload, 'load'):
            # One level deep
            payload = packet.payload.load
        elif hasattr(packet, 'payload') and hasattr(packet.payload, 'payload') and hasattr(packet.payload.payload, 'load'):
            # Two levels deep
            payload = packet.payload.payload.load
            
        # Convert bytes to string if needed
        if payload and isinstance(payload, bytes):
            try:
                payload = payload.decode('utf-8', errors='ignore')
            except:
                return
        
        if not payload:
            return
            
        # Get source and destination if available
        src = "Unknown"
        dst = "Unknown"
        src_port = ""
        dst_port = ""
        
        # Try to get IP addresses
        if hasattr(packet, 'src') and hasattr(packet, 'dst'):
            src = packet.src
            dst = packet.dst
        
        # Try to get ports for TCP/UDP
        if hasattr(packet, 'sport') and hasattr(packet, 'dport'):
            src_port = f":{packet.sport}"
            dst_port = f":{packet.dport}"
        
        connection = f"{src}{src_port} → {dst}{dst_port}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Check each pattern
        for sensitivity_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, payload)
            if matches:
                # Found sensitive data!
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]  # Get first group if it's a tuple of groups
                        
                    # Create a sensitive data finding
                    finding = {
                        'type': sensitivity_type,
                        'data': match,
                        'connection': connection,
                        'timestamp': timestamp,
                        'packet': packet  # Store reference to packet
                    }
                    
                    # Add to findings list
                    self.found_sensitive_data.append(finding)
                    
                    # Log the finding
                    self.log(f"[!] SENSITIVE DATA DETECTED: {sensitivity_type} in traffic {connection}", 
                            error=True, phase="SECURITY")
                    
                    # Send a real-time alert if enabled
                    if self.real_time_alerts.get():
                        # Create alert message
                        alert_message = f"""
SECURITY ALERT! Sensitive Data Detected:
Type: {sensitivity_type}
Connection: {connection}
Timestamp: {timestamp}
Data: {match[:30]}{'...' if len(match) > 30 else ''}
                        """
                        
                        # Write alert to file
                        try:
                            alerts_dir = os.path.join(os.getcwd(), "alerts")
                            if not os.path.exists(alerts_dir):
                                os.makedirs(alerts_dir)
                                
                            alert_file = os.path.join(alerts_dir, f"alert_{timestamp.replace(':', '-').replace(' ', '_')}.txt")
                            with open(alert_file, 'w') as f:
                                f.write(alert_message)
                        except Exception as e:
                            self.log(f"Failed to save alert: {str(e)}", error=True)
                        
                        # Send desktop notification if possible
                        try:
                            # Try using notify-send (Linux)
                            if os.name == 'posix':
                                subprocess.run([
                                    'notify-send', 
                                    'SECURITY ALERT: Sensitive Data Detected',
                                    f'Type: {sensitivity_type}\nConnection: {connection}'
                                ], 
                                timeout=1,
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE)
                        except:
                            pass
    
    def cleanup(self):
        """Clean up resources when closing the Traffic Analysis window"""
        # Stop any ongoing operations
        if hasattr(self, 'capture_thread') and self.capture_thread and self.capture_thread.is_alive():
            if hasattr(self, '_stop_capture'):
                self._stop_capture()
                
        # Clean up matplotlib resources if available
        if MATPLOTLIB_AVAILABLE and plt:
            for widget_name in ['overview_canvas', 'security_canvas', 'packet_dist_canvas']:
                if hasattr(self, widget_name):
                    try:
                        widget = getattr(self, widget_name)
                        if hasattr(widget, 'figure'):
                            plt.close(widget.figure)
                    except:
                        pass
        
        # Release memory
        self.current_packets = []
        self.packet_stats = {}