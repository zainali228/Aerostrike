#!/usr/bin/env python3
"""
GUI Manager for NetworkPentestPro
Handles all UI components, events, and threading for the application
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import threading
import os
import sys
import json
import time
from datetime import datetime
import logging
from typing import Dict, List, Optional, Callable, Any, Tuple

# Import application modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.pentest_core import NetworkTarget, PentestController, AttackType
from modules.report_generator import ReportGenerator
from utils.config_manager import ConfigManager
from utils.security_utils import SecurityUtils
from templates.dialogs.advanced_options import create_advanced_dialog
from templates.dialogs.attack_all import create_attack_all_dialog
from templates.dialogs.network_detail import create_network_detail_dialog
from templates.dialogs.report_config import create_report_config_dialog

class GUIManager:
    """Main GUI manager for the application"""
    
    def __init__(self, root: tk.Tk, config: Dict[str, Any], logger: logging.Logger):
        """Initialize GUI Manager"""
        self.root = root
        self.config = config
        self.logger = logger
        
        # Initialize controller
        self.controller = PentestController(callback=self.log)
        self.report_generator = ReportGenerator(logger=logger)
        
        # Initialize state variables
        self.scanning = False
        self.attacking = False
        self.selected_network = None
        self.networks = []
        self.dark_mode = self.config.get('theme', 'dark') == 'dark'
        self.dev_mode = self.config.get('dev_mode', False)
        
        # Configure root window
        self.root.title("NetworkPentestPro - Advanced Wireless Security Testing")
        self.root.geometry("1280x800")
        self.root.minsize(1024, 768)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Set up GUI components
        self.setup_styles()
        self.create_main_frame()
        self.create_menu()
        self.create_toolbar()
        self.create_network_list()
        self.create_detail_pane()
        self.create_console()
        self.create_status_bar()
        
        # Set up tag configuration for console
        self.setup_console_tags()
        
        # Initialize interfaces
        self.refresh_interfaces()
        
        # Apply theme
        self.apply_theme()
        
        # Log startup
        self.log(f"NetworkPentestPro started in {'DEVELOPMENT' if self.dev_mode else 'NORMAL'} mode")
        
        # Check prerequisites
        self.check_prerequisites()
    
    def setup_styles(self):
        """Configure ttk styles"""
        self.style = ttk.Style()
        
        # Default theme
        self.style.theme_use('clam')
        
        # Configure common styles
        self.style.configure("TButton", padding=6, relief="flat", font=('Helvetica', 10))
        self.style.configure("TLabel", font=('Helvetica', 10))
        self.style.configure("TFrame", relief="flat")
        self.style.configure("Toolbar.TFrame", relief="raised")
        self.style.configure("Header.TLabel", font=('Helvetica', 12, 'bold'))
        
        # Configure custom button styles
        self.style.configure("Primary.TButton", foreground="#ffffff", background="#007bff")
        self.style.configure("Success.TButton", foreground="#ffffff", background="#28a745")
        self.style.configure("Danger.TButton", foreground="#ffffff", background="#dc3545")
        self.style.configure("Warning.TButton", foreground="#212529", background="#ffc107")
        self.style.configure("Info.TButton", foreground="#ffffff", background="#17a2b8")
        
        # Configure treeview
        self.style.configure("Treeview", 
                          rowheight=25, 
                          font=('Helvetica', 10))
        self.style.configure("Treeview.Heading", 
                          font=('Helvetica', 10, 'bold'))
        
    def create_main_frame(self):
        """Create main application frame"""
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create paned window for resizable sections
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left frame for network list
        self.left_frame = ttk.Frame(self.paned_window)
        
        # Right frame for details and console
        self.right_frame = ttk.Frame(self.paned_window)
        
        # Add frames to paned window
        self.paned_window.add(self.left_frame, weight=1)
        self.paned_window.add(self.right_frame, weight=2)
        
        # Create vertical paned window for right section
        self.right_pane = ttk.PanedWindow(self.right_frame, orient=tk.VERTICAL)
        self.right_pane.pack(fill=tk.BOTH, expand=True)
        
        # Detail frame in top right
        self.detail_frame = ttk.Frame(self.right_pane)
        
        # Console frame in bottom right
        self.console_frame = ttk.Frame(self.right_pane)
        
        # Add frames to right pane
        self.right_pane.add(self.detail_frame, weight=2)
        self.right_pane.add(self.console_frame, weight=1)
    
    def create_menu(self):
        """Create application menu"""
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        # File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Save Config", command=self.save_config)
        self.file_menu.add_command(label="Load Config", command=self.load_config)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Generate Report", command=self.generate_report)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.on_close)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        
        # Scan menu
        self.scan_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.scan_menu.add_command(label="Start Scan", command=self.start_scan)
        self.scan_menu.add_command(label="Stop Scan", command=self.stop_scan)
        self.scan_menu.add_separator()
        self.scan_menu.add_command(label="Clear Results", command=self.clear_results)
        self.menu_bar.add_cascade(label="Scan", menu=self.scan_menu)
        
        # Attack menu
        self.attack_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.attack_menu.add_command(label="WPS Attack", command=lambda: self.launch_attack("WPS"))
        self.attack_menu.add_command(label="WPA Handshake", command=lambda: self.launch_attack("WPA"))
        self.attack_menu.add_command(label="WEP Attack", command=lambda: self.launch_attack("WEP"))
        self.attack_menu.add_command(label="PMKID Attack", command=lambda: self.launch_attack("PMKID"))
        self.attack_menu.add_separator()
        self.attack_menu.add_command(label="Default Credentials", command=lambda: self.launch_attack("DEFAULT_CREDS"))
        self.attack_menu.add_command(label="Evil Twin", command=lambda: self.launch_attack("EVIL_TWIN"))
        self.attack_menu.add_separator()
        self.attack_menu.add_command(label="Test All Networks", command=self.show_attack_all_dialog)
        self.menu_bar.add_cascade(label="Attack", menu=self.attack_menu)
        
        # Tools menu
        self.tools_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.tools_menu.add_command(label="Test Injection", command=self.test_injection)
        self.tools_menu.add_command(label="Monitor Mode", command=self.toggle_monitor_mode)
        self.tools_menu.add_command(label="Advanced Options", command=self.show_advanced_options)
        self.menu_bar.add_cascade(label="Tools", menu=self.tools_menu)
        
        # Theme menu
        self.theme_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.theme_menu.add_command(label="Dark Mode", command=lambda: self.set_theme("dark"))
        self.theme_menu.add_command(label="Light Mode", command=lambda: self.set_theme("light"))
        self.menu_bar.add_cascade(label="Theme", menu=self.theme_menu)
        
        # Help menu
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.help_menu.add_command(label="Help", command=self.show_help)
        self.help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
    
    def create_toolbar(self):
        """Create toolbar with main controls"""
        self.toolbar = ttk.Frame(self.main_frame, style="Toolbar.TFrame")
        self.toolbar.pack(fill=tk.X, padx=5, pady=2)
        
        # Interface selection
        ttk.Label(self.toolbar, text="Interface:").pack(side=tk.LEFT, padx=5)
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(self.toolbar, 
                                          textvariable=self.interface_var,
                                          width=10,
                                          state="readonly")
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        self.interface_combo.bind("<<ComboboxSelected>>", self.on_interface_changed)
        
        # Refresh interfaces button
        self.refresh_btn = ttk.Button(self.toolbar, 
                                    text="⟳", 
                                    width=3,
                                    command=self.refresh_interfaces)
        self.refresh_btn.pack(side=tk.LEFT, padx=2)
        
        # Separator
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y, pady=2)
        
        # Scan time
        ttk.Label(self.toolbar, text="Scan Time:").pack(side=tk.LEFT, padx=5)
        
        self.scan_time_var = tk.IntVar(value=60)
        self.scan_time_combo = ttk.Combobox(self.toolbar, 
                                         textvariable=self.scan_time_var,
                                         width=5,
                                         values=[30, 60, 120, 300],
                                         state="readonly")
        self.scan_time_combo.pack(side=tk.LEFT, padx=5)
        
        # Channel selection
        ttk.Label(self.toolbar, text="Channel:").pack(side=tk.LEFT, padx=5)
        
        self.channel_var = tk.StringVar(value="All")
        self.channel_combo = ttk.Combobox(self.toolbar, 
                                       textvariable=self.channel_var,
                                       width=5,
                                       values=["All", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"],
                                       state="readonly")
        self.channel_combo.pack(side=tk.LEFT, padx=5)
        
        # Separator
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y, pady=2)
        
        # Scan button
        self.scan_btn = ttk.Button(self.toolbar,
                                 text="Start Scan",
                                 style="Primary.TButton",
                                 command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        # Stop scan button
        self.stop_btn = ttk.Button(self.toolbar,
                                 text="Stop",
                                 style="Danger.TButton",
                                 command=self.stop_scan,
                                 state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Advanced Options button
        self.advanced_btn = ttk.Button(self.toolbar,
                                     text="Advanced",
                                     command=self.show_advanced_options)
        self.advanced_btn.pack(side=tk.RIGHT, padx=5)
        
        # Toggle theme button
        self.theme_btn = ttk.Button(self.toolbar,
                                  text="🌙" if self.dark_mode else "☀️",
                                  width=3,
                                  command=self.toggle_theme)
        self.theme_btn.pack(side=tk.RIGHT, padx=5)
    
    def create_network_list(self):
        """Create network list treeview"""
        # Frame for the network list
        self.network_list_frame = ttk.LabelFrame(self.left_frame, text="Detected Networks")
        self.network_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview with scrollbars
        self.tree_frame = ttk.Frame(self.network_list_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbars
        self.tree_y_scroll = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL)
        self.tree_x_scroll = ttk.Scrollbar(self.tree_frame, orient=tk.HORIZONTAL)
        
        # Network treeview
        self.network_tree = ttk.Treeview(self.tree_frame, 
                                      columns=("bssid", "channel", "security", "signal", "clients"),
                                      show="headings",
                                      yscrollcommand=self.tree_y_scroll.set,
                                      xscrollcommand=self.tree_x_scroll.set)
        
        # Configure scrollbars
        self.tree_y_scroll.config(command=self.network_tree.yview)
        self.tree_x_scroll.config(command=self.network_tree.xview)
        
        # Add columns to treeview
        self.network_tree.heading("bssid", text="BSSID")
        self.network_tree.heading("channel", text="Ch")
        self.network_tree.heading("security", text="Security")
        self.network_tree.heading("signal", text="Signal")
        self.network_tree.heading("clients", text="Clients")
        
        # Configure column widths
        self.network_tree.column("bssid", width=140, minwidth=120)
        self.network_tree.column("channel", width=40, minwidth=30)
        self.network_tree.column("security", width=100, minwidth=80)
        self.network_tree.column("signal", width=60, minwidth=50)
        self.network_tree.column("clients", width=60, minwidth=50)
        
        # Pack treeview and scrollbars
        self.network_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind selection event
        self.network_tree.bind("<<TreeviewSelect>>", self.on_network_selected)
        
        # Context menu for right-click
        self.network_context_menu = tk.Menu(self.network_tree, tearoff=0)
        self.network_context_menu.add_command(label="View Details", command=self.show_network_details)
        self.network_context_menu.add_separator()
        self.network_context_menu.add_command(label="WPS Attack", command=lambda: self.launch_attack("WPS"))
        self.network_context_menu.add_command(label="WPA Handshake", command=lambda: self.launch_attack("WPA"))
        self.network_context_menu.add_command(label="WEP Attack", command=lambda: self.launch_attack("WEP"))
        self.network_context_menu.add_command(label="PMKID Attack", command=lambda: self.launch_attack("PMKID"))
        self.network_context_menu.add_command(label="Default Credentials", command=lambda: self.launch_attack("DEFAULT_CREDS"))
        self.network_context_menu.add_command(label="Deauth Clients", command=lambda: self.launch_attack("DEAUTH"))
        self.network_context_menu.add_command(label="Evil Twin", command=lambda: self.launch_attack("EVIL_TWIN"))
        
        # Bind right-click event
        self.network_tree.bind("<Button-3>", self.show_network_context_menu)
        
        # Control buttons
        self.network_btn_frame = ttk.Frame(self.network_list_frame)
        self.network_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Attack button
        self.attack_btn = ttk.Button(self.network_btn_frame,
                                   text="Attack",
                                   style="Danger.TButton",
                                   command=self.attack_selected,
                                   state=tk.DISABLED)
        self.attack_btn.pack(side=tk.LEFT, padx=5)
        
        # Test All button
        self.test_all_btn = ttk.Button(self.network_btn_frame,
                                     text="Test All",
                                     command=self.show_attack_all_dialog)
        self.test_all_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear button
        self.clear_btn = ttk.Button(self.network_btn_frame,
                                  text="Clear",
                                  command=self.clear_results)
        self.clear_btn.pack(side=tk.RIGHT, padx=5)
    
    def create_detail_pane(self):
        """Create network detail pane"""
        # Detail frame
        self.details_label_frame = ttk.LabelFrame(self.detail_frame, text="Network Details")
        self.details_label_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a canvas for details
        self.detail_canvas = tk.Canvas(self.details_label_frame, background="#2d2d2d")
        self.detail_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a frame inside the canvas
        self.detail_inner_frame = ttk.Frame(self.detail_canvas)
        self.detail_inner_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        self.detail_scrollbar = ttk.Scrollbar(self.details_label_frame, 
                                           orient=tk.VERTICAL, 
                                           command=self.detail_canvas.yview)
        self.detail_canvas.configure(yscrollcommand=self.detail_scrollbar.set)
        self.detail_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind frame to canvas
        self.detail_canvas_frame = self.detail_canvas.create_window((0, 0), 
                                                               window=self.detail_inner_frame, 
                                                               anchor=tk.NW)
        
        # Configure canvas to expand with frame
        self.detail_inner_frame.bind("<Configure>", self.on_detail_frame_configure)
        self.detail_canvas.bind("<Configure>", self.on_detail_canvas_configure)
        
        # Initial message
        self.empty_label = ttk.Label(self.detail_inner_frame, 
                                   text="Select a network to view details",
                                   font=("Helvetica", 12),
                                   foreground="#aaaaaa")
        self.empty_label.pack(expand=True, padx=20, pady=20)
    
    def create_console(self):
        """Create console output area"""
        # Console frame
        self.console_label_frame = ttk.LabelFrame(self.console_frame, text="Console Output")
        self.console_label_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Console text
        self.console = ScrolledText(self.console_label_frame, 
                                  height=10,
                                  wrap=tk.WORD,
                                  background="#1e1e1e",
                                  foreground="#e0e0e0",
                                  font=("Consolas", 10))
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Console control buttons
        self.console_btn_frame = ttk.Frame(self.console_label_frame)
        self.console_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Clear console button
        self.clear_console_btn = ttk.Button(self.console_btn_frame,
                                         text="Clear Console",
                                         command=self.clear_console)
        self.clear_console_btn.pack(side=tk.RIGHT, padx=5)
        
        # Save console button
        self.save_console_btn = ttk.Button(self.console_btn_frame,
                                        text="Save Output",
                                        command=self.save_console)
        self.save_console_btn.pack(side=tk.RIGHT, padx=5)
    
    def create_status_bar(self):
        """Create status bar at bottom of window"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Status label
        self.status_label = ttk.Label(self.status_bar, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Mode label
        self.mode_label = ttk.Label(self.status_bar, text="Mode: Managed")
        self.mode_label.pack(side=tk.RIGHT, padx=10)
        
        # Interface label
        self.interface_label = ttk.Label(self.status_bar, text="Interface: None")
        self.interface_label.pack(side=tk.RIGHT, padx=10)
        
        # Development mode indicator
        if self.dev_mode:
            self.dev_label = ttk.Label(self.status_bar, 
                                     text="DEVELOPMENT MODE", 
                                     foreground="#ff5555",
                                     font=("Helvetica", 9, "bold"))
            self.dev_label.pack(side=tk.RIGHT, padx=10)
    
    def setup_console_tags(self):
        """Set up tags for console text"""
        self.console.tag_configure("error", foreground="#ff5555")
        self.console.tag_configure("warning", foreground="#ffaa55")
        self.console.tag_configure("success", foreground="#55ff55")
        self.console.tag_configure("info", foreground="#5599ff")
        self.console.tag_configure("timestamp", foreground="#aaaaaa")
        
        # Tags for different attack phases
        self.console.tag_configure("SCAN", foreground="#55aaff")
        self.console.tag_configure("ATTACK", foreground="#ffaa00")
        self.console.tag_configure("HARDWARE", foreground="#aa55ff")
        self.console.tag_configure("REPORT", foreground="#55ffaa")
    
    def log(self, message: str, error: bool = False, warning: bool = False, 
          success: bool = False, phase: str = None):
        """Add message to console with timestamp"""
        # Create timestamp
        timestamp = datetime.now().strftime("[%H:%M:%S] ")
        
        # Ensure console exists
        if not hasattr(self, 'console'):
            return
            
        # Add timestamp
        self.console.insert(tk.END, timestamp, "timestamp")
        
        # Add phase prefix if provided
        if phase:
            self.console.insert(tk.END, f"[{phase}] ", phase)
        
        # Add message with appropriate tag
        if error:
            self.console.insert(tk.END, f"{message}\n", "error")
        elif warning:
            self.console.insert(tk.END, f"{message}\n", "warning")
        elif success:
            self.console.insert(tk.END, f"{message}\n", "success")
        else:
            self.console.insert(tk.END, f"{message}\n")
        
        # Auto-scroll to bottom
        self.console.see(tk.END)
        
        # Log to application logger
        if error:
            self.logger.error(message)
        elif warning:
            self.logger.warning(message)
        elif success:
            self.logger.info(f"SUCCESS: {message}")
        else:
            self.logger.info(message)
    
    def refresh_interfaces(self):
        """Refresh available wireless interfaces"""
        # Get interfaces
        interfaces = SecurityUtils.list_wireless_interfaces()
        
        # Update interface combo values
        self.interface_combo['values'] = interfaces
        
        if interfaces:
            # Select first interface or keep current if still available
            current = self.interface_var.get()
            if current and current in interfaces:
                self.interface_var.set(current)
            else:
                self.interface_var.set(interfaces[0])
                
            # Update controller with selected interface
            self.on_interface_changed(None)
            
            self.log(f"Found {len(interfaces)} wireless interfaces")
        else:
            self.interface_var.set("")
            self.log("No wireless interfaces found", warning=True)
    
    def on_interface_changed(self, event):
        """Handle interface selection change"""
        interface = self.interface_var.get()
        if interface:
            # Update controller
            self.controller.set_interface(interface)
            
            # Update interface label
            self.interface_label.config(text=f"Interface: {interface}")
            
            # Update mode label
            mode = SecurityUtils.get_interface_mode(interface)
            self.mode_label.config(text=f"Mode: {mode.capitalize()}")
            
            self.log(f"Selected interface: {interface} (Mode: {mode})")
        else:
            self.interface_label.config(text="Interface: None")
            self.mode_label.config(text="Mode: None")
    
    def toggle_monitor_mode(self):
        """Toggle monitor mode on current interface"""
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "No interface selected")
            return
            
        # Get current mode
        current_mode = SecurityUtils.get_interface_mode(interface)
        
        # Toggle mode
        if current_mode == "monitor":
            # Disable monitor mode
            self.log(f"Disabling monitor mode on {interface}...")
            success, new_interface = SecurityUtils.set_monitor_mode(interface, False, self.log)
        else:
            # Enable monitor mode
            self.log(f"Enabling monitor mode on {interface}...")
            success, new_interface = SecurityUtils.set_monitor_mode(interface, True, self.log)
        
        if success:
            # Update interface combo
            self.refresh_interfaces()
            
            # Select the new interface
            if new_interface in self.interface_combo['values']:
                self.interface_var.set(new_interface)
                self.on_interface_changed(None)
        else:
            self.log(f"Failed to change interface mode", error=True)
    
    def test_injection(self):
        """Test packet injection capability"""
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "No interface selected")
            return
            
        # Start test in a thread
        threading.Thread(target=self._test_injection_thread, daemon=True).start()
    
    def _test_injection_thread(self):
        """Thread for injection testing"""
        # Disable interface combo and buttons during test
        self.interface_combo.config(state="disabled")
        self.refresh_btn.config(state="disabled")
        
        # Update status
        self.status_label.config(text="Testing injection...")
        
        try:
            # Run injection test
            success, message, rate = self.controller.test_injection()
            
            if success:
                self.log(f"Injection test successful: {message}", success=True)
                if rate > 0:
                    self.log(f"Injection success rate: {rate}%", success=True)
            else:
                self.log(f"Injection test failed: {message}", error=True)
        finally:
            # Re-enable interface controls
            self.interface_combo.config(state="readonly")
            self.refresh_btn.config(state="normal")
            
            # Update status
            self.status_label.config(text="Ready")
    
    def start_scan(self):
        """Start network scan"""
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "No interface selected")
            return
            
        # Get scan parameters
        scan_time = self.scan_time_var.get()
        channel = self.channel_var.get()
        if channel == "All":
            channel = None
            
        # Start scan in a thread
        threading.Thread(target=self._scan_thread, 
                       args=(scan_time, channel), 
                       daemon=True).start()
    
    def _scan_thread(self, duration: int, channel: str = None):
        """Thread for network scanning"""
        self.scanning = True
        
        # Update UI state
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Scanning...")
        
        try:
            # Start scan
            success = self.controller.start_scan(duration, channel)
            
            if not success:
                self.log("Failed to start scan", error=True)
                return
                
            # Clear existing results
            self.clear_network_tree()
            
            # Wait for scan to complete or be stopped
            start_time = time.time()
            while self.scanning and time.time() - start_time < duration:
                # Update tree with current results
                self.update_network_tree()
                
                # Update status
                elapsed = time.time() - start_time
                remaining = max(0, duration - elapsed)
                progress = min(100, (elapsed / duration) * 100)
                self.status_label.config(text=f"Scanning: {progress:.1f}% ({remaining:.0f}s remaining)")
                
                # Sleep a bit
                time.sleep(1)
                
            # Final update of results
            self.update_network_tree()
            
            if self.scanning:  # Completed naturally
                self.log(f"Scan completed, found {len(self.networks)} networks", success=True)
            else:  # Stopped by user
                self.log("Scan stopped by user")
        finally:
            # Stop scan if still running
            self.controller.stop_scan()
            
            # Update UI state
            self.scanning = False
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Ready")
            
            # Enable attack button if networks were found
            if self.networks:
                self.test_all_btn.config(state=tk.NORMAL)
    
    def stop_scan(self):
        """Stop ongoing scan"""
        if self.scanning:
            self.scanning = False
            self.controller.stop_scan()
            self.log("Stopping scan...")
            
            # Update UI state
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Ready")
    
    def update_network_tree(self):
        """Update network treeview with current scan results"""
        # Get networks from controller
        self.networks = self.controller.get_networks()
        
        # Sort by signal strength
        self.networks.sort(key=lambda x: x.signal_strength, reverse=True)
        
        # Clear existing items
        for item in self.network_tree.get_children():
            # Get BSSID from item values
            values = self.network_tree.item(item, "values")
            bssid = values[0] if values else None
            
            # Check if this network is still in the results
            if not any(n.bssid == bssid for n in self.networks):
                self.network_tree.delete(item)
        
        # Add or update networks
        for network in self.networks:
            # Format security for display
            security = network.security_type
            
            # Format signal strength
            signal = f"{network.signal_strength}%"
            
            # Format client count
            clients = str(network.client_count)
            
            # Check if network already in tree
            item_id = None
            for item in self.network_tree.get_children():
                values = self.network_tree.item(item, "values")
                if values and values[0] == network.bssid:
                    item_id = item
                    break
            
            # Create item values
            values = (
                network.bssid,
                network.channel,
                security,
                signal,
                clients
            )
            
            if item_id:
                # Update existing item
                self.network_tree.item(item_id, values=values)
            else:
                # Insert new item
                self.network_tree.insert("", tk.END, values=values, tags=(security,))
    
    def clear_network_tree(self):
        """Clear all items from network treeview"""
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
    
    def on_network_selected(self, event):
        """Handle network selection in treeview"""
        selected_items = self.network_tree.selection()
        if not selected_items:
            # Clear details
            self.clear_details()
            self.attack_btn.config(state=tk.DISABLED)
            self.selected_network = None
            return
            
        # Get selected item
        item_id = selected_items[0]
        values = self.network_tree.item(item_id, "values")
        
        if not values:
            return
            
        # Get BSSID
        bssid = values[0]
        
        # Find network in list
        network = None
        for n in self.networks:
            if n.bssid == bssid:
                network = n
                break
                
        if not network:
            return
            
        # Update selected network
        self.selected_network = network
        
        # Enable attack button
        self.attack_btn.config(state=tk.NORMAL)
        
        # Update details
        self.update_details(network)
    
    def update_details(self, network: NetworkTarget):
        """Update detail pane with network information"""
        # Clear existing content
        self.clear_details()
        
        # Get theme colors
        bg_color = "#2d2d2d" if self.dark_mode else "#f5f5f5"
        fg_color = "#e0e0e0" if self.dark_mode else "#333333"
        header_color = "#55aaff" if self.dark_mode else "#0066cc"
        border_color = "#444444" if self.dark_mode else "#cccccc"
        
        # Create detail sections
        self.create_detail_header(network, bg_color, fg_color, header_color)
        self.create_basic_details(network, bg_color, fg_color, border_color)
        self.create_security_details(network, bg_color, fg_color, border_color)
        self.create_client_details(network, bg_color, fg_color, border_color)
        self.create_risk_assessment(network, bg_color, fg_color, border_color)
    
    def create_detail_header(self, network: NetworkTarget, bg_color: str, fg_color: str, header_color: str):
        """Create header section for network details"""
        # Header frame
        header_frame = ttk.Frame(self.detail_inner_frame)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # SSID label
        ssid_label = ttk.Label(header_frame, 
                             text=network.ssid,
                             font=("Helvetica", 16, "bold"),
                             foreground=header_color)
        ssid_label.pack(side=tk.LEFT)
        
        # BSSID label
        bssid_label = ttk.Label(header_frame,
                              text=f"({network.bssid})",
                              font=("Helvetica", 10),
                              foreground=fg_color)
        bssid_label.pack(side=tk.LEFT, padx=10)
        
        # View details button
        details_btn = ttk.Button(header_frame,
                               text="View Details",
                               command=self.show_network_details)
        details_btn.pack(side=tk.RIGHT)
    
    def create_basic_details(self, network: NetworkTarget, bg_color: str, fg_color: str, border_color: str):
        """Create basic details section"""
        # Create frame
        basic_frame = ttk.LabelFrame(self.detail_inner_frame, text="Basic Information")
        basic_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Create grid
        grid = ttk.Frame(basic_frame)
        grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Channel
        ttk.Label(grid, text="Channel:", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(grid, text=network.channel).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Frequency
        ttk.Label(grid, text="Frequency:", font=("Helvetica", 10, "bold")).grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(grid, text=network.frequency).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Signal Strength
        ttk.Label(grid, text="Signal:", font=("Helvetica", 10, "bold")).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        
        # Create signal strength bar
        signal_frame = ttk.Frame(grid)
        signal_frame.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        signal_text = ttk.Label(signal_frame, text=f"{network.signal_strength}%")
        signal_text.pack(side=tk.LEFT)
        
        # Signal bar (using canvas)
        signal_canvas = tk.Canvas(signal_frame, width=50, height=15, bg=bg_color, highlightthickness=0)
        signal_canvas.pack(side=tk.LEFT, padx=5)
        
        # Determine signal bar color
        if network.signal_strength > 70:
            bar_color = "#00cc00"  # Green
        elif network.signal_strength > 40:
            bar_color = "#cccc00"  # Yellow
        else:
            bar_color = "#cc0000"  # Red
            
        # Draw signal bar
        bar_width = int(network.signal_strength / 100 * 50)
        signal_canvas.create_rectangle(0, 0, bar_width, 15, fill=bar_color, outline="")
        
        # Vendor
        ttk.Label(grid, text="Vendor:", font=("Helvetica", 10, "bold")).grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(grid, text=network.vendor if network.vendor else "Unknown").grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Client Count
        ttk.Label(grid, text="Clients:", font=("Helvetica", 10, "bold")).grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(grid, text=str(network.client_count)).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # First Seen
        ttk.Label(grid, text="First Seen:", font=("Helvetica", 10, "bold")).grid(row=2, column=2, sticky=tk.W, padx=5, pady=2)
        
        # Format time or show 'Now' if recent
        if network.first_seen > 0:
            first_seen_str = datetime.fromtimestamp(network.first_seen).strftime('%H:%M:%S')
        else:
            first_seen_str = "Now"
            
        ttk.Label(grid, text=first_seen_str).grid(row=2, column=3, sticky=tk.W, padx=5, pady=2)
    
    def create_security_details(self, network: NetworkTarget, bg_color: str, fg_color: str, border_color: str):
        """Create security details section"""
        # Create frame
        security_frame = ttk.LabelFrame(self.detail_inner_frame, text="Security Information")
        security_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Create grid
        grid = ttk.Frame(security_frame)
        grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Security Type
        ttk.Label(grid, text="Security:", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        
        # Determine security display text and color
        if not network.security:
            security_text = "Open (Unsecured)"
            security_color = "#cc0000"  # Red
        else:
            security_text = ", ".join(network.security)
            if "WEP" in network.security:
                security_color = "#cc6600"  # Orange
            elif "WPA2" in network.security:
                security_color = "#00cc00"  # Green
            elif "WPA" in network.security:
                security_color = "#cccc00"  # Yellow
            else:
                security_color = fg_color
                
        ttk.Label(grid, text=security_text, foreground=security_color).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Authentication
        ttk.Label(grid, text="Authentication:", font=("Helvetica", 10, "bold")).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(grid, text=network.authentication if network.authentication else "N/A").grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Encryption
        ttk.Label(grid, text="Encryption:", font=("Helvetica", 10, "bold")).grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(grid, text=network.encryption if network.encryption else "N/A").grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # WPS Status
        ttk.Label(grid, text="WPS:", font=("Helvetica", 10, "bold")).grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        
        # Determine WPS color
        if network.wps_status == "Enabled":
            wps_color = "#cc6600"  # Orange (potential vulnerability)
        elif network.wps_status == "Disabled":
            wps_color = "#00cc00"  # Green
        else:
            wps_color = fg_color
            
        ttk.Label(grid, text=network.wps_status, foreground=wps_color).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
    
    def create_client_details(self, network: NetworkTarget, bg_color: str, fg_color: str, border_color: str):
        """Create client details section"""
        if not network.clients:
            return
            
        # Create frame
        client_frame = ttk.LabelFrame(self.detail_inner_frame, text="Connected Clients")
        client_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Create list
        client_list = ttk.Frame(client_frame)
        client_list.pack(fill=tk.X, padx=10, pady=10)
        
        # Show up to 5 clients
        for i, client in enumerate(network.clients[:5]):
            ttk.Label(client_list, text=f"{i+1}. {client}", font=("Helvetica", 9)).pack(anchor=tk.W, padx=5, pady=1)
            
        # Show count if there are more
        if len(network.clients) > 5:
            ttk.Label(client_list, 
                    text=f"...and {len(network.clients) - 5} more", 
                    font=("Helvetica", 9, "italic")).pack(anchor=tk.W, padx=5, pady=1)
    
    def create_risk_assessment(self, network: NetworkTarget, bg_color: str, fg_color: str, border_color: str):
        """Create risk assessment section"""
        # Create frame
        risk_frame = ttk.LabelFrame(self.detail_inner_frame, text="Risk Assessment")
        risk_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Create content
        content = ttk.Frame(risk_frame)
        content.pack(fill=tk.X, padx=10, pady=10)
        
        # Risk Score
        ttk.Label(content, text="Risk Score:", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        
        # Determine risk label and color
        if network.risk_score > 80:
            risk_label = "Critical"
            risk_color = "#cc0000"  # Red
        elif network.risk_score > 60:
            risk_label = "High"
            risk_color = "#cc6600"  # Orange
        elif network.risk_score > 40:
            risk_label = "Medium"
            risk_color = "#cccc00"  # Yellow
        elif network.risk_score > 20:
            risk_label = "Low"
            risk_color = "#66cc00"  # Light Green
        else:
            risk_label = "Very Low"
            risk_color = "#00cc00"  # Green
            
        risk_text = f"{network.risk_score}/100 ({risk_label})"
        ttk.Label(content, text=risk_text, foreground=risk_color).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Risk bar
        risk_canvas = tk.Canvas(content, width=150, height=15, bg=bg_color, highlightthickness=0)
        risk_canvas.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        
        # Draw risk bar
        bar_width = int(network.risk_score / 100 * 150)
        
        # Gradient colors
        grad_colors = [
            (0, "#00cc00"),    # Green
            (30, "#66cc00"),   # Light Green
            (50, "#cccc00"),   # Yellow
            (70, "#cc6600"),   # Orange
            (90, "#cc0000")    # Red
        ]
        
        # Find appropriate color based on risk score
        bar_color = grad_colors[-1][1]  # Default to highest risk color
        for threshold, color in grad_colors:
            if network.risk_score <= threshold:
                bar_color = color
                break
                
        risk_canvas.create_rectangle(0, 0, bar_width, 15, fill=bar_color, outline="")
        
        # Known vulnerabilities
        if network.vulnerabilities:
            ttk.Label(content, text="Vulnerabilities:", font=("Helvetica", 10, "bold")).grid(row=2, column=0, sticky=tk.W, padx=5, pady=(10, 2))
            
            # List vulnerabilities
            for i, vuln in enumerate(network.vulnerabilities):
                ttk.Label(content, text=f"• {vuln}", foreground="#cc0000").grid(row=3+i, column=0, columnspan=2, sticky=tk.W, padx=5, pady=1)
    
    def clear_details(self):
        """Clear detail pane"""
        # Clear all widgets in detail frame
        for widget in self.detail_inner_frame.winfo_children():
            widget.destroy()
            
        # Add empty message
        self.empty_label = ttk.Label(self.detail_inner_frame, 
                                   text="Select a network to view details",
                                   font=("Helvetica", 12),
                                   foreground="#aaaaaa")
        self.empty_label.pack(expand=True, padx=20, pady=20)
    
    def on_detail_frame_configure(self, event):
        """Update scroll region when inner frame size changes"""
        self.detail_canvas.configure(scrollregion=self.detail_canvas.bbox("all"))
    
    def on_detail_canvas_configure(self, event):
        """Resize inner frame when canvas size changes"""
        self.detail_canvas.itemconfig(self.detail_canvas_frame, width=event.width)
    
    def show_network_context_menu(self, event):
        """Display context menu for network"""
        item = self.network_tree.identify_row(event.y)
        if item:
            # Select the item
            self.network_tree.selection_set(item)
            self.on_network_selected(None)
            
            # Enable/disable menu items based on network type
            if self.selected_network:
                # WPS attack only for WPS-enabled networks
                wps_state = tk.NORMAL if self.selected_network.wps_status == "Enabled" else tk.DISABLED
                self.network_context_menu.entryconfig("WPS Attack", state=wps_state)
                
                # WPA attack only for WPA/WPA2 networks
                wpa_state = tk.NORMAL if any(s in self.selected_network.security for s in ["WPA", "WPA2"]) else tk.DISABLED
                self.network_context_menu.entryconfig("WPA Handshake", state=wpa_state)
                self.network_context_menu.entryconfig("PMKID Attack", state=wpa_state)
                
                # WEP attack only for WEP networks
                wep_state = tk.NORMAL if "WEP" in self.selected_network.security else tk.DISABLED
                self.network_context_menu.entryconfig("WEP Attack", state=wep_state)
                
                # Deauth only if clients connected
                deauth_state = tk.NORMAL if self.selected_network.client_count > 0 else tk.DISABLED
                self.network_context_menu.entryconfig("Deauth Clients", state=deauth_state)
            
            # Show context menu
            self.network_context_menu.tk_popup(event.x_root, event.y_root)
    
    def attack_selected(self):
        """Show attack options for selected network"""
        if not self.selected_network:
            return
            
        # Create a popup menu with attack options
        menu = tk.Menu(self.root, tearoff=0)
        
        # Add attack options based on network type
        if "WEP" in self.selected_network.security:
            menu.add_command(label="WEP Attack", command=lambda: self.launch_attack("WEP"))
            
        if any(s in self.selected_network.security for s in ["WPA", "WPA2"]):
            menu.add_command(label="WPA Handshake", command=lambda: self.launch_attack("WPA"))
            menu.add_command(label="PMKID Attack", command=lambda: self.launch_attack("PMKID"))
            
        if self.selected_network.wps_status == "Enabled":
            menu.add_command(label="WPS Attack", command=lambda: self.launch_attack("WPS"))
            
        # Always show these options
        menu.add_separator()
        menu.add_command(label="Default Credentials", command=lambda: self.launch_attack("DEFAULT_CREDS"))
        
        if self.selected_network.client_count > 0:
            menu.add_command(label="Deauth Clients", command=lambda: self.launch_attack("DEAUTH"))
            
        menu.add_command(label="Evil Twin", command=lambda: self.launch_attack("EVIL_TWIN"))
        
        # Position menu near attack button
        x = self.attack_btn.winfo_rootx()
        y = self.attack_btn.winfo_rooty() + self.attack_btn.winfo_height()
        menu.tk_popup(x, y)
    
    def launch_attack(self, attack_type: str):
        """Launch specified attack on selected network"""
        if not self.selected_network:
            messagebox.showerror("Error", "No network selected")
            return
            
        # Convert string to enum
        try:
            attack_enum = AttackType[attack_type]
        except KeyError:
            self.log(f"Invalid attack type: {attack_type}", error=True)
            return
            
        # Start attack in a thread
        threading.Thread(target=self._attack_thread, 
                       args=(attack_enum, self.selected_network),
                       daemon=True).start()
    
    def _attack_thread(self, attack_type: AttackType, network: NetworkTarget):
        """Thread for running attack"""
        self.attacking = True
        
        # Update UI state
        self.status_label.config(text=f"Running {attack_type.name} attack...")
        
        try:
            # Execute attack based on type
            if attack_type == AttackType.WPS:
                self._run_wps_attack(network)
            elif attack_type == AttackType.WPA:
                self._run_wpa_attack(network)
            elif attack_type == AttackType.WEP:
                self._run_wep_attack(network)
            elif attack_type == AttackType.PMKID:
                self._run_pmkid_attack(network)
            elif attack_type == AttackType.DEFAULT_CREDS:
                self._run_default_creds_attack(network)
            elif attack_type == AttackType.DEAUTH:
                self._run_deauth_attack(network)
            elif attack_type == AttackType.EVIL_TWIN:
                self._run_evil_twin_attack(network)
            else:
                self.log(f"Attack type {attack_type.name} not implemented", error=True)
        finally:
            # Update UI state
            self.attacking = False
            self.status_label.config(text="Ready")
    
    def _run_wps_attack(self, network: NetworkTarget):
        """Run WPS PIN attack"""
        self.log(f"Starting WPS PIN attack on {network.ssid} ({network.bssid})...", phase="ATTACK")
        
        # Get attack timeout from params
        timeout = self.controller.attack_params.wps_timeout
        
        # Run attack
        success, pin, password = self.controller.perform_wps_pin_attack(
            network.bssid, 
            network.channel, 
            timeout
        )
        
        if success:
            self.log(f"WPS PIN attack successful!", success=True, phase="ATTACK")
            self.log(f"WPS PIN: {pin}")
            self.log(f"WPA Password: {password}", success=True)
            
            # Add to network details
            network.vulnerabilities.append("WPS PIN Vulnerable")
            network.credentials["wps_pin"] = pin
            network.credentials["wpa_password"] = password
            
            # Show success message
            self.root.after(0, lambda: messagebox.showinfo(
                "WPS Attack Successful",
                f"Successfully recovered WPS PIN and password for {network.ssid}\n\n"
                f"WPS PIN: {pin}\n"
                f"WPA Password: {password}"
            ))
        else:
            self.log(f"WPS PIN attack failed", error=True, phase="ATTACK")
    
    def _run_wpa_attack(self, network: NetworkTarget):
        """Run WPA handshake capture"""
        self.log(f"Starting WPA handshake capture on {network.ssid} ({network.bssid})...", phase="ATTACK")
        
        # Get attack timeout from params
        timeout = self.controller.attack_params.wpa_timeout
        
        # Run attack
        success, capture_file = self.controller.capture_wpa_handshake(
            network.bssid, 
            network.channel, 
            timeout
        )
        
        if success:
            self.log(f"WPA handshake captured successfully: {capture_file}", success=True, phase="ATTACK")
            
            # Add to network details
            network.vulnerabilities.append("WPA Handshake Captured")
            
            # Show success message
            self.root.after(0, lambda: messagebox.showinfo(
                "WPA Attack Successful",
                f"Successfully captured WPA handshake for {network.ssid}\n\n"
                f"Capture file: {capture_file}\n\n"
                "You can now attempt to crack the password using a wordlist."
            ))
        else:
            self.log(f"WPA handshake capture failed", error=True, phase="ATTACK")
    
    def _run_wep_attack(self, network: NetworkTarget):
        """Run WEP IV collection"""
        self.log(f"Starting WEP IV collection on {network.ssid} ({network.bssid})...", phase="ATTACK")
        
        # Get attack timeout from params
        timeout = self.controller.attack_params.wep_timeout
        
        # Run attack
        success, capture_file = self.controller.collect_wep_ivs(
            network.bssid, 
            network.channel, 
            timeout
        )
        
        if success:
            self.log(f"WEP IVs collected successfully: {capture_file}", success=True, phase="ATTACK")
            
            # Add to network details
            network.vulnerabilities.append("WEP Encryption (Insecure)")
            
            # Show success message
            self.root.after(0, lambda: messagebox.showinfo(
                "WEP Attack Successful",
                f"Successfully collected WEP IVs for {network.ssid}\n\n"
                f"Capture file: {capture_file}\n\n"
                "You can now attempt to crack the WEP key using aircrack-ng."
            ))
        else:
            self.log(f"WEP IV collection failed", error=True, phase="ATTACK")
    
    def _run_pmkid_attack(self, network: NetworkTarget):
        """Run PMKID attack"""
        self.log(f"Starting PMKID attack on {network.ssid} ({network.bssid})...", phase="ATTACK")
        
        # Get attack timeout from params
        timeout = self.controller.attack_params.pmkid_timeout
        
        # Run attack
        success, capture_file = self.controller.perform_pmkid_attack(
            network.bssid, 
            timeout
        )
        
        if success:
            self.log(f"PMKID captured successfully: {capture_file}", success=True, phase="ATTACK")
            
            # Add to network details
            network.vulnerabilities.append("PMKID Vulnerable")
            
            # Show success message
            self.root.after(0, lambda: messagebox.showinfo(
                "PMKID Attack Successful",
                f"Successfully captured PMKID for {network.ssid}\n\n"
                f"Capture file: {capture_file}\n\n"
                "You can now attempt to crack the password using hashcat."
            ))
        else:
            self.log(f"PMKID attack failed", error=True, phase="ATTACK")
    
    def _run_default_creds_attack(self, network: NetworkTarget):
        """Check for default credentials"""
        self.log(f"Checking for default credentials on {network.ssid} ({network.bssid})...", phase="ATTACK")
        
        # Run attack
        success, creds = self.controller.check_default_credentials(network.bssid)
        
        if success and creds:
            self.log(f"Default credentials found! {len(creds)} credential sets discovered.", success=True, phase="ATTACK")
            
            # Add to network details
            network.vulnerabilities.append("Default Credentials")
            network.credentials["default"] = creds
            
            # Format credentials for display
            creds_str = "\n".join([f"Username: {c['username']}, Password: {c['password']}" for c in creds])
            
            # Show success message
            self.root.after(0, lambda: messagebox.showinfo(
                "Default Credentials Found",
                f"Found default credentials for {network.ssid}\n\n"
                f"{creds_str}"
            ))
        else:
            self.log(f"No default credentials found", phase="ATTACK")
    
    def _run_deauth_attack(self, network: NetworkTarget):
        """Run deauthentication attack"""
        self.log(f"Starting deauthentication attack on {network.ssid} ({network.bssid})...", phase="ATTACK")
        
        # Get deauth packet count from params
        count = self.controller.attack_params.deauth_packets
        
        # Run attack
        success = self.controller.perform_deauth_attack(network.bssid, None, count)
        
        if success:
            self.log(f"Deauthentication attack completed successfully", success=True, phase="ATTACK")
        else:
            self.log(f"Deauthentication attack failed", error=True, phase="ATTACK")
    
    def _run_evil_twin_attack(self, network: NetworkTarget):
        """Run Evil Twin attack"""
        self.log(f"Starting Evil Twin attack for {network.ssid} ({network.bssid})...", phase="ATTACK")
        
        # Get template type from params
        template_type = self.controller.attack_params.evil_twin_template_type
        
        # Run attack
        success = self.controller.launch_evil_twin_attack(
            network.bssid,
            network.ssid,
            network.channel,
            template_type
        )
        
        if success:
            self.log(f"Evil Twin attack started successfully", success=True, phase="ATTACK")
            
            # Show success message
            self.root.after(0, lambda: messagebox.showinfo(
                "Evil Twin Attack Started",
                f"Evil Twin attack for {network.ssid} started successfully.\n\n"
                "The fake AP is now active and waiting for connections.\n"
                "Any captured credentials will be displayed in the console."
            ))
        else:
            self.log(f"Evil Twin attack failed to start", error=True, phase="ATTACK")
    
    def show_network_details(self):
        """Show detailed network information dialog"""
        if not self.selected_network:
            return
            
        # Create dialog
        create_network_detail_dialog(self.root, self.selected_network, self.dark_mode, self.log)
    
    def show_advanced_options(self):
        """Show advanced options dialog"""
        # Create dialog
        create_advanced_dialog(self.root, self.controller, self.dark_mode, self.log)
    
    def show_attack_all_dialog(self):
        """Show dialog for attacking all networks"""
        if not self.networks:
            messagebox.showerror("Error", "No networks found")
            return
            
        # Sort networks by signal strength
        sorted_networks = sorted(self.networks, key=lambda x: x.signal_strength, reverse=True)
        
        # Create dialog
        create_attack_all_dialog(self.root, sorted_networks, self.controller, self.dark_mode, self.log)
    
    def clear_results(self):
        """Clear scan results"""
        # Clear network list
        self.clear_network_tree()
        
        # Clear details
        self.clear_details()
        
        # Reset state
        self.selected_network = None
        self.networks = []
        self.attack_btn.config(state=tk.DISABLED)
        self.test_all_btn.config(state=tk.DISABLED)
        
        self.log("Scan results cleared")
    
    def clear_console(self):
        """Clear console output"""
        self.console.delete(1.0, tk.END)
        self.log("Console cleared")
    
    def save_console(self):
        """Save console output to file"""
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Select file
        filename = filedialog.asksaveasfilename(
            initialfile=f"networkpentestpro_log_{timestamp}.txt",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if not filename:
            return
            
        try:
            # Save console content
            with open(filename, 'w') as f:
                f.write(self.console.get(1.0, tk.END))
                
            self.log(f"Console output saved to: {filename}", success=True)
        except Exception as e:
            self.log(f"Error saving console output: {str(e)}", error=True)
    
    def generate_report(self):
        """Generate penetration testing report"""
        if not self.networks:
            messagebox.showerror("Error", "No scan results available")
            return
            
        # Show report configuration dialog
        create_report_config_dialog(self.root, self.networks, self.report_generator, self.dark_mode, self.log)
    
    def save_config(self):
        """Save current configuration"""
        # Get current configuration
        config = {
            'interface': self.interface_var.get(),
            'scan_time': self.scan_time_var.get(),
            'channel': self.channel_var.get(),
            'theme': 'dark' if self.dark_mode else 'light',
            'attack_params': self.controller.attack_params.to_dict()
        }
        
        # Save configuration
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                 "config", "config.json")
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            # Save config
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
                
            self.log(f"Configuration saved to: {config_path}", success=True)
        except Exception as e:
            self.log(f"Error saving configuration: {str(e)}", error=True)
    
    def load_config(self):
        """Load configuration from file"""
        # Get config path
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                 "config", "config.json")
        
        if not os.path.exists(config_path):
            self.log("No saved configuration found", warning=True)
            return
            
        try:
            # Load config
            with open(config_path, 'r') as f:
                config = json.load(f)
                
            # Update interface if available
            if 'interface' in config and config['interface'] in self.interface_combo['values']:
                self.interface_var.set(config['interface'])
                self.on_interface_changed(None)
                
            # Update scan time
            if 'scan_time' in config:
                self.scan_time_var.set(config['scan_time'])
                
            # Update channel
            if 'channel' in config:
                self.channel_var.set(config['channel'])
                
            # Update theme
            if 'theme' in config:
                self.set_theme(config['theme'])
                
            # Update attack parameters
            if 'attack_params' in config:
                for key, value in config['attack_params'].items():
                    if hasattr(self.controller.attack_params, key):
                        setattr(self.controller.attack_params, key, value)
                
            self.log("Configuration loaded", success=True)
        except Exception as e:
            self.log(f"Error loading configuration: {str(e)}", error=True)
    
    def set_theme(self, theme: str):
        """Set application theme"""
        self.dark_mode = theme == 'dark'
        self.theme_btn.config(text="🌙" if self.dark_mode else "☀️")
        self.apply_theme()
    
    def toggle_theme(self):
        """Toggle between dark and light mode"""
        self.dark_mode = not self.dark_mode
        self.theme_btn.config(text="🌙" if self.dark_mode else "☀️")
        self.apply_theme()
    
    def apply_theme(self):
        """Apply current theme to UI elements"""
        # Theme colors
        if self.dark_mode:
            bg_color = "#2d2d2d"
            fg_color = "#e0e0e0"
            select_bg = "#0066cc"
            highlight_bg = "#444444"
            console_bg = "#1e1e1e"
            console_fg = "#e0e0e0"
            tree_bg = "#333333"
            tree_fg = "#ffffff"
            entry_bg = "#333333"
            entry_fg = "#ffffff"
            button_bg = "#444444"
            button_fg = "#ffffff"
        else:
            bg_color = "#f0f0f0"
            fg_color = "#000000"
            select_bg = "#99ccff"
            highlight_bg = "#e0e0e0"
            console_bg = "#ffffff"
            console_fg = "#000000"
            tree_bg = "#ffffff"
            tree_fg = "#000000"
            entry_bg = "#ffffff"
            entry_fg = "#000000"
            button_bg = "#e0e0e0"
            button_fg = "#000000"
        
        # Configure styles
        self.style.configure("TFrame", background=bg_color)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        self.style.configure("TButton", background=button_bg, foreground=button_fg)
        self.style.configure("TCheckbutton", background=bg_color, foreground=fg_color)
        self.style.configure("TRadiobutton", background=bg_color, foreground=fg_color)
        self.style.configure("TLabelframe", background=bg_color, foreground=fg_color)
        self.style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
        self.style.configure("TNotebook", background=bg_color, foreground=fg_color)
        self.style.configure("TNotebook.Tab", background=button_bg, foreground=button_fg)
        
        # Configure treeview colors
        self.style.configure("Treeview", 
                          background=tree_bg, 
                          foreground=tree_fg,
                          fieldbackground=tree_bg)
        self.style.map("Treeview", 
                     background=[('selected', select_bg)],
                     foreground=[('selected', '#ffffff')])
        
        # Update console colors
        self.console.config(background=console_bg, foreground=console_fg)
        
        # Update detail canvas
        self.detail_canvas.config(background=bg_color)
        
        # Update all frames
        for widget in self.root.winfo_children():
            if isinstance(widget, ttk.Frame) or isinstance(widget, ttk.LabelFrame):
                widget.config(style="TFrame")
        
        # Update menu colors
        self.menu_bar.config(background=bg_color, foreground=fg_color)
        
        # Save theme in config
        self.config['theme'] = 'dark' if self.dark_mode else 'light'
    
    def check_prerequisites(self):
        """Check for required prerequisites"""
        missing_tools = []
        
        # Tools to check
        tools = [
            "aircrack-ng",
            "airodump-ng",
            "aireplay-ng",
            "airmon-ng",
            "reaver",
            "wash",
            "hcxdumptool",
            "hcxpcapngtool"
        ]
        
        # Skip check in development mode
        if self.dev_mode:
            self.log("Development mode: Skipping prerequisite check", phase="HARDWARE")
            return
        
        # Check each tool
        for tool in tools:
            if shutil.which(tool) is None:
                missing_tools.append(tool)
        
        if missing_tools:
            self.log(f"Missing required tools: {', '.join(missing_tools)}", warning=True, phase="HARDWARE")
            self.log("Some functionality may be limited", warning=True, phase="HARDWARE")
            
            # Show warning message
            message = (
                f"The following tools are missing:\n\n"
                f"{', '.join(missing_tools)}\n\n"
                f"Some functionality may be limited. Install missing tools with:\n\n"
                f"sudo apt-get install aircrack-ng reaver hcxtools"
            )
            
            self.root.after(1000, lambda: messagebox.showwarning("Missing Tools", message))
        else:
            self.log("All required tools are installed", success=True, phase="HARDWARE")
    
    def show_help(self):
        """Show help dialog"""
        # Help content
        help_text = """
NetworkPentestPro - Advanced Wireless Security Testing Tool

IMPORTANT: Only use this tool on networks you own or have explicit permission to test!

Basic Usage:
1. Select a wireless interface from the dropdown
2. Click "Start Scan" to discover nearby networks
3. Select a network from the list to view details
4. Use the "Attack" button or right-click menu to test security

Attack Types:
- WPS Attack: Tests for vulnerable WPS implementation
- WPA Handshake: Captures 4-way handshake for offline cracking
- WEP Attack: Collects IVs for WEP key recovery
- PMKID Attack: Attempts to capture PMKID without client
- Default Credentials: Checks for default router passwords
- Deauth Clients: Sends deauthentication packets
- Evil Twin: Creates fake AP for credential harvesting

For more detailed information, please refer to the documentation.
"""
        
        # Create dialog
        help_dialog = tk.Toplevel(self.root)
        help_dialog.title("NetworkPentestPro Help")
        help_dialog.geometry("600x500")
        help_dialog.transient(self.root)
        help_dialog.grab_set()
        
        # Apply theme
        help_dialog.configure(background="#2d2d2d" if self.dark_mode else "#f0f0f0")
        
        # Content frame
        content_frame = ttk.Frame(help_dialog)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Help text
        help_text_widget = ScrolledText(content_frame, 
                                      wrap=tk.WORD,
                                      background="#2d2d2d" if self.dark_mode else "#ffffff",
                                      foreground="#e0e0e0" if self.dark_mode else "#000000",
                                      font=("Helvetica", 11))
        help_text_widget.pack(fill=tk.BOTH, expand=True)
        help_text_widget.insert(tk.END, help_text)
        help_text_widget.config(state=tk.DISABLED)
        
        # Close button
        close_btn = ttk.Button(help_dialog, text="Close", command=help_dialog.destroy)
        close_btn.pack(pady=10)
    
    def show_about(self):
        """Show about dialog"""
        # About content
        about_text = """
NetworkPentestPro v3.0
Advanced Wireless Security Testing Tool

This tool is designed for security professionals to perform 
authorized security assessments of wireless networks.

Features:
• Real-time network scanning and detection
• Multiple attack vectors: WPS, WPA, WEP, PMKID
• Default credential testing
• Evil Twin attack capabilities
• Comprehensive reporting

WARNING: Using this tool against networks without explicit 
permission is illegal and unethical.

Copyright © 2023
"""
        
        # Create dialog
        about_dialog = tk.Toplevel(self.root)
        about_dialog.title("About NetworkPentestPro")
        about_dialog.geometry("400x450")
        about_dialog.transient(self.root)
        about_dialog.grab_set()
        
        # Apply theme
        about_dialog.configure(background="#2d2d2d" if self.dark_mode else "#f0f0f0")
        
        # Content frame
        content_frame = ttk.Frame(about_dialog)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Logo
        try:
            logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                   "static", "icons", "logo.svg")
            if os.path.exists(logo_path):
                logo_img = tk.PhotoImage(file=logo_path)
                logo_label = ttk.Label(content_frame, image=logo_img)
                logo_label.image = logo_img
                logo_label.pack(pady=10)
        except Exception:
            # If logo can't be loaded, show text instead
            logo_label = ttk.Label(content_frame, 
                                 text="NetworkPentestPro",
                                 font=("Helvetica", 16, "bold"))
            logo_label.pack(pady=10)
        
        # About text
        about_text_widget = ScrolledText(content_frame, 
                                      wrap=tk.WORD,
                                      height=15,
                                      background="#2d2d2d" if self.dark_mode else "#ffffff",
                                      foreground="#e0e0e0" if self.dark_mode else "#000000",
                                      font=("Helvetica", 11))
        about_text_widget.pack(fill=tk.BOTH, expand=True)
        about_text_widget.insert(tk.END, about_text)
        about_text_widget.config(state=tk.DISABLED)
        
        # Close button
        close_btn = ttk.Button(about_dialog, text="Close", command=about_dialog.destroy)
        close_btn.pack(pady=10)
    
    def on_close(self):
        """Handle window close event"""
        # Check if scan or attack is running
        if self.scanning or self.attacking:
            if not messagebox.askyesno("Confirm Exit", 
                                     "A scan or attack is in progress. Are you sure you want to exit?"):
                return
                
        # Stop any ongoing operations
        if self.scanning:
            self.stop_scan()
            
        if hasattr(self.controller, 'stop_event'):
            self.controller.stop_event.set()
            
        # Save config before exit
        self.save_config()
        
        # Close window
        self.root.destroy()
