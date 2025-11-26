#!/usr/bin/env python3
"""
Dialog Utilities for WiFi Penetration Testing Tool
Provides utility functions for dialog windows and maximization
"""

import tkinter as tk
from tkinter import ttk

def create_maximize_button(parent, window):
    """Create a maximize/restore button for a dialog window
    
    Args:
        parent: Parent widget for the button
        window: Dialog window to maximize/restore
        
    Returns:
        Button widget
    """
    # Create a button with toggle functionality
    def toggle_maximize():
        # Check current state 
        if hasattr(window, 'zoomed') and window.zoomed:
            # Restore window
            try:
                window.state('normal')
            except Exception:
                # Fallback for Linux/macOS
                window.geometry("800x600+50+50")
            window.zoomed = False
            max_btn.config(text="□")
        else:
            # Maximize window - platform compatible
            try:
                window.state('zoomed')  # Windows
            except Exception:
                # For Linux/macOS use maximize geometry
                width = window.winfo_screenwidth() - 50
                height = window.winfo_screenheight() - 50
                window.geometry(f"{width}x{height}+25+25")
            window.zoomed = True
            max_btn.config(text="■")
            
    # Create button with appropriate icon
    max_btn = ttk.Button(parent, text="□", width=2, command=toggle_maximize)
    
    # Set initial state attribute
    window.zoomed = False
    
    return max_btn

def configure_dialog_for_display(dialog):
    """Configure a dialog window for proper display
    
    This ensures dialogs are properly sized and centered on the screen.
    Works on all platforms (Windows, Linux, macOS).
    
    Args:
        dialog: Dialog window to configure
    """
    # Make sure the dialog is usable on different screen sizes
    screen_width = dialog.winfo_screenwidth()
    screen_height = dialog.winfo_screenheight()
    
    # Get current dialog size
    dialog_width = dialog.winfo_width()
    dialog_height = dialog.winfo_height()
    
    # Set maximum size
    max_width = min(screen_width - 100, 1200)
    max_height = min(screen_height - 100, 800)
    
    # Adjust size if needed
    if dialog_width > max_width or dialog_height > max_height:
        new_width = min(dialog_width, max_width)
        new_height = min(dialog_height, max_height)
        dialog.geometry(f"{new_width}x{new_height}")
    
    # Center on screen
    x = (screen_width - dialog.winfo_width()) // 2
    y = (screen_height - dialog.winfo_height()) // 2
    dialog.geometry(f"+{x}+{y}")
    
    # Make sure to update
    dialog.update_idletasks()
    
    # Set custom attribute for tracking maximized state
    dialog.zoomed = False

def create_advanced_dialog(self):
    """Create a simplified advanced options dialog that will display properly"""
    # Create dialog window
    dialog = tk.Toplevel(self.root)
    dialog.title("Advanced Options")
    dialog.geometry("800x600")
    dialog.transient(self.root)
    dialog.grab_set()
    
    # Apply theme
    bg = "#2d2d2d" if self.dark_mode else "#f0f0f0"
    fg = "#ffffff" if self.dark_mode else "#000000"
    dialog.configure(bg=bg)
    
    # Header with maximize button
    header_frame = tk.Frame(dialog, bg=bg)
    header_frame.pack(fill=tk.X, padx=10, pady=10)
    
    # Title
    title_label = tk.Label(
        header_frame,
        text="Advanced Configuration",
        font=("Helvetica", 14, "bold"),
        bg=bg, fg=fg
    )
    title_label.pack(side=tk.LEFT, padx=10)
    
    # Maximize button
    def toggle_maximize():
        is_zoomed = dialog.state() == 'zoomed'
        dialog.state('normal' if is_zoomed else 'zoomed')
        max_btn.config(text="□" if is_zoomed else "■")
        
    max_btn = ttk.Button(header_frame, text="□", width=2, command=toggle_maximize)
    max_btn.pack(side=tk.RIGHT, padx=5)
    
    # Create notebook with tabs
    notebook = ttk.Notebook(dialog)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Create tabs
    wpa_tab = ttk.Frame(notebook)
    wps_tab = ttk.Frame(notebook)
    wep_tab = ttk.Frame(notebook)
    default_creds_tab = ttk.Frame(notebook)
    scan_tab = ttk.Frame(notebook)
    interface_tab = ttk.Frame(notebook)
    settings_tab = ttk.Frame(notebook)
    about_tab = ttk.Frame(notebook)
    
    # Add tabs to notebook
    notebook.add(wpa_tab, text="WPA Attack")
    notebook.add(wps_tab, text="WPS Attack")
    notebook.add(wep_tab, text="WEP Attack")
    notebook.add(default_creds_tab, text="Default Credentials")
    notebook.add(scan_tab, text="Scanning")
    notebook.add(interface_tab, text="Interface Management")
    notebook.add(settings_tab, text="General Settings")
    notebook.add(about_tab, text="About")
    
    # Setup tab content
    try:
        # Access the original tab setup methods
        self.setup_wpa_tab(wpa_tab)
        self.setup_wps_tab(wps_tab)
        self.setup_wep_tab(wep_tab)
        self.setup_default_creds_tab(default_creds_tab)
        self.setup_scan_tab(scan_tab)
        self.setup_interface_tab(interface_tab)
        self.setup_settings_tab(settings_tab)
        self.setup_about_tab(about_tab)
    except Exception as e:
        # Add error message to console log
        self.log(f"Error setting up advanced tabs: {str(e)}", error=True)
        
        # Add a simple message in each tab
        for tab, name in [
            (wpa_tab, "WPA Attack"), 
            (wps_tab, "WPS Attack"),
            (wep_tab, "WEP Attack"),
            (default_creds_tab, "Default Credentials"),
            (scan_tab, "Scanning"),
            (interface_tab, "Interface Management"),
            (settings_tab, "Settings"),
            (about_tab, "About")
        ]:
            frame = tk.Frame(tab, bg=bg, padx=20, pady=20)
            frame.pack(fill=tk.BOTH, expand=True)
            
            label = tk.Label(
                frame, 
                text=f"{name} Settings", 
                font=("Helvetica", 12, "bold"),
                bg=bg, fg=fg
            )
            label.pack(pady=10)
            
            message = tk.Label(
                frame,
                text="Configure settings for this attack type.",
                bg=bg, fg=fg
            )
            message.pack(pady=10)
    
    # Button frame
    button_frame = tk.Frame(dialog, bg=bg)
    button_frame.pack(fill=tk.X, padx=10, pady=10)
    
    # Save button
    save_btn = ttk.Button(
        button_frame,
        text="Save Settings",
        command=lambda: self.save_advanced_settings(dialog)
    )
    save_btn.pack(side=tk.LEFT, padx=5)
    
    # Close button
    close_btn = ttk.Button(
        button_frame,
        text="Close",
        command=dialog.destroy
    )
    close_btn.pack(side=tk.RIGHT, padx=5)
    
    # Make sure it opens maximized
    dialog.update_idletasks()
    dialog.state('zoomed')
    
    return dialog

def create_attack_all_dialog(self, sorted_networks):
    """Create a simplified Auto Attack Sequencer dialog that will display properly"""
    # Create dialog window
    dialog = tk.Toplevel(self.root)
    dialog.title("Auto Attack Sequencer")
    dialog.geometry("800x600")
    dialog.transient(self.root)
    dialog.grab_set()
    
    # Apply theme
    bg = "#2d2d2d" if self.dark_mode else "#f0f0f0"
    fg = "#ffffff" if self.dark_mode else "#000000"
    dialog.configure(bg=bg)
    
    # Header with maximize button
    header_frame = tk.Frame(dialog, bg=bg)
    header_frame.pack(fill=tk.X, padx=10, pady=10)
    
    # Title
    title_label = tk.Label(
        header_frame,
        text="Automated Attack Sequence",
        font=("Helvetica", 14, "bold"),
        bg=bg, fg=fg
    )
    title_label.pack(side=tk.LEFT, padx=10)
    
    # Maximize button
    def toggle_maximize():
        is_zoomed = dialog.state() == 'zoomed'
        dialog.state('normal' if is_zoomed else 'zoomed')
        max_btn.config(text="□" if is_zoomed else "■")
        
    max_btn = ttk.Button(header_frame, text="□", width=2, command=toggle_maximize)
    max_btn.pack(side=tk.RIGHT, padx=5)
    
    # Description
    desc_frame = tk.Frame(dialog, bg=bg)
    desc_frame.pack(fill=tk.X, padx=20, pady=10)
    
    network_count = len(sorted_networks)
    description = tk.Label(
        desc_frame,
        text=f"This will test {network_count} network{'s' if network_count != 1 else ''} in order of signal strength.",
        wraplength=700,
        bg=bg, fg=fg
    )
    description.pack(anchor=tk.W)
    
    # Network list
    list_frame = tk.LabelFrame(dialog, text="Networks to Test", bg=bg, fg=fg)
    list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    # Create treeview
    columns = ("ssid", "bssid", "security", "signal")
    tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
    
    # Configure columns
    tree.heading("ssid", text="Network Name")
    tree.heading("bssid", text="BSSID")
    tree.heading("security", text="Security")
    tree.heading("signal", text="Signal")
    
    tree.column("ssid", width=150)
    tree.column("bssid", width=150)
    tree.column("security", width=120)
    tree.column("signal", width=70)
    
    # Scrollbar
    scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    
    # Place treeview and scrollbar
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Fill treeview
    for net in sorted_networks:
        # Format security
        security = ", ".join(net.security) if net.security else "Open"
        
        # Add to treeview
        tree.insert("", tk.END, values=(
            net.ssid,
            net.bssid,
            security,
            f"{getattr(net, 'signal_strength', 0)}%" if hasattr(net, 'signal_strength') else "?"
        ))
    
    # Options
    options_frame = tk.LabelFrame(dialog, text="Attack Options", bg=bg, fg=fg)
    options_frame.pack(fill=tk.X, padx=20, pady=10)
    
    # Create columns for options
    opts_frame = tk.Frame(options_frame, bg=bg)
    opts_frame.pack(fill=tk.X, padx=10, pady=10)
    
    left_col = tk.Frame(opts_frame, bg=bg)
    left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    right_col = tk.Frame(opts_frame, bg=bg)
    right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
    
    # Attack checkboxes
    def_creds_var = tk.BooleanVar(value=True)
    wps_var = tk.BooleanVar(value=True)
    wpa_var = tk.BooleanVar(value=True)
    wep_var = tk.BooleanVar(value=True)
    port_scan_var = tk.BooleanVar(value=True)
    
    # Left column
    def_creds_check = tk.Checkbutton(
        left_col,
        text="Default Credentials Check",
        variable=def_creds_var,
        bg=bg, fg=fg
    )
    def_creds_check.pack(anchor=tk.W, pady=2)
    
    wps_check = tk.Checkbutton(
        left_col,
        text="WPS PIN Attack",
        variable=wps_var,
        bg=bg, fg=fg
    )
    wps_check.pack(anchor=tk.W, pady=2)
    
    wpa_check = tk.Checkbutton(
        left_col,
        text="WPA Handshake Capture",
        variable=wpa_var,
        bg=bg, fg=fg
    )
    wpa_check.pack(anchor=tk.W, pady=2)
    
    wep_check = tk.Checkbutton(
        left_col,
        text="WEP Attack",
        variable=wep_var,
        bg=bg, fg=fg
    )
    wep_check.pack(anchor=tk.W, pady=2)
    
    # Right column
    # PMKID and Evil Twin modules have been removed
    
    port_scan_check = tk.Checkbutton(
        right_col,
        text="Port Scanning",
        variable=port_scan_var,
        bg=bg, fg=fg
    )
    port_scan_check.pack(anchor=tk.W, pady=2)
    
    # Timeout
    timeout_frame = tk.Frame(options_frame, bg=bg)
    timeout_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
    
    timeout_label = tk.Label(
        timeout_frame,
        text="Timeout per attack (seconds):",
        bg=bg, fg=fg
    )
    timeout_label.pack(side=tk.LEFT, padx=(0, 5))
    
    timeout_var = tk.IntVar(value=60)
    timeout_entry = ttk.Spinbox(
        timeout_frame,
        from_=10,
        to=300,
        textvariable=timeout_var,
        width=5
    )
    timeout_entry.pack(side=tk.LEFT)
    
    # Button frame
    button_frame = tk.Frame(dialog, bg=bg)
    button_frame.pack(fill=tk.X, padx=20, pady=20)
    
    # Warning
    warning_label = tk.Label(
        button_frame,
        text="⚠️ Only use against networks you own or have permission to test!",
        fg="#FF0000",
        bg=bg
    )
    warning_label.pack(side=tk.LEFT)
    
    # Start button
    start_btn = ttk.Button(
        button_frame,
        text="Start Assessment",
        command=lambda: self.run_sequential_tests(
            sorted_networks,
            {
                "DEFAULT_CREDS": def_creds_var.get(),
                "WPS": wps_var.get(),
                "WPA": wpa_var.get(),
                "WEP": wep_var.get(),
                "PORT_SCAN": port_scan_var.get()
            },
            timeout_var.get(),
            dialog
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
    
    # Make sure it opens maximized
    dialog.update_idletasks()
    dialog.state('zoomed')
    
    return dialog
