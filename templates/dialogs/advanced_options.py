#!/usr/bin/env python3
"""
Advanced Options Dialog for NetworkPentestPro
Allows configuration of attack parameters and advanced settings
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import json
from typing import Callable, Dict, Any, Optional

def create_advanced_dialog(root: tk.Tk, controller, dark_mode: bool = True, log_callback: Callable = None):
    """
    Create and display advanced options dialog
    
    Args:
        root: Parent window
        controller: Controller instance with attack parameters
        dark_mode: Whether to use dark mode theme
        log_callback: Callback function for logging
    """
    # Create dialog window
    dialog = tk.Toplevel(root)
    dialog.title("Advanced Options")
    dialog.geometry("800x600")
    dialog.transient(root)
    dialog.grab_set()
    
    # Configure dialog for display
    configure_dialog_for_display(dialog)
    
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    dialog.configure(bg=bg)
    
    # Header with maximize button
    header_frame = ttk.Frame(dialog)
    header_frame.pack(fill=tk.X, padx=10, pady=10)
    
    # Title
    title_label = ttk.Label(
        header_frame,
        text="Advanced Configuration",
        font=("Helvetica", 14, "bold")
    )
    title_label.pack(side=tk.LEFT, padx=10)
    
    # Add maximize button
    max_btn = create_maximize_button(header_frame, dialog)
    max_btn.pack(side=tk.RIGHT, padx=5)
    
    # Create notebook with tabs
    notebook = ttk.Notebook(dialog)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Create tabs
    wpa_tab = ttk.Frame(notebook)
    wps_tab = ttk.Frame(notebook)
    wep_tab = ttk.Frame(notebook)
    pmkid_tab = ttk.Frame(notebook)
    evil_twin_tab = ttk.Frame(notebook)
    default_creds_tab = ttk.Frame(notebook)
    scan_tab = ttk.Frame(notebook)
    interface_tab = ttk.Frame(notebook)
    settings_tab = ttk.Frame(notebook)
    
    # Add tabs to notebook
    notebook.add(wpa_tab, text="WPA Attack")
    notebook.add(wps_tab, text="WPS Attack")
    notebook.add(wep_tab, text="WEP Attack")
    notebook.add(pmkid_tab, text="PMKID Attack")
    notebook.add(evil_twin_tab, text="Evil Twin")
    notebook.add(default_creds_tab, text="Default Credentials")
    notebook.add(scan_tab, text="Scanning")
    notebook.add(interface_tab, text="Interface Management")
    notebook.add(settings_tab, text="General Settings")
    
    # Setup tab content
    setup_wpa_tab(wpa_tab, controller, dark_mode)
    setup_wps_tab(wps_tab, controller, dark_mode)
    setup_wep_tab(wep_tab, controller, dark_mode)
    setup_pmkid_tab(pmkid_tab, controller, dark_mode)
    setup_evil_twin_tab(evil_twin_tab, controller, dark_mode)
    setup_default_creds_tab(default_creds_tab, controller, dark_mode)
    setup_scan_tab(scan_tab, controller, dark_mode)
    setup_interface_tab(interface_tab, controller, dark_mode)
    setup_settings_tab(settings_tab, controller, dark_mode)
    
    # Button frame
    button_frame = ttk.Frame(dialog)
    button_frame.pack(fill=tk.X, padx=10, pady=10)
    
    # Save button
    save_btn = ttk.Button(
        button_frame,
        text="Save Settings",
        command=lambda: save_advanced_settings(dialog, controller, log_callback)
    )
    save_btn.pack(side=tk.LEFT, padx=5)
    
    # Close button
    close_btn = ttk.Button(
        button_frame,
        text="Close",
        command=dialog.destroy
    )
    close_btn.pack(side=tk.RIGHT, padx=5)
    
    return dialog

def setup_wpa_tab(tab: ttk.Frame, controller, dark_mode: bool):
    """Setup WPA attack settings tab"""
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    
    # Create frame with padding
    frame = ttk.Frame(tab, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # WPA Timeout
    ttk.Label(frame, text="Handshake Capture Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    
    wpa_timeout_var = tk.IntVar(value=controller.attack_params.wpa_timeout)
    wpa_timeout_spin = ttk.Spinbox(
        frame, 
        from_=10, 
        to=300, 
        textvariable=wpa_timeout_var, 
        width=5
    )
    wpa_timeout_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Deauth Packet Count
    ttk.Label(frame, text="Deauthentication Packet Count:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    
    deauth_count_var = tk.IntVar(value=controller.attack_params.deauth_packets)
    deauth_count_spin = ttk.Spinbox(
        frame, 
        from_=1, 
        to=50, 
        textvariable=deauth_count_var, 
        width=5
    )
    deauth_count_spin.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
    
    # WPA Wordlist
    ttk.Label(frame, text="WPA Wordlist:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
    
    wpa_wordlist_var = tk.StringVar(value=controller.attack_params.wpa_wordlist)
    wpa_wordlist_entry = ttk.Entry(
        frame,
        textvariable=wpa_wordlist_var,
        width=40
    )
    wpa_wordlist_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Browse button
    ttk.Button(
        frame,
        text="Browse",
        command=lambda: browse_file(wpa_wordlist_var)
    ).grid(row=2, column=2, sticky=tk.W, padx=5, pady=5)
    
    # Multi-burst Deauth option
    multi_deauth_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        frame,
        text="Use Multi-Burst Deauthentication (more aggressive)",
        variable=multi_deauth_var
    ).grid(row=3, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    # Target all clients option
    target_all_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Target All Clients (broadcast deauth)",
        variable=target_all_var
    ).grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    # Save references to variables for later retrieval
    tab.wpa_timeout_var = wpa_timeout_var
    tab.deauth_count_var = deauth_count_var
    tab.wpa_wordlist_var = wpa_wordlist_var
    tab.multi_deauth_var = multi_deauth_var
    tab.target_all_var = target_all_var

def setup_wps_tab(tab: ttk.Frame, controller, dark_mode: bool):
    """Setup WPS attack settings tab"""
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    
    # Create frame with padding
    frame = ttk.Frame(tab, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # WPS Timeout
    ttk.Label(frame, text="WPS Attack Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    
    wps_timeout_var = tk.IntVar(value=controller.attack_params.wps_timeout)
    wps_timeout_spin = ttk.Spinbox(
        frame, 
        from_=30, 
        to=600, 
        textvariable=wps_timeout_var, 
        width=5
    )
    wps_timeout_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    # WPS PIN Attempts
    ttk.Label(frame, text="PIN Attempts per Target:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    
    wps_attempts_var = tk.IntVar(value=controller.attack_params.wps_pin_attempts)
    wps_attempts_spin = ttk.Spinbox(
        frame, 
        from_=1, 
        to=20, 
        textvariable=wps_attempts_var, 
        width=5
    )
    wps_attempts_spin.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
    
    # WPS PIN Wordlist
    ttk.Label(frame, text="WPS PIN Wordlist:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
    
    wps_wordlist_var = tk.StringVar(value=controller.attack_params.wps_pin_wordlist)
    wps_wordlist_entry = ttk.Entry(
        frame,
        textvariable=wps_wordlist_var,
        width=40
    )
    wps_wordlist_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Browse button
    ttk.Button(
        frame,
        text="Browse",
        command=lambda: browse_file(wps_wordlist_var)
    ).grid(row=2, column=2, sticky=tk.W, padx=5, pady=5)
    
    # Delay between attempts
    ttk.Label(frame, text="Delay Between PIN Attempts (seconds):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
    
    pin_delay_var = tk.IntVar(value=2)
    pin_delay_spin = ttk.Spinbox(
        frame, 
        from_=0, 
        to=10, 
        textvariable=pin_delay_var, 
        width=5
    )
    pin_delay_spin.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Prioritize common PINs
    common_pins_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Prioritize Common/Default PINs",
        variable=common_pins_var
    ).grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    # Auto lockout detection
    lockout_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Auto-detect AP Lockout and Pause Attack",
        variable=lockout_var
    ).grid(row=5, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    # Save references to variables for later retrieval
    tab.wps_timeout_var = wps_timeout_var
    tab.wps_attempts_var = wps_attempts_var
    tab.wps_wordlist_var = wps_wordlist_var
    tab.pin_delay_var = pin_delay_var
    tab.common_pins_var = common_pins_var
    tab.lockout_var = lockout_var

def setup_wep_tab(tab: ttk.Frame, controller, dark_mode: bool):
    """Setup WEP attack settings tab"""
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    
    # Create frame with padding
    frame = ttk.Frame(tab, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # WEP Timeout
    ttk.Label(frame, text="WEP IV Collection Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    
    wep_timeout_var = tk.IntVar(value=controller.attack_params.wep_timeout)
    wep_timeout_spin = ttk.Spinbox(
        frame, 
        from_=60, 
        to=600, 
        textvariable=wep_timeout_var, 
        width=5
    )
    wep_timeout_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    # IV Goal
    ttk.Label(frame, text="IV Collection Goal:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    
    iv_goal_var = tk.IntVar(value=controller.attack_params.wep_iv_goal)
    iv_goal_spin = ttk.Spinbox(
        frame, 
        from_=5000, 
        to=100000, 
        textvariable=iv_goal_var, 
        width=8
    )
    iv_goal_spin.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Attack methods frame
    method_frame = ttk.LabelFrame(frame, text="WEP Attack Methods")
    method_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=10)
    
    # Attack method checkboxes
    arp_replay_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        method_frame,
        text="ARP Replay Attack",
        variable=arp_replay_var
    ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    
    frag_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        method_frame,
        text="Fragmentation Attack",
        variable=frag_var
    ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
    
    chop_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        method_frame,
        text="Chop-Chop Attack",
        variable=chop_var
    ).grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
    
    cafe_latte_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        method_frame,
        text="Cafe-Latte Attack",
        variable=cafe_latte_var
    ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
    
    p0841_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        method_frame,
        text="P0841 Attack",
        variable=p0841_var
    ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
    
    hirte_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        method_frame,
        text="Hirte Attack",
        variable=hirte_var
    ).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
    
    # Auto crack option
    auto_crack_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Automatically Attempt WEP Key Cracking After Collection",
        variable=auto_crack_var
    ).grid(row=3, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    # Save references to variables for later retrieval
    tab.wep_timeout_var = wep_timeout_var
    tab.iv_goal_var = iv_goal_var
    tab.arp_replay_var = arp_replay_var
    tab.frag_var = frag_var
    tab.chop_var = chop_var
    tab.cafe_latte_var = cafe_latte_var
    tab.p0841_var = p0841_var
    tab.hirte_var = hirte_var
    tab.auto_crack_var = auto_crack_var

def setup_pmkid_tab(tab: ttk.Frame, controller, dark_mode: bool):
    """Setup PMKID attack settings tab"""
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    
    # Create frame with padding
    frame = ttk.Frame(tab, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # PMKID Timeout
    ttk.Label(frame, text="PMKID Attack Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    
    pmkid_timeout_var = tk.IntVar(value=controller.attack_params.pmkid_timeout)
    pmkid_timeout_spin = ttk.Spinbox(
        frame, 
        from_=30, 
        to=300, 
        textvariable=pmkid_timeout_var, 
        width=5
    )
    pmkid_timeout_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Client association timing
    ttk.Label(frame, text="Association Wait Time (seconds):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    
    assoc_time_var = tk.IntVar(value=10)
    assoc_time_spin = ttk.Spinbox(
        frame, 
        from_=5, 
        to=30, 
        textvariable=assoc_time_var, 
        width=5
    )
    assoc_time_spin.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Attack Techniques frame
    technique_frame = ttk.LabelFrame(frame, text="PMKID Attack Techniques")
    technique_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=10)
    
    # Attack technique options
    direct_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        technique_frame,
        text="Direct Association",
        variable=direct_var
    ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    
    broadcast_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        technique_frame,
        text="Broadcast Approach",
        variable=broadcast_var
    ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
    
    targeted_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        technique_frame,
        text="Targeted Approach",
        variable=targeted_var
    ).grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
    
    # Auto convert option
    convert_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Auto-Convert PMKID to Hashcat Format",
        variable=convert_var
    ).grid(row=3, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    # Auto-attempt cracking
    crack_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        frame,
        text="Automatically Attempt Password Cracking After Capture",
        variable=crack_var
    ).grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    # Save references to variables for later retrieval
    tab.pmkid_timeout_var = pmkid_timeout_var
    tab.assoc_time_var = assoc_time_var
    tab.direct_var = direct_var
    tab.broadcast_var = broadcast_var
    tab.targeted_var = targeted_var
    tab.convert_var = convert_var
    tab.crack_var = crack_var

def setup_evil_twin_tab(tab: ttk.Frame, controller, dark_mode: bool):
    """Setup Evil Twin attack settings tab"""
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    
    # Create frame with padding
    frame = ttk.Frame(tab, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # Template selection
    ttk.Label(frame, text="Portal Template:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    
    template_var = tk.StringVar(value=controller.attack_params.evil_twin_template_type)
    template_combo = ttk.Combobox(
        frame,
        textvariable=template_var,
        values=["generic", "router", "isp", "social", "update"],
        width=15,
        state="readonly"
    )
    template_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Custom template option
    custom_var = tk.BooleanVar(value=controller.attack_params.use_custom_template)
    custom_check = ttk.Checkbutton(
        frame,
        text="Use Custom Template",
        variable=custom_var,
        command=lambda: toggle_custom_template(custom_var, template_path_entry, template_combo)
    )
    custom_check.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    
    # Custom template path
    template_path_var = tk.StringVar(value=controller.attack_params.evil_twin_template_path)
    template_path_entry = ttk.Entry(
        frame,
        textvariable=template_path_var,
        width=40,
        state="disabled"
    )
    template_path_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Browse button
    browse_btn = ttk.Button(
        frame,
        text="Browse",
        command=lambda: browse_file(template_path_var),
        state="disabled"
    )
    browse_btn.grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
    
    # Update states based on current value
    if custom_var.get():
        template_path_entry.config(state="normal")
        browse_btn.config(state="normal")
        template_combo.config(state="disabled")
    
    # Network Settings frame
    network_frame = ttk.LabelFrame(frame, text="Network Settings")
    network_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=10)
    
    # DHCP Settings
    ttk.Label(network_frame, text="DHCP IP Range:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    
    ip_range_var = tk.StringVar(value="192.168.1.2,192.168.1.100,12h")
    ip_range_entry = ttk.Entry(
        network_frame,
        textvariable=ip_range_var,
        width=30
    )
    ip_range_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Gateway IP
    ttk.Label(network_frame, text="Gateway IP:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    
    gateway_var = tk.StringVar(value="192.168.1.1")
    gateway_entry = ttk.Entry(
        network_frame,
        textvariable=gateway_var,
        width=15
    )
    gateway_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Web Server Port
    ttk.Label(network_frame, text="Web Server Port:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
    
    port_var = tk.IntVar(value=8080)
    port_spin = ttk.Spinbox(
        network_frame,
        from_=1024,
        to=65535,
        textvariable=port_var,
        width=7
    )
    port_spin.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Channel
    ttk.Label(network_frame, text="AP Channel:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
    
    channel_var = tk.StringVar(value="1")
    channel_combo = ttk.Combobox(
        network_frame,
        textvariable=channel_var,
        values=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"],
        width=5,
        state="readonly"
    )
    channel_combo.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Options frame
    options_frame = ttk.LabelFrame(frame, text="Attack Options")
    options_frame.grid(row=3, column=0, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=10)
    
    # Attack options
    captive_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        options_frame,
        text="Enable Captive Portal Detection",
        variable=captive_var
    ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    
    mitm_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        options_frame,
        text="Enable MITM Sniffing",
        variable=mitm_var
    ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
    
    ssl_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        options_frame,
        text="Enable SSL Strip",
        variable=ssl_var
    ).grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
    
    karma_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        options_frame,
        text="Enable KARMA Attack",
        variable=karma_var
    ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
    
    deauth_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        options_frame,
        text="Deauthenticate Clients from Real AP",
        variable=deauth_var
    ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
    
    internet_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        options_frame,
        text="Provide Internet Access After Capture",
        variable=internet_var
    ).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
    
    # Save references to variables for later retrieval
    tab.template_var = template_var
    tab.custom_var = custom_var
    tab.template_path_var = template_path_var
    tab.ip_range_var = ip_range_var
    tab.gateway_var = gateway_var
    tab.port_var = port_var
    tab.channel_var = channel_var
    tab.captive_var = captive_var
    tab.mitm_var = mitm_var
    tab.ssl_var = ssl_var
    tab.karma_var = karma_var
    tab.deauth_var = deauth_var
    tab.internet_var = internet_var

def setup_default_creds_tab(tab: ttk.Frame, controller, dark_mode: bool):
    """Setup Default Credentials attack settings tab"""
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    
    # Create frame with padding
    frame = ttk.Frame(tab, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # Default credentials wordlist
    ttk.Label(frame, text="Default Credentials Wordlist:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    
    creds_wordlist_var = tk.StringVar(value=controller.attack_params.default_creds_wordlist)
    creds_wordlist_entry = ttk.Entry(
        frame,
        textvariable=creds_wordlist_var,
        width=40
    )
    creds_wordlist_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Browse button
    ttk.Button(
        frame,
        text="Browse",
        command=lambda: browse_file(creds_wordlist_var)
    ).grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
    
    # Connection timeout
    ttk.Label(frame, text="Connection Timeout (seconds):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    
    conn_timeout_var = tk.IntVar(value=5)
    conn_timeout_spin = ttk.Spinbox(
        frame,
        from_=1,
        to=30,
        textvariable=conn_timeout_var,
        width=5
    )
    conn_timeout_spin.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Pause between attempts
    ttk.Label(frame, text="Pause Between Attempts (seconds):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
    
    pause_var = tk.DoubleVar(value=0.5)
    pause_spin = ttk.Spinbox(
        frame,
        from_=0.0,
        to=5.0,
        increment=0.1,
        textvariable=pause_var,
        width=5
    )
    pause_spin.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Target types frame
    target_frame = ttk.LabelFrame(frame, text="Target Types")
    target_frame.grid(row=3, column=0, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=10)
    
    # Target type checkboxes
    router_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        target_frame,
        text="Routers",
        variable=router_var
    ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    
    camera_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        target_frame,
        text="IP Cameras",
        variable=camera_var
    ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
    
    nvr_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        target_frame,
        text="NVRs/DVRs",
        variable=nvr_var
    ).grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
    
    iot_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        target_frame,
        text="IoT Devices",
        variable=iot_var
    ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
    
    ap_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        target_frame,
        text="Access Points",
        variable=ap_var
    ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
    
    nas_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        target_frame,
        text="NAS Devices",
        variable=nas_var
    ).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
    
    # Test options
    adaptive_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Use Adaptive Testing (Skip Unlikely Combinations)",
        variable=adaptive_var
    ).grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    vendor_prioritize_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Prioritize Vendor-Specific Credentials",
        variable=vendor_prioritize_var
    ).grid(row=5, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    stop_on_success_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Stop Testing Target After First Success",
        variable=stop_on_success_var
    ).grid(row=6, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
    
    # Save references to variables for later retrieval
    tab.creds_wordlist_var = creds_wordlist_var
    tab.conn_timeout_var = conn_timeout_var
    tab.pause_var = pause_var
    tab.router_var = router_var
    tab.camera_var = camera_var
    tab.nvr_var = nvr_var
    tab.iot_var = iot_var
    tab.ap_var = ap_var
    tab.nas_var = nas_var
    tab.adaptive_var = adaptive_var
    tab.vendor_prioritize_var = vendor_prioritize_var
    tab.stop_on_success_var = stop_on_success_var

def setup_scan_tab(tab: ttk.Frame, controller, dark_mode: bool):
    """Setup Scanning settings tab"""
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    
    # Create frame with padding
    frame = ttk.Frame(tab, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # Channel hop interval
    ttk.Label(frame, text="Channel Hopping Interval (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    
    hop_interval_var = tk.IntVar(value=controller.attack_params.channel_hop_interval)
    hop_interval_spin = ttk.Spinbox(
        frame,
        from_=1,
        to=10,
        textvariable=hop_interval_var,
        width=5
    )
    hop_interval_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Scan frequencies
    frequency_frame = ttk.LabelFrame(frame, text="Scan Frequencies")
    frequency_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=10)
    
    # Frequency options
    freq_2ghz_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frequency_frame,
        text="2.4 GHz (Channels 1-14)",
        variable=freq_2ghz_var
    ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    
    freq_5ghz_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        frequency_frame,
        text="5 GHz (All Channels)",
        variable=freq_5ghz_var
    ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
    
    # MAC vendor lookup
    vendor_lookup_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Enable MAC Vendor Lookup",
        variable=vendor_lookup_var
    ).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # GPS logging
    gps_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        frame,
        text="Enable GPS Logging (if device available)",
        variable=gps_var
    ).grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # Device type detection
    device_detection_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Enable Device Type Detection",
        variable=device_detection_var
    ).grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # Auto save scan results
    autosave_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Auto-Save Scan Results",
        variable=autosave_var
    ).grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # Auto save path
    ttk.Label(frame, text="Auto-Save Directory:").grid(row=6, column=0, sticky=tk.W, padx=5, pady=5)
    
    autosave_path_var = tk.StringVar(value="./scans")
    autosave_path_entry = ttk.Entry(
        frame,
        textvariable=autosave_path_var,
        width=30
    )
    autosave_path_entry.grid(row=6, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Save references to variables for later retrieval
    tab.hop_interval_var = hop_interval_var
    tab.freq_2ghz_var = freq_2ghz_var
    tab.freq_5ghz_var = freq_5ghz_var
    tab.vendor_lookup_var = vendor_lookup_var
    tab.gps_var = gps_var
    tab.device_detection_var = device_detection_var
    tab.autosave_var = autosave_var
    tab.autosave_path_var = autosave_path_var

def setup_interface_tab(tab: ttk.Frame, controller, dark_mode: bool):
    """Setup Interface Management settings tab"""
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    
    # Create frame with padding
    frame = ttk.Frame(tab, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # Interface management options
    auto_monitor_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Automatically Enable Monitor Mode When Needed",
        variable=auto_monitor_var
    ).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    auto_kill_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Automatically Kill Conflicting Processes",
        variable=auto_kill_var
    ).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    restore_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Restore Interface Mode On Exit",
        variable=restore_var
    ).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # Interface mode preference
    ttk.Label(frame, text="Preferred Monitor Mode Method:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
    
    method_var = tk.StringVar(value="airmon-ng")
    method_combo = ttk.Combobox(
        frame,
        textvariable=method_var,
        values=["airmon-ng", "iw", "iwconfig", "manual"],
        width=15,
        state="readonly"
    )
    method_combo.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Driver override
    ttk.Label(frame, text="Driver Override (if needed):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
    
    driver_var = tk.StringVar(value="")
    driver_entry = ttk.Entry(
        frame,
        textvariable=driver_var,
        width=20
    )
    driver_entry.grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Disable Hardware Management frame
    hw_frame = ttk.LabelFrame(frame, text="Hardware Management")
    hw_frame.grid(row=5, column=0, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=10)
    
    # Hardware management options
    txpower_var = tk.IntVar(value=20)
    ttk.Label(hw_frame, text="TX Power (dBm):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    txpower_spin = ttk.Spinbox(
        hw_frame,
        from_=1,
        to=30,
        textvariable=txpower_var,
        width=5
    )
    txpower_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    freq_override_var = tk.StringVar(value="")
    ttk.Label(hw_frame, text="Frequency Override (MHz):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    freq_override_entry = ttk.Entry(
        hw_frame,
        textvariable=freq_override_var,
        width=10
    )
    freq_override_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
    
    custom_mac_var = tk.StringVar(value="")
    ttk.Label(hw_frame, text="Custom MAC Address:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
    custom_mac_entry = ttk.Entry(
        hw_frame,
        textvariable=custom_mac_var,
        width=20
    )
    custom_mac_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Random MAC option
    random_mac_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        hw_frame,
        text="Use Random MAC Address for Attacks",
        variable=random_mac_var
    ).grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # Save references to variables for later retrieval
    tab.auto_monitor_var = auto_monitor_var
    tab.auto_kill_var = auto_kill_var
    tab.restore_var = restore_var
    tab.method_var = method_var
    tab.driver_var = driver_var
    tab.txpower_var = txpower_var
    tab.freq_override_var = freq_override_var
    tab.custom_mac_var = custom_mac_var
    tab.random_mac_var = random_mac_var

def setup_settings_tab(tab: ttk.Frame, controller, dark_mode: bool):
    """Setup General Settings tab"""
    # Apply theme
    bg = "#2d2d2d" if dark_mode else "#f0f0f0"
    fg = "#ffffff" if dark_mode else "#000000"
    
    # Create frame with padding
    frame = ttk.Frame(tab, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # Theme selection
    ttk.Label(frame, text="UI Theme:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    
    theme_var = tk.StringVar(value="dark" if dark_mode else "light")
    theme_combo = ttk.Combobox(
        frame,
        textvariable=theme_var,
        values=["dark", "light"],
        width=10,
        state="readonly"
    )
    theme_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Logging level
    ttk.Label(frame, text="Logging Level:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    
    log_level_var = tk.StringVar(value="INFO")
    log_level_combo = ttk.Combobox(
        frame,
        textvariable=log_level_var,
        values=["DEBUG", "INFO", "WARNING", "ERROR"],
        width=10,
        state="readonly"
    )
    log_level_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Auto-save configuration
    autosave_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Auto-Save Configuration on Exit",
        variable=autosave_var
    ).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # Confirm actions
    confirm_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Confirm Before Running Attacks",
        variable=confirm_var
    ).grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # Play sounds
    sound_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Play Sounds for Events",
        variable=sound_var
    ).grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # Check for updates
    update_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        frame,
        text="Check for Updates on Startup",
        variable=update_var
    ).grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
    
    # Developer options
    dev_frame = ttk.LabelFrame(frame, text="Developer Options")
    dev_frame.grid(row=6, column=0, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=10)
    
    # Developer options
    dev_mode_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        dev_frame,
        text="Enable Development Mode",
        variable=dev_mode_var
    ).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    
    debug_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        dev_frame,
        text="Show Debug Information",
        variable=debug_var
    ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
    
    verbosity_var = tk.IntVar(value=1)
    ttk.Label(dev_frame, text="Console Verbosity:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
    verbosity_spin = ttk.Spinbox(
        dev_frame,
        from_=0,
        to=3,
        textvariable=verbosity_var,
        width=5
    )
    verbosity_spin.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Data directory
    ttk.Label(frame, text="Data Directory:").grid(row=7, column=0, sticky=tk.W, padx=5, pady=5)
    
    data_dir_var = tk.StringVar(value="./data")
    data_dir_entry = ttk.Entry(
        frame,
        textvariable=data_dir_var,
        width=30
    )
    data_dir_entry.grid(row=7, column=1, sticky=tk.W, padx=5, pady=5)
    
    # Browse button
    ttk.Button(
        frame,
        text="Browse",
        command=lambda: browse_directory(data_dir_var)
    ).grid(row=7, column=2, sticky=tk.W, padx=5, pady=5)
    
    # Save references to variables for later retrieval
    tab.theme_var = theme_var
    tab.log_level_var = log_level_var
    tab.autosave_var = autosave_var
    tab.confirm_var = confirm_var
    tab.sound_var = sound_var
    tab.update_var = update_var
    tab.dev_mode_var = dev_mode_var
    tab.debug_var = debug_var
    tab.verbosity_var = verbosity_var
    tab.data_dir_var = data_dir_var

def toggle_custom_template(custom_var, template_entry, template_combo):
    """Toggle custom template entry state"""
    if custom_var.get():
        template_entry.config(state="normal")
        template_combo.config(state="disabled")
    else:
        template_entry.config(state="disabled")
        template_combo.config(state="readonly")

def browse_file(var):
    """Browse for a file and set the path in the given variable"""
    path = filedialog.askopenfilename()
    if path:
        var.set(path)

def browse_directory(var):
    """Browse for a directory and set the path in the given variable"""
    path = filedialog.askdirectory()
    if path:
        var.set(path)

def save_advanced_settings(dialog, controller, log_callback=None):
    """Save advanced settings from dialog to controller"""
    try:
        # Get notebook
        notebook = None
        for child in dialog.winfo_children():
            if isinstance(child, ttk.Notebook):
                notebook = child
                break
                
        if not notebook:
            if log_callback:
                log_callback("Error: Could not find settings notebook", error=True)
            return
        
        # Get tabs
        tabs = notebook.tabs()
        
        # WPA Tab
        wpa_tab = notebook.nametowidget(tabs[0])
        if hasattr(wpa_tab, 'wpa_timeout_var'):
            controller.attack_params.wpa_timeout = wpa_tab.wpa_timeout_var.get()
        if hasattr(wpa_tab, 'deauth_count_var'):
            controller.attack_params.deauth_packets = wpa_tab.deauth_count_var.get()
        if hasattr(wpa_tab, 'wpa_wordlist_var'):
            controller.attack_params.wpa_wordlist = wpa_tab.wpa_wordlist_var.get()
        
        # WPS Tab
        wps_tab = notebook.nametowidget(tabs[1])
        if hasattr(wps_tab, 'wps_timeout_var'):
            controller.attack_params.wps_timeout = wps_tab.wps_timeout_var.get()
        if hasattr(wps_tab, 'wps_attempts_var'):
            controller.attack_params.wps_pin_attempts = wps_tab.wps_attempts_var.get()
        if hasattr(wps_tab, 'wps_wordlist_var'):
            controller.attack_params.wps_pin_wordlist = wps_tab.wps_wordlist_var.get()
        
        # WEP Tab
        wep_tab = notebook.nametowidget(tabs[2])
        if hasattr(wep_tab, 'wep_timeout_var'):
            controller.attack_params.wep_timeout = wep_tab.wep_timeout_var.get()
        if hasattr(wep_tab, 'iv_goal_var'):
            controller.attack_params.wep_iv_goal = wep_tab.iv_goal_var.get()
        
        # PMKID Tab
        pmkid_tab = notebook.nametowidget(tabs[3])
        if hasattr(pmkid_tab, 'pmkid_timeout_var'):
            controller.attack_params.pmkid_timeout = pmkid_tab.pmkid_timeout_var.get()
        
        # Evil Twin Tab
        evil_twin_tab = notebook.nametowidget(tabs[4])
        if hasattr(evil_twin_tab, 'template_var'):
            controller.attack_params.evil_twin_template_type = evil_twin_tab.template_var.get()
        if hasattr(evil_twin_tab, 'custom_var'):
            controller.attack_params.use_custom_template = evil_twin_tab.custom_var.get()
        if hasattr(evil_twin_tab, 'template_path_var'):
            controller.attack_params.evil_twin_template_path = evil_twin_tab.template_path_var.get()
        
        # Default Credentials Tab
        default_creds_tab = notebook.nametowidget(tabs[5])
        if hasattr(default_creds_tab, 'creds_wordlist_var'):
            controller.attack_params.default_creds_wordlist = default_creds_tab.creds_wordlist_var.get()
        
        # Scan Tab
        scan_tab = notebook.nametowidget(tabs[6])
        if hasattr(scan_tab, 'hop_interval_var'):
            controller.attack_params.channel_hop_interval = scan_tab.hop_interval_var.get()
        
        if log_callback:
            log_callback("Advanced settings saved successfully", success=True)
            
    except Exception as e:
        if log_callback:
            log_callback(f"Error saving advanced settings: {str(e)}", error=True)

def configure_dialog_for_display(dialog):
    """Configure dialog for proper display"""
    # Make dialog resizable
    dialog.resizable(True, True)
    
    # Center dialog on parent window
    parent = dialog.master
    dialog.withdraw()  # Hide temporarily
    
    # Wait for dialog to be ready
    dialog.update_idletasks()
    
    # Calculate position
    parent_width = parent.winfo_width()
    parent_height = parent.winfo_height()
    parent_x = parent.winfo_rootx()
    parent_y = parent.winfo_rooty()
    
    dialog_width = dialog.winfo_width()
    dialog_height = dialog.winfo_height()
    
    x = parent_x + (parent_width - dialog_width) // 2
    y = parent_y + (parent_height - dialog_height) // 2
    
    # Set position
    dialog.geometry(f"+{x}+{y}")
    
    # Show dialog
    dialog.deiconify()

def create_maximize_button(parent, dialog):
    """Create a maximize button for the dialog"""
    max_btn = ttk.Button(parent, text="□", width=3)
    
    # Define maximize function
    def toggle_maximize():
        if dialog.state() == 'zoomed':
            dialog.state('normal')
            max_btn.config(text="□")
        else:
            dialog.state('zoomed')
            max_btn.config(text="■")
    
    max_btn.config(command=toggle_maximize)
    return max_btn
