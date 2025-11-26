#!/usr/bin/env python3
"""
Attack All Networks Dialog for NetworkPentestPro
Allows configuration and execution of sequential attacks on multiple networks
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
from typing import List, Callable, Dict, Any

def create_attack_all_dialog(root: tk.Tk, networks: List, controller, dark_mode: bool = True, log_callback: Callable = None):
    """
    Create and display attack all networks dialog
    
    Args:
        root: Parent window
        networks: List of NetworkTarget objects
        controller: Controller instance
        dark_mode: Whether to use dark mode theme
        log_callback: Callback function for logging
    """
    # Create dialog window
    dialog = tk.Toplevel(root)
    dialog.title("Auto Attack Sequencer")
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
        text="Automated Attack Sequence",
        font=("Helvetica", 14, "bold")
    )
    title_label.pack(side=tk.LEFT, padx=10)
    
    # Add maximize button
    max_btn = create_maximize_button(header_frame, dialog)
    max_btn.pack(side=tk.RIGHT, padx=5)
    
    # Description
    desc_frame = ttk.Frame(dialog)
    desc_frame.pack(fill=tk.X, padx=20, pady=10)
    
    network_count = len(networks)
    description = ttk.Label(
        desc_frame,
        text=f"This will test {network_count} network{'s' if network_count != 1 else ''} in order of signal strength.",
        wraplength=700
    )
    description.pack(anchor=tk.W)
    
    # Network list
    list_frame = ttk.LabelFrame(dialog, text="Networks to Test")
    list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    # Create treeview
    columns = ("ssid", "bssid", "security", "signal")
    tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
    
    # Configure columns
    tree.heading("ssid", text="Network Name")
    tree.heading("bssid", text="BSSID")
    tree.heading("security", text="Security")
    tree.heading("signal", text="Signal")
    
    tree.column("ssid", width=200)
    tree.column("bssid", width=150)
    tree.column("security", width=120)
    tree.column("signal", width=70)
    
    # Scrollbar
    scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    
    # Place treeview and scrollbar
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Fill treeview
    for network in networks:
        # Format security
        if hasattr(network, 'security'):
            security = ", ".join(network.security) if network.security else "Open"
        else:
            security = network.get('security_type', "Unknown")
            
        # Format signal strength
        if hasattr(network, 'signal_strength'):
            signal = f"{network.signal_strength}%"
        else:
            signal = f"{network.get('signal_strength', '?')}%"
            
        # Get SSID and BSSID
        ssid = network.ssid if hasattr(network, 'ssid') else network.get('ssid', "Unknown")
        bssid = network.bssid if hasattr(network, 'bssid') else network.get('bssid', "Unknown")
        
        # Add to treeview
        tree.insert("", tk.END, values=(
            ssid,
            bssid,
            security,
            signal
        ))
    
    # Options
    options_frame = ttk.LabelFrame(dialog, text="Attack Options")
    options_frame.pack(fill=tk.X, padx=20, pady=10)
    
    # Create columns for options
    opts_frame = ttk.Frame(options_frame)
    opts_frame.pack(fill=tk.X, padx=10, pady=10)
    
    left_col = ttk.Frame(opts_frame)
    left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    right_col = ttk.Frame(opts_frame)
    right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
    
    # Attack checkboxes
    def_creds_var = tk.BooleanVar(value=True)
    wps_var = tk.BooleanVar(value=True)
    wpa_var = tk.BooleanVar(value=True)
    wep_var = tk.BooleanVar(value=True)
    pmkid_var = tk.BooleanVar(value=True)
    evil_twin_var = tk.BooleanVar(value=False)
    port_scan_var = tk.BooleanVar(value=True)
    
    # Left column
    def_creds_check = ttk.Checkbutton(
        left_col,
        text="Default Credentials Check",
        variable=def_creds_var
    )
    def_creds_check.pack(anchor=tk.W, pady=2)
    
    wps_check = ttk.Checkbutton(
        left_col,
        text="WPS PIN Attack",
        variable=wps_var
    )
    wps_check.pack(anchor=tk.W, pady=2)
    
    wpa_check = ttk.Checkbutton(
        left_col,
        text="WPA Handshake Capture",
        variable=wpa_var
    )
    wpa_check.pack(anchor=tk.W, pady=2)
    
    wep_check = ttk.Checkbutton(
        left_col,
        text="WEP Attack",
        variable=wep_var
    )
    wep_check.pack(anchor=tk.W, pady=2)
    
    # Right column
    pmkid_check = ttk.Checkbutton(
        right_col,
        text="PMKID Attack",
        variable=pmkid_var
    )
    pmkid_check.pack(anchor=tk.W, pady=2)
    
    evil_twin_check = ttk.Checkbutton(
        right_col,
        text="Evil Twin Attack",
        variable=evil_twin_var
    )
    evil_twin_check.pack(anchor=tk.W, pady=2)
    
    port_scan_check = ttk.Checkbutton(
        right_col,
        text="Port Scanning",
        variable=port_scan_var
    )
    port_scan_check.pack(anchor=tk.W, pady=2)
    
    # Timeout
    timeout_frame = ttk.Frame(options_frame)
    timeout_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
    
    timeout_label = ttk.Label(
        timeout_frame,
        text="Timeout per attack (seconds):"
    )
    timeout_label.pack(side=tk.LEFT, padx=(0, 5))
    
    timeout_var = tk.IntVar(value=60)
    timeout_spin = ttk.Spinbox(
        timeout_frame,
        from_=10,
        to=300,
        textvariable=timeout_var,
        width=5
    )
    timeout_spin.pack(side=tk.LEFT)
    
    # Additional options
    add_opts_frame = ttk.Frame(options_frame)
    add_opts_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
    
    stop_on_success_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(
        add_opts_frame,
        text="Stop Testing Network After First Successful Attack",
        variable=stop_on_success_var
    ).pack(side=tk.LEFT, padx=(0, 20))
    
    parallel_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(
        add_opts_frame,
        text="Parallel Testing (Advanced)",
        variable=parallel_var
    ).pack(side=tk.LEFT)
    
    # Button frame
    button_frame = ttk.Frame(dialog)
    button_frame.pack(fill=tk.X, padx=20, pady=20)
    
    # Warning
    warning_label = ttk.Label(
        button_frame,
        text="⚠️ Only use against networks you own or have permission to test!",
        foreground="#FF0000"
    )
    warning_label.pack(side=tk.LEFT)
    
    # Start button
    start_btn = ttk.Button(
        button_frame,
        text="Start Assessment",
        command=lambda: start_sequential_tests(
            dialog, 
            networks, 
            controller, 
            {
                "DEFAULT_CREDS": def_creds_var.get(),
                "WPS": wps_var.get(),
                "WPA": wpa_var.get(),
                "WEP": wep_var.get(),
                "PMKID": pmkid_var.get(),
                "EVIL_TWIN": evil_twin_var.get(),
                "PORT_SCAN": port_scan_var.get()
            },
            timeout_var.get(),
            log_callback
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
    
    return dialog

def start_sequential_tests(dialog, networks, controller, attack_types, timeout, log_callback):
    """Start sequential testing in a background thread"""
    # Confirm with user
    confirm = messagebox.askyesno(
        "Confirm Sequential Testing",
        "This will run multiple attack techniques on all selected networks.\n\n"
        "IMPORTANT: Only use against networks you own or have permission to test!\n\n"
        "Continue with testing?",
        icon="warning"
    )
    
    if not confirm:
        return
    
    # Start testing in a thread
    threading.Thread(
        target=run_tests_thread,
        args=(dialog, networks, controller, attack_types, timeout, log_callback),
        daemon=True
    ).start()

def run_tests_thread(dialog, networks, controller, attack_types, timeout, log_callback):
    """Run sequential tests in background thread"""
    if log_callback:
        log_callback("Starting sequential network testing...", phase="ATTACK")
    
    try:
        # Run the sequential tests
        results = controller.run_sequential_tests(
            networks,
            attack_types,
            timeout,
            dialog
        )
        
        # Process results
        success_count = 0
        for bssid, result in results.items():
            for attack_name, attack_result in result.get("attacks", {}).items():
                if attack_result.get("success"):
                    success_count += 1
        
        # Log completion
        if log_callback:
            log_callback(f"Sequential testing complete. {success_count} successful attacks.", 
                      success=True, phase="ATTACK")
        
        # Show results
        dialog.after(0, lambda: show_results_dialog(dialog, results, log_callback))
        
    except Exception as e:
        if log_callback:
            log_callback(f"Error in sequential testing: {str(e)}", error=True, phase="ATTACK")
        
        # Show error
        dialog.after(0, lambda: messagebox.showerror(
            "Testing Error",
            f"An error occurred during testing:\n{str(e)}"
        ))

def show_results_dialog(parent_dialog, results, log_callback):
    """Show results of sequential testing"""
    # Create results dialog
    results_dialog = tk.Toplevel(parent_dialog)
    results_dialog.title("Sequential Testing Results")
    results_dialog.geometry("700x500")
    results_dialog.transient(parent_dialog)
    results_dialog.grab_set()
    
    # Configure dialog for display
    configure_dialog_for_display(results_dialog)
    
    # Apply theme (use same as parent)
    if hasattr(parent_dialog, 'configure'):
        bg = parent_dialog.cget('background')
        results_dialog.configure(background=bg)
    
    # Header
    header_frame = ttk.Frame(results_dialog)
    header_frame.pack(fill=tk.X, padx=10, pady=10)
    
    title_label = ttk.Label(
        header_frame,
        text="Sequential Testing Results",
        font=("Helvetica", 14, "bold")
    )
    title_label.pack(side=tk.LEFT, padx=10)
    
    # Calculate statistics
    total_networks = len(results)
    successful_networks = sum(1 for bssid, result in results.items() 
                           if any(attack.get("success") 
                                for attack in result.get("attacks", {}).values()))
    
    total_attacks = sum(len(result.get("attacks", {})) for result in results.values())
    successful_attacks = sum(sum(1 for attack in result.get("attacks", {}).values() 
                              if attack.get("success")) 
                           for result in results.values())
    
    # Summary
    summary_frame = ttk.Frame(results_dialog)
    summary_frame.pack(fill=tk.X, padx=20, pady=10)
    
    summary_text = (
        f"Tested {total_networks} networks with {total_attacks} attack attempts.\n"
        f"Successfully compromised {successful_networks} networks with {successful_attacks} successful attacks."
    )
    
    summary_label = ttk.Label(
        summary_frame,
        text=summary_text,
        wraplength=650
    )
    summary_label.pack(anchor=tk.W)
    
    # Results
    results_frame = ttk.LabelFrame(results_dialog, text="Detailed Results")
    results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    # Create notebook for network tabs
    notebook = ttk.Notebook(results_frame)
    notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Create a tab for each network
    for bssid, result in results.items():
        ssid = result.get("ssid", "Unknown")
        
        # Create tab
        tab = ttk.Frame(notebook)
        notebook.add(tab, text=ssid)
        
        # Create content for tab
        create_network_result_tab(tab, result)
    
    # Button frame
    button_frame = ttk.Frame(results_dialog)
    button_frame.pack(fill=tk.X, padx=20, pady=10)
    
    # Close button
    close_btn = ttk.Button(
        button_frame,
        text="Close",
        command=results_dialog.destroy
    )
    close_btn.pack(side=tk.RIGHT, padx=5)
    
    # Generate report button
    report_btn = ttk.Button(
        button_frame,
        text="Generate Report",
        command=lambda: generate_report(results_dialog, results, log_callback)
    )
    report_btn.pack(side=tk.RIGHT, padx=5)

def create_network_result_tab(tab, result):
    """Create content for a network result tab"""
    # Create scrollable frame
    canvas = tk.Canvas(tab)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    scrollbar = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=canvas.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    canvas.configure(yscrollcommand=scrollbar.set)
    
    # Create frame for content
    content_frame = ttk.Frame(canvas)
    canvas_window = canvas.create_window((0, 0), window=content_frame, anchor=tk.NW)
    
    # Configure canvas to expand with content
    def on_frame_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))
    
    content_frame.bind("<Configure>", on_frame_configure)
    
    def on_canvas_configure(event):
        canvas.itemconfig(canvas_window, width=event.width)
    
    canvas.bind("<Configure>", on_canvas_configure)
    
    # Network information
    info_frame = ttk.LabelFrame(content_frame, text="Network Information")
    info_frame.pack(fill=tk.X, padx=10, pady=5)
    
    # Create grid for network info
    info_grid = ttk.Frame(info_frame)
    info_grid.pack(fill=tk.X, padx=10, pady=5)
    
    # BSSID
    ttk.Label(info_grid, text="BSSID:", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    ttk.Label(info_grid, text=result.get("bssid", "Unknown")).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
    
    # Channel
    ttk.Label(info_grid, text="Channel:", font=("Helvetica", 10, "bold")).grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
    ttk.Label(info_grid, text=result.get("channel", "Unknown")).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
    
    # Security
    ttk.Label(info_grid, text="Security:", font=("Helvetica", 10, "bold")).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
    
    security_str = ", ".join(result.get("security", [])) if result.get("security") else "Open"
    ttk.Label(info_grid, text=security_str).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
    
    # Attack results
    attack_frame = ttk.LabelFrame(content_frame, text="Attack Results")
    attack_frame.pack(fill=tk.X, padx=10, pady=5)
    
    # Create table for attack results
    attack_table = ttk.Treeview(attack_frame, columns=("attack", "result", "details"), show="headings", height=6)
    attack_table.pack(fill=tk.X, padx=10, pady=5)
    
    # Configure columns
    attack_table.heading("attack", text="Attack Type")
    attack_table.heading("result", text="Result")
    attack_table.heading("details", text="Details")
    
    attack_table.column("attack", width=150)
    attack_table.column("result", width=80)
    attack_table.column("details", width=300)
    
    # Fill table with attack results
    attack_results = result.get("attacks", {})
    for attack_name, attack_result in attack_results.items():
        # Format attack name
        attack_name_formatted = attack_name.replace("_", " ").title()
        
        # Determine result
        success = attack_result.get("success", False)
        result_text = "Success" if success else "Failed"
        
        # Format details
        details = ""
        if success:
            if attack_name == "wps" and attack_result.get("pin") and attack_result.get("password"):
                details = f"WPS PIN: {attack_result.get('pin')}, Password: {attack_result.get('password')}"
            elif attack_name in ["wpa", "wep", "pmkid"] and attack_result.get("capture_file"):
                details = f"Capture file: {attack_result.get('capture_file')}"
            elif attack_name == "default_creds" and attack_result.get("creds"):
                creds = attack_result.get("creds", [])
                if creds:
                    cred_details = []
                    for cred in creds[:2]:  # Show first two credential sets
                        cred_details.append(f"{cred.get('username')}:{cred.get('password')}")
                    if len(creds) > 2:
                        cred_details.append(f"... and {len(creds) - 2} more")
                    details = ", ".join(cred_details)
        else:
            details = attack_result.get("message", "Attack unsuccessful")
        
        # Add to table
        attack_table.insert("", tk.END, values=(
            attack_name_formatted,
            result_text,
            details
        ))
    
    # Summary
    summary_frame = ttk.Frame(content_frame)
    summary_frame.pack(fill=tk.X, padx=10, pady=10)
    
    # Count successful attacks
    successful = sum(1 for attack in attack_results.values() if attack.get("success", False))
    total = len(attack_results)
    
    summary_text = f"Summary: {successful} of {total} attacks were successful."
    
    if successful > 0:
        summary_text += " This network is vulnerable."
    else:
        summary_text += " No vulnerabilities were found with the selected attacks."
        
    ttk.Label(summary_frame, text=summary_text, wraplength=600).pack(anchor=tk.W)
    
    # Recommendations
    if successful > 0:
        rec_frame = ttk.LabelFrame(content_frame, text="Security Recommendations")
        rec_frame.pack(fill=tk.X, padx=10, pady=5)
        
        recommendations = []
        
        # Generate recommendations based on successful attacks
        for attack_name, attack_result in attack_results.items():
            if attack_result.get("success", False):
                if attack_name == "wps":
                    recommendations.append("Disable WPS on this device or upgrade to a newer device with stronger WPS security.")
                elif attack_name == "wep":
                    recommendations.append("Replace WEP encryption with WPA2 or WPA3 encryption immediately.")
                elif attack_name == "wpa" or attack_name == "pmkid":
                    recommendations.append("Use a longer, more complex WPA password (at least 12 random characters).")
                elif attack_name == "default_creds":
                    recommendations.append("Change default credentials on all network devices.")
        
        # Add general recommendations
        if not recommendations:
            recommendations = [
                "Keep firmware updated on all network devices.",
                "Use WPA2/WPA3 with a strong, unique password.",
                "Consider isolating IoT devices on a separate network."
            ]
        
        # Add recommendations to frame
        for i, rec in enumerate(recommendations):
            ttk.Label(rec_frame, text=f"• {rec}", wraplength=600).pack(anchor=tk.W, padx=10, pady=2)

def generate_report(dialog, results, log_callback):
    """Generate a report from test results"""
    # This function would typically call into the report generator module
    if log_callback:
        log_callback("Report generation not implemented in this dialog", warning=True)
        
    messagebox.showinfo(
        "Report Generation",
        "Report generation from this dialog is not yet implemented.\n\n"
        "Please use the main Report Generation feature from the File menu."
    )

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
