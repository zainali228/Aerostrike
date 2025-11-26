#!/usr/bin/env python3
"""
Online AI Security Helper for WiFi Penetration Testing Tool
Provides advanced AI-powered security analysis using online AI exclusively
"""

import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
from datetime import datetime
import json
from typing import Dict, List, Any, Optional, Callable

# Import AI assistant
from src.ai_assistant import AIAssistant


class UnifiedAIHelper:
    """Online AI Security Helper for advanced network security analysis"""
    
    def __init__(self, parent, controller=None, on_close_callback=None):
        """Initialize the Online AI Security Helper
        
        Args:
            parent: Parent tkinter window/frame
            controller: Main application controller
            on_close_callback: Function to call when dialog is closed
        """
        self.parent = parent
        self.controller = controller
        self.on_close_callback = on_close_callback
        
        # Initialize online assistant only
        self.online_assistant = None
        # We've completely removed offline assistant functionality
        
        self.dark_mode = True  # Default to dark mode
        
        # Try to detect dark mode from parent
        if hasattr(controller, 'dark_mode'):
            self.dark_mode = controller.dark_mode
        
        # Configure colors
        self.bg_color = "#2d2d2d" if self.dark_mode else "#f0f0f0"
        self.fg_color = "#ffffff" if self.dark_mode else "#000000"
        self.accent_color = "#9F44D3"  # Purple accent
        self.highlight_color = "#480B86" if self.dark_mode else "#c880ff"
        self.input_bg = "#1e1e1e" if self.dark_mode else "#ffffff"
        self.output_bg = "#1e1e1e" if self.dark_mode else "#ffffff"
        self.panel_bg = "#333333" if self.dark_mode else "#e0e0e0"
        
        # Create the dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Online WiFi Security AI Helper")
        self.dialog.geometry("1100x800")
        self.dialog.minsize(900, 700)
        
        # Configure dialog
        if self.dark_mode:
            self.dialog.configure(bg=self.bg_color)
        
        # Make dialog non-modal so user can interact with other parts of the application
        self.dialog.transient(parent)
        
        # Handle close event
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Track active tab to handle tab-specific functionality
        self.active_tab = "online"
        
        # Initialize UI components
        self.create_ui()
        
        # Initialize assistants
        self.initialize_assistants()
    
    def create_ui(self):
        """Create all UI components with tabbed interface"""
        # Main frame
        self.main_frame = ttk.Frame(self.dialog)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # API key frame in top right
        self.api_key_frame = ttk.Frame(self.main_frame)
        self.api_key_frame.pack(side=tk.TOP, anchor=tk.NE, padx=5, pady=5)
        
        # Add API key button with prominent styling
        self.api_key_btn = ttk.Button(
            self.api_key_frame,
            text="Set API Key (Required)",
            command=self.set_api_key,
            width=20
        )
        self.api_key_btn.pack(side=tk.RIGHT, padx=5)
        
        # Status label for API key
        self.api_status_var = tk.StringVar(value="API Status: Not Set")
        self.api_status_label = ttk.Label(
            self.api_key_frame,
            textvariable=self.api_status_var,
            font=("Helvetica", 9)
        )
        self.api_status_label.pack(side=tk.RIGHT, padx=5)
        
        # Main content frame
        self.main_content_frame = ttk.Frame(self.main_frame)
        self.main_content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create online AI frame
        self.online_frame = ttk.Frame(self.main_content_frame)
        self.online_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create content for online tab
        self.create_online_tab()
        
        # Status bar at bottom
        self.status_bar = ttk.Frame(self.main_frame)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)
        
        self.status_var = tk.StringVar(value="Initializing...")
        self.status_label = ttk.Label(
            self.status_bar,
            textvariable=self.status_var,
            font=("Helvetica", 9),
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def create_online_tab(self):
        """Create content for online AI assistant tab"""
        # Main frame for online tab
        frame = ttk.Frame(self.online_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title frame
        title_frame = ttk.Frame(frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title_label = ttk.Label(
            title_frame, 
            text="Online AI Security Assistant",
            font=("Helvetica", 14, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        # Model info
        self.online_model_var = tk.StringVar(value="Model: Not Connected")
        model_label = ttk.Label(
            title_frame,
            textvariable=self.online_model_var,
            font=("Helvetica", 10, "italic")
        )
        model_label.pack(side=tk.RIGHT)
        
        # Chat display
        chat_frame = ttk.Frame(frame)
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Chat output (conversation history)
        self.online_chat_output = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            bg=self.output_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10,
            state=tk.DISABLED
        )
        self.online_chat_output.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for different message types
        self.online_chat_output.tag_config("user", foreground="#4cc9f0", font=("Helvetica", 11, "bold"))
        self.online_chat_output.tag_config("assistant", foreground="#90be6d", font=("Helvetica", 11))
        self.online_chat_output.tag_config("system", foreground="#f9c74f", font=("Helvetica", 10, "italic"))
        
        # Input area
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=(10, 0))
        
        # User input field
        self.online_user_input = scrolledtext.ScrolledText(
            input_frame,
            wrap=tk.WORD,
            height=4,
            bg=self.input_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10
        )
        self.online_user_input.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        # Add placeholder text
        self.online_user_input.insert(tk.END, "Type your question here...")
        self.online_user_input.bind("<FocusIn>", lambda e: self._clear_placeholder(self.online_user_input))
        
        # Bind Enter key
        self.online_user_input.bind("<Return>", lambda e: self.handle_online_enter(e))
        
        # Buttons frame
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Send button
        self.online_send_btn = ttk.Button(
            button_frame,
            text="Send",
            command=self.send_online_message,
            state=tk.DISABLED
        )
        self.online_send_btn.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))
        
        # Quick question buttons
        self.create_online_quick_buttons(frame)
    
# Removed offline AI functionality - using online AI exclusively
    
    def create_ask_tab(self):
        """Create content for Ask Questions tab"""
        # Main frame
        frame = ttk.Frame(self.ask_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Chat display
        chat_frame = ttk.Frame(frame)
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Chat output
        self.offline_chat_output = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            bg=self.output_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10,
            state=tk.DISABLED
        )
        self.offline_chat_output.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags
        self.offline_chat_output.tag_config("user", foreground="#4cc9f0", font=("Helvetica", 11, "bold"))
        self.offline_chat_output.tag_config("assistant", foreground="#90be6d", font=("Helvetica", 11))
        self.offline_chat_output.tag_config("system", foreground="#f9c74f", font=("Helvetica", 10, "italic"))
        
        # Input area
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=(10, 0))
        
        # User input field
        self.offline_user_input = scrolledtext.ScrolledText(
            input_frame,
            wrap=tk.WORD,
            height=4,
            bg=self.input_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10
        )
        self.offline_user_input.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        # Add placeholder text
        self.offline_user_input.insert(tk.END, "Ask a security question...")
        self.offline_user_input.bind("<FocusIn>", lambda e: self._clear_placeholder(self.offline_user_input))
        
        # Bind Enter key
        self.offline_user_input.bind("<Return>", lambda e: self.handle_offline_enter(e))
        
        # Buttons frame
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Send button
        self.offline_send_btn = ttk.Button(
            button_frame,
            text="Send",
            command=self.send_offline_message,
            state=tk.DISABLED
        )
        self.offline_send_btn.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))
        
        # Common questions
        questions_frame = ttk.LabelFrame(frame, text="Common WiFi Security Questions")
        questions_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Create a grid of question buttons
        questions = [
            "What is WPA2?",
            "Explain KRACK attack",
            "What is WPS?",
            "How to secure my WiFi?",
            "What is WPA3?",
            "Explain MAC filtering"
        ]
        
        # Create buttons grid
        buttons_frame = ttk.Frame(questions_frame)
        buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        for i, question in enumerate(questions):
            row = i // 3
            col = i % 3
            
            btn = ttk.Button(
                buttons_frame,
                text=question,
                command=lambda q=question: self.ask_offline_quick_question(q)
            )
            btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
        
        # Configure grid columns to have equal width
        for i in range(3):
            buttons_frame.columnconfigure(i, weight=1)
    
    def create_analyze_tab(self):
        """Create content for Network Analysis tab"""
        # Main frame
        frame = ttk.Frame(self.analyze_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Instructions
        ttk.Label(
            frame,
            text="Upload network scan results for offline analysis",
            font=("Helvetica", 12, "bold")
        ).pack(pady=(0, 10))
        
        # Upload area
        upload_frame = ttk.LabelFrame(frame, text="Upload Scan Data")
        upload_frame.pack(fill=tk.X, pady=10)
        
        upload_btn = ttk.Button(
            upload_frame,
            text="Upload Network Scan",
            command=self.upload_network_scan
        )
        upload_btn.pack(padx=10, pady=10)
        
        # Analysis results area
        results_frame = ttk.LabelFrame(frame, text="Analysis Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.analyze_output = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            bg=self.output_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10,
            state=tk.DISABLED
        )
        self.analyze_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Buttons for quick analysis
        quick_frame = ttk.LabelFrame(frame, text="Quick Analysis")
        quick_frame.pack(fill=tk.X, pady=10)
        
        buttons_frame = ttk.Frame(quick_frame)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(
            buttons_frame,
            text="Check Common Vulnerabilities",
            command=lambda: self.analyze_network("common_vulns")
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        ttk.Button(
            buttons_frame,
            text="Check Rogue Access Points",
            command=lambda: self.analyze_network("rogue_ap")
        ).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Button(
            buttons_frame,
            text="Check Weak Encryption",
            command=lambda: self.analyze_network("weak_encryption")
        ).grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        
        ttk.Button(
            buttons_frame,
            text="Check Default Credentials",
            command=lambda: self.analyze_network("default_creds")
        ).grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        # Configure grid columns to have equal width
        for i in range(2):
            buttons_frame.columnconfigure(i, weight=1)
    
    def create_report_tab(self):
        """Create content for Report Generation tab"""
        # Main frame
        frame = ttk.Frame(self.report_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Instructions
        ttk.Label(
            frame,
            text="Generate security assessment reports",
            font=("Helvetica", 12, "bold")
        ).pack(pady=(0, 10))
        
        # Report options
        options_frame = ttk.LabelFrame(frame, text="Report Options")
        options_frame.pack(fill=tk.X, pady=10)
        
        form_frame = ttk.Frame(options_frame)
        form_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Company info
        ttk.Label(form_frame, text="Company Name:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.company_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.company_var, width=30).grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        
        ttk.Label(form_frame, text="Report Title:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.report_title_var = tk.StringVar(value="WiFi Security Assessment Report")
        ttk.Entry(form_frame, textvariable=self.report_title_var, width=30).grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        
        ttk.Label(form_frame, text="Include Network Scan:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.include_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(form_frame, variable=self.include_scan_var).grid(row=2, column=1, sticky="w", padx=5, pady=5)
        
        ttk.Label(form_frame, text="Include Vulnerabilities:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.include_vulns_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(form_frame, variable=self.include_vulns_var).grid(row=3, column=1, sticky="w", padx=5, pady=5)
        
        ttk.Label(form_frame, text="Include Recommendations:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.include_rec_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(form_frame, variable=self.include_rec_var).grid(row=4, column=1, sticky="w", padx=5, pady=5)
        
        form_frame.columnconfigure(1, weight=1)
        
        # Buttons for report generation
        buttons_frame = ttk.Frame(frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            buttons_frame,
            text="Preview Report",
            command=self.preview_report
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Generate PDF Report",
            command=self.generate_report
        ).pack(side=tk.LEFT, padx=5)
        
        # Report preview area
        preview_frame = ttk.LabelFrame(frame, text="Report Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.report_preview = scrolledtext.ScrolledText(
            preview_frame,
            wrap=tk.WORD,
            bg=self.output_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10,
            state=tk.DISABLED
        )
        self.report_preview.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_fix_tab(self):
        """Create content for Error Fixing tab"""
        # Main frame
        frame = ttk.Frame(self.fix_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Instructions
        ttk.Label(
            frame,
            text="Diagnose and fix common WiFi security issues",
            font=("Helvetica", 12, "bold")
        ).pack(pady=(0, 10))
        
        # Error description area
        desc_frame = ttk.LabelFrame(frame, text="Describe the Issue")
        desc_frame.pack(fill=tk.X, pady=10)
        
        self.error_input = scrolledtext.ScrolledText(
            desc_frame,
            wrap=tk.WORD,
            height=4,
            bg=self.input_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10
        )
        self.error_input.pack(fill=tk.X, padx=10, pady=10)
        
        # Add placeholder text
        self.error_input.insert(tk.END, "Describe your WiFi security issue or error message...")
        self.error_input.bind("<FocusIn>", lambda e: self._clear_placeholder(self.error_input))
        
        # Analyze button
        ttk.Button(
            desc_frame,
            text="Analyze Issue",
            command=self.analyze_error
        ).pack(padx=10, pady=(0, 10))
        
        # Results area
        results_frame = ttk.LabelFrame(frame, text="Diagnosis & Solutions")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.fix_output = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            bg=self.output_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10,
            state=tk.DISABLED
        )
        self.fix_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Common issues
        issues_frame = ttk.LabelFrame(frame, text="Common Issues")
        issues_frame.pack(fill=tk.X, pady=10)
        
        buttons_frame = ttk.Frame(issues_frame)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        common_issues = [
            "Can't connect to WiFi",
            "WPA handshake not captured",
            "Deauthentication not working",
            "Monitor mode problems",
            "Wireless adapter issues",
            "Hash cracking fails"
        ]
        
        for i, issue in enumerate(common_issues):
            row = i // 2
            col = i % 2
            
            btn = ttk.Button(
                buttons_frame,
                text=issue,
                command=lambda i=issue: self.select_common_issue(i)
            )
            btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
        
        # Configure grid columns to have equal width
        for i in range(2):
            buttons_frame.columnconfigure(i, weight=1)
    
    def create_online_quick_buttons(self, parent):
        """Create buttons for quick questions in online tab"""
        quick_frame = ttk.LabelFrame(parent, text="Quick Security Questions")
        quick_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Grid for buttons
        button_frame = ttk.Frame(quick_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Define common questions
        questions = [
            "How do I capture a WPA handshake?",
            "What does the port scan result mean?",
            "How to crack a captured handshake?",
            "Explain WiFi security vulnerabilities",
            "What is post-exploitation?",
            "How to secure a network?"
        ]
        
        # Create buttons in a grid (2 rows x 3 columns)
        for i, question in enumerate(questions):
            row = i // 3
            col = i % 3
            
            btn = ttk.Button(
                button_frame,
                text=question,
                command=lambda q=question: self.ask_online_quick_question(q)
            )
            btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
        
        # Configure grid columns to have equal width
        for i in range(3):
            button_frame.columnconfigure(i, weight=1)
    
    def on_tab_changed(self, event):
        """Handle tab change event"""
        tab_id = event.widget.select()
        tab_name = event.widget.tab(tab_id, "text")
        
        if tab_name == "Online AI Assistant":
            self.active_tab = "online"
        else:
            self.active_tab = "offline"
        
        # Update status based on active tab
        self.update_status(f"Active: {tab_name}")
    
    def initialize_assistants(self):
        """Initialize online AI assistant"""
        self.update_status("Initializing AI assistant...")
        
        # Start initialization in a separate thread
        threading.Thread(target=self._initialize_online_assistant, daemon=True).start()
    
    def _initialize_online_assistant(self):
        """Initialize the online AI assistant"""
        try:
            # Get API key from environment (if exists)
            api_key = os.environ.get("OPENAI_API_KEY")
            
            if not api_key:
                self.update_online_model_info("API Key Required")
                self.add_online_system_message("An OpenAI API key is required to use the AI Security Helper.")
                self.add_online_system_message("Please click 'Set API Key' button in the top right to configure your key.")
                self.api_status_var.set("API Status: No API Key")
                
                # Show warning message to user
                messagebox.showwarning("API Key Required", 
                                     "An OpenAI API key is required to use the AI Security Helper.\n\n"
                                     "Please click 'Set API Key' to configure your API key.")
                return
            
            # Initialize the assistant
            self.online_assistant = AIAssistant(
                use_openai=True, 
                api_key=api_key,
                log_callback=self.log_message
            )
            
            # Check if assistant is available
            if self.online_assistant.is_available():
                model_name = self.online_assistant.get_model_name()
                self.update_online_model_info(f"Model: {model_name}")
                self.enable_online_input()
                self.api_status_var.set(f"API Status: Connected ({model_name})")
                
                # Add welcome message
                self.add_online_system_message("AI Security Helper is ready! Ask security questions or analyze your network.")
                self.add_online_system_message("For example, try asking about WiFi security best practices, vulnerability assessment, or password cracking techniques.")
            else:
                self.update_online_model_info("No online model available")
                self.add_online_system_message("AI Assistant is not available. Please check your API key.")
                self.api_status_var.set("API Status: Not Connected")
                
                # Show error message to user
                messagebox.showerror("Connection Error", 
                                   "Could not connect to the OpenAI service.\n\n"
                                   "Please check your API key and internet connection.")
        except Exception as e:
            self.update_status(f"Error initializing online assistant: {str(e)}")
            self.add_online_system_message(f"Error initializing AI assistant: {str(e)}")
            self.add_online_system_message("Please check your API key and internet connection.")
            
            # Show error message to user
            messagebox.showerror("AI Assistant Error", 
                               f"Error initializing the AI Security Helper: {str(e)}\n\n"
                               "Please check your API key and internet connection.")
    
# Removed offline AI functionality - using online AI exclusively
    
    def set_api_key(self):
        """Open dialog to set OpenAI API key"""
        # Create a simple dialog to enter API key
        api_key_dialog = tk.Toplevel(self.dialog)
        api_key_dialog.title("Set OpenAI API Key")
        api_key_dialog.geometry("400x150")
        api_key_dialog.transient(self.dialog)
        api_key_dialog.grab_set()
        
        # Configure dialog
        if self.dark_mode:
            api_key_dialog.configure(bg=self.bg_color)
        
        # Create API key input
        frame = ttk.Frame(api_key_dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        ttk.Label(frame, text="Enter your OpenAI API Key:").pack(pady=(0, 5))
        
        api_key_var = tk.StringVar()
        api_key_entry = ttk.Entry(frame, textvariable=api_key_var, width=50, show="*")
        api_key_entry.pack(pady=5, fill=tk.X)
        
        # Set current key if available
        if self.online_assistant and hasattr(self.online_assistant, 'api_key') and self.online_assistant.api_key:
            api_key_var.set(self.online_assistant.api_key)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            button_frame, 
            text="Cancel", 
            command=api_key_dialog.destroy
        ).pack(side=tk.RIGHT, padx=(5, 0))
        
        ttk.Button(
            button_frame,
            text="Save",
            command=lambda: self._save_api_key(api_key_var.get(), api_key_dialog)
        ).pack(side=tk.RIGHT)
    
    def _save_api_key(self, api_key, dialog):
        """Save the API key and reinitialize assistant"""
        if not api_key:
            messagebox.showerror("Error", "API Key cannot be empty")
            return
        
        # Close the dialog
        dialog.destroy()
        
        # Save the API key to environment
        os.environ["OPENAI_API_KEY"] = api_key
        
        # Reinitialize online assistant
        self.update_status("Reinitializing with new API Key...")
        self.add_online_system_message("Reinitializing with new API Key...")
        
        threading.Thread(target=self._initialize_online_assistant, daemon=True).start()
    
    # Online assistant methods
    def handle_online_enter(self, event):
        """Handle Enter key press in online input"""
        # If Shift+Enter, allow normal behavior (new line)
        if event.state & 0x1:  # Shift is pressed
            return
        
        # Otherwise, send the message
        self.send_online_message()
        return "break"  # Prevent default Enter behavior
    
    def send_online_message(self):
        """Send message to online assistant"""
        # Get message text
        message = self.online_user_input.get(1.0, tk.END).strip()
        
        # Skip if empty or just the placeholder
        if not message or message == "Type your question here...":
            return
        
        # Check if assistant is available
        if not self.online_assistant or not self.online_assistant.is_available():
            self.add_online_system_message("Online AI Assistant is not available. Please check your API key.")
            return
        
        # Add user message to chat
        self.add_online_user_message(message)
        
        # Clear input field
        self.online_user_input.delete(1.0, tk.END)
        
        # Disable send button
        self.online_send_btn.config(state=tk.DISABLED)
        self.update_status("Getting online response...")
        
        # Send message to assistant in a separate thread
        threading.Thread(target=self._get_online_response, args=(message,), daemon=True).start()
    
    def _get_online_response(self, message):
        """Get response from online AI assistant"""
        try:
            # Get response from assistant
            response = self.online_assistant.ask(message)
            
            # Add response to chat
            self.add_online_assistant_message(response)
            
            # Update status
            self.update_status("Ready")
        except Exception as e:
            # Log error
            error_message = f"Error getting response: {str(e)}"
            self.log_message(error_message, error=True)
            
            # Add error message to chat
            self.add_online_system_message(f"Error: {str(e)}")
            
            # Update status
            self.update_status("Error getting response")
        finally:
            # Re-enable send button
            self.enable_online_input()
    
    def ask_online_quick_question(self, question):
        """Ask a predefined quick question to online assistant"""
        # Clear any placeholder
        self.online_user_input.delete(1.0, tk.END)
        # Set the question in the input field
        self.online_user_input.insert(tk.END, question)
        # Send the message
        self.send_online_message()
    
    def add_online_user_message(self, message):
        """Add a user message to the online chat output"""
        self.online_chat_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        self.online_chat_output.insert(tk.END, f"[{timestamp}] You: ", "user")
        
        # Add message
        self.online_chat_output.insert(tk.END, f"{message}\n\n")
        
        # Scroll to bottom
        self.online_chat_output.see(tk.END)
        self.online_chat_output.config(state=tk.DISABLED)
    
    def add_online_assistant_message(self, message):
        """Add an assistant message to the online chat output"""
        self.online_chat_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        self.online_chat_output.insert(tk.END, f"[{timestamp}] Assistant: ", "assistant")
        
        # Add message
        self.online_chat_output.insert(tk.END, f"{message}\n\n")
        
        # Scroll to bottom
        self.online_chat_output.see(tk.END)
        self.online_chat_output.config(state=tk.DISABLED)
    
    def add_online_system_message(self, message):
        """Add a system message to the online chat output"""
        self.online_chat_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        self.online_chat_output.insert(tk.END, f"[{timestamp}] System: ", "system")
        
        # Add message
        self.online_chat_output.insert(tk.END, f"{message}\n\n")
        
        # Scroll to bottom
        self.online_chat_output.see(tk.END)
        self.online_chat_output.config(state=tk.DISABLED)
    
    def update_online_model_info(self, message):
        """Update the online model info message"""
        if self.dialog.winfo_exists():
            self.online_model_var.set(message)
    
    def enable_online_input(self):
        """Enable the online input field and send button"""
        if self.dialog.winfo_exists():
            self.online_send_btn.config(state=tk.NORMAL)
    
    # Offline assistant methods
    def handle_offline_enter(self, event):
        """Handle Enter key press in offline input"""
        # If Shift+Enter, allow normal behavior (new line)
        if event.state & 0x1:  # Shift is pressed
            return
        
        # Otherwise, send the message
        self.send_offline_message()
        return "break"  # Prevent default Enter behavior
    
    def send_offline_message(self):
        """Send message to offline assistant"""
        # Get message text
        message = self.offline_user_input.get(1.0, tk.END).strip()
        
        # Skip if empty or just the placeholder
        if not message or message == "Ask a security question...":
            return
        
        # Offline functionality has been removed
        self.add_offline_system_message("Offline Security Helper has been removed. Please use the Online AI Assistant.")
        return
        
        # Add user message to chat
        self.add_offline_user_message(message)
        
        # Clear input field
        self.offline_user_input.delete(1.0, tk.END)
        
        # Disable send button
        self.offline_send_btn.config(state=tk.DISABLED)
        self.update_status("Getting offline response...")
        
        # Send message to assistant in a separate thread
        threading.Thread(target=self._get_offline_response, args=(message,), daemon=True).start()
    
    def _get_offline_response(self, message):
        """Get response from offline AI assistant"""
        try:
            # Get response from assistant
            response = self.offline_assistant.ask_question(message, "wifi_security")
            
            # Add response to chat
            self.add_offline_assistant_message(response)
            
            # Update status
            self.update_status("Ready")
        except Exception as e:
            # Log error
            error_message = f"Error getting response: {str(e)}"
            self.log_message(error_message, error=True)
            
            # Add error message to chat
            self.add_offline_system_message(f"Error: {str(e)}")
            
            # Update status
            self.update_status("Error getting response")
        finally:
            # Re-enable send button
            self.enable_offline_input()
    
    def ask_offline_quick_question(self, question):
        """Ask a predefined quick question to offline assistant"""
        # Clear any placeholder
        self.offline_user_input.delete(1.0, tk.END)
        # Set the question in the input field
        self.offline_user_input.insert(tk.END, question)
        # Send the message
        self.send_offline_message()
    
    def add_offline_user_message(self, message):
        """Add a user message to the offline chat output"""
        self.offline_chat_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        self.offline_chat_output.insert(tk.END, f"[{timestamp}] You: ", "user")
        
        # Add message
        self.offline_chat_output.insert(tk.END, f"{message}\n\n")
        
        # Scroll to bottom
        self.offline_chat_output.see(tk.END)
        self.offline_chat_output.config(state=tk.DISABLED)
    
    def add_offline_assistant_message(self, message):
        """Add an assistant message to the offline chat output"""
        self.offline_chat_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        self.offline_chat_output.insert(tk.END, f"[{timestamp}] Helper: ", "assistant")
        
        # Add message
        self.offline_chat_output.insert(tk.END, f"{message}\n\n")
        
        # Scroll to bottom
        self.offline_chat_output.see(tk.END)
        self.offline_chat_output.config(state=tk.DISABLED)
    
    def add_offline_system_message(self, message):
        """Add a system message to the offline chat output"""
        self.offline_chat_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        self.offline_chat_output.insert(tk.END, f"[{timestamp}] System: ", "system")
        
        # Add message
        self.offline_chat_output.insert(tk.END, f"{message}\n\n")
        
        # Scroll to bottom
        self.offline_chat_output.see(tk.END)
        self.offline_chat_output.config(state=tk.DISABLED)
    
    def enable_offline_input(self):
        """Enable the offline input field and send button"""
        if self.dialog.winfo_exists():
            self.offline_send_btn.config(state=tk.NORMAL)
    
    # Network analysis methods
    def upload_network_scan(self):
        """Upload a network scan file for analysis"""
        # Open file dialog
        file_path = filedialog.askopenfilename(
            title="Upload Network Scan",
            filetypes=[
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        # Read file and analyze
        self.update_status(f"Analyzing {os.path.basename(file_path)}...")
        
        # Process in a thread
        threading.Thread(target=self._process_scan_file, args=(file_path,), daemon=True).start()
    
    def _process_scan_file(self, file_path):
        """Process a network scan file in a separate thread"""
        try:
            # Read file based on extension
            ext = os.path.splitext(file_path)[1].lower()
            data = None
            
            with open(file_path, 'r') as f:
                if ext == '.json':
                    data = json.load(f)
                else:
                    data = f.read()
            
            # We now only use online AI
            # Try to analyze with online assistant instead
            if self.online_assistant and self.online_assistant.is_available():
                prompt = f"Analyze this network data: {str(data)[:1000]}..." if len(str(data)) > 1000 else str(data)
                result = self._get_online_response(prompt)
                self.update_analyze_output(result)
            else:
                self.update_analyze_output("Online AI assistant is required for analysis. Please set your API key.")
        except Exception as e:
            self.update_analyze_output(f"Error analyzing file: {str(e)}")
        finally:
            self.update_status("Ready")
    
    def analyze_network(self, analysis_type):
        """Perform a specific network analysis"""
        self.update_status(f"Running {analysis_type} analysis...")
        
        # Process in a thread
        threading.Thread(target=self._run_analysis, args=(analysis_type,), daemon=True).start()
    
    def _run_analysis(self, analysis_type):
        """Run network analysis in a separate thread"""
        try:
            # Map analysis type to function
            result = "Analysis not implemented."
            
            # Using online assistant instead of offline
            if self.online_assistant and self.online_assistant.is_available():
                # Create appropriate prompt based on analysis type
                if analysis_type == "common_vulns":
                    prompt = "Analyze my network for common WiFi vulnerabilities and provide recommendations."
                elif analysis_type == "rogue_ap":
                    prompt = "Explain how to detect rogue access points in my network and what risks they pose."
                elif analysis_type == "weak_encryption":
                    prompt = "Check for weak encryption in my WiFi networks and provide security recommendations."
                elif analysis_type == "default_creds":
                    prompt = "Explain how to identify devices using default credentials in my network."
                else:
                    prompt = f"Analyze my network for {analysis_type} issues."
                
                # Get response from online AI
                result = self._get_online_response(prompt)
                self.update_analyze_output(result)
            else:
                self.update_analyze_output("Online AI assistant is required for analysis. Please set your API key.")
        except Exception as e:
            self.update_analyze_output(f"Error during analysis: {str(e)}")
        finally:
            self.update_status("Ready")
    
    def update_analyze_output(self, text):
        """Update the analysis output text"""
        self.analyze_output.config(state=tk.NORMAL)
        self.analyze_output.delete(1.0, tk.END)
        self.analyze_output.insert(tk.END, text)
        self.analyze_output.config(state=tk.DISABLED)
    
    # Report generation methods
    def preview_report(self):
        """Preview the security report"""
        self.update_status("Generating report preview...")
        
        # Process in a thread
        threading.Thread(target=self._generate_report_preview, daemon=True).start()
    
    def _generate_report_preview(self):
        """Generate report preview in a separate thread"""
        try:
            # Get report options
            company = self.company_var.get() or "Client Company"
            title = self.report_title_var.get() or "WiFi Security Assessment Report"
            include_scan = self.include_scan_var.get()
            include_vulns = self.include_vulns_var.get()
            include_rec = self.include_rec_var.get()
            
            # Generate preview
            preview = f"# {title}\n\n"
            preview += f"Company: {company}\n"
            preview += f"Date: {datetime.now().strftime('%Y-%m-%d')}\n\n"
            
            # Add sections based on options
            if include_scan:
                preview += "## Network Scan Results\n\n"
                preview += "- Access Points: 12\n"
                preview += "- Clients: 25\n"
                preview += "- Encryption: WPA2-PSK (8), WPA2-Enterprise (2), WPA (1), Open (1)\n\n"
            
            if include_vulns:
                preview += "## Vulnerabilities Found\n\n"
                preview += "1. **High Risk**: WPS Enabled on 3 access points\n"
                preview += "2. **Medium Risk**: Weak passwords detected\n"
                preview += "3. **Medium Risk**: Default SSID in use\n"
                preview += "4. **Low Risk**: MAC filtering not enabled\n\n"
            
            if include_rec:
                preview += "## Recommendations\n\n"
                preview += "1. Disable WPS on all access points\n"
                preview += "2. Use strong, complex passwords for all WiFi networks\n"
                preview += "3. Change default SSIDs to non-identifying names\n"
                preview += "4. Enable MAC filtering as an additional security layer\n"
                preview += "5. Consider implementing 802.1X authentication for corporate networks\n\n"
            
            preview += "## Summary\n\n"
            preview += "The WiFi security assessment found several vulnerabilities that should be addressed. "
            preview += "Overall security posture is rated as MEDIUM RISK, with recommended actions outlined above."
            
            # Update preview
            self.update_report_preview(preview)
        except Exception as e:
            self.update_report_preview(f"Error generating preview: {str(e)}")
        finally:
            self.update_status("Ready")
    
    def generate_report(self):
        """Generate and save PDF report"""
        self.update_status("Generating PDF report...")
        
        # Process in a thread
        threading.Thread(target=self._generate_pdf_report, daemon=True).start()
    
    def _generate_pdf_report(self):
        """Generate PDF report in a separate thread"""
        try:
            # Get report options
            company = self.company_var.get() or "Client Company"
            title = self.report_title_var.get() or "WiFi Security Assessment Report"
            
            # Get save location
            file_path = filedialog.asksaveasfilename(
                title="Save Report",
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf")]
            )
            
            if not file_path:
                self.update_status("Report generation cancelled")
                return
            
            # Create reports directory if it doesn't exist
            os.makedirs("reports", exist_ok=True)
            
            # Import the comprehensive report generator
            from src.comprehensive_report import ComprehensiveReport
            
            # Create a report generator instance
            report_gen = ComprehensiveReport()
            
            # Set metadata
            report_gen.set_metadata(
                company_name=company,
                report_title=title
            )
            
            # Get network scan data
            network_scan_data = self._collect_network_scan_data()
            if network_scan_data:
                report_gen.add_network_scan_data(network_scan_data)
            
            # Get attack data
            attack_data = self._collect_attack_data()
            for attack in attack_data:
                report_gen.add_attack_data(attack)
            
            # Get traffic analysis data
            traffic_data = self._collect_traffic_analysis_data()
            if traffic_data:
                report_gen.add_traffic_analysis_data(traffic_data)
            
            # Get post-exploitation data
            post_exploitation_data = self._collect_post_exploitation_data()
            if post_exploitation_data:
                report_gen.add_post_exploitation_data(post_exploitation_data)
            
            # Get vulnerabilities
            vulnerabilities = self._collect_vulnerability_data()
            for vuln in vulnerabilities:
                report_gen.add_vulnerability(vuln)
            
            # Generate recommendations based on available AI
            if self.online_assistant and self.online_assistant.is_available():
                self.update_status("Using online AI to enhance recommendations...")
                report_gen.generate_recommendations(self.online_assistant)
            else:
                # Use standard recommendations without AI when no API key is available
                self.update_status("Using built-in recommendations...")
                report_gen.generate_recommendations(None)
            
            # Generate charts for visualization
            report_gen.generate_charts()
            
            # Generate the PDF report
            self.update_status("Creating comprehensive PDF report...")
            report_path = report_gen.generate_pdf_report(file_path)
            
            # Show success message
            if report_path and os.path.exists(report_path):
                messagebox.showinfo("Report Generated", f"Comprehensive report saved to: {report_path}")
                self.update_status(f"Report saved to: {report_path}")
            else:
                messagebox.showerror("Report Generation Failed", "Failed to generate report")
                self.update_status("Report generation failed")
        except Exception as e:
            messagebox.showerror("Error", f"Report generation failed: {str(e)}")
            self.update_status(f"Report generation failed: {str(e)}")
    
    def _collect_network_scan_data(self):
        """Collect network scan data for reporting"""
        try:
            # Try to get data from controller or stored data
            if hasattr(self, 'controller') and self.controller:
                # Check if controller has access to scan results
                if hasattr(self.controller, 'scan_results') and self.controller.scan_results:
                    ap_list = []
                    for ap in self.controller.scan_results:
                        ap_data = {
                            "ssid": ap.get("essid", "Unknown"),
                            "bssid": ap.get("bssid", "Unknown"),
                            "channel": ap.get("channel", 0),
                            "signal": ap.get("power", 0),
                            "encryption": ap.get("encryption", "Unknown"),
                            "wps_enabled": ap.get("wps", False),
                            "clients": len(ap.get("clients", []))
                        }
                        ap_list.append(ap_data)
                    
                    # Check if hosts are available
                    hosts_list = []
                    if hasattr(self.controller, 'hosts') and self.controller.hosts:
                        for host in self.controller.hosts:
                            host_data = {
                                "ip": host.get("ip", "Unknown"),
                                "hostname": host.get("hostname", "Unknown"),
                                "mac": host.get("mac", "Unknown"),
                                "vendor": host.get("vendor", "Unknown"),
                                "os": host.get("os", "Unknown"),
                                "open_ports": host.get("open_ports", [])
                            }
                            hosts_list.append(host_data)
                    
                    return {
                        "access_points": ap_list,
                        "hosts": hosts_list
                    }
            
            # Return sample data structure
            return {
                "access_points": [],
                "hosts": []
            }
        except Exception as e:
            print(f"Error collecting network scan data: {str(e)}")
            return {}
    
    def _collect_attack_data(self):
        """Collect attack data for reporting"""
        try:
            # Try to get data from controller or stored data
            attacks = []
            if hasattr(self, 'controller') and self.controller:
                # Check if controller has access to attack results
                if hasattr(self.controller, 'attack_results') and self.controller.attack_results:
                    for attack in self.controller.attack_results:
                        attack_data = {
                            "type": attack.get("type", "Unknown"),
                            "target": attack.get("target", "Unknown"),
                            "ssid": attack.get("ssid", "Unknown"),
                            "success": attack.get("success", False),
                            "details": attack.get("details", "No details available"),
                            "time_taken": attack.get("time_taken", "Unknown")
                        }
                        
                        # Add specific attack data
                        if attack.get("type") == "wpa_handshake" and attack.get("success"):
                            attack_data["password"] = attack.get("password", "Unknown")
                        
                        if attack.get("type") == "deauth" and attack.get("success"):
                            attack_data["affected_clients"] = attack.get("affected_clients", 0)
                        
                        attacks.append(attack_data)
            
            return attacks
        except Exception as e:
            print(f"Error collecting attack data: {str(e)}")
            return []
    
    def _collect_traffic_analysis_data(self):
        """Collect traffic analysis data for reporting"""
        try:
            # Try to get data from traffic monitor
            if hasattr(self, 'controller') and self.controller:
                # Check if controller has traffic monitor data
                if hasattr(self.controller, 'traffic_monitor') and self.controller.traffic_monitor:
                    traffic_monitor = self.controller.traffic_monitor
                    
                    # Collect stats
                    stats = {
                        "total_packets": traffic_monitor.total_packets if hasattr(traffic_monitor, 'total_packets') else 0,
                        "total_bytes": traffic_monitor.total_bytes if hasattr(traffic_monitor, 'total_bytes') else 0,
                        "total_hosts": len(traffic_monitor.ip_stats) if hasattr(traffic_monitor, 'ip_stats') else 0
                    }
                    
                    # Collect protocol stats
                    protocol_stats = traffic_monitor.protocol_stats if hasattr(traffic_monitor, 'protocol_stats') else {}
                    
                    # Collect sensitive data findings
                    sensitive_data = []
                    if hasattr(traffic_monitor, 'sensitive_data_alerts'):
                        for alert in traffic_monitor.sensitive_data_alerts:
                            sensitive_data.append({
                                "type": alert.get("type", "Unknown"),
                                "protocol": alert.get("protocol", "Unknown"),
                                "source": alert.get("source", "Unknown"),
                                "destination": alert.get("destination", "Unknown"),
                                "details": alert.get("description", "No details available")
                            })
                    
                    # Check for unencrypted protocols
                    unencrypted_protocols = []
                    if protocol_stats:
                        for protocol in ["HTTP", "FTP", "TELNET", "SMTP", "POP3", "SNMP"]:
                            if protocol in protocol_stats and protocol_stats[protocol] > 0:
                                unencrypted_protocols.append(protocol)
                    
                    # Check for unusual traffic
                    unusual_traffic = []
                    if hasattr(traffic_monitor, 'traffic_alerts'):
                        for alert in traffic_monitor.traffic_alerts:
                            unusual_traffic.append({
                                "type": alert.get("type", "Unknown activity"),
                                "description": alert.get("description", "No details available")
                            })
                    
                    return {
                        "stats": stats,
                        "protocol_stats": protocol_stats,
                        "sensitive_data_found": sensitive_data,
                        "unencrypted_protocols": unencrypted_protocols,
                        "unusual_traffic": unusual_traffic
                    }
            
            return {}
        except Exception as e:
            print(f"Error collecting traffic analysis data: {str(e)}")
            return {}
    
    def _collect_post_exploitation_data(self):
        """Collect post-exploitation data for reporting"""
        try:
            # Try to get data from controller or stored data
            if hasattr(self, 'controller') and self.controller:
                # Check if controller has post-exploitation module
                if hasattr(self.controller, 'post_exploitation') and self.controller.post_exploitation:
                    post_module = self.controller.post_exploitation
                    
                    # Network map
                    network_map = {
                        "gateway": post_module.gateway_ip if hasattr(post_module, 'gateway_ip') else "Unknown",
                        "subnet": post_module.subnet if hasattr(post_module, 'subnet') else "Unknown",
                        "dhcp_server": post_module.dhcp_server if hasattr(post_module, 'dhcp_server') else "Unknown",
                        "dns_servers": post_module.dns_servers if hasattr(post_module, 'dns_servers') else []
                    }
                    
                    # Hosts
                    hosts = []
                    if hasattr(post_module, 'hosts') and post_module.hosts:
                        for host in post_module.hosts:
                            host_data = {
                                "ip": host.ip if hasattr(host, 'ip') else "Unknown",
                                "hostname": host.hostname if hasattr(host, 'hostname') else "Unknown",
                                "os": host.os if hasattr(host, 'os') else "Unknown",
                                "type": host.type if hasattr(host, 'type') else "unknown",
                                "compromised": host.compromised if hasattr(host, 'compromised') else False,
                                "access_level": host.access_level if hasattr(host, 'access_level') else "None"
                            }
                            
                            # Vulnerabilities
                            if hasattr(host, 'vulnerabilities') and host.vulnerabilities:
                                host_data["vulnerabilities"] = host.vulnerabilities
                            
                            # Default credentials
                            if hasattr(host, 'default_credentials'):
                                host_data["default_credentials"] = host.default_credentials
                            
                            # Missing patches
                            if hasattr(host, 'missing_patches') and host.missing_patches:
                                host_data["missing_patches"] = host.missing_patches
                            
                            # Privilege escalation
                            if hasattr(host, 'privilege_escalation') and host.privilege_escalation:
                                host_data["privilege_escalation"] = host.privilege_escalation
                            
                            hosts.append(host_data)
                    
                    # Lateral movement
                    lateral_movement = {
                        "successful": False
                    }
                    if hasattr(post_module, 'lateral_movement') and post_module.lateral_movement:
                        lateral_movement = post_module.lateral_movement
                    
                    return {
                        "network_map": network_map,
                        "hosts": hosts,
                        "lateral_movement": lateral_movement
                    }
            
            return {}
        except Exception as e:
            print(f"Error collecting post-exploitation data: {str(e)}")
            return {}
    
    def _collect_vulnerability_data(self):
        """Collect vulnerability data for reporting"""
        try:
            # Collected vulnerabilities
            vulnerabilities = []
            
            # Try to collect from controller
            if hasattr(self, 'controller') and self.controller:
                # Check if controller has vulnerability data
                if hasattr(self.controller, 'vulnerabilities') and self.controller.vulnerabilities:
                    vulnerabilities.extend(self.controller.vulnerabilities)
            
            return vulnerabilities
        except Exception as e:
            print(f"Error collecting vulnerability data: {str(e)}")
            return []
    
    def update_report_preview(self, text):
        """Update the report preview text"""
        self.report_preview.config(state=tk.NORMAL)
        self.report_preview.delete(1.0, tk.END)
        self.report_preview.insert(tk.END, text)
        self.report_preview.config(state=tk.DISABLED)
    
    # Error fixing methods
    def analyze_error(self):
        """Analyze and fix an error described by the user"""
        # Get error description
        error_desc = self.error_input.get(1.0, tk.END).strip()
        
        # Skip if empty or just the placeholder
        if not error_desc or error_desc == "Describe your WiFi security issue or error message...":
            messagebox.showwarning("Input Required", "Please describe the issue you're experiencing")
            return
        
        self.update_status("Analyzing issue...")
        
        # Process in a thread
        threading.Thread(target=self._analyze_error, args=(error_desc,), daemon=True).start()
    
    def _analyze_error(self, error_desc):
        """Analyze error in a separate thread"""
        try:
            # We now use online AI exclusively
            if self.online_assistant and self.online_assistant.is_available():
                # Use online assistant for error analysis
                prompt = f"Diagnose and fix this WiFi security or penetration testing error: {error_desc}"
                solution = self._get_online_response(prompt)
                self.update_fix_output(solution)
            else:
                self.update_fix_output("Online AI assistant is required for error analysis. Please set your API key.")
        except Exception as e:
            self.update_fix_output(f"Error analyzing issue: {str(e)}")
        finally:
            self.update_status("Ready")
    
    def select_common_issue(self, issue):
        """Select a common issue from the list"""
        # Set the issue in the input field
        self.error_input.delete(1.0, tk.END)
        self.error_input.insert(tk.END, issue)
        
        # Trigger analysis
        self.analyze_error()
    
    def update_fix_output(self, text):
        """Update the fix output text"""
        self.fix_output.config(state=tk.NORMAL)
        self.fix_output.delete(1.0, tk.END)
        self.fix_output.insert(tk.END, text)
        self.fix_output.config(state=tk.DISABLED)
    
    # General utility methods
    def _clear_placeholder(self, text_widget):
        """Clear placeholder text when user clicks in the input field"""
        text = text_widget.get(1.0, tk.END).strip()
        if text == "Type your question here..." or \
           text == "Ask a security question..." or \
           text == "Describe your WiFi security issue or error message...":
            text_widget.delete(1.0, tk.END)
    
    def update_status(self, message):
        """Update the status message"""
        if self.dialog.winfo_exists():
            self.status_var.set(message)
    
    def log_message(self, message, error=False, warning=False):
        """Log a message to console and status bar"""
        prefix = ""
        if error:
            prefix = "[ERROR] "
        elif warning:
            prefix = "[WARNING] "
        
        # Log to console
        print(f"{prefix}{message}")
        
        # Update status bar
        self.update_status(message)
    
    def on_close(self):
        """Handle dialog close event"""
        # Clean up resources
        if self.online_assistant:
            pass  # Any cleanup needed
            
        # We now only use online AI, removed offline assistant check
            
        # Call custom close callback if provided
        if self.on_close_callback:
            self.on_close_callback()
            
        # Destroy dialog
        self.dialog.destroy()


# Test function to launch the helper
def test_unified_ai_helper():
    """Test function to launch the unified AI helper"""
    root = tk.Tk()
    root.title("Test")
    root.geometry("300x200")
    
    def show_helper():
        UnifiedAIHelper(root)
    
    button = ttk.Button(root, text="Show AI Helper", command=show_helper)
    button.pack(pady=20)
    
    root.mainloop()


if __name__ == "__main__":
    test_unified_ai_helper()