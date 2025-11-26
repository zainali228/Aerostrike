#!/usr/bin/env python3
"""
AI Assistant GUI Module for Aero Strike (AI-Powered Wifi Penetration Testing Tool)
Provides user interface for interacting with the AI assistant
"""

import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from typing import Dict, List, Any, Optional, Callable

class AIAssistantGUI:
    """GUI for AI Assistant that provides real-time help for penetration testing"""
    
    def __init__(self, parent, controller=None, on_close_callback=None):
        """Initialize the AI Assistant GUI
        
        Args:
            parent: Parent tkinter window/frame
            controller: Main application controller
            on_close_callback: Function to call when dialog is closed
        """
        self.parent = parent
        self.controller = controller
        self.on_close_callback = on_close_callback
        self.assistant = None
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
        
        # Create the dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("AI Security Assistant")
        self.dialog.geometry("900x700")
        self.dialog.minsize(800, 600)
        
        # Configure dialog
        if self.dark_mode:
            self.dialog.configure(bg=self.bg_color)
        
        # Set dialog to be modal
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Handle close event
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Initialize UI components
        self.create_ui()
        
        # Initialize AI Assistant
        self.initialize_assistant()
    
    def create_ui(self):
        """Create all UI components"""
        # Main frame
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title and model info
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Left side - Title
        title_label = ttk.Label(
            title_frame, 
            text="AI Security Assistant",
            font=("Helvetica", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        # Right side - Model info
        self.model_var = tk.StringVar(value="Loading...")
        model_label = ttk.Label(
            title_frame,
            textvariable=self.model_var,
            font=("Helvetica", 10, "italic")
        )
        model_label.pack(side=tk.RIGHT)
        
        # Chat display
        chat_frame = ttk.Frame(main_frame)
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Chat output (conversation history)
        self.chat_output = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            bg=self.output_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10,
            state=tk.DISABLED
        )
        self.chat_output.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for different message types
        self.chat_output.tag_config("user", foreground="#4cc9f0", font=("Helvetica", 11, "bold"))
        self.chat_output.tag_config("assistant", foreground="#90be6d", font=("Helvetica", 11))
        self.chat_output.tag_config("system", foreground="#f9c74f", font=("Helvetica", 10, "italic"))
        
        # Input area
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(10, 0))
        
        # User input field
        self.user_input = scrolledtext.ScrolledText(
            input_frame,
            wrap=tk.WORD,
            height=4,
            bg=self.input_bg,
            fg=self.fg_color,
            font=("Helvetica", 11),
            padx=10,
            pady=10
        )
        self.user_input.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        # Bind Enter key to send (with Shift+Enter for new line)
        self.user_input.bind("<Return>", self.handle_enter)
        
        # Add placeholder text
        self.user_input.insert(tk.END, "Type your question here...")
        self.user_input.bind("<FocusIn>", self._clear_placeholder)
        
        # Buttons frame
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Send button
        self.send_btn = ttk.Button(
            button_frame,
            text="Send",
            command=self.send_message,
            state=tk.DISABLED
        )
        self.send_btn.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))
        
        # API Key button
        self.api_key_btn = ttk.Button(
            button_frame,
            text="API Key",
            command=self.set_api_key
        )
        self.api_key_btn.pack(side=tk.TOP, fill=tk.X)
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="Initializing...")
        status_label = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            font=("Helvetica", 9),
            anchor=tk.W
        )
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Quick question buttons
        self.create_quick_question_buttons(main_frame)
    
    def create_quick_question_buttons(self, parent):
        """Create buttons for quick questions"""
        quick_frame = ttk.LabelFrame(parent, text="Quick Questions")
        quick_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Grid for buttons
        button_frame = ttk.Frame(quick_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Define common questions
        questions = [
            "How do I capture a WPA handshake?",
            "What does the port scan result mean?",
            "How to crack a captured handshake?",
            "Explain WPS vulnerabilities",
            "Common WiFi security issues",
            "What is post-exploitation?"
        ]
        
        # Create buttons in a grid (2 rows x 3 columns)
        for i, question in enumerate(questions):
            row = i // 3
            col = i % 3
            
            btn = ttk.Button(
                button_frame,
                text=question,
                command=lambda q=question: self.ask_quick_question(q)
            )
            btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
        
        # Configure grid columns to have equal width
        for i in range(3):
            button_frame.columnconfigure(i, weight=1)
    
    def ask_quick_question(self, question):
        """Ask a predefined quick question"""
        # Clear any placeholder
        self.user_input.delete(1.0, tk.END)
        # Set the question in the input field
        self.user_input.insert(tk.END, question)
        # Send the message
        self.send_message()
    
    def _clear_placeholder(self, event):
        """Clear placeholder text when user clicks in the input field"""
        if self.user_input.get(1.0, tk.END).strip() == "Type your question here...":
            self.user_input.delete(1.0, tk.END)
    
    def handle_enter(self, event):
        """Handle Enter key press"""
        # If Shift+Enter, allow normal behavior (new line)
        if event.state & 0x1:  # Shift is pressed
            return
        
        # Otherwise, send the message
        self.send_message()
        return "break"  # Prevent default Enter behavior
    
    def initialize_assistant(self):
        """Initialize the AI Assistant"""
        self.update_status("Initializing AI Assistant...")
        
        # Start initialization in a separate thread
        threading.Thread(target=self._initialize_assistant_thread, daemon=True).start()
    
    def _initialize_assistant_thread(self):
        """Thread function to initialize the AI Assistant"""
        try:
            # Import the AI Assistant module
            from src.ai_assistant import AIAssistant
            
            # Get API key from environment (if exists)
            api_key = os.environ.get("OPENAI_API_KEY")
            
            # Initialize the assistant
            self.assistant = AIAssistant(
                use_openai=True, 
                api_key=api_key,
                log_callback=self.log_message
            )
            
            # Check if assistant is available
            if self.assistant.is_available():
                model_name = self.assistant.get_model_name()
                self.update_status(f"AI Assistant ready using {model_name}")
                self.update_model_info(f"Model: {model_name}")
                self.enable_input()
                
                # Add welcome message
                self.add_system_message("AI Assistant is ready to help with your security questions!")
            else:
                self.update_status("AI Assistant not available")
                self.update_model_info("No AI model available")
                self.add_system_message("AI Assistant is not available. Please check your API key or network connection.")
        except Exception as e:
            self.update_status(f"Error initializing AI Assistant: {str(e)}")
            self.add_system_message(f"Error initializing AI Assistant: {str(e)}")
    
    def send_message(self):
        """Send the user's message to the AI Assistant"""
        # Get message text
        message = self.user_input.get(1.0, tk.END).strip()
        
        # Skip if empty or just the placeholder
        if not message or message == "Type your question here...":
            return
        
        # Check if assistant is available
        if not self.assistant or not self.assistant.is_available():
            self.add_system_message("AI Assistant is not available. Please check your API key.")
            return
        
        # Add user message to chat
        self.add_user_message(message)
        
        # Clear input field
        self.user_input.delete(1.0, tk.END)
        
        # Disable send button
        self.send_btn.config(state=tk.DISABLED)
        self.update_status("Getting response...")
        
        # Send message to assistant in a separate thread
        threading.Thread(target=self._get_assistant_response, args=(message,), daemon=True).start()
    
    def _get_assistant_response(self, message):
        """Get response from AI Assistant in a separate thread"""
        try:
            # Get response from assistant
            response = self.assistant.ask(message)
            
            # Add response to chat
            self.add_assistant_message(response)
            
            # Update status
            self.update_status("Ready")
        except Exception as e:
            # Log error
            error_message = f"Error getting response: {str(e)}"
            self.log_message(error_message, error=True)
            
            # Add error message to chat
            self.add_system_message(f"Error: {str(e)}")
            
            # Update status
            self.update_status("Error getting response")
        finally:
            # Re-enable send button
            self.enable_input()
    
    def add_user_message(self, message):
        """Add a user message to the chat output"""
        self.chat_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        self.chat_output.insert(tk.END, f"[{timestamp}] You: ", "user")
        
        # Add message
        self.chat_output.insert(tk.END, f"{message}\n\n")
        
        # Scroll to bottom
        self.chat_output.see(tk.END)
        self.chat_output.config(state=tk.DISABLED)
    
    def add_assistant_message(self, message):
        """Add an assistant message to the chat output"""
        self.chat_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        self.chat_output.insert(tk.END, f"[{timestamp}] Assistant: ", "assistant")
        
        # Add message
        self.chat_output.insert(tk.END, f"{message}\n\n")
        
        # Scroll to bottom
        self.chat_output.see(tk.END)
        self.chat_output.config(state=tk.DISABLED)
    
    def add_system_message(self, message):
        """Add a system message to the chat output"""
        self.chat_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%H:%M:%S")
        self.chat_output.insert(tk.END, f"[{timestamp}] System: ", "system")
        
        # Add message
        self.chat_output.insert(tk.END, f"{message}\n\n")
        
        # Scroll to bottom
        self.chat_output.see(tk.END)
        self.chat_output.config(state=tk.DISABLED)
    
    def update_status(self, message):
        """Update the status message"""
        if self.dialog.winfo_exists():
            self.status_var.set(message)
    
    def update_model_info(self, message):
        """Update the model info message"""
        if self.dialog.winfo_exists():
            self.model_var.set(message)
    
    def enable_input(self):
        """Enable the input field and send button"""
        if self.dialog.winfo_exists():
            self.send_btn.config(state=tk.NORMAL)
    
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
        if self.assistant and self.assistant.api_key:
            api_key_var.set(self.assistant.api_key)
        
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
        
        # Reinitialize assistant
        self.update_status("Reinitializing with new API Key...")
        self.add_system_message("Reinitializing with new API Key...")
        
        threading.Thread(target=self._reinitialize_assistant, args=(api_key,), daemon=True).start()
    
    def _reinitialize_assistant(self, api_key):
        """Reinitialize the assistant with a new API key"""
        try:
            # Import the AI Assistant module
            from src.ai_assistant import AIAssistant
            
            # Initialize the assistant
            self.assistant = AIAssistant(
                use_openai=True, 
                api_key=api_key,
                log_callback=self.log_message
            )
            
            # Check if assistant is available
            if self.assistant.is_available():
                model_name = self.assistant.get_model_name()
                self.update_status(f"AI Assistant ready using {model_name}")
                self.update_model_info(f"Model: {model_name}")
                self.enable_input()
                
                # Add welcome message
                self.add_system_message("AI Assistant reinitialized successfully!")
            else:
                self.update_status("AI Assistant not available with the new API key")
                self.add_system_message("Failed to initialize AI Assistant with the new API key.")
        except Exception as e:
            self.update_status(f"Error reinitializing AI Assistant: {str(e)}")
            self.add_system_message(f"Error reinitializing AI Assistant: {str(e)}")
    
    def log_message(self, message, error=False, warning=False):
        """Log a message to the console and status bar"""
        if error:
            print(f"[ERROR] {message}")
            self.update_status(f"Error: {message}")
        elif warning:
            print(f"[WARNING] {message}")
            self.update_status(f"Warning: {message}")
        else:
            print(f"[INFO] {message}")
            self.update_status(message)
    
    def on_close(self):
        """Handle dialog close event"""
        # Call the on_close callback if provided
        if self.on_close_callback:
            self.on_close_callback()
        
        # Destroy the dialog
        self.dialog.destroy()
    
    def diagnose_error(self, error_traceback):
        """Use AI assistant to diagnose an error"""
        if not self.assistant or not self.assistant.is_available():
            self.add_system_message("AI Assistant is not available to diagnose errors.")
            return
        
        # Add error message
        self.add_system_message(f"Diagnosing error:\n{error_traceback}")
        
        # Disable send button
        self.send_btn.config(state=tk.DISABLED)
        
        # Update status
        self.update_status("Diagnosing error...")
        
        # Get diagnosis in a separate thread
        threading.Thread(target=self._get_error_diagnosis, args=(error_traceback,), daemon=True).start()
    
    def _get_error_diagnosis(self, error_traceback):
        """Get error diagnosis from AI Assistant in a separate thread"""
        try:
            # Get diagnosis
            diagnosis = self.assistant.diagnose_error(error_traceback)
            
            # Add diagnosis to chat
            self.add_assistant_message(diagnosis)
            
            # Update status
            self.update_status("Error diagnosis complete")
        except Exception as e:
            # Log error
            error_message = f"Error getting diagnosis: {str(e)}"
            self.log_message(error_message, error=True)
            
            # Add error message to chat
            self.add_system_message(f"Error: {str(e)}")
            
            # Update status
            self.update_status("Error getting diagnosis")
        finally:
            # Re-enable send button
            self.enable_input()
    
    def cleanup(self):
        """Clean up resources when closing"""
        pass  # Nothing to clean up currently

# Standalone test
if __name__ == "__main__":
    root = tk.Tk()
    root.title("AI Assistant Test")
    root.geometry("800x600")
    
    # Set dark mode for the root window
    root.configure(bg="#2d2d2d")
    
    # Create a button to open the assistant
    def open_assistant():
        AIAssistantGUI(root)
    
    button = ttk.Button(root, text="Open AI Assistant", command=open_assistant)
    button.pack(padx=20, pady=20)
    
    root.mainloop()