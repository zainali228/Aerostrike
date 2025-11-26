#!/usr/bin/env python3
"""
Aero Strike (AI-Powered Wifi Penetration Testing Tool)
Network scanning and wireless security testing for security professionals
"""

import os
import sys
import tkinter as tk
from tkinter import messagebox
import subprocess

# Create necessary directories
os.makedirs("reports", exist_ok=True)
os.makedirs("captures", exist_ok=True)
os.makedirs("logs", exist_ok=True)

try:
    # Check if running as root (required for most WiFi operations)
    is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
    
    # Import GUI
    from src.wifipentest_gui import WiFiPentestGUI
    
    # Start the application
    if __name__ == "__main__":
        root = tk.Tk()
        root.title("Aero Strike (AI-Powered Wifi Penetration Testing Tool)")
        
        # Set window size and position
        window_width = 1100
        window_height = 700
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Create app
        app = WiFiPentestGUI(root)
        
        # Start main loop
        root.mainloop()
        
except Exception as e:
    # Handle initialization errors
    print(f"Error starting application: {str(e)}")
    try:
        messagebox.showerror("Error", f"Failed to start application: {str(e)}")
    except:
        # If tkinter is not available, just print to console
        print("GUI initialization failed. This application requires GUI support.")
    sys.exit(1)