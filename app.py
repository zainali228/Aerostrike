#!/usr/bin/env python3
"""
Aero Strike (AI-Powered Wifi Penetration Testing Tool)
For security professionals to assess WiFi networks, IoT devices, and cameras
with real-time scanning and attack capabilities
"""

import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
import threading
import argparse
import json
import logging
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import modules
from modules.gui_manager import GUIManager
from utils.config_manager import ConfigManager
from utils.security_utils import SecurityUtils

def setup_logging():
    """Configure logging for the application"""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"aerostrike_{timestamp}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("AeroStrike")

def check_development_environment():
    """Check if running in development environment"""
    return 'REPL_ID' in os.environ or 'REPLIT' in os.environ

def check_root_privileges():
    """Check if application is running with root privileges"""
    if check_development_environment():
        return True  # Skip check in dev environment
    
    if os.name == 'posix':
        return os.geteuid() == 0
    return True  # Skip check on non-POSIX systems

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='NetworkPentestPro - Wireless Penetration Testing Tool')
    parser.add_argument('--dev', action='store_true', help='Run in development mode (no hardware required)')
    parser.add_argument('--interface', type=str, help='Specify wireless interface to use')
    parser.add_argument('--theme', choices=['dark', 'light'], help='Specify UI theme')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    return parser.parse_args()

def main():
    """Main application entry point"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Check privileges
    is_dev_mode = args.dev or check_development_environment()
    if not is_dev_mode and not check_root_privileges():
        print("ERROR: This application requires root privileges.")
        print("Please run with sudo: sudo python3 app.py")
        sys.exit(1)
    
    # Initialize config manager
    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
    os.makedirs(config_dir, exist_ok=True)
    config_manager = ConfigManager(config_dir)
    
    # Load configuration
    config = config_manager.load_config()
    
    # Override configuration with command line arguments
    if args.interface:
        config['interface'] = args.interface
    if args.theme:
        config['theme'] = args.theme
    
    # Set development mode if required
    if is_dev_mode:
        logger.info("Running in DEVELOPMENT MODE (simulated hardware)")
        config['dev_mode'] = True
    
    # Initialize UI
    root = tk.Tk()
    root.title("NetworkPentestPro v3.0")
    
    # Set icon if available
    try:
        root.iconbitmap("static/icons/favicon.ico")
    except tk.TclError:
        logger.debug("Icon not found, using default")
    
    # Create GUI manager
    app = GUIManager(root, config, logger)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()
