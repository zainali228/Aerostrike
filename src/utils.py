#!/usr/bin/env python3
"""
Utility functions for WiFi Penetration Testing Tool
"""

import os
import json
import tkinter as tk
from io import BytesIO
import base64

# Configuration file path
CONFIG_FILE = os.path.expanduser("~/.config/wifipentest/config.json")

def save_config(config_data):
    """Save configuration to JSON file
    
    Args:
        config_data: Configuration dictionary to save
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        
        # Write config file
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_data, f, indent=2)
            
        return True
    except Exception as e:
        print(f"Error saving configuration: {str(e)}")
        return False
        
def load_config():
    """Load configuration from JSON file
    
    Returns:
        dict: Configuration dictionary or None if file not found
    """
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        print(f"Error loading configuration: {str(e)}")
        return {}
        
def get_icon_as_image(width=64, height=64):
    """Generate a robot icon as a tkinter PhotoImage
    
    Instead of loading from a file, we generate one dynamically from SVG data.
    This ensures we have an icon even if asset files are missing.
    
    Args:
        width: Icon width
        height: Icon height
        
    Returns:
        PhotoImage: Tkinter PhotoImage object
    """
    try:
        # Check if we have the icon file
        icon_path = os.path.join("assets", "robot_icon.svg")
        if os.path.exists(icon_path):
            # Use a library that can render SVG if available
            try:
                from PIL import Image, ImageTk
                import cairosvg
                
                # Convert SVG to PNG in memory
                png_data = BytesIO()
                with open(icon_path, 'rb') as f:
                    cairosvg.svg2png(file_obj=f, write_to=png_data, 
                                    output_width=width, output_height=height)
                png_data.seek(0)
                
                # Create PhotoImage
                pil_img = Image.open(png_data)
                return ImageTk.PhotoImage(pil_img)
            except ImportError:
                # Fall back to generating icon
                pass
                
        # Generate a simple icon (a colored rectangle)
        icon = tk.PhotoImage(width=width, height=height)
        for y in range(height):
            for x in range(width):
                # Create a blue-to-purple gradient
                r = int(100 + (x / width) * 100)
                g = int(50 + (y / height) * 50)
                b = int(150 + ((x + y) / (width + height)) * 100)
                color = f'#{r:02x}{g:02x}{b:02x}'
                icon.put(color, (x, y))
                
        return icon
    except Exception as e:
        print(f"Error creating icon: {str(e)}")
        # Return a blank image if all else fails
        return tk.PhotoImage(width=width, height=height)

def format_mac_address(mac):
    """Format MAC address consistently
    
    Args:
        mac: MAC address string
    
    Returns:
        str: Formatted MAC address (XX:XX:XX:XX:XX:XX)
    """
    if not mac:
        return ""
        
    # Remove any separators and convert to uppercase
    clean_mac = ''.join(c for c in mac if c.isalnum()).upper()
    
    # Format with colons
    if len(clean_mac) == 12:
        return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))
    else:
        return mac  # Return original if invalid
        
def format_signal_strength(dbm):
    """Convert dBm signal strength to percentage
    
    Args:
        dbm: Signal strength in dBm
    
    Returns:
        int: Signal strength percentage (0-100)
    """
    try:
        dbm_val = int(dbm)
        # Convert dBm to percentage (typical range: -30 to -90 dBm)
        # -30dBm (excellent) = 100%, -90dBm (unusable) = 0%
        if dbm_val >= -30:
            return 100
        elif dbm_val <= -90:
            return 0
        else:
            return min(100, max(0, int(2 * (dbm_val + 90))))
    except (ValueError, TypeError):
        return 0

def human_readable_file_size(size_bytes):
    """Convert bytes to human-readable format
    
    Args:
        size_bytes: Size in bytes
    
    Returns:
        str: Human-readable size (e.g., "1.23 MB")
    """
    if size_bytes < 0:
        return "0 B"
        
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    unit_index = 0
    
    while size_bytes >= 1024 and unit_index < len(units) - 1:
        size_bytes /= 1024
        unit_index += 1
        
    return f"{size_bytes:.2f} {units[unit_index]}"

def is_valid_interface(interface_name):
    """Check if interface name is valid
    
    Args:
        interface_name: Interface name to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    if not interface_name:
        return False
        
    # Check if it exists in /sys/class/net/
    return os.path.exists(f"/sys/class/net/{interface_name}")

def is_valid_bssid(bssid):
    """Check if BSSID is valid
    
    Args:
        bssid: BSSID string to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    if not bssid:
        return False
        
    # Format and check
    formatted = format_mac_address(bssid)
    
    # Check format (XX:XX:XX:XX:XX:XX)
    import re
    return bool(re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', formatted))

def sanitize_filename(filename):
    """Sanitize filename to be safe for filesystem
    
    Args:
        filename: Filename to sanitize
    
    Returns:
        str: Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
        
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
        
    return filename

def create_temp_directory(name):
    """Create a temporary directory for tool operations
    
    Args:
        name: Directory name
    
    Returns:
        str: Path to created directory
    """
    temp_dir = os.path.join("/tmp", name)
    os.makedirs(temp_dir, exist_ok=True)
    
    return temp_dir

def color_for_risk_level(risk_score):
    """Get color for risk level visualization
    
    Args:
        risk_score: Risk score (0-100)
    
    Returns:
        str: Hex color code
    """
    if risk_score >= 75:
        return "#ff5252"  # High risk - red
    elif risk_score >= 50:
        return "#ffb142"  # Medium risk - orange
    elif risk_score >= 25:
        return "#ffd966"  # Low risk - yellow
    else:
        return "#7bed9f"  # Secure - green
