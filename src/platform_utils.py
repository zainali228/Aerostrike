#!/usr/bin/env python3
"""
Platform-specific utilities for WiFi Penetration Testing Tool
Provides cross-platform compatibility functions
"""

import tkinter as tk
import platform
import os

def maximize_window(window):
    """
    Maximize a window in a cross-platform compatible way
    
    Args:
        window: The window to maximize
    """
    system = platform.system()
    
    try:
        if system == "Windows":
            # Windows-specific
            window.state('zoomed')
        elif system == "Linux":
            # Linux-specific (using geometry)
            screen_width = window.winfo_screenwidth()
            screen_height = window.winfo_screenheight()
            window.geometry(f"{screen_width-50}x{screen_height-50}+25+25")
        elif system == "Darwin":
            # macOS-specific
            screen_width = window.winfo_screenwidth()
            screen_height = window.winfo_screenheight()
            window.geometry(f"{screen_width-50}x{screen_height-50}+25+25")
        else:
            # Generic fallback
            screen_width = window.winfo_screenwidth()
            screen_height = window.winfo_screenheight()
            window.geometry(f"{screen_width-100}x{screen_height-100}+50+50")
            
        # Set custom attribute for tracking maximized state
        window.is_maximized = True
    except Exception as e:
        print(f"Warning: Could not maximize window: {e}")
        window.is_maximized = False

def restore_window(window):
    """
    Restore a window from maximized state
    
    Args:
        window: The window to restore
    """
    try:
        # Try standard method first
        window.state('normal')
    except:
        # Fallback to a reasonable size
        window.geometry("800x600+50+50")
        
    # Update maximized state tracking
    window.is_maximized = False

def toggle_maximize(window, button=None):
    """
    Toggle window between maximized and normal state
    
    Args:
        window: The window to toggle
        button: Optional button to update text
    """
    is_max = getattr(window, 'is_maximized', False)
    
    if is_max:
        restore_window(window)
        if button:
            button.config(text="□")
    else:
        maximize_window(window)
        if button:
            button.config(text="■")