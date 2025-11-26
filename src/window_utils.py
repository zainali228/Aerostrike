#!/usr/bin/env python3
"""
Cross-platform window utility functions for WiFi Penetration Testing Tool
Ensures consistent behavior across Windows, Linux, and macOS
"""

import tkinter as tk
from tkinter import ttk
import platform

def maximize_window(window):
    """
    Maximize a window in a platform-independent way
    
    Args:
        window: The window to maximize
    """
    try:
        # Try Windows-specific approach first
        window.state('zoomed')
    except Exception:
        # Fallback for Linux/macOS
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        window.geometry(f"{screen_width-50}x{screen_height-50}+25+25")
    
    # Set custom attribute for state tracking
    window.is_maximized = True

def restore_window(window):
    """
    Restore a window from maximized state
    
    Args:
        window: The window to restore
    """
    try:
        # Try standard method first
        window.state('normal')
    except Exception:
        # Fallback to a reasonable size
        window.geometry("800x600+100+100")
    
    # Update state tracking
    window.is_maximized = False

def toggle_window_state(window, button=None):
    """
    Toggle a window between maximized and normal states
    
    Args:
        window: The window to toggle
        button: Optional button to update (text changes based on state)
    """
    is_maximized = getattr(window, 'is_maximized', False)
    
    if is_maximized:
        restore_window(window)
        if button:
            button.config(text="□")
    else:
        maximize_window(window)
        if button:
            button.config(text="■")

def create_maximize_button(parent, window):
    """
    Create a maximize/restore button for a window
    
    Args:
        parent: Parent widget for the button
        window: Window to control
        
    Returns:
        Button widget
    """
    # Initialize state tracking attribute
    window.is_maximized = False
    
    # Create button with toggle function
    max_btn = ttk.Button(
        parent, 
        text="□", 
        width=2,
        command=lambda: toggle_window_state(window, max_btn)
    )
    
    return max_btn

def center_window(window):
    """
    Center a window on the screen
    
    Args:
        window: Window to center
    """
    # Make sure window size is updated
    window.update_idletasks()
    
    # Get dimensions
    width = window.winfo_width()
    height = window.winfo_height()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    
    # Calculate position
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    
    # Position window
    window.geometry(f"+{x}+{y}")