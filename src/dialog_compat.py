#!/usr/bin/env python3
"""
Cross-platform dialog compatibility utilities for WiFi Penetration Testing Tool
Ensures dialogs work properly on Windows, Linux, and macOS
"""

import tkinter as tk
import platform

def maximize_dialog(dialog):
    """
    Maximize a dialog window in a cross-platform compatible way
    
    Args:
        dialog: The dialog window to maximize
    """
    # Set custom attribute for tracking
    dialog.maximized = True
    
    # Try platform-specific maximization
    try:
        # Windows approach
        dialog.state('zoomed')
    except Exception:
        # Fallback for Linux/macOS
        width = dialog.winfo_screenwidth() - 100
        height = dialog.winfo_screenheight() - 100
        dialog.geometry(f"{width}x{height}+50+50")

def restore_dialog(dialog):
    """
    Restore a dialog window from maximized state
    
    Args:
        dialog: The dialog window to restore
    """
    # Reset custom attribute
    dialog.maximized = False
    
    # Try platform-specific restoration
    try:
        dialog.state('normal')
    except Exception:
        # Fallback for Linux/macOS
        dialog.geometry("800x600+50+50")

def toggle_maximize_dialog(dialog, button=None):
    """
    Toggle a dialog window between maximized and normal states
    
    Args:
        dialog: The dialog window to toggle
        button: Optional button to update its text
    """
    # Check current state using custom attribute
    is_maximized = hasattr(dialog, 'maximized') and dialog.maximized
    
    if is_maximized:
        restore_dialog(dialog)
        if button:
            button.config(text="□")
    else:
        maximize_dialog(dialog)
        if button:
            button.config(text="■")
            
def create_maximize_button(parent, dialog):
    """
    Create a maximize/restore button for a dialog
    
    Args:
        parent: Parent widget for the button
        dialog: Dialog window to control
        
    Returns:
        Button widget
    """
    # Initialize state tracking attribute
    dialog.maximized = False
    
    # Create button with toggle functionality
    max_btn = tk.Button(
        parent, 
        text="□", 
        width=2,
        command=lambda: toggle_maximize_dialog(dialog, max_btn)
    )
    
    return max_btn

def center_dialog(dialog):
    """
    Center a dialog on the screen
    
    Args:
        dialog: Dialog window to center
    """
    # Get screen dimensions
    screen_width = dialog.winfo_screenwidth()
    screen_height = dialog.winfo_screenheight()
    
    # Get dialog dimensions
    dialog.update_idletasks()
    width = dialog.winfo_width()
    height = dialog.winfo_height()
    
    # Calculate position
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    
    # Set position
    dialog.geometry(f"+{x}+{y}")