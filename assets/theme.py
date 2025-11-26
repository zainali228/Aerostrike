#!/usr/bin/env python3
"""
Theme utilities for Aero Strike (AI-Powered Wifi Penetration Testing Tool)
Custom theme settings and color schemes
"""

import tkinter as tk
from tkinter import ttk

class ThemeManager:
    """Theme manager for consistent styling across the application"""
    
    # Color scheme definitions with enhanced button colors
    DARK_THEME = {
        "bg": "#2d2d2d",
        "fg": "#ffffff",
        "accent": "#9F44D3",  # Purple accent
        "secondary_bg": "#3d3d3d",
        "highlight": "#480B86",  # Darker purple
        "warning": "#ffb142",
        "error": "#ff5252",
        "success": "#2ed573",
        "border": "#555555",
        "disabled": "#666666",
        
        # Enhanced button colors
        "scan_button": "#4285F4",  # Bright blue
        "attack_button": "#EA4335",  # Bright red
        "report_button": "#34A853",  # Bright green
        "analyze_button": "#FBBC05",  # Bright yellow
        "ai_button": "#9C27B0",  # Bright purple
        "post_exploit_button": "#FF6D00",  # Bright orange
        "settings_button": "#607D8B",  # Blue grey
        "help_button": "#009688",  # Teal
        "default_button": "#6B56DD"  # Purple-blue
    }
    
    LIGHT_THEME = {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "accent": "#9F44D3",  # Purple accent
        "secondary_bg": "#e0e0e0",
        "highlight": "#c880ff",  # Lighter purple
        "warning": "#ffb142",
        "error": "#ff5252",
        "success": "#2ed573",
        "border": "#cccccc",
        "disabled": "#999999",
        
        # Enhanced button colors
        "scan_button": "#4285F4",  # Bright blue
        "attack_button": "#EA4335",  # Bright red
        "report_button": "#34A853",  # Bright green
        "analyze_button": "#FBBC05",  # Bright yellow
        "ai_button": "#9C27B0",  # Bright purple
        "post_exploit_button": "#FF6D00",  # Bright orange
        "settings_button": "#607D8B",  # Blue grey
        "help_button": "#009688",  # Teal
        "default_button": "#7E57C2"  # Lighter purple-blue
    }
    
    # Font sizes with adjustment options
    FONT_SIZES = {
        "small": {
            "default": 9,
            "header": 12,
            "title": 14,
            "button": 9,
            "console": 9
        },
        "medium": {
            "default": 10,
            "header": 14,
            "title": 16,
            "button": 10,
            "console": 10
        },
        "large": {
            "default": 12,
            "header": 16,
            "title": 18,
            "button": 12,
            "console": 12
        },
        "extra_large": {
            "default": 14,
            "header": 18,
            "title": 20,
            "button": 14,
            "console": 14
        }
    }
    
    def __init__(self, root, dark_mode=True, font_size="medium"):
        """Initialize theme manager
        
        Args:
            root: Tkinter root window
            dark_mode: Whether to use dark mode
            font_size: Font size setting ("small", "medium", "large", "extra_large")
        """
        self.root = root
        self.dark_mode = dark_mode
        self.font_size = font_size if font_size in self.FONT_SIZES else "medium"
        self.style = ttk.Style()
        
        # Apply theme
        self.apply_theme()
        
    def apply_theme(self):
        """Apply current theme to all widgets"""
        # Get current theme colors
        colors = self.DARK_THEME if self.dark_mode else self.LIGHT_THEME
        
        # Get font sizes based on current setting
        fonts = self.FONT_SIZES[self.font_size]
        
        # Configure ttk styles
        self.style.configure("TFrame", background=colors["bg"])
        self.style.configure("TLabel", background=colors["bg"], foreground=colors["fg"], 
                           font=("Helvetica", fonts["default"]))
        self.style.configure("TButton", background=colors["secondary_bg"], foreground=colors["fg"], 
                           font=("Helvetica", fonts["button"]), padding=6)
        self.style.configure("TNotebook", background=colors["bg"], foreground=colors["fg"])
        self.style.configure("TNotebook.Tab", background=colors["secondary_bg"], foreground=colors["fg"], 
                           font=("Helvetica", fonts["default"]))
        
        # Create custom styles with font size
        self.style.configure("Header.TLabel", 
                           font=("Helvetica", fonts["header"], "bold"), 
                           background=colors["bg"], 
                           foreground=colors["fg"])
        self.style.configure("Subheader.TLabel", 
                           font=("Helvetica", fonts["header"]-2, "bold"), 
                           background=colors["bg"], 
                           foreground=colors["fg"])
        self.style.configure("Title.TLabel", 
                           font=("Helvetica", fonts["title"], "bold"), 
                           background=colors["bg"], 
                           foreground=colors["fg"])
        
        # Console text style
        self.root.option_add("*Text.font", ("Courier", fonts["console"]))
        
        # Action button styles
        self.style.configure("Action.TButton", 
                           background=colors["accent"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
        
        self.style.configure("Warning.TButton", 
                           background=colors["warning"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
        
        self.style.configure("Success.TButton", 
                           background=colors["success"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
        
        self.style.configure("Error.TButton", 
                           background=colors["error"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
                           
        # Colorful button styles for different actions
        self.style.configure("Scan.TButton", 
                           background=colors["scan_button"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
                           
        self.style.configure("Attack.TButton", 
                           background=colors["attack_button"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
                           
        self.style.configure("Report.TButton", 
                           background=colors["report_button"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
                           
        self.style.configure("Analyze.TButton", 
                           background=colors["analyze_button"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
                           
        self.style.configure("AI.TButton", 
                           background=colors["ai_button"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
                           
        self.style.configure("PostExploit.TButton", 
                           background=colors["post_exploit_button"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
                           
        self.style.configure("Settings.TButton", 
                           background=colors["settings_button"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
                           
        self.style.configure("Help.TButton", 
                           background=colors["help_button"], 
                           foreground="#ffffff",
                           font=("Helvetica", fonts["button"], "bold"),
                           padding=8)
        
        # Tree style for network list
        self.style.configure("Treeview", 
                            background=colors["secondary_bg"], 
                            foreground=colors["fg"],
                            fieldbackground=colors["secondary_bg"],
                            borderwidth=1,
                            relief="solid")
        
        self.style.map("Treeview", 
                     background=[('selected', colors["accent"])],
                     foreground=[('selected', '#ffffff')])
        
        # Progressbar style
        self.style.configure("TProgressbar",
                            background=colors["accent"],
                            troughcolor=colors["secondary_bg"],
                            borderwidth=0,
                            thickness=8)
        
        # Configure standard Tkinter widgets that need special handling
        try:
            # Set standard font
            default_font = ("Helvetica", 10)
            self.root.option_add("*Font", default_font)
            
            # Configure console and other Text widgets
            text_widgets = self._find_widgets_by_class(self.root, tk.Text)
            for w in text_widgets:
                w.config(bg=colors["secondary_bg"], fg=colors["fg"],
                        insertbackground=colors["fg"],
                        selectbackground=colors["accent"],
                        selectforeground="#ffffff",
                        borderwidth=1,
                        relief="solid")
                        
            # Configure listboxes
            listboxes = self._find_widgets_by_class(self.root, tk.Listbox)
            for w in listboxes:
                w.config(bg=colors["secondary_bg"], fg=colors["fg"],
                        selectbackground=colors["accent"],
                        selectforeground="#ffffff",
                        borderwidth=1,
                        relief="solid")
                        
            # Configure frames
            frames = self._find_widgets_by_class(self.root, tk.Frame)
            for w in frames:
                w.config(bg=colors["bg"])
                        
            # Configure labels
            labels = self._find_widgets_by_class(self.root, tk.Label)
            for w in labels:
                w.config(bg=colors["bg"], fg=colors["fg"])
                
            # Configure buttons
            buttons = self._find_widgets_by_class(self.root, tk.Button)
            for w in buttons:
                w.config(bg=colors["secondary_bg"], fg=colors["fg"],
                        activebackground=colors["accent"],
                        activeforeground="#ffffff")
                        
            # Configure checkbuttons
            checks = self._find_widgets_by_class(self.root, tk.Checkbutton)
            for w in checks:
                w.config(bg=colors["bg"], fg=colors["fg"],
                        activebackground=colors["bg"],
                        activeforeground=colors["fg"],
                        selectcolor=colors["secondary_bg"])
        except Exception as e:
            print(f"Error applying theme to widgets: {str(e)}")
            
    def _find_widgets_by_class(self, parent, widget_class):
        """Find all widgets of specific class in parent
        
        Args:
            parent: Parent widget
            widget_class: Widget class to find
            
        Returns:
            list: List of widgets
        """
        widgets = []
        
        # Add parent if it matches
        if isinstance(parent, widget_class):
            widgets.append(parent)
            
        # Add children
        try:
            for child in parent.winfo_children():
                widgets.extend(self._find_widgets_by_class(child, widget_class))
        except (AttributeError, tk.TclError):
            pass
            
        return widgets
        
    def toggle_theme(self):
        """Toggle between light and dark theme"""
        self.dark_mode = not self.dark_mode
        self.apply_theme()
        
    def set_font_size(self, size):
        """Change the font size
        
        Args:
            size: Font size to use ("small", "medium", "large", "extra_large")
        """
        if size in self.FONT_SIZES:
            self.font_size = size
            self.apply_theme()
        
    def get_theme_colors(self):
        """Get current theme colors
        
        Returns:
            dict: Theme color dictionary
        """
        return self.DARK_THEME if self.dark_mode else self.LIGHT_THEME
        
    def create_custom_widget_styles(self):
        """Create additional custom widget styles"""
        colors = self.get_theme_colors()
        
        # Create styles for specific widgets
        self.style.configure("Console.TFrame", 
                            background=colors["secondary_bg"], 
                            borderwidth=1, 
                            relief="solid")
        
        self.style.configure("Card.TFrame", 
                            background=colors["secondary_bg"], 
                            borderwidth=1, 
                            relief="raised")
        
        self.style.configure("Status.TLabel", 
                            background=colors["secondary_bg"], 
                            foreground=colors["fg"],
                            font=("Helvetica", 9))
                            
        # Custom theme for ttk.Combobox
        self.style.map("TCombobox",
                      selectbackground=[('readonly', colors["accent"])],
                      selectforeground=[('readonly', "#ffffff")])
