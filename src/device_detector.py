#!/usr/bin/env python3
"""
Device Detector Module for WiFi Penetration Testing Tool
Detects device types based on MAC address, SSID patterns, and other fingerprints
"""

import os
import re
import json
from typing import Dict, List, Optional

class DeviceDetector:
    """Device detection for wireless networks and clients"""
    
    def __init__(self):
        """Initialize the device detector"""
        self.vendor_db = {}
        self.device_signatures = {}
        self.device_types = {
            "router": ["router", "gateway", "ap", "access point", "wireless", "wifi", "network"],
            "camera": ["camera", "cam", "webcam", "ipcam", "surveillance", "cctv", "dvr", "nvr"],
            "iot": ["smart", "iot", "sensor", "thermostat", "bulb", "switch", "plug", "light", "hub"],
            "media": ["tv", "television", "roku", "firetv", "apple tv", "chromecast", "stream"],
            "mobile": ["phone", "mobile", "smartphone", "tablet", "ipad", "android"],
            "computer": ["pc", "mac", "desktop", "laptop", "computer", "workstation"],
            "printer": ["print", "printer", "scanner", "photosmart", "officejet", "laserjet"],
            "automotive": ["car", "vehicle", "tesla", "bmw", "audi", "mercedes", "toyota", "ford"]
        }
        
        # Load vendor database and device signatures
        self.load_vendor_database()
        self.load_device_signatures()
        
    def load_vendor_database(self):
        """Load MAC address vendor database"""
        # Try common paths for MAC address vendor database
        vendor_files = [
            "/usr/share/ieee-data/oui.txt",
            "/usr/share/nmap/nmap-mac-prefixes",
            "data/mac-vendors.txt"
        ]
        
        for vendor_file in vendor_files:
            if os.path.exists(vendor_file):
                self._load_vendor_file(vendor_file)
                return
                
        # If no vendor file found, load minimal database
        self._load_default_vendors()
        
    def _load_vendor_file(self, file_path):
        """Load vendor database from file
        
        Args:
            file_path: Path to vendor database file
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    # Handle different file formats
                    if file_path.endswith('oui.txt'):
                        # Format: 00-50-56   (hex)                VMware, Inc.
                        parts = line.split('(hex)')
                        if len(parts) == 2:
                            mac_prefix = parts[0].strip().replace('-', ':').lower()
                            vendor = parts[1].strip()
                            self.vendor_db[mac_prefix] = vendor
                    elif file_path.endswith('nmap-mac-prefixes'):
                        # Format: 0050F2 Microsoft
                        parts = line.split(' ', 1)
                        if len(parts) == 2:
                            mac = parts[0].strip().lower()
                            # Format MAC prefix with colons
                            mac_prefix = ':'.join([mac[i:i+2] for i in range(0, min(6, len(mac)), 2)])
                            vendor = parts[1].strip()
                            self.vendor_db[mac_prefix] = vendor
                    else:
                        # Generic format: mac<tab>vendor
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            mac_prefix = parts[0].strip().lower()
                            vendor = parts[1].strip()
                            self.vendor_db[mac_prefix] = vendor
        except Exception as e:
            print(f"Error loading vendor database: {str(e)}")
            
    def _load_default_vendors(self):
        """Load default minimal vendor database"""
        # Add common vendors as fallback
        default_vendors = {
            "00:18:dd": "Silicondust",  # HDHomeRun
            "00:1d:c2": "Nintendo",
            "00:21:5c": "Intel Corporate",
            "00:22:69": "Hon Hai Precision", # Foxconn
            "00:23:32": "Apple, Inc.",
            "00:25:bc": "Apple, Inc.",
            "08:00:27": "Oracle VirtualBox",
            "0c:8b:fd": "Intel Corporate",
            "24:a2:e1": "Apple, Inc.",
            "54:60:09": "Google, Inc.",
            "8c:85:90": "Apple, Inc.",
            "b8:27:eb": "Raspberry Pi Foundation",
            "ec:fa:bc": "Xiaomi Communications",
            "f4:f5:d8": "Google, Inc.",
            "fc:f1:36": "Samsung Electronics",
            "b0:c5:54": "D-Link International",
            "00:0d:88": "D-Link Corporation",
            "00:1c:df": "Belkin International Inc.",
            "00:26:f2": "NETGEAR",
            "74:da:38": "Edimax Technology",
            "e8:12:fe": "Tianjin Guo Wei Electronic"
        }
        
        self.vendor_db.update(default_vendors)
        
    def load_device_signatures(self):
        """Load device type signatures from JSON"""
        # Try to load from file
        signature_files = [
            "data/device_signatures.json"
        ]
        
        # Check for external signature files
        for signature_file in signature_files:
            if os.path.exists(signature_file):
                try:
                    with open(signature_file, 'r') as f:
                        self.device_signatures = json.load(f)
                    return
                except Exception as e:
                    print(f"Error loading device signatures: {str(e)}")
                    
        # Load default signatures if file not found
        self._load_default_signatures()
        
    def _load_default_signatures(self):
        """Load default device signatures"""
        # Default SSID signatures for device types
        self.device_signatures = {
            "router": {
                "ssid_patterns": [
                    r"linksys", r"netgear", r"asus", r"tplink", r"router", r"gateway", 
                    r"dlink", r"belkin", r"^dd-wrt", r"tomato", r"^home-?router"
                ],
                "vendor_keywords": [
                    "netgear", "tplink", "asus", "linksys", "belkin", "dlink", "ubiquiti",
                    "mikrotik", "huawei", "cisco", "aruba"
                ]
            },
            "camera": {
                "ssid_patterns": [
                    r"cam", r"camera", r"ipcam", r"hikvision", r"dahua", r"ring", r"arlo",
                    r"nest[\s-]cam", r"wyze"
                ],
                "vendor_keywords": [
                    "hikvision", "dahua", "axis", "hanwha", "bosch", "panasonic",
                    "avigilon", "foscam", "amcrest", "vivotek", "ring"
                ]
            },
            "iot": {
                "ssid_patterns": [
                    r"echo", r"alexa", r"hue", r"nest", r"ring", r"smartthings", r"sonos",
                    r"philips", r"wemo", r"thermostat", r"smart[\s-]?hub", r"eero"
                ],
                "vendor_keywords": [
                    "amazon", "google", "philips", "sonos", "xiaomi", "tuya", "broadlink",
                    "smartthings", "wemo", "lifx", "ikea", "trådfri", "tradfri", "kasa"
                ]
            },
            "media": {
                "ssid_patterns": [
                    r"tv", r"roku", r"firetv", r"appletv", r"chromecast", r"shield", r"android[\s-]?tv",
                    r"smart[\s-]?tv", r"^lgtv", r"^samsungtv", r"^sonytv"
                ],
                "vendor_keywords": [
                    "roku", "amazon", "sony", "samsung", "lg electronics", "vizio", "hisense",
                    "tcl", "apple"
                ]
            },
            "mobile": {
                "ssid_patterns": [
                    r"iphone", r"galaxys", r"pixel", r"oneplus", r"xiaomi", r"huawei", r"oppo", r"vivo"
                ],
                "vendor_keywords": [
                    "apple", "samsung", "google", "xiaomi", "huawei", "oppo", "vivo", "oneplus",
                    "motorola", "nokia", "zte", "sony"
                ]
            }
        }
        
    def get_vendor(self, mac_address: str) -> str:
        """Get vendor name from MAC address
        
        Args:
            mac_address: MAC address to look up
            
        Returns:
            str: Vendor name or "Unknown"
        """
        if not mac_address:
            return "Unknown"
            
        # Clean and format MAC
        mac = mac_address.lower().replace('-', ':')
        
        # Try different prefix lengths
        for prefix_len in [8, 7, 6, 5]:  # Try 3, 2.5, and 2 byte prefixes
            prefix = mac[:prefix_len]
            if prefix in self.vendor_db:
                return self.vendor_db[prefix]
                
        return "Unknown"
        
    def detect_device_type(self, ssid: str, vendor: str, bssid: str = None) -> str:
        """Detect device type based on SSID and vendor
        
        Args:
            ssid: Network SSID
            vendor: Device vendor
            bssid: Optional BSSID for additional detection
            
        Returns:
            str: Device type or "unknown"
        """
        if not ssid and not vendor:
            return "unknown"
            
        # Normalize inputs
        ssid_lower = ssid.lower() if ssid else ""
        vendor_lower = vendor.lower() if vendor else ""
        
        # Check against device signatures
        for device_type, signatures in self.device_signatures.items():
            # Check SSID patterns
            if ssid_lower and "ssid_patterns" in signatures:
                for pattern in signatures["ssid_patterns"]:
                    if re.search(pattern, ssid_lower):
                        return device_type
                        
            # Check vendor keywords
            if vendor_lower and "vendor_keywords" in signatures:
                for keyword in signatures["vendor_keywords"]:
                    if keyword in vendor_lower:
                        return device_type
                        
        # Check for generic device types in SSID
        if ssid_lower:
            for device_type, keywords in self.device_types.items():
                for keyword in keywords:
                    if keyword in ssid_lower:
                        return device_type
                        
        # Default classification based on MAC address OUI
        # TODO: Add more sophisticated fingerprinting
        
        return "unknown"
        
    def estimate_device_model(self, ssid: str, vendor: str) -> Optional[str]:
        """Attempt to estimate device model from SSID and vendor
        
        Args:
            ssid: Network SSID
            vendor: Device vendor
            
        Returns:
            Optional[str]: Estimated model or None
        """
        if not ssid or not vendor:
            return None
            
        # Normalize inputs
        ssid_lower = ssid.lower()
        vendor_lower = vendor.lower()
        
        # Common model patterns
        # Router models
        router_patterns = {
            "netgear": [
                (r"netgear([a-z0-9]+)", "Netgear {}"),
                (r"ntgr([a-z0-9]+)", "Netgear {}")
            ],
            "linksys": [
                (r"linksys([a-z0-9]+)", "Linksys {}")
            ],
            "asus": [
                (r"asus([a-z0-9\-_]+)", "Asus {}"),
                (r"rt-([a-z0-9\-_]+)", "Asus RT-{}")
            ],
            "tp-link": [
                (r"tp-link([a-z0-9\-_]+)", "TP-Link {}"),
                (r"tl-([a-z0-9\-_]+)", "TP-Link TL-{}")
            ],
            "d-link": [
                (r"dlink([a-z0-9\-_]+)", "D-Link {}"),
                (r"dir-([0-9]+)", "D-Link DIR-{}")
            ]
        }
        
        # Find vendor in our patterns
        for v, patterns in router_patterns.items():
            if v in vendor_lower:
                # Try each pattern
                for pattern, format_str in patterns:
                    match = re.search(pattern, ssid_lower)
                    if match:
                        return format_str.format(match.group(1).upper())
                        
        # Check for IoT devices
        if "camera" in ssid_lower:
            for cam_brand in ["hikvision", "dahua", "foscam", "axis", "nest"]:
                if cam_brand in vendor_lower or cam_brand in ssid_lower:
                    return f"{cam_brand.title()} Camera"
                    
        # No match found
        return None
        
    def classify_network(self, network):
        """Classify network type and device
        
        Args:
            network: NetworkTarget object
            
        Returns:
            dict: Classification information
        """
        result = {
            "type": "unknown",
            "model": None,
            "purpose": "unknown",
            "risk_factors": []
        }
        
        # Detect device type
        result["type"] = self.detect_device_type(network.ssid, network.vendor, network.bssid)
        
        # Estimate model if possible
        result["model"] = self.estimate_device_model(network.ssid, network.vendor)
        
        # Determine purpose based on type
        if result["type"] == "router":
            result["purpose"] = "Network Infrastructure"
        elif result["type"] == "camera":
            result["purpose"] = "Surveillance"
        elif result["type"] == "iot":
            result["purpose"] = "Smart Home/IoT"
        elif result["type"] == "media":
            result["purpose"] = "Entertainment"
        elif result["type"] == "mobile":
            result["purpose"] = "Personal Device"
        
        # Identify risk factors
        risk_factors = []
        
        # Check security
        if not network.security:
            risk_factors.append("Open Network (No Encryption)")
        elif "WEP" in network.security:
            risk_factors.append("WEP Encryption (Easily Crackable)")
        elif "WPA" in network.security and "WPA2" not in network.security:
            risk_factors.append("WPA1 (Outdated Encryption)")
            
        # Check for default SSID patterns indicating default configuration
        default_ssid_patterns = [
            r"linksys", r"netgear", r"^dlink", r"^tp-link", r"^asus", r"^belkin",
            r"^wifi", r"^wireless", r"^default", r"^setup"
        ]
        
        for pattern in default_ssid_patterns:
            if re.search(pattern, network.ssid.lower()):
                risk_factors.append("Default/Generic SSID (Potential Default Configuration)")
                break
                
        # Check for WPS
        if network.wps_status == "Enabled":
            risk_factors.append("WPS Enabled (Potential PIN Vulnerability)")
            
        # Add risk factors to result
        result["risk_factors"] = risk_factors
        
        return result
        
    def get_device_info(self, mac_address: str) -> Dict:
        """Get detailed device information for a client
        
        Args:
            mac_address: Client MAC address
            
        Returns:
            dict: Device information
        """
        vendor = self.get_vendor(mac_address)
        
        # Analyze MAC address structure
        mac_type = "Unknown"
        if mac_address:
            # Check if locally administered
            first_byte = int(mac_address.replace(':', '').replace('-', '')[:2], 16)
            if first_byte & 0x02:
                mac_type = "Locally Administered"
            else:
                mac_type = "Globally Unique"
                
            # Check if individual/group
            if first_byte & 0x01:
                mac_type += " (Group Address)"
            else:
                mac_type += " (Individual Address)"
                
        # Determine likely device type based on vendor
        device_type = "Unknown"
        if vendor:
            vendor_lower = vendor.lower()
            
            # Mobile devices
            if any(x in vendor_lower for x in ["apple", "samsung", "xiaomi", "huawei", "oppo", "vivo", "oneplus"]):
                device_type = "Mobile Device"
            # Laptops/PCs
            elif any(x in vendor_lower for x in ["dell", "intel", "hp", "lenovo", "asus", "acer", "microsoft"]):
                device_type = "Computer"
            # IoT devices
            elif any(x in vendor_lower for x in ["nest", "ring", "echo", "philips", "sonos", "belkin"]):
                device_type = "IoT Device"
                
        return {
            "vendor": vendor,
            "mac_type": mac_type,
            "device_type": device_type
        }
