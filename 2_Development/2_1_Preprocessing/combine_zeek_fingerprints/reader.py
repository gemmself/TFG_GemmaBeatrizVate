"""Functions for reading and processing Zeek log files."""

import subprocess
import pandas as pd
import numpy as np
from pathlib import Path


def extract_mac_maps(pcap_path):
    """Extract IP-to-MAC mappings from a PCAP file using tshark."""
    if not pcap_path.exists():
        return {}
    
    # Define the tshark command to extract source IP and corresponding MAC address
    cmd = ["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "ip.src", "-e", "eth.src", "-E", "separator=,"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {}
        
        ip_mac = {}
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            # Each line should contain the source IP and MAC address separated by a comma
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2 and parts[0] and parts[1]:
                ip_mac[parts[0]] = parts[1].lower()
        
        return ip_mac
    except:
        return {}


def read_zeek_log(file_path):
    """Read a Zeek log file into a pandas DataFrame."""
    if not file_path.exists():
        return pd.DataFrame()
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        columns = None
        data_lines = []
        
        # Parse the Zeek log lines to extract column names and data
        for line in lines:
            if line.startswith('#fields'):
                columns = line.replace('#fields', '').strip().split('\t')
            elif not line.startswith('#') and line.strip():
                data_lines.append(line.strip())
        
        if not columns:
            return pd.DataFrame()
        
        data = []
        # Handle cases where data lines may have fewer or more fields than the header
        for line in data_lines:
            parts = line.split('\t')
            if len(parts) == len(columns):
                data.append(parts)
            else:
                if len(parts) < len(columns):
                    parts.extend([''] * (len(columns) - len(parts)))
                else:
                    parts = parts[:len(columns)]
                data.append(parts)
        
        df = pd.DataFrame(data, columns=columns)
        df = df.replace('-', np.nan)
        return df
            
    except Exception as e:
        return pd.DataFrame()