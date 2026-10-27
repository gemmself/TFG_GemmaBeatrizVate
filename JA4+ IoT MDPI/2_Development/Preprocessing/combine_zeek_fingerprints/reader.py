"""Functions for reading and processing Zeek log files."""

import os
import glob
import subprocess
import pandas as pd
import numpy as np
from pathlib import Path

def extract_mac_from_zeek_logs(conn_df, dhcp_df, pcap_dir=None):
    """Extrae mapeo IP-a-MAC desde dhcp.log o directamente inspeccionando las cabeceras de los PCAPs."""
    ip_mac = {}
    
    # 1. Intentar desde dhcp.log usando los nombres nativos de Zeek (client_addr, mac_addr o mac)
    if not dhcp_df.empty:
        ip_col = next((c for c in ['assigned_ip', 'client_addr', 'id.orig_h'] if c in dhcp_df.columns), None)
        mac_col = next((c for c in ['mac', 'mac_addr', 'orig_l2_addr'] if c in dhcp_df.columns), None)
        
        if ip_col and mac_col:
            valid_dhcp = dhcp_df.dropna(subset=[ip_col, mac_col])
            for _, r in valid_dhcp.iterrows():
                ip_val = str(r[ip_col]).strip()
                mac_val = str(r[mac_col]).strip().lower()
                if ip_val and mac_val and mac_val != '-':
                    ip_mac[ip_val] = mac_val

    # 2. Si Zeek no registró MACs en capa 3/4, extraer la IP fija de cada PCAP usando tshark
    if len(ip_mac) < 10 and pcap_dir and pcap_dir.exists():
        print("   -> Extrayendo mapeo IP-MAC directamente desde los archivos PCAP...")
        for pcap_file in pcap_dir.glob("*.pcap*"):
            # Extraer MAC del nombre del archivo (ej. AmazonEcho_44650d56ccd3.pcap)
            stem = pcap_file.stem.replace(".pcap", "").replace(".pcapng", "")
            parts = stem.split("_")
            if len(parts) >= 2:
                raw_mac = parts[1].lower()
                # Formatear a 44:65:0d:56:cc:d3
                if len(raw_mac) == 12:
                    formatted_mac = ":".join(raw_mac[i:i+2] for i in range(0, 12, 2))
                else:
                    formatted_mac = raw_mac
                
                # Extraer la IP local (192.168.1.X) predominante de este PCAP
                cmd = f"tshark -r '{pcap_file}' -Y 'ip.src matches \"^192\\.168\\.\"' -T fields -e ip.src | head -n 50 | sort | uniq -c | sort -nr | head -n 1"
                try:
                    out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
                    if out:
                        ip_found = out.split()[-1]
                        ip_mac[ip_found] = formatted_mac
                except Exception:
                    pass

    return ip_mac

def read_zeek_log(file_path):
    """Read a Zeek log file into a pandas DataFrame."""
    if not file_path.exists():
        return pd.DataFrame()
    
    try:
        columns = None
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.startswith('#fields'):
                    columns = line.replace('#fields', '').strip().split('\t')
                    break
        
        if not columns:
            return pd.DataFrame()

        df = pd.read_csv(
            file_path,
            sep='\t',
            comment='#',
            header=None,
            names=columns,
            low_memory=False,
            na_values=['-', '(empty)'],
            dtype=str
        )
        return df
            
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return pd.DataFrame()