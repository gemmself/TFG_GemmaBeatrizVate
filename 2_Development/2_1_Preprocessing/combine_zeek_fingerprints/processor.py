"""Functions for processing and normalizing Zeek log data."""

import numpy as np
import pandas as pd


def process_conn_log(df):
    """Normalize Zeek connection fields into the common schema."""
    if df.empty:
        return df
    
    # Define the mapping from Zeek's conn.log fields to our common schema
    rename_map = {
        'uid': 'connection_id', 'ts': 'timestamp',
        'id.orig_h': 'src_ip', 'id.orig_p': 'src_port',
        'id.resp_h': 'dst_ip', 'id.resp_p': 'dst_port',
        'proto': 'protocol', 'service': 'service', 'conn_state': 'conn_state', 'duration': 'duration'
    }
    
    for old, new in rename_map.items():
        if old in df.columns:
            df[new] = df[old]
    
    for field in ['ja4l', 'ja4ls', 'ja4t', 'ja4ts']:
        if field not in df.columns:
            df[field] = np.nan
    
    return df


def process_http_log(df):
    """Normalize HTTP-specific fields."""
    if df.empty:
        return df
    
    # Define the mapping from Zeek's http.log fields to our common schema
    rename_map = {
        'uid': 'connection_id', 'ts': 'timestamp',
        'id.orig_h': 'src_ip', 'id.orig_p': 'src_port',
        'id.resp_h': 'dst_ip', 'id.resp_p': 'dst_port',
        'method': 'http_method', 'host': 'http_host',
        'uri': 'http_uri', 'user_agent': 'http_user_agent'
    }
    
    for old, new in rename_map.items():
        if old in df.columns:
            df[new] = df[old]
    
    if 'ja4h' not in df.columns:
        df['ja4h'] = np.nan
    
    return df


def process_ssl_log(df):
    """Normalize TLS fields and expose SNI."""
    if df.empty:
        return df
    
    # Define the mapping from Zeek's ssl.log fields to our common schema
    rename_map = {
        'uid': 'connection_id', 
        'ts': 'timestamp',
        'id.orig_h': 'src_ip', 
        'id.orig_p': 'src_port',
        'id.resp_h': 'dst_ip', 
        'id.resp_p': 'dst_port',
        'server_name': 'sni'
    }
    
    for old, new in rename_map.items():
        if old in df.columns:
            df[new] = df[old]
    
    for field in ['ja4', 'ja4s']:
        if field not in df.columns:
            df[field] = np.nan
    
    return df


def calculate_ja4x_for_connections(ssl_df, x509_df):
    """Calculate JA4X for each TLS connection using the certificates."""
    try:
        from .ja4x import calculate_ja4x_for_certificate
    except ImportError:
        from ja4x import calculate_ja4x_for_certificate
    
    if ssl_df.empty or x509_df.empty:
        return ssl_df
    
    print("   Calculating JA4X for certificates...")
    
    # Create the fingerprint -> JA4X mapping from x509.log
    fingerprint_to_ja4x = {}
    for _, row in x509_df.iterrows():
        fingerprint = row.get('fingerprint', '')
        if fingerprint and not pd.isna(fingerprint):
            ja4x = calculate_ja4x_for_certificate(row)
            if ja4x:
                fingerprint_to_ja4x[fingerprint] = ja4x
    
    print(f"   JA4X calculated: {len(fingerprint_to_ja4x)} certificates")
    
    # Look for the fingerprint column in ssl.log
    fp_col = None
    for col in ['cert_chain_fps', 'certificate_fingerprint', 'server_cert_fingerprint']:
        if col in ssl_df.columns:
            fp_col = col
            break
    
    if fp_col and fingerprint_to_ja4x:
        print(f"   Assigning JA4X using column: {fp_col}")
        
        # Define a function to extract JA4X based on the fingerprint(s) in the ssl.log entry
        def get_ja4x(fingerprints_str):
            if pd.isna(fingerprints_str):
                return np.nan
            fps_str = str(fingerprints_str).strip('[]').strip('"').strip("'")
            if not fps_str:
                return np.nan
            fps = [fp.strip().strip("'").strip('"') for fp in fps_str.split(',')]
            for fp in fps:
                if fp in fingerprint_to_ja4x:
                    return fingerprint_to_ja4x[fp]
            return np.nan
        
        # Apply the function to assign JA4X values to the ssl_df
        ssl_df['ja4x'] = ssl_df[fp_col].apply(get_ja4x)
        matched = ssl_df['ja4x'].notna().sum()
        print(f"   JA4X assigned: {matched}/{len(ssl_df)} ({matched/len(ssl_df)*100:.1f}%)")
    else:
        if not fp_col:
            print("   No fingerprint column was found in ssl.log")
        if not fingerprint_to_ja4x:
            print("   JA4X values could not be calculated from x509.log")
        ssl_df['ja4x'] = np.nan
    
    return ssl_df


def assign_devices(df, ip_mac_map):
    """Assign device information based on IP-to-MAC mappings."""
    try:
        from .config import MAC_TO_DEVICE, MAC_TO_CATEGORY
    except ImportError:
        from config import MAC_TO_DEVICE, MAC_TO_CATEGORY
    
    if df.empty:
        return df

# Define a function to determine device info based on source/destination IPs and the IP-to-MAC mapping
    def get_device_info(row):
        mac_found = None
        
        # First check the source IP
        if 'src_ip' in row and pd.notna(row['src_ip']):
            ip = str(row['src_ip'])
            if ip in ip_mac_map:
                mac_found = ip_mac_map[ip]
        
        # If not found, check the destination IP
        if not mac_found and 'dst_ip' in row and pd.notna(row['dst_ip']):
            ip = str(row['dst_ip'])
            if ip in ip_mac_map:
                mac_found = ip_mac_map[ip]
                
        if mac_found and mac_found in MAC_TO_DEVICE:
            return mac_found, MAC_TO_DEVICE[mac_found], MAC_TO_CATEGORY[mac_found]
        elif mac_found:
            return mac_found, "UNKNOWN", "UNKNOWN"
        return "", "UNKNOWN", "UNKNOWN"
    
    device_info = df.apply(get_device_info, axis=1, result_type='expand')
    device_info.columns = ['mac_address', 'device_name', 'device_category']
    
    for col in device_info.columns:
        df[col] = device_info[col]
    
    return df