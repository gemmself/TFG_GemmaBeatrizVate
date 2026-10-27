#!/usr/bin/env python3
"""
Main script to combine all JA4 fingerprints from Zeek logs into a single CSV.
Includes direct JA4X calculation from x509.log.

Usage:
    python3 combine_zeek_fingerprints.py
"""

from combine_zeek_fingerprints.config import (
    BASE_DIR, ZEEK_LOG_DIR, PCAP_DIR, OUTPUT_FILE,
    MAC_TO_DEVICE, MAC_TO_CATEGORY
)

from combine_zeek_fingerprints.reader import (
    read_zeek_log, extract_mac_from_zeek_logs
)

from combine_zeek_fingerprints.processor import (
    process_conn_log, process_http_log, process_ssl_log,
    calculate_ja4x_for_connections, assign_devices
)

def main():
    print("=" * 70)
    print("Combining Zeek fingerprints into a single CSV with JA4X calculation (UNSW)")
    print("=" * 70)
    
    print("\n1. LOADING LOGS...")
    conn_df = read_zeek_log(ZEEK_LOG_DIR / "conn.log")
    http_df = read_zeek_log(ZEEK_LOG_DIR / "http.log")
    ssl_df = read_zeek_log(ZEEK_LOG_DIR / "ssl.log")
    x509_df = read_zeek_log(ZEEK_LOG_DIR / "x509.log")
    dhcp_df = read_zeek_log(ZEEK_LOG_DIR / "dhcp.log")
    
    print(f"   conn.log: {len(conn_df)}")
    print(f"   http.log: {len(http_df)}")
    print(f"   ssl.log: {len(ssl_df)}")
    print(f"   x509.log: {len(x509_df)}")
    print(f"   dhcp.log: {len(dhcp_df)}")
    
    print("\n2. EXTRACTING IP-TO-MAC MAPPINGS FROM LOGS & PCAPS...")
    ip_mac_map = extract_mac_from_zeek_logs(conn_df, dhcp_df, pcap_dir=PCAP_DIR)
    print(f"   {len(ip_mac_map)} IP-to-MAC mappings extracted")

    print("\n3. PROCESSING LOGS...")
    conn_df = process_conn_log(conn_df)
    http_df = process_http_log(http_df)
    ssl_df = process_ssl_log(ssl_df)
    
    print("\n4. CALCULATING JA4X FROM X509.LOG...")
    ssl_df = calculate_ja4x_for_connections(ssl_df, x509_df)
    
    print("\n5. ASSIGNING DEVICES...")
    conn_df = assign_devices(conn_df, ip_mac_map)
    http_df = assign_devices(http_df, ip_mac_map)
    ssl_df = assign_devices(ssl_df, ip_mac_map)
    
    print("\n6. COMBINING DATA (Focusing on Encrypted/TLS traffic)...")
    valid_ssl = ssl_df.dropna(subset=['ja4'], how='all') if 'ja4' in ssl_df.columns else ssl_df
    combined = valid_ssl.copy()
    
    if not conn_df.empty:
        conn_cols = ['connection_id', 'ja4t', 'ja4ts', 'ja4l', 'ja4ls', 'protocol', 'service', 'duration', 'conn_state']
        conn_cols = [c for c in conn_cols if c in conn_df.columns]
        combined = combined.merge(conn_df[conn_cols], on='connection_id', how='left')

    if not http_df.empty:
        http_cols = ['connection_id', 'http_method', 'http_host', 'http_uri', 'http_user_agent', 'ja4h']
        http_cols = [c for c in http_cols if c in http_df.columns]
        combined = combined.merge(http_df[http_cols], on='connection_id', how='left')
    
    cols_order = [
        'connection_id', 'timestamp', 'device_name', 'device_category', 'mac_address',
        'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'ja4', 'ja4s', 'ja4x', 'sni',
        'ja4l', 'ja4ls', 'ja4t', 'ja4ts',
        'ja4h', 'http_method', 'http_host', 'http_uri', 'http_user_agent',
        'protocol', 'service', 'duration', 'conn_state'
    ]
    
    existing = [c for c in cols_order if c in combined.columns]
    combined = combined[existing]
    
    print("\n7. SAVING...")
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(OUTPUT_FILE, index=False)
    
    print(f"\nFile: {OUTPUT_FILE}")
    print(f"Records: {len(combined)}")
    print(f"Columns: {len(combined.columns)}")
    
    identified = (combined['device_name'] != 'UNKNOWN').sum()
    print(f"\nIdentified devices: {combined['device_name'].nunique()}")
    print(f"Identified records: {identified}/{len(combined)} ({identified/len(combined)*100:.1f}%)")
    print("\nDevice distribution:")
    print(combined['device_name'].value_counts())
    
    print("\n" + "=" * 70)
    print("PROCESS COMPLETED")
    print("=" * 70)

if __name__ == "__main__":
    main()