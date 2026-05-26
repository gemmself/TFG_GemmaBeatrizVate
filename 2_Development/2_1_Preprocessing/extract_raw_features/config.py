"""extract_raw_features/config.py

Configuration constants and paths for the raw feature extraction module.
"""

import os
import platform
from pathlib import Path

BASE_DIR = Path("/mnt/d/TFG_GemmaBeatrizVate")

# Default paths
DEFAULT_INPUT_FILE = BASE_DIR / "1_Data" / "zeek_logs" / "combined_fingerprints.csv"
DEFAULT_OUTPUT_FILE = BASE_DIR / "1_Data" / "raw_fingerprints" / "raw_features.csv"

# Expected fingerprint columns in the input CSV
FINGERPRINT_COLUMNS = ['ja4', 'ja4s', 'ja4x', 'ja4h', 'ja4l', 'ja4ls', 'ja4t', 'ja4ts', 'sni']

# Base columns that are always preserved in the output
BASE_COLUMNS = [
    'connection_id', 'timestamp', 'device_name', 'device_category',
    'mac_address', 'src_ip', 'dst_ip', 'protocol', 'service', 'duration', 'conn_state'
]

# Fingerprint parsers mapping
FINGERPRINT_PARSERS = {
    'ja4': ('JA4', 'parse_ja4'),
    'ja4s': ('JA4S', 'parse_ja4s'),
    'ja4x': ('JA4X', 'parse_ja4x'),
    'ja4h': ('JA4H', 'parse_ja4h'),
    'ja4l': ('JA4L', 'parse_ja4l'),
    'ja4ls': ('JA4LS', 'parse_ja4l'),
    'ja4t': ('JA4T', 'parse_ja4t'),
    'ja4ts': ('JA4TS', 'parse_ja4t'),
    'sni': ('SNI', 'parse_sni')
}