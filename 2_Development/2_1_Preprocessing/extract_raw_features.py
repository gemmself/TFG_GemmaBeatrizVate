#!/usr/bin/env python3
"""
extract_raw_features.py

This script takes the unified CSV with JA4+ fingerprints and extracts raw
features (individual components) for machine learning or dictionary building.

Usage:
    python extract_raw_features.py
"""

import sys
from pathlib import Path

# Add the module to the path
sys.path.insert(0, str(Path(__file__).parent))

from extract_raw_features import extract_all_raw_features
from extract_raw_features.config import DEFAULT_INPUT_FILE, DEFAULT_OUTPUT_FILE


def main():
    # Use default paths from config
    input_file = str(DEFAULT_INPUT_FILE)
    output_file = str(DEFAULT_OUTPUT_FILE)
    
    # Ensure output directory exists
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    
    print("="*60)
    print("JA4+ RAW FEATURE EXTRACTOR")
    print("="*60)
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print("="*60)
    
    if not Path(input_file).exists():
        print(f"ERROR: Input file not found: {input_file}")
        sys.exit(1)
    
    df_result = extract_all_raw_features(input_file, output_file)
    
    if df_result is not None:
        print("\n" + "="*60)
        print("PROCESS COMPLETED SUCCESSFULLY")
        print("="*60)


if __name__ == "__main__":
    main()
