"""extract_raw_features/processor.py

Main processing logic for extracting raw features from JA4+ fingerprints.
"""

import numpy as np
import pandas as pd
from pathlib import Path

from .parsers import (
    parse_ja4, parse_ja4s, parse_ja4x, parse_ja4h,
    parse_ja4l, parse_ja4t, parse_sni
)
from .config import FINGERPRINT_COLUMNS, BASE_COLUMNS


# Parser functions mapping
FINGERPRINT_PARSERS = {
    'ja4': ('JA4', parse_ja4),
    'ja4s': ('JA4S', parse_ja4s),
    'ja4x': ('JA4X', parse_ja4x),
    # 'ja4h': ('JA4H', parse_ja4h),
    # 'ja4l': ('JA4L', lambda x: parse_ja4l(x, 'ja4l')),
    # 'ja4ls': ('JA4LS', lambda x: parse_ja4l(x, 'ja4ls')),
    'ja4t': ('JA4T', lambda x: parse_ja4t(x, 'ja4t')),
    'ja4ts': ('JA4TS', lambda x: parse_ja4t(x, 'ja4ts')),
    'sni': ('SNI', parse_sni)
}


def load_input_file(input_file):
    """
    Load the input CSV file with automatic delimiter detection.
    """
    print(f"\nReading file: {input_file}")
    try:
        df = pd.read_csv(input_file, dtype=str, sep=None, engine='python')
    except Exception:
        df = pd.read_csv(input_file, dtype=str, sep=';')
    
    print(f"   Rows: {len(df)}")
    print(f"   Original columns: {len(df.columns)}")
    
    return df


def analyze_fingerprint_coverage(df):
    """
    Analyze which fingerprint columns are available and their coverage.
    """
    available_cols = set(df.columns)
    
    print("\nAvailable fingerprint columns:")
    fingerprint_cols_present = []
    fp_coverage = {}
    
    for col in FINGERPRINT_COLUMNS:
        if col in available_cols:
            non_null = df[col].notna().sum()
            total = len(df)
            pct = (non_null / total * 100)
            print(f"    {col}: {non_null}/{total} ({pct:.1f}%)")
            fingerprint_cols_present.append(col)
            fp_coverage[col] = {'non_null': non_null, 'pct': pct}
        else:
            print(f"    {col}: Not available")
    
    return fingerprint_cols_present, fp_coverage


def convert_timestamp(df):
    """
    Convert timestamp column to human-readable datetime string.
    """
    if 'timestamp' not in df.columns:
        return df
    
    df = df.copy()
    df['timestamp_clean'] = df['timestamp'].astype(str).str.replace(',', '.')
    timestamps_float = pd.to_numeric(df['timestamp_clean'], errors='coerce')
    
    valid_mask = (timestamps_float > 1e9) & (timestamps_float < 2e9)
    
    if valid_mask.any():
        timestamps_dt = pd.to_datetime(timestamps_float[valid_mask], unit='s')
        df['timestamp'] = ''
        df.loc[valid_mask, 'timestamp'] = timestamps_dt.dt.strftime('%Y-%m-%d %H:%M:%S.%f')
        df.loc[~valid_mask, 'timestamp'] = np.nan
        print(f"\nTimestamp converted: {valid_mask.sum()} valid values, {(~valid_mask).sum()} invalid values")
    else:
        print(f"\nNo valid timestamps were found")
        df['timestamp'] = df['timestamp_clean']
    
    df = df.drop(columns=['timestamp_clean'])
    
    return df


def process_fingerprints(df, fingerprint_cols_present):
    """
    Process each fingerprint type and extract raw features.
    """
    all_raw_dfs = []
    features_count = {}
    
    for fp_col, (fp_name, parser_func) in FINGERPRINT_PARSERS.items():
        if fp_col in fingerprint_cols_present:
            print(f"\nProcessing {fp_name} ({fp_col})...")
            
            fp_raw = df[fp_col].apply(parser_func).apply(pd.Series)
            n_features = len(fp_raw.columns)
            features_count[fp_name] = n_features
            print(f"   {n_features} features extracted")
            all_raw_dfs.append(fp_raw)
    
    if not all_raw_dfs:
        print("\nNo fingerprint columns were found to process")
        return None, {}
    
    raw_features_df = pd.concat(all_raw_dfs, axis=1)
    
    return raw_features_df, features_count


def calculate_rtt(raw_features_df):
    """
    Calculate RTT from JA4L and JA4LS latency fingerprints.
    """
    rtt_df = pd.DataFrame(index=raw_features_df.index)
    
    ja4l_col = None
    ja4ls_col = None
    
    for col in raw_features_df.columns:
        if col.startswith('ja4l_') and ('id' in col):
            ja4l_col = col
        elif col.startswith('ja4ls_') and ('id' in col):
            ja4ls_col = col
    
    if ja4l_col and ja4ls_col:
        print(f"\nCalculating actual RTT from {ja4l_col} and {ja4ls_col}...")
        
        ja4l_values = pd.to_numeric(raw_features_df[ja4l_col], errors='coerce')
        ja4ls_values = pd.to_numeric(raw_features_df[ja4ls_col], errors='coerce')
        
        rtt_us = abs(ja4ls_values - ja4l_values)
        
        rtt_df['rtt_us'] = rtt_us.apply(lambda x: f"{x:.0f}" if pd.notna(x) else np.nan)
        rtt_df['rtt_ms'] = (rtt_us / 1000).apply(lambda x: f"{x:.3f}" if pd.notna(x) else np.nan)
        rtt_df['rtt_sec'] = (rtt_us / 1_000_000).apply(lambda x: f"{x:.6f}" if pd.notna(x) else np.nan)
        
        valid_rtt = rtt_us.notna().sum()
        if valid_rtt > 0:
            print(f"   RTT calculated for {valid_rtt} connections")
    
    return rtt_df


def convert_numeric_to_string(df):
    """
    Convert all numeric columns to string format.
    """
    def to_str_if_notna(val):
        if pd.isna(val):
            return val
        if isinstance(val, (int, float)):
            if isinstance(val, float) and val.is_integer():
                return str(int(val))
            return str(val)
        return val
    
    for col in df.columns:
        df[col] = df[col].apply(to_str_if_notna)
    
    return df


def create_individual_files(df, raw_features_df, fingerprint_cols_present, 
                            available_base_cols, rtt_df, output_file):
    """
    Create individual CSV files for each fingerprint type.
    """
    individual_files = []
    
    if not output_file:
        return individual_files
    
    output_path = Path(output_file)
    
    for fp_col, (fp_name, parser_func) in FINGERPRINT_PARSERS.items():
        if fp_col in fingerprint_cols_present:
            fp_raw = raw_features_df[[col for col in raw_features_df.columns 
                                       if col.startswith(f"{fp_col}_")]]
            
            fp_individual = pd.concat([
                df[available_base_cols],
                df[[fp_col]],
                fp_raw
            ], axis=1)
            
            if fp_name in ['JA4L', 'JA4LS'] and not rtt_df.empty:
                fp_individual = pd.concat([fp_individual, rtt_df], axis=1)
            
            individual_path = output_path.parent / f"{fp_name}_raw.csv"
            fp_individual.to_csv(individual_path, index=False)
            individual_files.append(str(individual_path))
            print(f"   Individual file saved: {individual_path}")
    
    return individual_files


def build_final_dataframe(df, fingerprint_cols_present, available_base_cols, 
                          rtt_df, raw_features_df):
    """
    Build the final complete dataframe with all features.
    """
    dfs_to_concat = [df[available_base_cols]]
    
    if fingerprint_cols_present:
        dfs_to_concat.append(df[fingerprint_cols_present])
        print(f"Adding original fingerprints: {fingerprint_cols_present}")
    
    if not rtt_df.empty:
        dfs_to_concat.append(rtt_df)
        print(f"Adding calculated RTT columns: {list(rtt_df.columns)}")
    
    dfs_to_concat.append(raw_features_df)
    
    final_df = pd.concat(dfs_to_concat, axis=1)
    
    return final_df


def print_summary(final_df, fingerprint_cols_present, rtt_df, raw_features_df, features_count):
    """
    Print the final summary statistics.
    """
    print(f"\nFINAL SUMMARY:")
    print(f"   - Rows: {len(final_df)}")
    print(f"   - Total columns: {len(final_df.columns)}")
    
    available_base_cols = [col for col in BASE_COLUMNS if col in final_df.columns]
    print(f"   - Identification columns: {len(available_base_cols)}")
    print(f"   - Original fingerprint columns: {len(fingerprint_cols_present)}")
    print(f"   - Calculated RTT columns: {len(rtt_df.columns) if not rtt_df.empty else 0}")
    print(f"   - Raw feature columns: {len(raw_features_df.columns)}")
    
    print("\nFeatures by fingerprint type:")
    for name, count in features_count.items():
        print(f"   - {name}: {count} features")


def save_output(final_df, output_file):
    """
    Save the output files.
    """
    if not output_file:
        return
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"\nSaving FULL version...")
    final_df.to_csv(output_file, index=False)
    print(f"   File saved: {output_file}")
    
    # Clean version without nulls
    clean_df = final_df.dropna()
    if len(clean_df) > 0:
        clean_file = output_path.parent / f"{output_path.stem}_clean{output_path.suffix}"
        clean_df.to_csv(clean_file, index=False)
        print(f"\nSaving FULLY CLEAN version...")
        print(f"   File saved: {clean_file}")
        print(f"   Rows: {len(clean_df)} | Removed: {len(final_df) - len(clean_df)}")


def extract_all_raw_features(input_file, output_file=None):
    """
    Main function to extract all raw features from JA4+ fingerprints.
    """
    # Load input file
    df = load_input_file(input_file)
    
    # Analyze fingerprint coverage
    fingerprint_cols_present, fp_coverage = analyze_fingerprint_coverage(df)
    
    # Convert timestamp
    df = convert_timestamp(df)
    
    # Get available base columns
    available_base_cols = [col for col in BASE_COLUMNS if col in df.columns]
    
    # Process fingerprints
    raw_features_df, features_count = process_fingerprints(df, fingerprint_cols_present)
    
    if raw_features_df is None:
        return None
    
    # Calculate RTT
    rtt_df = calculate_rtt(raw_features_df)
    
    # Convert numeric columns to string
    raw_features_df = convert_numeric_to_string(raw_features_df)
    
    # Create individual files
    individual_files = create_individual_files(
        df, raw_features_df, fingerprint_cols_present,
        available_base_cols, rtt_df, output_file
    )
    
    # Build final dataframe
    final_df = build_final_dataframe(
        df, fingerprint_cols_present, available_base_cols,
        rtt_df, raw_features_df
    )
    
    # Print summary
    print_summary(final_df, fingerprint_cols_present, rtt_df, raw_features_df, features_count)
    
    # Save output
    save_output(final_df, output_file)
    
    return final_df