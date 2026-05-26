"""extract_raw_features/parsers.py

Parsing functions for each JA4+ fingerprint type.
Each function extracts raw features from a fingerprint string.
"""

import numpy as np
import pandas as pd


def parse_ja4(ja4_str):
    """
    Split a JA4 fingerprint (TLS Client Fingerprint).
    Format: protocol_tlsversion_sni_cipherCount_extensionCount_alpn_cipherHash_extensionHash
    Example: t13d1516h2_8daaf6152771_02713d6af862
    """
    features = {}
    if pd.isna(ja4_str) or ja4_str == '':
        return {
            'ja4_protocol': np.nan,
            'ja4_tls_version': np.nan,
            'ja4_sni_type': np.nan,
            'ja4_n_ciphers': np.nan,
            'ja4_n_extensions': np.nan,
            'ja4_alpn': np.nan,
            'ja4_cipher_hash': np.nan,
            'ja4_extension_hash': np.nan
        }
    
    try:
        parts = ja4_str.split('_')
        if len(parts) >= 3:
            a_part = parts[0]
            if a_part and len(a_part) >= 10:
                features['ja4_protocol'] = a_part[0]
                features['ja4_tls_version'] = a_part[1:3]
                features['ja4_sni_type'] = a_part[3]
                cipher_count_str = a_part[4:6]
                features['ja4_n_ciphers'] = int(cipher_count_str) if cipher_count_str.isdigit() else np.nan
                ext_count_str = a_part[6:8]
                features['ja4_n_extensions'] = int(ext_count_str) if ext_count_str.isdigit() else np.nan
                features['ja4_alpn'] = a_part[8:10]
            else:
                features['ja4_protocol'] = np.nan
                features['ja4_tls_version'] = np.nan
                features['ja4_sni_type'] = np.nan
                features['ja4_n_ciphers'] = np.nan
                features['ja4_n_extensions'] = np.nan
                features['ja4_alpn'] = np.nan
            
            features['ja4_cipher_hash'] = parts[1] if len(parts) > 1 else np.nan
            features['ja4_extension_hash'] = parts[2] if len(parts) > 2 else np.nan
            
    except Exception as e:
        print(f"Error parsing JA4 '{ja4_str}': {e}")
        features = {k: np.nan for k in ['ja4_protocol', 'ja4_tls_version', 'ja4_sni_type',
                                        'ja4_n_ciphers', 'ja4_n_extensions', 'ja4_alpn',
                                        'ja4_cipher_hash', 'ja4_extension_hash']}
      
    return features


def parse_ja4s(ja4s_str):
    """
    Split a JA4S fingerprint (TLS Server Fingerprint).
    """
    features = {}
    if pd.isna(ja4s_str) or ja4s_str == '':
        return {
            'ja4s_protocol': np.nan,
            'ja4s_tls_version': np.nan,
            'ja4s_n_extensions': np.nan,
            'ja4s_alpn': np.nan,
            'ja4s_cipher_chosen': np.nan,
            'ja4s_extension_hash': np.nan
        }
    
    try:
        parts = str(ja4s_str).split('_')
        
        if len(parts) >= 3:
            a_part = parts[0]
            if a_part and len(a_part) >= 7:
                features['ja4s_protocol'] = a_part[0]
                features['ja4s_tls_version'] = a_part[1:3]
                ext_count_str = a_part[3:5]
                features['ja4s_n_extensions'] = int(ext_count_str) if ext_count_str.isdigit() else np.nan
                features['ja4s_alpn'] = a_part[5:7]
            else:
                features['ja4s_protocol'] = np.nan
                features['ja4s_tls_version'] = np.nan
                features['ja4s_n_extensions'] = np.nan
                features['ja4s_alpn'] = np.nan
            
            features['ja4s_cipher_chosen'] = parts[1] if len(parts) > 1 else np.nan
            features['ja4s_extension_hash'] = parts[2] if len(parts) > 2 else np.nan
            
    except Exception as e:
        print(f"Error parsing JA4S '{ja4s_str}': {e}")
        features = {k: np.nan for k in ['ja4s_protocol', 'ja4s_tls_version', 'ja4s_n_extensions',
                                        'ja4s_alpn', 'ja4s_cipher_chosen', 'ja4s_extension_hash']}
    
    return features


def parse_ja4x(ja4x_str):
    """
    Split a JA4X fingerprint (Certificate Fingerprint).
    """
    features = {}
    if pd.isna(ja4x_str) or ja4x_str == '':
        return {
            'ja4x_issuer_hash': np.nan, 
            'ja4x_subject_hash': np.nan,
            'ja4x_extensions_hash': np.nan
        }
    
    try:
        parts = ja4x_str.split('_')
        features['ja4x_issuer_hash'] = parts[0] if len(parts) > 0 else np.nan
        features['ja4x_subject_hash'] = parts[1] if len(parts) > 1 else np.nan
        features['ja4x_extensions_hash'] = parts[2] if len(parts) > 2 else np.nan
        
    except Exception as e:
        print(f"Error parsing JA4X '{ja4x_str}': {e}")
        features = {k: np.nan for k in ['ja4x_issuer_hash', 'ja4x_subject_hash', 
                                        'ja4x_extensions_hash']}
    
    return features


def parse_ja4h(ja4h_str):
    """
    Split a JA4H fingerprint (HTTP Fingerprint).
    """
    features = {}
    if pd.isna(ja4h_str) or ja4h_str == '':
        return {
            'ja4h_method': np.nan,
            'ja4h_version': np.nan,
            'ja4h_has_cookie': np.nan,
            'ja4h_has_referer': np.nan,
            'ja4h_n_headers': np.nan,
            'ja4h_language': np.nan,
            'ja4h_headers_hash': np.nan,
            'ja4h_cookies_hash': np.nan,
            'ja4h_cookie_values_hash': np.nan
        }
    
    try:
        parts = ja4h_str.split('_')
        
        a_part = parts[0] if len(parts) > 0 else ''
        if a_part and len(a_part) >= 12:
            features['ja4h_method'] = a_part[0:2]
            features['ja4h_version'] = a_part[2:4]
            features['ja4h_has_cookie'] = a_part[4]
            features['ja4h_has_referer'] = a_part[5]
            n_headers_str = a_part[6:8]
            features['ja4h_n_headers'] = int(n_headers_str) if n_headers_str.isdigit() else np.nan
            features['ja4h_language'] = a_part[8:12]
        else:
            features['ja4h_method'] = np.nan
            features['ja4h_version'] = np.nan
            features['ja4h_has_cookie'] = np.nan
            features['ja4h_has_referer'] = np.nan
            features['ja4h_n_headers'] = np.nan
            features['ja4h_language'] = np.nan
        
        features['ja4h_headers_hash'] = parts[1] if len(parts) > 1 else np.nan
        features['ja4h_cookies_hash'] = parts[2] if len(parts) > 2 else np.nan
        features['ja4h_cookie_values_hash'] = parts[3] if len(parts) > 3 else np.nan
        
    except Exception as e:
        print(f"Error parsing JA4H '{ja4h_str}': {e}")
        features = {k: np.nan for k in ['ja4h_method', 'ja4h_version', 'ja4h_has_cookie',
                                        'ja4h_has_referer', 'ja4h_n_headers', 'ja4h_language',
                                        'ja4h_headers_hash', 'ja4h_cookies_hash', 
                                        'ja4h_cookie_values_hash']}
    
    return features


def parse_ja4l(ja4l_str, prefix='ja4l'):
    """
    Split a JA4L/JA4LS fingerprint (Latency Client/Server).
    """
    features = {}
    if pd.isna(ja4l_str) or ja4l_str == '':
        return {
            f'{prefix}_id': np.nan,
            f'{prefix}_ttl': np.nan,
            f'{prefix}_is_quic': np.nan,
            f'{prefix}_hop_count': np.nan
        }
    
    try:
        ja4l_str = str(ja4l_str).strip()
        
        is_quic = ja4l_str.endswith('_q')
        clean_str = ja4l_str.replace('_q', '')
        parts = clean_str.split('_')
        
        id_value = np.nan
        if len(parts) > 0 and parts[0]:
            try:
                id_value = float(parts[0])
            except:
                id_value = np.nan
        
        ttl = np.nan
        hop_count = np.nan
        if len(parts) > 1 and parts[1]:
            try:
                ttl = float(parts[1])
                if ttl <= 64:
                    hop_count = 64 - ttl
                elif ttl <= 128:
                    hop_count = 128 - ttl
                else:
                    hop_count = 255 - ttl
            except:
                ttl = np.nan
                hop_count = np.nan
        
        features = {
            f'{prefix}_id': id_value,
            f'{prefix}_ttl': ttl,
            f'{prefix}_is_quic': 1 if is_quic else 0,
            f'{prefix}_hop_count': hop_count
        }
        
    except Exception as e:
        print(f"   Error parsing {prefix} '{ja4l_str}': {e}")
        features = {
            f'{prefix}_id': np.nan, 
            f'{prefix}_ttl': np.nan, 
            f'{prefix}_is_quic': np.nan,
            f'{prefix}_hop_count': np.nan 
        }
    
    return features


def parse_ja4t(ja4t_str, prefix='ja4t'):
    """
    Split a JA4T/JA4TS fingerprint (TCP Client/Server).
    """
    features = {}
    if pd.isna(ja4t_str) or ja4t_str == '':
        return {
            f'{prefix}_window_size': np.nan,
            f'{prefix}_option_list': np.nan,
            f'{prefix}_mss': np.nan,
            f'{prefix}_scale': np.nan,
            f'{prefix}_num_options': np.nan,
            f'{prefix}_has_timestamp': np.nan,
            f'{prefix}_has_sack': np.nan,
            f'{prefix}_has_window_scale': np.nan
        }
    
    try:
        ja4t_str = str(ja4t_str).strip()
        parts = ja4t_str.split('_')
        
        window_size = np.nan
        if len(parts) > 0 and parts[0]:
            try:
                window_size = float(parts[0])
            except:
                window_size = np.nan
        
        option_list = parts[1] if len(parts) > 1 else np.nan
        
        mss = np.nan
        if len(parts) > 2 and parts[2]:
            try:
                mss = float(parts[2])
            except:
                mss = np.nan
        
        scale = np.nan
        if len(parts) > 3 and parts[3]:
            try:
                scale = float(parts[3])
            except:
                scale = np.nan
        
        num_options = np.nan
        has_timestamp = np.nan
        has_sack = np.nan
        has_window_scale = np.nan
        
        if isinstance(option_list, str) and option_list != np.nan:
            options = option_list.split('-')
            num_options = float(len(options))
            has_timestamp = 1.0 if '8' in options else 0.0
            has_sack = 1.0 if '4' in options else 0.0
            has_window_scale = 1.0 if '3' in options else 0.0
        
        features = {
            f'{prefix}_window_size': window_size,
            f'{prefix}_option_list': option_list,
            f'{prefix}_mss': mss,
            f'{prefix}_scale': scale,
            f'{prefix}_num_options': num_options,
            f'{prefix}_has_timestamp': has_timestamp,
            f'{prefix}_has_sack': has_sack,
            f'{prefix}_has_window_scale': has_window_scale
        }
    except Exception as e:
        print(f"   Error parsing {prefix} '{ja4t_str}': {e}")
        features = {
            f'{prefix}_window_size': np.nan,
            f'{prefix}_option_list': np.nan,
            f'{prefix}_mss': np.nan,
            f'{prefix}_scale': np.nan,
            f'{prefix}_num_options': np.nan,
            f'{prefix}_has_timestamp': np.nan,
            f'{prefix}_has_sack': np.nan,
            f'{prefix}_has_window_scale': np.nan
        }
    
    return features


def parse_sni(sni_str):
    """
    Extract SNI (Server Name Indication) as a single feature.
    """
    if pd.isna(sni_str) or sni_str == '' or sni_str == '(empty)':
        return {'sni': np.nan}
    
    try:
        sni_str = str(sni_str).strip()
        if sni_str == '' or sni_str == '(empty)':
            return {'sni': np.nan}
        return {'sni': sni_str}
    except Exception as e:
        print(f"Error parsing SNI '{sni_str}': {e}")
        return {'sni': np.nan}


# Parser mapping for dynamic lookup
PARSER_MAPPING = {
    'ja4': parse_ja4,
    'ja4s': parse_ja4s,
    'ja4x': parse_ja4x,
    'ja4h': parse_ja4h,
    'ja4l': lambda x: parse_ja4l(x, 'ja4l'),
    'ja4ls': lambda x: parse_ja4l(x, 'ja4ls'),
    'ja4t': lambda x: parse_ja4t(x, 'ja4t'),
    'ja4ts': lambda x: parse_ja4t(x, 'ja4ts'),
    'sni': parse_sni
}


def get_parser(fingerprint_type):
    """Get the parser function for a given fingerprint type."""
    return PARSER_MAPPING.get(fingerprint_type)