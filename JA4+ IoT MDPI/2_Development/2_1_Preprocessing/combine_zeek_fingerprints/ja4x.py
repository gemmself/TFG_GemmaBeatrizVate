"""JA4X fingerprint calculation from x509 certificates."""

import hashlib

# This module implements the JA4X fingerprinting method based on x509 certificate information.
# Its behaviour is inspired by the JA4X implementation in the python FOXIO's script, but adapted to work with Zeek's x509.log data.

def encode_variable_length_quantity(v: int) -> list:
    """Encode OID segments using DER variable-length quantity rules."""
    m = 0x00
    output = []
    while v >= 0x80:
        output.insert(0, (v & 0x7F) | m)
        v = v >> 7
        m = 0x80
    output.insert(0, v | m)
    return output


def oid_to_hex(oid: str) -> str:
    """Convert a dotted OID string into the hexadecimal payload used by JA4X."""
    try:
        a = [int(x) for x in oid.split(".")]
        oid_encoded = [a[0] * 40 + a[1]]
        for n in a[2:]:
            oid_encoded.extend(encode_variable_length_quantity(n))
        oid_encoded.insert(0, len(oid_encoded))
        oid_encoded.insert(0, 0x06)
        return "".join("{:02x}".format(num) for num in oid_encoded)[4:]
    except:
        return ""


def sha_encode(items):
    """Hash a list of items and return first 8 hex characters."""
    if not items:
        return "00000000"
    items_str = ",".join(sorted(items))
    return hashlib.sha256(items_str.encode('utf8')).hexdigest()[:8]


def extract_oids_from_dn(dn_string):
    """Keep only the distinguished-name attributes that contribute to JA4X."""
    import pandas as pd
    
    oids = []
    attr_to_oid = {
        'CN': '2.5.4.3', 'L': '2.5.4.7', 'ST': '2.5.4.8',
        'O': '2.5.4.10', 'OU': '2.5.4.11', 'C': '2.5.4.6',
        'STREET': '2.5.4.9', 'EMAILADDRESS': '1.2.840.113549.1.9.1',
        'SUBJECTALTNAME': '2.5.29.17'
    }
    
    if not dn_string or pd.isna(dn_string):
        return oids
    
    parts = str(dn_string).split(',')
    for part in parts:
        part = part.strip()
        if '=' in part:
            attr, _ = part.split('=', 1)
            if attr.upper() in attr_to_oid:
                oids.append(attr_to_oid[attr.upper()])
    
    return oids


def extract_extensions_from_row(row):
    """Build the subset of certificate extensions that JA4X uses."""
    import pandas as pd
    
    extensions = []
    if 'basic_constraints.ca' in row and pd.notna(row['basic_constraints.ca']):
        if str(row['basic_constraints.ca']).lower() in ['t', 'true', '1']:
            extensions.append('2.5.29.19')
    
    san_fields = ['san.dns', 'san.uri', 'san.email', 'san.ip']
    for field in san_fields:
        if field in row and pd.notna(row[field]) and str(row[field]) != '-':
            extensions.append('2.5.29.17')
            break
    
    return list(set(extensions))


def calculate_ja4x_for_certificate(row):
    """Calculate JA4X from a certificate row."""
    import pandas as pd
    
    try:
        subject = row.get('certificate.subject', '')
        issuer = row.get('certificate.issuer', '')
        
        if not subject or pd.isna(subject) or subject == '-':
            return None
        
        subject_oids = extract_oids_from_dn(str(subject))
        issuer_oids = extract_oids_from_dn(str(issuer)) if not pd.isna(issuer) and issuer != '-' else []
        
        subject_hex = [oid_to_hex(oid) for oid in subject_oids if oid_to_hex(oid)]
        issuer_hex = [oid_to_hex(oid) for oid in issuer_oids if oid_to_hex(oid)]
        
        extensions = extract_extensions_from_row(row)
        extensions_hex = [oid_to_hex(ext) for ext in extensions if oid_to_hex(ext)]
        
        issuer_hash = sha_encode(issuer_hex)
        subject_hash = sha_encode(subject_hex)
        
        if extensions_hex:
            extensions_hash = hashlib.sha256(",".join(extensions_hex).encode('utf8')).hexdigest()[:12]
        else:
            extensions_hash = "000000000000"
        
        return f"{issuer_hash}_{subject_hash}_{extensions_hash}"
        
    except Exception as e:
        return None