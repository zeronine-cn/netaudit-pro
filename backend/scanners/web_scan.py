
import requests
import ssl
import socket
import re
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor

# Security Headers to check
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def scan_http(target: str, port: int, vhost: str = None):
    try:
        # Determine protocol based on common playground ports
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{target}:{port}"
        
        headers = {'User-Agent': 'NetAudit-Audit-Bot/3.2'}
        if vhost: headers['Host'] = vhost
            
        # verify=False is critical to ignore cert errors and get the banner
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False, verify=False)
        server_banner = response.headers.get('Server', 'Unknown')
        
        missing_headers = [sh for sh in SECURITY_HEADERS if sh not in response.headers]

        return {
            "port": port,
            "status": "OPEN",
            "banner": server_banner,
            "headers": dict(response.headers),
            "vhost_matched": vhost if vhost else target,
            "deep_scan": {
                "missing_headers": missing_headers
            }
        }
    except Exception as e:
        return {"port": port, "status": "CLOSED", "error": str(e)}

def check_tls_vulnerability(target: str, port: int, vhost: str = None):
    results = {
        "weak_protocols": [],
        "weak_ciphers": [],
        "cert_info": None,
        "vulnerabilities": []
    }
    
    # Define probes for old protocols
    # Note: Modern systems may not have these constants if compiled without them, 
    # but we try to use generic SSLContext to probe.
    for version_name, proto in [("TLSv1.0", ssl.PROTOCOL_TLSv1), ("TLSv1.1", ssl.PROTOCOL_TLSv1_1)]:
        try:
            context = ssl.SSLContext(proto)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # CRITICAL: Lower security level to allow weak keys/protocols
            try: context.set_ciphers('DEFAULT:@SECLEVEL=0')
            except: pass
            
            with socket.create_connection((target, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                    results["weak_protocols"].append(version_name)
        except:
            pass

    # Specific probe for RC4 Ciphers
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Force RC4
        try: context.set_ciphers('RC4:@SECLEVEL=0')
        except: context.set_ciphers('RC4')
        
        with socket.create_connection((target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                cipher = ssock.cipher()
                if cipher and 'RC4' in cipher[0]:
                    results["weak_ciphers"].append("RC4")
    except:
        pass

    # General Cert Info & Weak Key Check
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try: context.set_ciphers('DEFAULT:@SECLEVEL=0')
        except: pass

        with socket.create_connection((target, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                cert_bin = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                now = datetime.utcnow()
                is_expired = now > cert.not_valid_after
                pub_key = cert.public_key()
                key_size = getattr(pub_key, 'key_size', 2048)
                
                results["cert_info"] = {
                    "subject": cert.subject.rfc4514_string(),
                    "expiry": cert.not_valid_after.strftime("%Y-%m-%d"),
                    "key_size": key_size,
                    "is_expired": is_expired
                }
                
                if is_expired: results["vulnerabilities"].append("CERT_EXPIRED")
                if key_size < 2048: results["vulnerabilities"].append("WEAK_KEY_SIZE")
    except:
        pass

    return results
