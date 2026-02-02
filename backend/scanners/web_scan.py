
import requests
import ssl
import socket
import re
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor

# 靶场敏感路径指纹库
SENSITIVE_PATHS = [
    {"path": "/.git/config", "pattern": "[core]"},
    {"path": "/.env", "pattern": "DB_PASSWORD"},
    {"path": "/phpinfo.php", "pattern": "phpinfo"},
    {"path": "/config.php.bak", "pattern": "<?php"},
    {"path": "/.vscode/sftp.json", "pattern": "password"},
    {"path": "/.htaccess", "pattern": "RewriteEngine"}
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def check_sensitive_paths(target: str, port: int, vhost: str = None):
    """
    针对靶场路径进行并发探测与指纹匹配。
    """
    protocol = "https" if port in [443, 8443] else "http"
    base_url = f"{protocol}://{target}:{port}"
    headers = {'User-Agent': 'NetAudit-Audit-Bot/3.2'}
    if vhost: headers['Host'] = vhost
    
    exposed = []
    
    def probe(item):
        try:
            full_url = f"{base_url.rstrip('/')}{item['path']}"
            r = requests.get(full_url, headers=headers, timeout=3, verify=False, allow_redirects=False)
            if r.status_code == 200:
                content = r.text
                if item['pattern'] in content:
                    return {
                        "path": item['path'], 
                        "status": 200, 
                        "evidence": content[:60].strip().replace('\n', ' ')
                    }
            return None
        except: return None

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(probe, SENSITIVE_PATHS))
        exposed = [r for r in results if r]
    
    return exposed

def scan_http(target: str, port: int, vhost: str = None):
    try:
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{target}:{port}"
        headers = {'User-Agent': 'NetAudit-Audit-Bot/3.2'}
        if vhost: headers['Host'] = vhost
            
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False, verify=False)
        server_banner = response.headers.get('Server', 'Unknown')
        missing_headers = [sh for sh in SECURITY_HEADERS if sh not in response.headers]

        return {
            "port": port,
            "status": "OPEN",
            "banner": server_banner,
            "headers": dict(response.headers),
            "deep_scan": {"missing_headers": missing_headers}
        }
    except Exception as e:
        return {"port": port, "status": "CLOSED", "error": str(e)}

def check_tls_vulnerability(target: str, port: int, vhost: str = None):
    results = {"weak_protocols": [], "weak_ciphers": [], "cert_info": None, "vulnerabilities": []}
    
    # 1. 弱协议探测
    for version_name, proto in [("TLSv1.0", ssl.PROTOCOL_TLSv1), ("TLSv1.1", ssl.PROTOCOL_TLSv1_1)]:
        try:
            context = ssl.SSLContext(proto)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try: context.set_ciphers('DEFAULT:@SECLEVEL=0')
            except: pass
            with socket.create_connection((target, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                    results["weak_protocols"].append(version_name)
        except: pass

    # 2. 弱加密套件 (RC4)
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try: context.set_ciphers('RC4:@SECLEVEL=0')
        except: context.set_ciphers('RC4')
        with socket.create_connection((target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                if 'RC4' in ssock.cipher()[0]: results["weak_ciphers"].append("RC4")
    except: pass

    # 3. 证书审计 (1024位密钥与过期)
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try: context.set_ciphers('DEFAULT:@SECLEVEL=0')
        except: pass
        with socket.create_connection((target, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                cert = x509.load_der_x509_certificate(ssock.getpeercert(True), default_backend())
                results["cert_info"] = {
                    "expiry": cert.not_valid_after.strftime("%Y-%m-%d"),
                    "key_size": getattr(cert.public_key(), 'key_size', 2048),
                    "is_expired": datetime.utcnow() > cert.not_valid_after
                }
    except: pass

    return results
