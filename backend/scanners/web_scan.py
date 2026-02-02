
import requests
import ssl
import socket
import re
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor

# 同步靶场路径
SENSITIVE_PATHS = [
    "/.git/config",
    "/.env",
    "/phpinfo.php",
    "/.vscode/sftp.json",
    "/config.php.bak",
    "/.htaccess",
    "/.bak"
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
    并发探测敏感目录及文件暴露。
    针对 .env, .git, phpinfo 等进行特征指纹校验。
    """
    protocol = "https" if port in [443, 8443] else "http"
    base_url = f"{protocol}://{target}:{port}"
    headers = {'User-Agent': 'NetAudit-Audit-Bot/3.2'}
    if vhost: headers['Host'] = vhost
    
    exposed = []
    
    def probe(path):
        try:
            full_url = f"{base_url.rstrip('/')}{path}"
            # verify=False 用于忽略自签名证书，allow_redirects=False 防止误报跳转页面
            r = requests.get(full_url, headers=headers, timeout=3, verify=False, allow_redirects=False)
            if r.status_code == 200:
                content = r.text.lower()
                # 增强判定逻辑：根据文件类型校验关键内容特征
                is_vuln = False
                if ".env" in path and ("db_password" in content or "app_key" in content or "database" in content):
                    is_vuln = True
                elif ".git" in path and "[core]" in content:
                    is_vuln = True
                elif "phpinfo" in path and ("php extension" in content or "system" in content):
                    is_vuln = True
                elif ".bak" in path or ".htaccess" in path:
                    is_vuln = True # 备份文件及配置文件通常 200 即视为风险
                
                if is_vuln:
                    return {"path": path, "status": 200, "evidence": content[:100].replace('\n', ' ')}
            return None
        except:
            return None

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
            "vhost_matched": vhost if vhost else target,
            "deep_scan": {
                "missing_headers": missing_headers
            }
        }
    except Exception as e:
        return {"port": port, "status": "CLOSED", "error": str(e)}

def check_tls_vulnerability(target: str, port: int, vhost: str = None):
    results = {"weak_protocols": [], "weak_ciphers": [], "cert_info": None, "vulnerabilities": []}
    
    # 探测 TLS 1.0/1.1 (强制降级以支持 1024位密钥连接)
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

    # 专项探测 RC4
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

    # 证书强度校验
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
