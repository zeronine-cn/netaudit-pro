
import requests
import ssl
import socket
import re
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor

# 离线探测常用的敏感路径集
SENSITIVE_PATHS = [
    "/.git/config",
    "/.env",
    "/phpinfo.php",
    "/info.php",
    "/.vscode/sftp.json",
    "/admin/",
    "/backup/",
    "/config.php.bak",
    "/.htaccess",
    "/robots.txt",
    "/server-status"
]

# 关键安全响应头检查列表
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def verify_vhost(target: str, port: int, vhost: str):
    """
    验证域名是否真的是该 IP 承载的有效虚拟主机
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=vhost) as ssock:
                cert_bin = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                try:
                    ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = ext.value.get_values_for_type(x509.GeneralName)
                    for san in sans:
                        pattern = san.replace('.', r'\.').replace('*', r'.*')
                        if re.fullmatch(pattern, vhost, re.IGNORECASE):
                            return True
                except:
                    cn = str(cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value)
                    if cn.lower() == vhost.lower():
                        return True
        return False
    except:
        try:
            r = requests.get(f"http://{target}:{port}", headers={"Host": vhost}, timeout=2, allow_redirects=False)
            return r.status_code not in [404, 421]
        except:
            return False

def probe_sensitive_paths(base_url, headers):
    """
    并发探测敏感目录
    """
    exposed = []
    
    def check_path(path):
        try:
            full_url = f"{base_url.rstrip('/')}{path}"
            # 仅做 HEAD 请求以减少流量，或者做 GET 但只读少量内容
            r = requests.get(full_url, headers=headers, timeout=2, allow_redirects=False, verify=False)
            # 排除 404, 403, 5xx，通常 200 或 3xx 可能代表存在
            if r.status_code == 200:
                # 二次校验：如果内容包含 404 文本（伪 404），则跳过
                if "404" not in r.text[:200].lower():
                    return {"path": path, "status": r.status_code}
            return None
        except:
            return None

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(check_path, SENSITIVE_PATHS))
        exposed = [r for r in results if r]
    
    return exposed

def scan_http(target: str, port: int, vhost: str = None):
    try:
        protocol = "https" if port == 443 or port == 8443 else "http"
        url = f"{protocol}://{target}:{port}"
        
        headers = {'User-Agent': 'NetAudit-Audit-Bot/3.1'}
        if vhost: headers['Host'] = vhost
            
        response = requests.get(url, headers=headers, timeout=4, allow_redirects=False, verify=False)
        server_banner = response.headers.get('Server', 'Unknown')
        
        # 深度探测：敏感目录扫描
        exposed_paths = probe_sensitive_paths(url, headers)
        
        # 深度探测：安全头分析
        missing_headers = []
        for sh in SECURITY_HEADERS:
            if sh not in response.headers:
                missing_headers.append(sh)

        return {
            "port": port,
            "status": "OPEN",
            "banner": server_banner,
            "headers": dict(response.headers),
            "vhost_matched": vhost if vhost else target,
            "deep_scan": {
                "exposed_paths": exposed_paths,
                "missing_headers": missing_headers
            }
        }
    except Exception as e:
        return {"port": port, "status": "CLOSED", "error": str(e)}

def check_tls_vulnerability(target: str, port: int, vhost: str = None):
    results = {
        "weak_protocols": [],
        "cert_info": None,
        "vulnerabilities": []
    }
    
    # 1. 检测老旧协议
    for version_name, version_const in [("TLSv1.0", ssl.PROTOCOL_TLSv1), ("TLSv1.1", ssl.PROTOCOL_TLSv1_1)]:
        try:
            context = ssl.SSLContext(version_const)
            with socket.create_connection((target, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                    results["weak_protocols"].append(version_name)
        except: pass

    # 2. 证书分析
    try:
        cert_pem = ssl.get_server_certificate((target, port))
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        
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
    except: pass

    return results
