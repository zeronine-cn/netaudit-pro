
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
import ssl
import socket
import re
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor

# 禁用 urllib3 的不安全请求警告
requests.packages.urllib3.disable_warnings()

# 靶场敏感路径指纹库 (增强版)
SENSITIVE_PATHS = [
    {"path": "/.git/config", "pattern": "repositoryformatversion", "name": "Git Config Leaked"},
    {"path": "/.env", "pattern": "=", "name": "Environment Config (.env)"}, # 只要有等号通常就是 env
    {"path": "/phpinfo.php", "pattern": "PHP Version", "name": "PHP Info Page"},
    {"path": "/config.php.bak", "pattern": "<?php", "name": "Backup Config File"},
    {"path": "/.vscode/sftp.json", "pattern": "{", "name": "VSCode SFTP Config"},
    {"path": "/.htaccess", "pattern": "RewriteEngine", "name": "Apache Config (.htaccess)"},
    {"path": "/.bak", "pattern": "", "name": "Backup File (Generic)"} # 只要200就报
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

# --- 核心修复：终极 SSL 兼容适配器 ---
class LegacySSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        # 创建一个极其宽容的 SSL 上下文
        context = create_urllib3_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # 强制允许所有弱加密套件和旧协议
        try:
            # OpenSSL 1.1.1+ / 3.0+ 需要设置 SECLEVEL=0 才能允许 RC4/MD5
            context.set_ciphers('DEFAULT:@SECLEVEL=0')
            context.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
        except Exception:
            # 如果失败，回退到允许所有
            context.set_ciphers('ALL:@SECLEVEL=0')
        
        kwargs['ssl_context'] = context
        return super(LegacySSLAdapter, self).init_poolmanager(*args, **kwargs)

def get_legacy_session():
    """获取一个能够连接老旧/弱安全服务器的 Session"""
    s = requests.Session()
    adapter = LegacySSLAdapter()
    s.mount('https://', adapter)
    s.mount('http://', adapter) # HTTP 也挂载，虽然主要影响 HTTPS
    s.headers.update({
        'User-Agent': 'NetAudit-Pro/3.2 (Security_Audit)',
        'Accept': '*/*'
    })
    s.verify = False
    return s

def check_sensitive_paths(target: str, port: int, vhost: str = None):
    """
    并发探测敏感路径
    """
    protocol = "https" if port in [443, 8443] else "http"
    base_url = f"{protocol}://{target}:{port}"
    
    headers = {}
    if vhost: headers['Host'] = vhost
    
    exposed = []
    
    def probe(item):
        try:
            full_url = f"{base_url.rstrip('/')}{item['path']}"
            session = get_legacy_session() # 每次请求获取新 session 避免污染
            
            # timeout 设置短一点，避免卡死
            r = session.get(full_url, headers=headers, timeout=5, allow_redirects=False)
            
            if r.status_code == 200:
                content = r.text
                # 指纹匹配逻辑
                is_hit = False
                if item['pattern'] == "": # 空 pattern 表示只要 200 就报
                    is_hit = True
                elif item['pattern'] in content:
                    is_hit = True
                # 针对 .env 的特殊宽松检查 (包含 key=value 结构)
                elif item['path'] == '/.env' and '=' in content:
                    is_hit = True

                if is_hit:
                    evidence = content[:100].strip().replace('\n', ' ')
                    return {
                        "path": item['path'], 
                        "status": 200, 
                        "evidence": evidence if len(evidence) > 0 else "[Binary/Empty]",
                        "name": item['name']
                    }
            return None
        except Exception as e:
            return None

    # 使用线程池并发
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(probe, SENSITIVE_PATHS))
        exposed = [r for r in results if r]
    
    return exposed

def scan_http(target: str, port: int, vhost: str = None):
    try:
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{target}:{port}"
        
        session = get_legacy_session()
        if vhost: session.headers['Host'] = vhost
            
        response = session.get(url, timeout=6, allow_redirects=False)
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
    
    # 1. 弱协议探测 (TLS 1.0 / 1.1)
    for version_name, proto in [("TLSv1.0", ssl.PROTOCOL_TLSv1), ("TLSv1.1", ssl.PROTOCOL_TLSv1_1)]:
        try:
            # 创建原始 socket 上下文探测
            context = ssl.SSLContext(proto)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try: 
                context.set_ciphers('DEFAULT:@SECLEVEL=0')
            except: pass
            
            with socket.create_connection((target, port), timeout=4) as sock:
                with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                    results["weak_protocols"].append(version_name)
        except: 
            pass # 连接失败说明不支持该旧协议，是好事

    # 2. 弱加密套件探测 (RC4)
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try: context.set_ciphers('RC4:@SECLEVEL=0')
        except: context.set_ciphers('RC4')
        
        with socket.create_connection((target, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                cipher_name = ssock.cipher()[0]
                if 'RC4' in cipher_name:
                    results["weak_ciphers"].append("RC4")
    except: pass

    # 3. 证书审计 (1024位密钥与过期)
    try:
        # 使用最宽容的方式获取证书，防止因握手失败拿不到证书
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try: context.set_ciphers('DEFAULT:@SECLEVEL=0')
        except: pass

        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                der_cert = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                
                results["cert_info"] = {
                    "expiry": cert.not_valid_after.strftime("%Y-%m-%d"),
                    "key_size": getattr(cert.public_key(), 'key_size', 2048),
                    "is_expired": datetime.utcnow() > cert.not_valid_after
                }
    except Exception as e:
        pass

    return results
