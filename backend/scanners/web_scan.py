import requests
import ssl
import socket
import re
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor

# 引入并禁用安全警告，防止日志污染
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 离线探测常用的敏感路径集 (新增 cookie.php, check.php 等常见测试入口)
SENSITIVE_PATHS = [
    "/.git/config",
    "/.env",
    "/phpinfo.php",
    "/info.php",
    "/cookie.php",
    "/check.php",
    "/api/test",
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

def fetch_url_headers(url: str):
    """
    前端工具箱专用：获取指定 URL 的 Header 信息
    """
    try:
        # 补全协议
        if not url.startswith('http'):
            url = 'http://' + url
            
        r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        return {
            "status": "success",
            "url": r.url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "cookies": r.cookies.get_dict()
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

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
    并发探测敏感目录，并提取有效响应的 Headers 和 Cookies 供后续分析
    """
    exposed = []
    
    def check_path(path):
        try:
            full_url = f"{base_url.rstrip('/')}{path}"
            # 必须使用 GET 获取完整 Header (HEAD 有时会被服务器特殊处理)
            r = requests.get(full_url, headers=headers, timeout=3, allow_redirects=False, verify=False)
            
            # 记录有效响应：增加 403/405 支持 (Nginx configured with always)
            valid_codes = [200, 301, 302, 307, 401, 403, 405]
            
            if r.status_code in valid_codes:
                # 过滤掉伪 404 (有些站点自定义 404 页面返回 200)
                if r.status_code == 200 and "404" in r.text[:200].lower():
                    return None
                
                # 提取 Cookies (处理 requests 合并问题，尝试从 raw 取)
                raw_cookies = []
                try:
                    raw_cookies = r.raw.headers.getlist('Set-Cookie')
                except:
                    val = r.headers.get('Set-Cookie')
                    if val: raw_cookies = [val]

                return {
                    "path": path, 
                    "status": r.status_code, 
                    "headers": r.headers, 
                    "raw_cookies": raw_cookies
                }
            return None
        except:
            return None

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(check_path, SENSITIVE_PATHS))
        exposed = [r for r in results if r]
    
    return exposed

def check_unsafe_methods(base_url, headers):
    """
    检测不安全的 HTTP 方法，并返回 OPTIONS 请求的 Headers
    """
    unsafe_methods = []
    options_headers = {}
    
    try:
        # 1. 发送 OPTIONS 请求
        r = requests.options(base_url, headers=headers, timeout=3, verify=False)
        options_headers = r.headers # 保存 OPTIONS 的响应头，用于 CORS 分析
        allow_header = r.headers.get('Allow', '')
        
        for method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
            if method in allow_header.upper():
                unsafe_methods.append(method)
        
        # 2. TRACE 验证
        if 'TRACE' not in unsafe_methods:
            try:
                r_trace = requests.request('TRACE', base_url, headers=headers, timeout=2, verify=False)
                if r_trace.status_code not in [403, 405, 501]:
                    unsafe_methods.append('TRACE (Active)')
            except: pass

    except: pass
    return unsafe_methods, options_headers

def check_https_redirect(target, port, headers):
    """
    [HTTP 专属] 检测是否自动跳转到 HTTPS
    """
    try:
        url = f"http://{target}:{port}"
        r = requests.get(url, headers=headers, timeout=3, allow_redirects=False, verify=False)
        # 只有明确返回 3xx 且 Location 指向 https 才算通过
        if r.status_code in [301, 302, 307, 308]:
            loc = r.headers.get("Location", "")
            if loc.lower().startswith("https://"):
                return True
    except: pass
    # 其他情况（包括 200, 403, 404）都视为未开启跳转
    return False

def scan_http(target: str, port: int, scheme: str = "http", vhost: str = None):
    """
    Web 服务综合扫描 (增强版)
    """
    try:
        url = f"{scheme}://{target}:{port}"
        headers = {'User-Agent': 'NetAudit-Audit-Bot/3.1'}
        if vhost: headers['Host'] = vhost
            
        # 1. 基础请求 (Root)
        response = requests.get(url, headers=headers, timeout=4, allow_redirects=False, verify=False)
        server_banner = response.headers.get('Server', 'Unknown')
        
        has_version_leak = False
        if server_banner != 'Unknown' and re.search(r'\d+\.\d+', server_banner):
            has_version_leak = True

        # 2. 深度探测：敏感目录 (同时收集它们的 Headers)
        exposed_paths_data = probe_sensitive_paths(url, headers)
        
        # 3. 深度探测：不安全方法 & OPTIONS Headers
        unsafe_methods, options_headers = check_unsafe_methods(url, headers)

        # 4. 数据聚合分析 (Header Analysis Aggregation)
        # 我们需要检查 Root, OPTIONS, 以及所有发现的敏感路径的 Headers
        # 只要任意一个地方出现了 CORS * 或者 不安全的 Cookie，都算漏洞
        
        all_header_sources = [response.headers, options_headers]
        for p in exposed_paths_data:
            all_header_sources.append(p['headers'])
            
        all_cookie_sources = []
        # 添加 Root 的 cookies
        try: all_cookie_sources.extend(response.raw.headers.getlist('Set-Cookie'))
        except: 
            if response.headers.get('Set-Cookie'): all_cookie_sources.append(response.headers.get('Set-Cookie'))
            
        # 添加敏感路径的 cookies
        for p in exposed_paths_data:
            all_cookie_sources.extend(p['raw_cookies'])

        # --- 分析逻辑 ---
        
        missing_headers = []
        for sh in SECURITY_HEADERS:
            # 简单策略：检查 Root 是否缺失 (通常安全头是全局配置)
            if sh not in response.headers:
                missing_headers.append(sh)

        # CORS 检查 (遍历所有收集到的 Header 源 - 增强版大小写不敏感)
        cors_issue = False
        for h in all_header_sources:
            # 遍历所有 key 寻找 Access-Control-Allow-Origin
            for k, v in h.items():
                if k.lower() == 'access-control-allow-origin':
                    if v == '*' or (v != '*' and h.get('Access-Control-Allow-Credentials') == 'true'):
                        cors_issue = True
                        break
            if cors_issue: break

        # Cookie 检查 (遍历所有收集到的 Cookies)
        cookie_issues = []
        # 去重
        unique_cookies = list(set(all_cookie_sources))
        
        for cookie_str in unique_cookies:
            parts = cookie_str.split(';')
            cookie_name = parts[0].split('=')[0].strip()
            lower_str = cookie_str.lower()
            
            # 记录问题
            issues = []
            if "secure" not in lower_str: issues.append("Missing Secure")
            if "httponly" not in lower_str: issues.append("Missing HttpOnly")
            
            if issues:
                cookie_issues.append(f"{cookie_name} ({', '.join(issues)})")

        # 5. 特殊检查
        specifics = {}
        if scheme == "http":
            specifics["https_redirect"] = check_https_redirect(target, port, headers)

        # 格式化 exposed_paths 输出
        exposed_paths_summary = [{"path": p["path"], "status": p["status"]} for p in exposed_paths_data]

        return {
            "port": port,
            "status": "OPEN",
            "banner": server_banner,
            "version_leak": has_version_leak,
            "headers": dict(response.headers),
            "vhost_matched": vhost if vhost else target,
            "deep_scan": {
                "exposed_paths": exposed_paths_summary,
                "missing_headers": missing_headers,
                "unsafe_methods": unsafe_methods,
                "cors_issue": cors_issue,
                "cookie_issues": cookie_issues, # 这是一个列表，只要非空，Analyzer 就会报漏洞
                "specifics": specifics
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
    
    protocols_to_test = []
    try:
        protocols_to_test.append(("TLSv1.0", ssl.TLSVersion.TLSv1))
        protocols_to_test.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1))
    except AttributeError:
        if hasattr(ssl, "PROTOCOL_TLSv1"):
            protocols_to_test.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
        if hasattr(ssl, "PROTOCOL_TLSv1_1"):
            protocols_to_test.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))

    for name, version_obj in protocols_to_test:
        try:
            if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                context.minimum_version = version_obj
                context.maximum_version = version_obj
            except:
                if isinstance(version_obj, int):
                     context = ssl.SSLContext(version_obj)
                     context.check_hostname = False
                     context.verify_mode = ssl.CERT_NONE

            try:
                context.set_ciphers('DEFAULT:@SECLEVEL=0')
            except:
                try: context.set_ciphers('DEFAULT')
                except: pass

            with socket.create_connection((target, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                    results["weak_protocols"].append(name)
        except: pass

    weak_suites_to_test = ["RC4", "RC4-MD5", "RC4-SHA", "DES-CBC3-SHA", "DES", "NULL", "EXP"]
    for cipher_str in weak_suites_to_test:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                try: context.set_ciphers(f'{cipher_str}:@SECLEVEL=0')
                except: context.set_ciphers(cipher_str)
            except ssl.SSLError: continue 

            with socket.create_connection((target, port), timeout=1) as sock:
                with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                    used_cipher = ssock.cipher()
                    if used_cipher:
                        results["weak_ciphers"].append(f"{cipher_str} ({used_cipher[0]})")
                        if "RC4" in cipher_str: break 
        except: pass

    try:
        cert_pem = ssl.get_server_certificate((target, port))
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        now = datetime.utcnow()
        is_expired = now > cert.not_valid_after
        pub_key = cert.public_key()
        key_size = getattr(pub_key, 'key_size', 2048)
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"

        results["cert_info"] = {
            "subject": cert.subject.rfc4514_string(),
            "expiry": cert.not_valid_after.strftime("%Y-%m-%d"),
            "key_size": key_size,
            "sig_algo": sig_algo,
            "is_expired": is_expired
        }
        
        if is_expired: results["vulnerabilities"].append("CERT_EXPIRED")
        if key_size < 2048: results["vulnerabilities"].append("WEAK_KEY_SIZE")
        if sig_algo.lower() in ['md5', 'sha1']: results["vulnerabilities"].append("WEAK_SIGNATURE")
        if results["weak_ciphers"]: results["vulnerabilities"].append("WEAK_CIPHER_SUITE")
            
    except: pass

    return results
