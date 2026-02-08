
import requests
import ssl
import socket
import re
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor, as_completed

# 引入并禁用安全警告，防止日志污染
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 离线探测常用的敏感路径集
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

def detect_web_scheme(target: str, port: int) -> str:
    """
    自动探测端口运行的是 HTTP 还是 HTTPS 协议
    """
    try:
        # 尝试 SSL 握手，如果成功则认为是 HTTPS
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                return "https"
    except:
        # 握手失败（如返回 HTTP 响应或超时），回退到 HTTP
        return "http"

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
            # 构造完整 URL，确保区分 HTTP/HTTPS
            full_url = f"{base_url.rstrip('/')}{path}"
            r = requests.get(full_url, headers=headers, timeout=3, allow_redirects=False, verify=False)
            valid_codes = [200, 301, 302, 307, 401, 403, 405]
            
            if r.status_code in valid_codes:
                if r.status_code == 200 and "404" in r.text[:200].lower():
                    return None
                
                raw_cookies = []
                try:
                    raw_cookies = r.raw.headers.getlist('Set-Cookie')
                except:
                    val = r.headers.get('Set-Cookie')
                    if val: raw_cookies = [val]

                return {
                    "path": path,
                    "full_url": full_url, # 返回完整 URL 方便区分
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
    unsafe_methods = []
    options_headers = {}
    try:
        r = requests.options(base_url, headers=headers, timeout=3, verify=False)
        options_headers = r.headers
        allow_header = r.headers.get('Allow', '')
        for method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
            if method in allow_header.upper():
                unsafe_methods.append(method)
        if 'TRACE' not in unsafe_methods:
            try:
                r_trace = requests.request('TRACE', base_url, headers=headers, timeout=2, verify=False)
                if r_trace.status_code not in [403, 405, 501]:
                    unsafe_methods.append('TRACE (Active)')
            except: pass
    except: pass
    return unsafe_methods, options_headers

def check_https_redirect(target, port, headers):
    try:
        url = f"http://{target}:{port}"
        r = requests.get(url, headers=headers, timeout=3, allow_redirects=False, verify=False)
        if r.status_code in [301, 302, 307, 308]:
            loc = r.headers.get("Location", "")
            if loc.lower().startswith("https://"):
                return True
    except: pass
    return False

def scan_http_target(target: str, port: int, scheme: str = "http", vhost: str = None):
    """
    基础 Web 扫描单元：针对单个 Target/VHost 组合进行探测
    """
    try:
        # 基础 URL 始终指向 IP，Host 头决定 VHost
        url = f"{scheme}://{target}:{port}"
        headers = {'User-Agent': 'NetAudit-Audit-Bot/3.1'}
        
        # 标记来源上下文
        context_label = f"{scheme.upper()}://{target}:{port}"
        if vhost: 
            headers['Host'] = vhost
            context_label = f"{scheme.upper()}://{vhost}:{port}"
            
        response = requests.get(url, headers=headers, timeout=4, allow_redirects=False, verify=False)
        server_banner = response.headers.get('Server', 'Unknown')
        
        has_version_leak = False
        if server_banner != 'Unknown' and re.search(r'\d+\.\d+', server_banner):
            has_version_leak = True

        exposed_paths_data = probe_sensitive_paths(url, headers)
        unsafe_methods, options_headers = check_unsafe_methods(url, headers)

        # 数据聚合分析
        all_header_sources = [response.headers, options_headers]
        for p in exposed_paths_data:
            all_header_sources.append(p['headers'])
            
        all_cookie_sources = []
        try: all_cookie_sources.extend(response.raw.headers.getlist('Set-Cookie'))
        except: 
            if response.headers.get('Set-Cookie'): all_cookie_sources.append(response.headers.get('Set-Cookie'))
        for p in exposed_paths_data:
            all_cookie_sources.extend(p['raw_cookies'])

        missing_headers = []
        for sh in SECURITY_HEADERS:
            if sh not in response.headers:
                missing_headers.append(sh)

        cors_issue = False
        for h in all_header_sources:
            for k, v in h.items():
                if k.lower() == 'access-control-allow-origin':
                    if v == '*' or (v != '*' and h.get('Access-Control-Allow-Credentials') == 'true'):
                        cors_issue = True
                        break
            if cors_issue: break

        cookie_issues = []
        unique_cookies = list(set(all_cookie_sources))
        for cookie_str in unique_cookies:
            lower_str = cookie_str.lower()
            issues = []
            if "secure" not in lower_str: issues.append("Missing Secure")
            if "httponly" not in lower_str: issues.append("Missing HttpOnly")
            if issues:
                cookie_name = cookie_str.split(';')[0].split('=')[0].strip()
                cookie_issues.append(f"{cookie_name} ({', '.join(issues)})")

        specifics = {}
        if scheme == "http":
            specifics["https_redirect"] = check_https_redirect(target, port, headers)

        # 核心修改：在结果中包含上下文来源，不再仅是路径
        exposed_paths_summary = []
        for p in exposed_paths_data:
            exposed_paths_summary.append({
                "path": p["path"],
                "status": p["status"],
                "url": p["full_url"],
                "context": context_label # 携带来源信息
            })

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
                "cookie_issues": cookie_issues,
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
    
    # 协议版本检测
    protocols_to_test = []
    if hasattr(ssl, "TLSVersion"):
        protocols_to_test.append(("TLSv1.0", ssl.TLSVersion.TLSv1))
        protocols_to_test.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1))
    else:
        if hasattr(ssl, "PROTOCOL_TLSv1"): protocols_to_test.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
        if hasattr(ssl, "PROTOCOL_TLSv1_1"): protocols_to_test.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))

    for name, version_obj in protocols_to_test:
        try:
            context = ssl.create_default_context()
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
            
            try: context.set_ciphers('DEFAULT:@SECLEVEL=0')
            except: pass

            with socket.create_connection((target, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                    results["weak_protocols"].append(name)
        except: pass

    # 弱加密套件检测
    weak_suites_to_test = ["RC4", "RC4-MD5", "RC4-SHA", "DES-CBC3-SHA", "DES", "NULL", "EXP"]
    for cipher_str in weak_suites_to_test:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try: context.set_ciphers(f'{cipher_str}:@SECLEVEL=0')
            except: 
                try: context.set_ciphers(cipher_str)
                except: continue

            with socket.create_connection((target, port), timeout=1) as sock:
                with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                    used = ssock.cipher()
                    if used: results["weak_ciphers"].append(f"{cipher_str} ({used[0]})")
                    if "RC4" in cipher_str: break 
        except: pass

    # 证书信息
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

def scan_web_service(target_ip: str, port: int, domains: list = None, is_deep_scan: bool = False, update_progress_cb = None):
    """
    统一 Web 服务扫描入口。
    1. 自动探测 HTTP/HTTPS 协议。
    2. 默认扫描 Root (IP)。
    3. 如果有域名，并发扫描所有域名。
    4. 聚合所有扫描结果，保留最大风险项。
    """
    
    # 1. 自动探测协议 (区别 HTTP 和 HTTPS)
    scheme = detect_web_scheme(target_ip, port)
    protocol_name = "HTTPS" if scheme == "https" else "HTTP"
    
    if update_progress_cb:
        update_progress_cb(f"[*] Detected protocol {protocol_name} on port {port}")

    # 2. 基础扫描：针对 IP (Root)
    # 这能发现直接访问 IP 时的敏感文件泄露 (如 .git, .env)
    web_res = scan_http_target(target_ip, port, scheme=scheme, vhost=None)
    
    # 为 IP 结果的路径添加标识，如果之前没有
    if 'deep_scan' in web_res:
        for p in web_res['deep_scan'].get('exposed_paths', []):
            if 'context' not in p or not p['context']:
                p['path'] = f"{p['path']} (Direct IP)"

    # 3. 并发域名扫描：针对所有关联域名
    if domains:
        if update_progress_cb:
            update_progress_cb(f"[*] Scanning {len(domains)} associated domains concurrently...")
        
        def scan_domain_worker(dom):
            return dom, scan_http_target(target_ip, port, scheme=scheme, vhost=dom)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_domain_worker, d) for d in domains]
            
            for future in as_completed(futures):
                try:
                    domain, domain_res = future.result()
                    
                    # 如果 IP 扫描结果为空/失败（如服务器禁止 IP 直接访问），直接采用域名的结果作为基准
                    if 'deep_scan' not in web_res and 'deep_scan' in domain_res:
                        web_res = domain_res
                        continue

                    # 结果融合逻辑：将域名扫描发现的额外信息合并到主结果中
                    if 'deep_scan' in web_res and 'deep_scan' in domain_res:
                        deep = web_res['deep_scan']
                        dom_deep = domain_res['deep_scan']

                        # A. 合并敏感目录 - 核心修改：移除去重逻辑，保留所有发现，明确区分来源
                        for p in dom_deep.get('exposed_paths', []):
                            # 创建副本以免修改原始引用
                            p_copy = p.copy()
                            # 明确标记该路径是在哪个域名下发现的，保留协议头
                            # 如果 scan_http_target 已经填充了 context，直接利用 path 组装
                            # 格式化为: /admin [Domain: example.com]
                            p_copy['path'] = f"{p['path']} [Domain: {domain}]" 
                            
                            # 无条件添加到主列表，确保 IP 和 域名的结果共存
                            deep.setdefault('exposed_paths', []).append(p_copy)

                        # B. 合并 CORS 问题
                        if dom_deep.get('cors_issue'):
                            deep['cors_issue'] = True

                        # C. 合并 Cookie 问题
                        for c in dom_deep.get('cookie_issues', []):
                            cookie_msg = f"{c} [Domain: {domain}]"
                            current_cookies = deep.get('cookie_issues', [])
                            if cookie_msg not in current_cookies:
                                deep.setdefault('cookie_issues', []).append(cookie_msg)

                        # D. 合并 Headers & Methods
                        deep['missing_headers'] = list(set(deep.get('missing_headers', [])) | set(dom_deep.get('missing_headers', [])))
                        deep['unsafe_methods'] = list(set(deep.get('unsafe_methods', [])) | set(dom_deep.get('unsafe_methods', [])))
                        
                except Exception as e:
                    pass

    # 4. VHost 碰撞 (仅深度模式)
    verified_vhosts = []
    if is_deep_scan and domains:
        if update_progress_cb:
            update_progress_cb(f"[*] Verifying Virtual Hosts on port {port}...")
        for domain in domains:
            if verify_vhost(target_ip, port, domain):
                verified_vhosts.append(domain)
    
    # 5. TLS 检测 (仅 HTTPS)
    tls_res = {}
    if protocol_name == "HTTPS":
        # 使用第一个域名进行 SNI 握手，如果没有域名则使用 IP
        primary_vhost = domains[0] if domains else None
        if update_progress_cb:
            update_progress_cb(f"[*] Analyzing TLS configuration...")
        tls_res = check_tls_vulnerability(target_ip, port, vhost=primary_vhost)

    # 返回聚合后的标准结构
    return {
        "protocol": protocol_name,
        "banner": web_res.get("banner", "Web Server"),
        "extra": {
            "web_results": web_res,
            "tls_results": tls_res,
            "verified_vhosts": verified_vhosts
        }
    }
