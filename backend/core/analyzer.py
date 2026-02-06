import json
import os

class SecurityAnalyzer:
    def __init__(self, rules_path: str = None):
        if not rules_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            rules_path = os.path.join(base_dir, "data", "compliance_rules.json")
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path: str):
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except: pass
        return {}

    def analyze_service(self, protocol: str, port: int, banner: str, extra_data: dict = None):
        findings = []
        banner_low = banner.lower()
        extra = extra_data or {}
        
        # 1. SSH: 弱口令 & 版本泄露
        if protocol == "SSH":
            if extra.get("weak_creds"):
                creds = extra["weak_creds"][0]
                findings.append({
                    "id": f"SSH-PWD-{port}", "protocol": protocol,
                    "check_item": "系统权限已失陷 (SSH 弱口令)", "risk_level": "高危",
                    "description": f"成功获取系统登录凭据：{creds['user']} / {creds['pass']}",
                    "detail_value": f"Valid Credential found on port {port}",
                    "suggestion": "立即修改密码，启用 MFA 认证。", "mlps_clause": "G3-安全计算环境-身份鉴别",
                    "metadata": {"is_compromised": True}
                })
            
            if "ssh" in banner_low and any(v in banner_low for v in ["ubuntu", "debian", "openssh"]):
                findings.append({
                    "id": f"SSH-BANNER-{port}", "protocol": protocol,
                    "check_item": "SSH 服务版本信息泄露", "risk_level": "低危",
                    "description": "SSH 服务端 Banner 暴露了具体的操作系统或软件版本。",
                    "detail_value": banner,
                    "suggestion": "修改 sshd_config 设置 DebianBanner no 或使用防火墙限制。",
                    "mlps_clause": "G3-安全计算环境-入侵防范"
                })

        # 2. Redis: 未授权访问
        if protocol == "Redis":
            res = extra.get("db_results", {})
            if res.get("vulnerable"):
                findings.append({
                    "id": f"REDIS-UNAUTH-{port}", "protocol": protocol,
                    "check_item": "数据库未授权访问 (匿名登录)", "risk_level": "高危",
                    "description": "Redis 服务器未启用密码认证，攻击者可远程执行任意指令并提取数据。",
                    "detail_value": res.get("detail", ""),
                    "suggestion": "1. 修改 redis.conf 启用 requirepass；2. 限制 bind 127.0.0.1。",
                    "mlps_clause": "G3-安全计算环境-身份鉴别",
                    "metadata": {"is_compromised": True, "db_type": "Redis"}
                })
            else:
                findings.append({
                    "id": f"REDIS-AUTH-{port}", "protocol": protocol,
                    "check_item": "Redis 服务探测", "risk_level": "安全",
                    "description": "检测到 Redis 服务已启用身份验证。",
                    "detail_value": "Auth Required.", "suggestion": "保持现状。", "mlps_clause": "G3-安全计算环境-身份鉴别"
                })

        # 3. 数据库通用 (MySQL/PG/Mongo): 服务暴露
        if protocol in ["MySQL", "PostgreSQL", "MongoDB"]:
            res = extra.get("db_results", {})
            if res.get("status") == "OPEN":
                findings.append({
                    "id": f"DB-OPEN-{port}", "protocol": protocol,
                    "check_item": f"{protocol} 服务暴露", "risk_level": "中危",
                    "description": f"发现 {protocol} 数据库服务端口对公网开放，增加了攻击面。",
                    "detail_value": res.get("banner", "Active"),
                    "suggestion": "1. 检查是否存在弱口令；2. 仅允许受信 IP 访问该端口。",
                    "mlps_clause": "G3-安全计算环境-入侵防范"
                })

        # 4. Web 协议 (HTTP/HTTPS): 综合分析
        if protocol in ["HTTP", "HTTPS"]:
            web_res = extra.get("web_results", {})
            tls_res = extra.get("tls_results", {})
            deep_scan = web_res.get("deep_scan", {})
            verified_vhosts = extra.get("verified_vhosts", [])

            # 4.1 虚拟主机发现 (VHost)
            if verified_vhosts:
                findings.append({
                    "id": f"WEB-VHOST-{port}", "protocol": protocol,
                    "check_item": "虚拟主机 (VHost) 碰撞成功", "risk_level": "中危",
                    "description": f"发现隐藏的虚拟主机域名: {', '.join(verified_vhosts)}",
                    "detail_value": str(verified_vhosts),
                    "suggestion": "确保内部测试域名不解析到公网，检查 Nginx/Apache 的 server_name 配置。",
                    "mlps_clause": "G3-安全计算环境-入侵防范"
                })

            # 4.2 敏感目录泄露
            if deep_scan.get("exposed_paths"):
                for path_obj in deep_scan["exposed_paths"]:
                    findings.append({
                        "id": f"WEB-DIR-{port}-{path_obj['path']}", "protocol": protocol,
                        "check_item": "Web 敏感文件/目录泄露", "risk_level": "高危",
                        "description": f"探测到敏感路径 {path_obj['path']} 可直接访问 (Status: {path_obj['status']})。",
                        "detail_value": f"Path: {path_obj['path']}",
                        "suggestion": "立即删除生产环境中的敏感文件或在 Web 服务器配置中禁止访问。",
                        "mlps_clause": "G3-安全计算环境-入侵防范"
                    })

            # 4.3 版本泄露
            server_header = web_res.get("banner", "")
            is_version_leak = web_res.get("version_leak", False)
            rule_leak = self.rules.get("HTTP_BANNER_LEAK", {})
            if is_version_leak and server_header != "Unknown":
                 findings.append({
                    "id": f"WEB-BANNER-{port}", 
                    "protocol": protocol,
                    "check_item": rule_leak.get("name", "Web 服务器版本信息泄露"),
                    "risk_level": "中危", 
                    "description": f"HTTP 响应头 Server 字段泄露了具体软件版本：{server_header}。{rule_leak.get('description', '')}",
                    "detail_value": f"Banner: {server_header}",
                    "suggestion": rule_leak.get("suggestion", "配置 Nginx (server_tokens off) 或 Apache (ServerTokens Prod) 隐藏版本。"),
                    "mlps_clause": rule_leak.get("clause_id", "G3-安全计算环境-入侵防范")
                })

            # 4.4 安全头缺失
            missing = deep_scan.get("missing_headers", [])
            if missing:
                rule_headers = self.rules.get("WEB_MISSING_HEADERS", {})
                findings.append({
                    "id": f"WEB-HEADER-{port}", 
                    "protocol": protocol,
                    "check_item": rule_headers.get("name", "Web 安全防护响应头缺失"), 
                    "risk_level": "低危",
                    "description": f"缺失关键安全头: {', '.join(missing[:3])} 等。",
                    "detail_value": f"Missing: {', '.join(missing)}",
                    "suggestion": rule_headers.get("suggestion", "配置 Web 服务器添加 X-Frame-Options, CSP 等安全头。"),
                    "mlps_clause": rule_headers.get("clause_id", "G3-安全计算环境-入侵防范")
                })
            
            # 不安全的 HTTP 方法
            unsafe_methods = deep_scan.get("unsafe_methods", [])
            if unsafe_methods:
                rule_methods = self.rules.get("WEB_UNSAFE_METHODS", {})
                findings.append({
                    "id": f"WEB-METHODS-{port}",
                    "protocol": protocol,
                    "check_item": rule_methods.get("name", "启用了不安全的 HTTP 方法"),
                    "risk_level": "中危",
                    "description": f"Web 服务器启用了 {', '.join(unsafe_methods)} 等危险方法，可能导致文件操作或 XST 攻击。",
                    "detail_value": f"Methods: {', '.join(unsafe_methods)}",
                    "suggestion": rule_methods.get("suggestion", "仅允许 GET, POST, HEAD 方法。"),
                    "mlps_clause": rule_methods.get("clause_id", "G3-安全计算环境-入侵防范")
                })

            # CORS 配置
            if deep_scan.get("cors_issue"):
                rule_cors = self.rules.get("WEB_CORS_ANY", {})
                findings.append({
                    "id": f"WEB-CORS-{port}",
                    "protocol": protocol,
                    "check_item": rule_cors.get("name", "CORS 跨域配置过度宽松"),
                    "risk_level": "高危",
                    "description": rule_cors.get("description", "Access-Control-Allow-Origin: *"),
                    "detail_value": "Origin: *",
                    "suggestion": rule_cors.get("suggestion", "严格限制白名单域名。"),
                    "mlps_clause": rule_cors.get("clause_id", "G3-安全计算环境-访问控制")
                })

            # Cookie 安全
            cookie_issues = deep_scan.get("cookie_issues", [])
            if cookie_issues:
                rule_cookie = self.rules.get("WEB_COOKIE_FLAGS", {})
                findings.append({
                    "id": f"WEB-COOKIE-{port}",
                    "protocol": protocol,
                    "check_item": rule_cookie.get("name", "Cookie 安全属性缺失"),
                    "risk_level": "中危",
                    "description": f"部分 Cookie 缺失 Secure 属性: {', '.join(cookie_issues[:2])} 等。",
                    "detail_value": str(cookie_issues),
                    "suggestion": rule_cookie.get("suggestion", "添加 Secure 和 HttpOnly 标志。"),
                    "mlps_clause": rule_cookie.get("clause_id", "G3-安全计算环境-身份鉴别")
                })
            
            # [NEW] HTTP 协议专属检查：未跳转 HTTPS
            specifics = deep_scan.get("specifics", {})
            if protocol == "HTTP" and specifics.get("https_redirect") is False:
                rule_redirect = self.rules.get("HTTP_NO_HTTPS", {})
                findings.append({
                    "id": f"HTTP-REDIRECT-{port}",
                    "protocol": "HTTP",
                    "check_item": rule_redirect.get("name", "HTTP 服务未启用 HTTPS 跳转"),
                    "risk_level": "低危", # 修正：统一使用中文枚举，确保前端渲染蓝色标签
                    "description": rule_redirect.get("description", "Web 服务未配置自动跳转 HTTPS，存在明文传输风险。"),
                    "detail_value": "No Redirect Found",
                    "suggestion": rule_redirect.get("suggestion", "配置 301 重定向至 HTTPS。"),
                    "mlps_clause": rule_redirect.get("clause_id", "G3-安全通信网络-通信保密性")
                })

            # 4.5 TLS 漏洞 (HTTPS Only)
            if protocol == "HTTPS":
                cert_vulns = tls_res.get("vulnerabilities", [])
                
                # 密钥强度检测
                if "WEAK_KEY_SIZE" in cert_vulns:
                    rule_weak_key = self.rules.get("TLS_WEAK_CERT", {})
                    findings.append({
                        "id": f"TLS-KEY-{port}", 
                        "protocol": "HTTPS",
                        "check_item": rule_weak_key.get("name", "数字证书密钥强度不足"),
                        "risk_level": "高危",
                        "description": f"证书公钥长度为 {tls_res.get('cert_info', {}).get('key_size')} 位 (不足 2048 位)，不满足通信保密性要求。",
                        "detail_value": f"Key Size: {tls_res.get('cert_info', {}).get('key_size')} bits",
                        "suggestion": rule_weak_key.get("suggestion", "重新生成密钥长度至少为 2048 位的 RSA 证书。"),
                        "mlps_clause": rule_weak_key.get("clause_id", "G3-安全通信网络-通信保密性")
                    })

                # 通信完整性检测
                if "WEAK_SIGNATURE" in cert_vulns:
                    rule_integrity = self.rules.get("TLS_WEAK_SIGNATURE", {})
                    findings.append({
                        "id": f"TLS-SIG-{port}", 
                        "protocol": "HTTPS",
                        "check_item": rule_integrity.get("name", "通信完整性校验不足"),
                        "risk_level": "高危",
                        "description": f"证书使用了弱哈希算法 ({tls_res.get('cert_info', {}).get('sig_algo')}) 进行签名，无法保证通信完整性。",
                        "detail_value": f"Sig Algo: {tls_res.get('cert_info', {}).get('sig_algo')}",
                        "suggestion": rule_integrity.get("suggestion", "使用 SHA-256 或更高强度的签名算法重新颁发证书。"),
                        "mlps_clause": rule_integrity.get("clause_id", "G3-安全通信网络-通信完整性")
                    })
                
                # 弱加密套件检测
                if "WEAK_CIPHER_SUITE" in cert_vulns and tls_res.get("weak_ciphers"):
                    rule_cipher = self.rules.get("TLS_WEAK_CIPHER", {})
                    weak_list = tls_res.get("weak_ciphers", [])
                    findings.append({
                        "id": f"TLS-CIPHER-{port}", 
                        "protocol": "HTTPS",
                        "check_item": rule_cipher.get("name", "启用了不安全的加密套件"),
                        "risk_level": "高危",
                        "description": f"服务端接受以下弱加密套件: {', '.join(weak_list)}，攻击者可破解通信内容。",
                        "detail_value": f"Suites: {', '.join(weak_list)}",
                        "suggestion": rule_cipher.get("suggestion", "禁用 RC4/DES/3DES 等算法。"),
                        "mlps_clause": rule_cipher.get("clause_id", "G3-安全通信网络-通信保密性")
                    })

                # 老旧协议检测
                weak_protos = tls_res.get("weak_protocols", [])
                if weak_protos:
                    rule_tls = self.rules.get("TLS_OLD_PROTO", {})
                    findings.append({
                        "id": f"TLS-OLD-{port}", 
                        "protocol": "HTTPS",
                        "check_item": rule_tls.get("name", "使用了不安全的加密协议"),
                        "risk_level": "高危",
                        "description": f"服务器启用了已弃用的老旧协议: {', '.join(weak_protos)}。",
                        "detail_value": str(weak_protos),
                        "suggestion": rule_tls.get("suggestion", "禁用 TLSv1.0/1.1，仅启用 TLSv1.2 及以上版本。"),
                        "mlps_clause": rule_tls.get("clause_id", "G3-安全通信网络-通信保密性")
                    })
                
                if "CERT_EXPIRED" in cert_vulns:
                    findings.append({
                        "id": f"TLS-EXP-{port}", "protocol": "HTTPS",
                        "check_item": "SSL/TLS 证书已过期", "risk_level": "高危",
                        "description": "服务器使用的数字证书已过期，无法保证通信可信度。",
                        "detail_value": f"Expired: {tls_res.get('cert_info', {}).get('expiry')}",
                        "suggestion": "立即更换有效的数字证书。",
                        "mlps_clause": "G3-安全通信网络-通信保密性"
                    })

        # 5. DNS 漏洞分析
        if protocol == "DNS":
            res = extra.get("dns_results", {})
            if res.get("vulnerable"):
                rule_dns = self.rules.get("DNS_ZONE_TRANSFER", {})
                findings.append({
                    "id": f"DNS-AXFR-{port}", 
                    "protocol": protocol,
                    "check_item": rule_dns.get("name", "DNS 区域传送漏洞"),
                    "risk_level": "高危",
                    "description": f"DNS 服务器允许非授权的区域传送 (AXFR)，导致 {res.get('records_count', 0)} 条解析记录泄露。",
                    "detail_value": "\n".join(res.get("records", [])),
                    "suggestion": rule_dns.get("suggestion", "在 Bind 配置中限制 'allow-transfer'。"),
                    "mlps_clause": rule_dns.get("clause_id", "G3-安全区域边界-边界防护")
                })
            else:
                 findings.append({
                    "id": f"DNS-OPEN-{port}", "protocol": protocol,
                    "check_item": "DNS 服务开放", "risk_level": "低危",
                    "description": "检测到 DNS (53) 端口开放，未发现区域传送风险。",
                    "detail_value": res.get("detail", "No Transfer"),
                    "suggestion": "确保仅对内网开放或已配置 ACL 访问控制。",
                    "mlps_clause": "G3-安全区域边界-访问控制"
                })

        # 6. 高危/非必要端口判定
        RISKY_PORTS = {
            21: {"name": "FTP", "desc": "明文传输协议，建议使用 SFTP", "risk": "中危"},
            23: {"name": "Telnet", "desc": "明文传输协议，完全不安全，建议使用 SSH", "risk": "高危"},
            135: {"name": "RPC", "desc": "易受攻击，严禁对公网开放", "risk": "高危"},
            139: {"name": "NetBIOS", "desc": "易泄露内网信息，严禁对公网开放", "risk": "高危"},
            445: {"name": "SMB", "desc": "存在永恒之蓝等高危漏洞，严禁对公网开放", "risk": "高危"},
            3389: {"name": "RDP", "desc": "远程桌面服务，易受勒索病毒攻击，建议仅对 VPN 开放", "risk": "高危"},
            5900: {"name": "VNC", "desc": "远程控制服务，建议设置强密码或限制访问 IP", "risk": "中危"},
            11211: {"name": "Memcached", "desc": "可能存在未授权访问漏洞", "risk": "中危"},
            27017: {"name": "MongoDB", "desc": "NoSQL 数据库，默认配置可能存在未授权访问", "risk": "中危"}
        }

        if port in RISKY_PORTS:
            info = RISKY_PORTS[port]
            rule_tcp = self.rules.get("TCP_PORT_OPEN", {})
            findings.append({
                "id": f"RISKY-PORT-{port}", 
                "protocol": "TCP",
                "check_item": "高危/非必要端口开放", 
                "risk_level": info["risk"],
                "description": f"检测到高危端口 {port} ({info['name']}) 处于开放状态。",
                "detail_value": f"Port {port} ({info['name']}) is OPEN. {info['desc']}",
                "suggestion": f"该端口属于高风险服务，请立即关闭或通过防火墙限制仅允许特定 IP 访问。",
                "mlps_clause": rule_tcp.get("clause_id", "G3-安全区域边界-访问控制")
            })

        # 7. 兜底
        if not findings:
            findings.append({
                "id": f"PORT-{port}", "protocol": protocol, "check_item": "常规端口开放", 
                "risk_level": "安全", "description": f"检测到 {protocol} 端口处于活动状态。",
                "detail_value": f"Port: {port}, Banner: {banner[:50]}", "suggestion": "核查业务必要性，遵循最小权限原则。", "mlps_clause": "G3-安全区域边界-访问控制"
            })

        return findings

    def calculate_score(self, defects: list):
        score = 100
        for d in defects:
            level = d.get('risk_level')
            if level == '高危': score -= 25
            elif level == '中危': score -= 10
            elif level == '低危': score -= 2
        return max(0, score)