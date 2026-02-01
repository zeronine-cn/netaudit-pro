
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
            if web_res.get("deep_scan", {}).get("exposed_paths"):
                for path_obj in web_res["deep_scan"]["exposed_paths"]:
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
            if len(server_header) > 2 and server_header != "Unknown":
                 findings.append({
                    "id": f"WEB-BANNER-{port}", "protocol": protocol,
                    "check_item": "Web 服务器版本信息泄露", "risk_level": "中危",
                    "description": f"HTTP 响应头 Server 字段泄露了具体软件版本：{server_header}",
                    "detail_value": server_header,
                    "suggestion": "配置 Nginx (server_tokens off) 或 Apache (ServerTokens Prod) 隐藏版本。",
                    "mlps_clause": "G3-安全计算环境-入侵防范"
                })

            # 4.4 安全头缺失
            missing = web_res.get("deep_scan", {}).get("missing_headers", [])
            if missing:
                findings.append({
                    "id": f"WEB-HEADER-{port}", "protocol": protocol,
                    "check_item": "Web 安全防护响应头缺失", "risk_level": "低危",
                    "description": f"缺失关键安全头: {', '.join(missing[:3])} 等。",
                    "detail_value": f"Missing: {', '.join(missing)}",
                    "suggestion": "配置 Web 服务器添加 X-Frame-Options, CSP 等安全头。",
                    "mlps_clause": "G3-安全计算环境-入侵防范"
                })

            # 4.5 TLS 漏洞 (HTTPS Only)
            if protocol == "HTTPS":
                weak_protos = tls_res.get("weak_protocols", [])
                if weak_protos:
                    findings.append({
                        "id": f"TLS-OLD-{port}", "protocol": "HTTPS",
                        "check_item": "使用了不安全的加密协议", "risk_level": "高危",
                        "description": f"服务器启用了已弃用的老旧协议: {', '.join(weak_protos)}。",
                        "detail_value": str(weak_protos),
                        "suggestion": "禁用 TLSv1.0/1.1，仅启用 TLSv1.2 及以上版本。",
                        "mlps_clause": "G3-安全通信网络-通信保密性"
                    })
                
                cert_vulns = tls_res.get("vulnerabilities", [])
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
                findings.append({
                    "id": f"DNS-AXFR-{port}", "protocol": protocol,
                    "check_item": "DNS 区域传送漏洞", "risk_level": "高危",
                    "description": f"DNS 服务器允许非授权的区域传送 (AXFR)，导致 {res.get('records_count', 0)} 条解析记录泄露。",
                    "detail_value": "\n".join(res.get("records", [])),
                    "suggestion": "在 Bind 配置中限制 'allow-transfer' 仅允许从 DNS 服务器 (Slave DNS) IP 访问。",
                    "mlps_clause": "G3-安全区域边界-边界防护"
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


        # 6. 兜底
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
