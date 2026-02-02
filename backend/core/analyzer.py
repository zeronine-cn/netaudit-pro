
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
        extra = extra_data or {}
        
        # 1. SSH (22, 2222)
        if protocol == "SSH":
            if extra.get("weak_creds"):
                creds = extra["weak_creds"][0]
                findings.append({
                    "id": f"SSH-PWD-{port}", "protocol": protocol,
                    "check_item": "系统权限已失陷 (SSH 弱口令)", "risk_level": "高危",
                    "description": f"成功发现有效凭据：{creds['user']} / {creds['pass']}",
                    "detail_value": f"Authenticated via {creds['user']}:{creds['pass']}",
                    "suggestion": "立即修改密码，改用公钥认证。", "mlps_clause": "G3-安全计算环境-身份鉴别",
                    "metadata": {"is_compromised": True}
                })
            
            if port == 2222:
                findings.append({
                    "id": f"SSH-PORT-VULN-{port}", "protocol": protocol,
                    "check_item": "非标端口服务暴露 (SSH)", "risk_level": "低危",
                    "description": "检测到 SSH 服务运行在非标准端口 2222。",
                    "detail_value": f"Port: {port}",
                    "suggestion": "遵循业务必要性原则，限制访问来源 IP。", "mlps_clause": "G3-安全区域边界-访问控制"
                })

        # 2. Web & TLS (80, 8080, 443, 8443)
        elif protocol in ["HTTP", "HTTPS"]:
            web_res = extra.get("web_results", {})
            tls_res = extra.get("tls_results", {})

            # 敏感文件检测
            exposed = web_res.get("deep_scan", {}).get("exposed_paths", [])
            for item in exposed:
                findings.append({
                    "id": f"WEB-FILE-{port}-{item['path']}", "protocol": protocol,
                    "check_item": "Web 敏感文件/目录泄露", "risk_level": "高危",
                    "description": f"探测到敏感路径 {item['path']} 可直接访问。",
                    "detail_value": f"Path: {item['path']}, Status: {item['status']}",
                    "suggestion": "立即删除该文件或限制目录访问权限。", "mlps_clause": "G3-安全计算环境-入侵防范"
                })

            # 响应头缺失
            missing = web_res.get("deep_scan", {}).get("missing_headers", [])
            if missing:
                findings.append({
                    "id": f"WEB-HEADER-{port}", "protocol": protocol,
                    "check_item": "Web 安全防护响应头缺失", "risk_level": "低危",
                    "description": f"缺失关键安全头: {', '.join(missing[:2])} 等。",
                    "detail_value": f"Missing: {', '.join(missing)}",
                    "suggestion": "在服务器配置中添加 X-Frame-Options 等安全头。", "mlps_clause": "G3-安全计算环境-入侵防范"
                })

            # HTTPS 深度分析
            if protocol == "HTTPS":
                if tls_res.get("weak_protocols"):
                    findings.append({
                        "id": f"TLS-OLD-{port}", "protocol": "HTTPS",
                        "check_item": "使用了不安全的加密协议 (TLS 1.0/1.1)", "risk_level": "高危",
                        "description": f"服务器启用了已弃用的老旧协议: {', '.join(tls_res['weak_protocols'])}。",
                        "detail_value": str(tls_res['weak_protocols']),
                        "suggestion": "禁用 TLSv1.0/1.1，仅保留 TLSv1.2 及以上。", "mlps_clause": "G3-安全通信网络-通信保密性"
                    })
                
                if tls_res.get("weak_ciphers"):
                    findings.append({
                        "id": f"TLS-WEAK-CIPHER-{port}", "protocol": "HTTPS",
                        "check_item": "启用了弱加密套件 (RC4)", "risk_level": "高危",
                        "description": "服务器允许使用 RC4 加密算法，无法满足机密性要求。",
                        "detail_value": "Cipher: RC4 detected",
                        "suggestion": "修改 ssl_ciphers 配置，禁用 RC4。", "mlps_clause": "G3-安全通信网络-通信保密性"
                    })

                cert_info = tls_res.get("cert_info")
                if cert_info:
                    if cert_info.get("is_expired"):
                        findings.append({
                            "id": f"TLS-EXP-{port}", "protocol": "HTTPS",
                            "check_item": "SSL/TLS 证书已过期", "risk_level": "高危",
                            "description": "证书有效期已过，无法验证身份。",
                            "detail_value": f"Expired at {cert_info.get('expiry')}",
                            "suggestion": "立即更换有效证书。", "mlps_clause": "G3-安全通信网络-通信保密性"
                        })
                    if cert_info.get("key_size", 2048) < 2048:
                        findings.append({
                            "id": f"TLS-WEAK-KEY-{port}", "protocol": "HTTPS",
                            "check_item": "数字证书密钥强度不足", "risk_level": "高危",
                            "description": f"证书密钥长度为 {cert_info.get('key_size')} 位，低于 2048 位基线要求。",
                            "detail_value": f"Current Key Size: {cert_info.get('key_size')} bits",
                            "suggestion": "重新生成 2048 位强度的证书。", "mlps_clause": "G3-安全通信网络-通信保密性"
                        })

        # 3. DNS (53, 5353)
        elif protocol == "DNS":
            dns_res = extra.get("dns_results", {})
            if dns_res.get("vulnerable"):
                findings.append({
                    "id": f"DNS-AXFR-{port}", "protocol": protocol,
                    "check_item": "DNS 区域传送漏洞 (AXFR)", "risk_level": "高危",
                    "description": f"DNS 服务允许非授权 AXFR 请求，导致资产列表泄露。",
                    "detail_value": f"Records Leaked: {dns_res.get('records_count')}",
                    "suggestion": "限制 allow-transfer 仅允许授权 IP。", "mlps_clause": "G3-安全区域边界-边界防护"
                })

        # 4. 数据库服务判定
        if protocol in ["MySQL", "Redis", "PostgreSQL"]:
            db_res = extra.get("db_results", {})
            if db_res.get("status") == "OPEN":
                findings.append({
                    "id": f"DB-OPEN-{port}", "protocol": protocol,
                    "check_item": f"数据库服务对外暴露 ({protocol})", "risk_level": "中危",
                    "description": f"检测到 {protocol} 端口处于监听状态，增加了攻击面。",
                    "detail_value": f"Port {port} is OPEN",
                    "suggestion": "通过防火墙限制该端口的访问来源。", "mlps_clause": "G3-安全区域边界-访问控制"
                })

        # 兜底
        if not findings:
            findings.append({
                "id": f"PORT-{port}", "protocol": protocol, "check_item": "常规服务开放", 
                "risk_level": "安全", "description": f"检测到 {protocol} 端口活动中。",
                "detail_value": f"Port {port} is active.", "suggestion": "遵循最小暴露原则。", "mlps_clause": "G3-安全区域边界-访问控制"
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
