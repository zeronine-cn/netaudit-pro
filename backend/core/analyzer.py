
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
        
        # 1. SSH Analysis
        if protocol == "SSH":
            if extra.get("weak_creds"):
                creds = extra["weak_creds"][0]
                findings.append({
                    "id": f"SSH-PWD-{port}", "protocol": protocol,
                    "check_item": "系统权限已失陷 (SSH 弱口令)", "risk_level": "高危",
                    "description": f"成功发现有效凭据：{creds['user']} / {creds['pass']}",
                    "detail_value": f"Authenticated via {creds['user']}:{creds['pass']}",
                    "suggestion": "立即修改密码，禁用密码登录，改用 SSH 密钥认证。", "mlps_clause": "G3-安全计算环境-身份鉴别",
                    "metadata": {"is_compromised": True}
                })
            
            # Version disclosure
            if any(v in banner_low for v in ["ubuntu", "debian", "openssh"]):
                findings.append({
                    "id": f"SSH-BANNER-{port}", "protocol": protocol,
                    "check_item": "SSH 服务版本信息泄露", "risk_level": "低危",
                    "description": "SSH 服务端 Banner 暴露了具体的操作系统或软件版本。",
                    "detail_value": banner,
                    "suggestion": "修改 sshd_config 设置 DebianBanner no。",
                    "mlps_clause": "G3-安全计算环境-入侵防范"
                })

        # 2. Web & TLS Analysis (The core for the playground)
        if protocol in ["HTTP", "HTTPS"]:
            web_res = extra.get("web_results", {})
            tls_res = extra.get("tls_results", {})

            # Banner Disclosure (server_tokens on)
            server_header = web_res.get("banner", "")
            if len(server_header) > 2 and server_header != "Unknown":
                 findings.append({
                    "id": f"WEB-BANNER-{port}", "protocol": protocol,
                    "check_item": "Web 服务器版本信息泄露", "risk_level": "中危",
                    "description": f"HTTP 响应头 Server 字段泄露了具体软件版本：{server_header}",
                    "detail_value": server_header,
                    "suggestion": "配置 Nginx (server_tokens off) 隐藏版本信息。",
                    "mlps_clause": "G3-安全计算环境-入侵防范"
                })

            # TLS Specifics
            if protocol == "HTTPS":
                # Old Protocols (TLS 1.0/1.1)
                weak_protos = tls_res.get("weak_protocols", [])
                if weak_protos:
                    findings.append({
                        "id": f"TLS-OLD-{port}", "protocol": "HTTPS",
                        "check_item": "使用了不安全的加密协议 (TLS 1.0/1.1)", "risk_level": "高危",
                        "description": f"服务器启用了已弃用的老旧协议: {', '.join(weak_protos)}。",
                        "detail_value": str(weak_protos),
                        "suggestion": "在 Nginx 配置中禁用 TLSv1.0/1.1。",
                        "mlps_clause": "G3-安全通信网络-通信保密性"
                    })
                
                # Weak Cipher (RC4)
                if tls_res.get("weak_ciphers"):
                    findings.append({
                        "id": f"TLS-WEAK-CIPHER-{port}", "protocol": "HTTPS",
                        "check_item": "启用了弱加密套件 (RC4)", "risk_level": "高危",
                        "description": "服务器允许使用 RC4 加密套件，该算法已被证明存在严重安全缺陷。",
                        "detail_value": "Cipher: " + ", ".join(tls_res["weak_ciphers"]),
                        "suggestion": "修改 ssl_ciphers 配置，禁用 RC4 等弱算法。",
                        "mlps_clause": "G3-安全通信网络-通信保密性"
                    })

                # Certificate Checks
                cert_vulns = tls_res.get("vulnerabilities", [])
                if "CERT_EXPIRED" in cert_vulns:
                    findings.append({
                        "id": f"TLS-EXP-{port}", "protocol": "HTTPS",
                        "check_item": "SSL/TLS 证书已过期", "risk_level": "高危",
                        "description": "服务器使用的数字证书已过期，无法保证通信的真实性。",
                        "detail_value": f"Expired on: {tls_res.get('cert_info', {}).get('expiry')}",
                        "suggestion": "立即更换有效的数字证书。",
                        "mlps_clause": "G3-安全通信网络-通信保密性"
                    })
                if "WEAK_KEY_SIZE" in cert_vulns:
                    findings.append({
                        "id": f"TLS-WEAK-KEY-{port}", "protocol": "HTTPS",
                        "check_item": "数字证书密钥强度不足", "risk_level": "高危",
                        "description": f"证书 RSA 密钥长度不足 (当前: {tls_res.get('cert_info', {}).get('key_size')} bits)，低于等保基线要求的 2048 位。",
                        "detail_value": f"Key Size: {tls_res.get('cert_info', {}).get('key_size')} bits",
                        "suggestion": "重新生成 2048 位或更高强度的 RSA 密钥证书。",
                        "mlps_clause": "G3-安全通信网络-通信保密性"
                    })

        # 3. DNS Analysis (Port 5353 AXFR)
        if protocol == "DNS":
            res = extra.get("dns_results", {})
            if res.get("vulnerable"):
                findings.append({
                    "id": f"DNS-AXFR-{port}", "protocol": protocol,
                    "check_item": "DNS 区域传送漏洞 (AXFR)", "risk_level": "高危",
                    "description": f"DNS 服务器允许非授权区域传送，导致 {res.get('records_count', 0)} 条解析记录泄露。",
                    "detail_value": "Nodes: " + ", ".join(res.get("records", [])),
                    "suggestion": "在 named.conf 中限制 allow-transfer 为特定的 Slave IP。",
                    "mlps_clause": "G3-安全区域边界-边界防护"
                })

        # Default fallback
        if not findings:
            findings.append({
                "id": f"PORT-{port}", "protocol": protocol, "check_item": "常规服务开放", 
                "risk_level": "安全", "description": f"检测到 {protocol} 服务运行正常。",
                "detail_value": f"Port {port} is active.", "suggestion": "遵循最小化暴露原则。", "mlps_clause": "G3-安全区域边界-访问控制"
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
