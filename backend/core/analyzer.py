
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
        
        # 1. SSH 弱口令检查
        if protocol == "SSH":
            weak_creds = extra.get("weak_creds", [])
            if weak_creds:
                rule = self.rules.get("SSH_WEAK_PASS", {})
                creds = weak_creds[0]
                findings.append({
                    "id": f"SSH-PWD-{port}",
                    "protocol": protocol,
                    "check_item": "系统权限已失陷 (SSH 弱口令)",
                    "risk_level": "高危",
                    "description": f"成功获取系统登录凭据：{creds['user']} / {creds['pass']}",
                    "detail_value": f"Exploit Data: Found Valid Credential pair on port {port}",
                    "suggestion": "1. 立即强制修改该账户密码；2. 启用多因素认证 (MFA)；3. 限制 SSH 来源 IP。",
                    "mlps_clause": "G3-安全计算环境-身份鉴别",
                    "metadata": {"is_compromised": True}
                })

        # 2. TLS/HTTPS 基础检查
        if protocol == "HTTPS" and "tls_results" in extra:
            tls = extra["tls_results"]
            if tls.get("weak_protocols"):
                rule = self.rules.get("TLS_OLD_PROTO", {})
                findings.append(self._format_finding(f"TLS-PROTO-{port}", protocol, rule, f"支持不安全协议: {', '.join(tls['weak_protocols'])}"))
            
            if tls.get("cert_info"):
                info = tls["cert_info"]
                if info.get("is_expired"):
                    findings.append(self._format_finding(f"TLS-CERT-EXP-{port}", protocol, {"name": "数字证书已过期", "risk_level": "High", "clause_id": "G3-安全通信网络"}, f"过期时间: {info['expiry']}"))
                if info.get("key_size", 2048) < 2048:
                    rule = self.rules.get("TLS_WEAK_CERT", {})
                    findings.append(self._format_finding(f"TLS-CERT-SIZE-{port}", protocol, rule, f"当前 RSA 密钥长度: {info['key_size']} bit"))

        # 3. Web 深度探测分析
        if protocol in ["HTTP", "HTTPS"] and "web_results" in extra:
            web = extra["web_results"]
            deep = web.get("deep_scan", {})
            
            # 敏感目录暴露
            exposed = deep.get("exposed_paths", [])
            if exposed:
                rule = self.rules.get("WEB_SENSITIVE_EXPOSURE", {})
                path_list = [f"{p['path']} (HTTP {p['status']})" for p in exposed]
                findings.append(self._format_finding(f"WEB-EXPOSED-{port}", protocol, rule, f"发现敏感暴露路径: {', '.join(path_list)}"))
            
            # 安全头缺失
            missing = deep.get("missing_headers", [])
            if missing:
                rule = self.rules.get("WEB_MISSING_HEADERS", {})
                findings.append(self._format_finding(f"WEB-HEADERS-{port}", protocol, rule, f"缺失安全响应头: {', '.join(missing)}"))

            # 指纹泄露
            if any(x in banner_low for x in ["nginx", "apache", "iis"]):
                rule = self.rules.get("HTTP_BANNER_LEAK", {})
                findings.append(self._format_finding(f"WEB-BANNER-{port}", protocol, rule, banner))

        # 4. DNS AXFR 检查
        if protocol == "DNS" and extra.get("dns_results"):
            dns = extra["dns_results"]
            if dns.get("vulnerable"):
                rule = self.rules.get("DNS_ZONE_TRANSFER", {})
                findings.append(self._format_finding(f"DNS-AXFR-{port}", protocol, rule, dns.get("detail", "")))

        # 5. 默认兜底
        if not findings:
            if protocol == "SSH" and "openssh" in banner_low:
                rule = self.rules.get("SSH_BANNER_LEAK", {})
                findings.append(self._format_finding(f"SSH-BANNER-{port}", protocol, rule, banner))
            else:
                rule = self.rules.get("TCP_PORT_OPEN", {})
                findings.append(self._format_finding(f"PORT-{port}", protocol, rule, f"开放端口: {port}"))

        return findings

    def _format_finding(self, id_val: str, protocol: str, rule: dict, detail: str):
        level_map = {"High": "高危", "Medium": "中危", "Low": "低危", "Info": "安全"}
        raw_level = rule.get("risk_level", "Low")
        return {
            "id": id_val, "protocol": protocol,
            "check_item": rule.get("name", "通用安全检查"),
            "risk_level": level_map.get(raw_level, "低危"),
            "description": rule.get("description", "检测到潜在安全风险。"),
            "detail_value": detail,
            "suggestion": rule.get("suggestion", "请核查此服务的必要性。"),
            "mlps_clause": rule.get("clause_id", "G3-访问控制")
        }

    def calculate_score(self, defects: list):
        score = 100
        for d in defects:
            level = d.get('risk_level')
            if level == '高危': score -= 25
            elif level == '中危': score -= 10
            elif level == '低危': score -= 2
        return max(0, score)
