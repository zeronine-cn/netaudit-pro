
import json
import os
import re

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
    
    def _get_rule_info(self, key, default_desc):
        rule = self.rules.get(key, {})
        return {
            "check_item": rule.get("name", default_desc),
            "risk_level": rule.get("risk_level", "中危"),
            "description": rule.get("description", default_desc),
            "suggestion": rule.get("suggestion", "请检查配置。"),
            "mlps_clause": f"{rule.get('clause_id', 'Unknown')} - {rule.get('clause_content', '')}"
        }

    def analyze_service(self, protocol: str, port: int, banner: str, extra_data: dict = None):
        findings = []
        extra = extra_data or {}
        
        # --- 1. SSH 协议审计 ---
        if protocol == "SSH":
            # [测试点: 弱口令检查]
            if extra.get("weak_creds"):
                creds = extra["weak_creds"][0]
                rule = self._get_rule_info("SSH_WEAK_PASS", "SSH 弱口令漏洞")
                findings.append({
                    "id": f"SSH-PWD-{port}", "protocol": protocol,
                    "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                    "description": f"发现有效凭据：{creds['user']} / {creds['pass']}",
                    "detail_value": f"Authenticated via {creds['user']}:{creds['pass']}",
                    "suggestion": rule["suggestion"], 
                    "mlps_clause": rule["mlps_clause"],
                    "metadata": {"is_compromised": True}
                })
            
            # [测试点: Banner 泄露]
            # 逻辑：如果 banner 包含数字（版本号）且包含软件名
            if banner and any(char.isdigit() for char in banner) and "SSH" in banner.upper():
                 rule = self._get_rule_info("SSH_BANNER_LEAK", "SSH 服务版本信息泄露")
                 findings.append({
                    "id": f"SSH-BANNER-{port}", "protocol": protocol,
                    "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                    "description": f"Banner 暴露了详细版本信息: {banner}",
                    "detail_value": f"Banner: {banner}",
                    "suggestion": rule["suggestion"], 
                    "mlps_clause": rule["mlps_clause"]
                })

        # --- 2. Web (HTTP/HTTPS) & TLS 审计 ---
        elif protocol in ["HTTP", "HTTPS"]:
            web_res = extra.get("web_results", {})
            tls_res = extra.get("tls_results", {})

            # [测试点: Web Banner 泄露] (HTTP Server Header)
            server_header = web_res.get("banner", "")
            # 逻辑：Server 头不为空，且包含数字（版本号），例如 "nginx/1.14.2"
            if server_header and any(char.isdigit() for char in server_header) and len(server_header) < 50:
                 rule = self._get_rule_info("HTTP_BANNER_LEAK", "Web 服务器版本信息泄露")
                 findings.append({
                    "id": f"HTTP-BANNER-{port}", "protocol": protocol,
                    "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                    "description": f"HTTP 响应头 Server 字段暴露了版本: {server_header}",
                    "detail_value": f"Server: {server_header}",
                    "suggestion": rule["suggestion"], 
                    "mlps_clause": rule["mlps_clause"]
                })

            # [测试点: 敏感目录暴露]
            exposed_paths = extra.get("sensitive_paths", [])
            for item in exposed_paths:
                rule = self._get_rule_info("WEB_SENSITIVE_EXPOSURE", "Web 敏感文件/目录泄露")
                findings.append({
                    "id": f"WEB-FILE-{port}-{item['path']}", "protocol": protocol,
                    "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                    "description": f"探测到敏感路径 {item['path']} 可直接访问。",
                    "detail_value": f"Path: {item['path']} | Evidence: {item.get('evidence', '')[:50]}...",
                    "suggestion": rule["suggestion"], 
                    "mlps_clause": rule["mlps_clause"]
                })

            # HTTPS 专属测试点
            if protocol == "HTTPS":
                # [测试点: 协议版本审计] (TLS 1.0/1.1)
                if tls_res.get("weak_protocols"):
                    rule = self._get_rule_info("TLS_OLD_PROTO", "使用了不安全的加密协议")
                    findings.append({
                        "id": f"TLS-OLD-{port}", "protocol": "HTTPS",
                        "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                        "description": f"服务器支持已弃用的协议: {', '.join(tls_res['weak_protocols'])}",
                        "detail_value": str(tls_res['weak_protocols']),
                        "suggestion": rule["suggestion"], 
                        "mlps_clause": rule["mlps_clause"]
                    })
                
                # [测试点: 弱加密套件] (RC4)
                if tls_res.get("weak_ciphers"):
                    rule = self._get_rule_info("TLS_WEAK_CIPHER", "启用了弱加密套件")
                    findings.append({
                        "id": f"TLS-WEAK-CIPHER-{port}", "protocol": "HTTPS",
                        "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                        "description": "检测到服务器允许 RC4 或 DES 等弱加密算法。",
                        "detail_value": f"Weak Ciphers: {tls_res['weak_ciphers']}",
                        "suggestion": rule["suggestion"], 
                        "mlps_clause": rule["mlps_clause"]
                    })

                cert_info = tls_res.get("cert_info")
                if cert_info:
                    # [测试点: 证书有效期]
                    if cert_info.get("is_expired"):
                        rule = self._get_rule_info("CERT_EXPIRED", "数字证书已过期")
                        findings.append({
                            "id": f"TLS-EXP-{port}", "protocol": "HTTPS",
                            "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                            "description": f"证书已于 {cert_info.get('expiry')} 过期。",
                            "detail_value": f"Expired Date: {cert_info.get('expiry')}",
                            "suggestion": rule["suggestion"], 
                            "mlps_clause": rule["mlps_clause"]
                        })
                    
                    # [测试点: 密钥强度审计] (< 2048 bit)
                    key_size = cert_info.get("key_size", 2048)
                    if key_size < 2048:
                        rule = self._get_rule_info("TLS_WEAK_KEY", "数字证书密钥强度不足")
                        findings.append({
                            "id": f"TLS-WEAK-KEY-{port}", "protocol": "HTTPS",
                            "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                            "description": f"证书 RSA 密钥长度为 {key_size} 位，低于等保要求的 2048 位。",
                            "detail_value": f"Key Size: {key_size} bits",
                            "suggestion": rule["suggestion"], 
                            "mlps_clause": rule["mlps_clause"]
                        })

        # --- 3. DNS 审计 ---
        elif protocol == "DNS":
            # [测试点: 区域传送]
            dns_res = extra.get("dns_results", {})
            if dns_res.get("vulnerable"):
                rule = self._get_rule_info("DNS_ZONE_TRANSFER", "DNS 区域传送漏洞 (AXFR)")
                findings.append({
                    "id": f"DNS-AXFR-{port}", "protocol": protocol,
                    "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                    "description": rule["description"],
                    "detail_value": f"Leaked Records: {dns_res.get('records_count')}",
                    "suggestion": rule["suggestion"], 
                    "mlps_clause": rule["mlps_clause"]
                })

        # --- 4. TCP/数据库 端口暴露 ---
        if protocol in ["MySQL", "Redis", "PostgreSQL", "MongoDB"]:
            db_res = extra.get("db_results", {})
            if db_res.get("status") == "OPEN":
                rule = self._get_rule_info("DB_OPEN", "数据库服务对外暴露")
                findings.append({
                    "id": f"DB-OPEN-{port}", "protocol": protocol,
                    "check_item": rule["check_item"], "risk_level": rule["risk_level"],
                    "description": f"检测到 {protocol} 端口处于开放状态。",
                    "detail_value": f"Port {port} is OPEN",
                    "suggestion": rule["suggestion"], 
                    "mlps_clause": rule["mlps_clause"]
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
