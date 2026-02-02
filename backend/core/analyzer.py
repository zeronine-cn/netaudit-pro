
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
        
        # 1. SSH 审计
        if protocol == "SSH":
            if extra.get("weak_creds"):
                creds = extra["weak_creds"][0]
                findings.append({
                    "id": f"SSH-PWD-{port}", "protocol": protocol,
                    "check_item": "系统权限已失陷 (SSH 弱口令)", "risk_level": "高危",
                    "description": f"发现有效凭据：{creds['user']} / {creds['pass']}",
                    "detail_value": f"Authenticated via {creds['user']}:{creds['pass']}",
                    "suggestion": "立即修改密码，改用强加密的 SSH 密钥认证。", 
                    "mlps_clause": "G3-安全计算环境-身份鉴别",
                    "metadata": {"is_compromised": True}
                })
            
            if port == 2222:
                findings.append({
                    "id": f"SSH-PORT-2222", "protocol": protocol,
                    "check_item": "非标端口服务暴露 (SSH)", "risk_level": "低危",
                    "description": "检测到 SSH 服务运行在 2222 端口。",
                    "detail_value": f"Port: {port}",
                    "suggestion": "限制访问来源 IP。", "mlps_clause": "G3-安全区域边界-访问控制"
                })

        # 2. Web 应用与 TLS 审计 (针对 80, 8080, 443, 8443)
        elif protocol in ["HTTP", "HTTPS"]:
            web_res = extra.get("web_results", {})
            tls_res = extra.get("tls_results", {})

            # 敏感文件泄露判定
            exposed_paths = extra.get("sensitive_paths", [])
            for item in exposed_paths:
                findings.append({
                    "id": f"WEB-FILE-{port}-{item['path']}", "protocol": protocol,
                    "check_item": "Web 敏感文件/目录泄露", "risk_level": "高危",
                    "description": f"探测到敏感路径 {item['path']} 可直接访问。",
                    "detail_value": f"Path: {item['path']}, Evidence: {item.get('evidence', '')}",
                    "suggestion": "删除开发配置文件和备份文件。", "mlps_clause": "G3-安全计算环境-入侵防范"
                })

            # 响应头缺失判定
            missing = web_res.get("deep_scan", {}).get("missing_headers", [])
            if missing:
                findings.append({
                    "id": f"WEB-HEADER-{port}", "protocol": protocol,
                    "check_item": "Web 安全防护响应头缺失", "risk_level": "低危",
                    "description": f"缺失安全头: {', '.join(missing[:2])} 等。",
                    "detail_value": f"Missing: {', '.join(missing)}",
                    "suggestion": "在服务器配置中添加安全响应头。", "mlps_clause": "G3-安全计算环境-入侵防范"
                })

            # HTTPS 协议与证书深度分析
            if protocol == "HTTPS":
                if tls_res.get("weak_protocols"):
                    findings.append({
                        "id": f"TLS-OLD-{port}", "protocol": "HTTPS",
                        "check_item": "使用了不安全的加密协议 (TLS 1.0/1.1)", "risk_level": "高危",
                        "description": f"服务器启用了已弃用的协议: {', '.join(tls_res['weak_protocols'])}。",
                        "detail_value": str(tls_res['weak_protocols']),
                        "suggestion": "仅保留 TLSv1.2 及以上版本。", "mlps_clause": "G3-安全通信网络-通信保密性"
                    })
                
                if tls_res.get("weak_ciphers"):
                    findings.append({
                        "id": f"TLS-WEAK-CIPHER-{port}", "protocol": "HTTPS",
                        "check_item": "启用了弱加密套件 (RC4)", "risk_level": "高危",
                        "description": "服务器允许使用 RC4 加密套件。",
                        "detail_value": "Detected: RC4",
                        "suggestion": "修改 ssl_ciphers 配置，禁用 RC4。", "mlps_clause": "G3-安全通信网络-通信保密性"
                    })

                cert_info = tls_res.get("cert_info")
                if cert_info:
                    if cert_info.get("is_expired"):
                        findings.append({
                            "id": f"TLS-EXP-{port}", "protocol": "HTTPS",
                            "check_item": "SSL/TLS 证书已过期", "risk_level": "高危",
                            "description": "证书有效期已过。",
                            "detail_value": f"Expired: {cert_info.get('expiry')}",
                            "suggestion": "立即更换有效证书。", "mlps_clause": "G3-安全通信网络-通信保密性"
                        })
                    # 关键逻辑：检测 1024位弱密钥
                    if cert_info.get("key_size", 2048) < 2048:
                        findings.append({
                            "id": f"TLS-WEAK-KEY-{port}", "protocol": "HTTPS",
                            "check_item": "数字证书密钥强度不足", "risk_level": "高危",
                            "description": f"证书 RSA 密钥长度为 {cert_info.get('key_size')} 位，低于 2048 位等保基线要求。",
                            "detail_value": f"Key Size: {cert_info.get('key_size')} bits",
                            "suggestion": "重新生成 2048 位或更高强度的数字证书。", "mlps_clause": "G3-安全通信网络-通信保密性"
                        })

        # 3. DNS 审计
        elif protocol == "DNS":
            dns_res = extra.get("dns_results", {})
            if dns_res.get("vulnerable"):
                findings.append({
                    "id": f"DNS-AXFR-{port}", "protocol": protocol,
                    "check_item": "DNS 区域传送漏洞 (AXFR)", "risk_level": "高危",
                    "description": "DNS 服务允许非授权 AXFR 请求。",
                    "detail_value": f"Records: {dns_res.get('records_count')}",
                    "suggestion": "限制 allow-transfer 仅允许授权 IP。", "mlps_clause": "G3-安全区域边界-边界防护"
                })

        # 4. 数据库分析
        if protocol in ["MySQL", "Redis"]:
            db_res = extra.get("db_results", {})
            if db_res.get("status") == "OPEN":
                findings.append({
                    "id": f"DB-OPEN-{port}", "protocol": protocol,
                    "check_item": f"数据库服务对外暴露 ({protocol})", "risk_level": "中危",
                    "description": f"检测到 {protocol} 端口处于开放状态。",
                    "detail_value": f"Port {port} is OPEN",
                    "suggestion": "通过防火墙限制该端口的访问来源。", "mlps_clause": "G3-安全区域边界-访问控制"
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
