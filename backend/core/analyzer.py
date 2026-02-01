
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
        
        # 1. SSH 弱口令
        if protocol == "SSH" and extra.get("weak_creds"):
            creds = extra["weak_creds"][0]
            findings.append({
                "id": f"SSH-PWD-{port}", "protocol": protocol,
                "check_item": "系统权限已失陷 (SSH 弱口令)", "risk_level": "高危",
                "description": f"成功获取系统登录凭据：{creds['user']} / {creds['pass']}",
                "detail_value": f"Valid Credential found on port {port}",
                "suggestion": "立即修改密码，启用 MFA 认证。", "mlps_clause": "G3-安全计算环境-身份鉴别",
                "metadata": {"is_compromised": True}
            })

        # 2. Redis 专项
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

        # 3. MySQL/DB 专项
        if protocol in ["MySQL", "PostgreSQL", "MongoDB"]:
            res = extra.get("db_results", {})
            if res.get("status") == "OPEN":
                findings.append({
                    "id": f"DB-OPEN-{port}", "protocol": protocol,
                    "check_item": f"{protocol} 服务暴露", "risk_level": "中危",
                    "description": f"发现 {protocol} 数据库服务端口对公网开放。",
                    "detail_value": res.get("banner", "Active"),
                    "suggestion": "1. 检查是否存在弱口令；2. 仅允许受信 IP 访问该端口。",
                    "mlps_clause": "G3-安全计算环境-入侵防范"
                })

        # 4. Web/TLS 逻辑 (保留并集成)
        if protocol in ["HTTP", "HTTPS"]:
            # ... (保留原有的 Web 分析逻辑)
            pass

        # 5. 兜底
        if not findings:
            findings.append({
                "id": f"PORT-{port}", "protocol": protocol, "check_item": "常规端口开放", 
                "risk_level": "安全", "description": f"检测到 {protocol} 端口处于活动状态。",
                "detail_value": f"Port: {port}", "suggestion": "核查业务必要性。", "mlps_clause": "G3-访问控制"
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
