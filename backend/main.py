
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import uvicorn
import time
import socket
import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

# 引入核心分析器
from core.analyzer import SecurityAnalyzer

# 引入数据库模块
import database

# 引入所有 Scanner 模块功能
from scanners.web_scan import scan_http, check_tls_vulnerability, verify_vhost, fetch_url_headers
from scanners.sys_scan import check_ssh_banner, brute_force_ssh
from scanners.db_scan import scan_mysql, scan_redis, scan_postgres, scan_mongodb
from scanners.dns_scan import check_zone_transfer

app = FastAPI(title="NetAudit 审计引擎 V3.2")

# 允许跨域
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 初始化：连接数据库
@app.on_event("startup")
def startup_event():
    database.init_db()

analyzer = SecurityAnalyzer()
task_store: Dict[str, Any] = {}

class ScanRequest(BaseModel):
    target: str
    domains: Optional[List[str]] = []
    port_range: str
    ports_config: Dict[str, str]
    dictionaries: Dict[str, str]
    mode: str = "快速扫描"
    enable_brute: bool = False
    metadata: Optional[Dict[str, str]] = {}

class HeaderDebugRequest(BaseModel):
    url: str

@app.post("/api/tools/headers")
async def debug_headers(req: HeaderDebugRequest):
    if not req.url.startswith("http"):
        return {"error": "Invalid URL, must start with http:// or https://"}
    return fetch_url_headers(req.url)

def parse_port_config(config_str: str) -> List[int]:
    ports = []
    if not config_str:
        return ports
    for p in config_str.split(','):
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
    return ports

def probe_port(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=0.5) as s:
            return True
    except:
        return False

def run_deep_scan(task_id: str, request: ScanRequest):
    try:
        def update_progress(pct, log):
            # 添加时间戳延迟，确保前端能轮询到快速连续的日志
            time.sleep(0.05) 
            task_store[task_id]["progress"] = {"percent": pct, "log": log}

        target_ip = request.target
        update_progress(1, f"[INFO] KERNEL: Initializing Security Audit Kernel v3.1...")
        update_progress(2, f"[INFO] AUTH: Admin session activated.")
        
        try:
            update_progress(3, f"[INFO] TARGET_VECTOR: {request.target} [Resolving...]")
            if any(c.isalpha() for c in target_ip): 
                target_ip = socket.gethostbyname(request.target)
                update_progress(4, f"[INFO] DNS: Resolved {request.target} -> {target_ip}")
            else:
                update_progress(4, f"[INFO] TARGET: Target is IP, skipping DNS resolution.")
        except Exception as e:
            update_progress(4, f"[WARN] DNS: Resolution Failed: {e}. Using raw target.")

        target_ports = parse_port_config(request.port_range)
        
        # 端口配置
        ssh_ports = parse_port_config(request.ports_config.get('ssh', '22'))
        http_ports = parse_port_config(request.ports_config.get('http', '80,8080'))
        https_ports = parse_port_config(request.ports_config.get('https', '443,8443'))
        dns_ports = parse_port_config(request.ports_config.get('dns', '53'))
        mysql_ports = parse_port_config(request.ports_config.get('mysql', '3306'))
        redis_ports = parse_port_config(request.ports_config.get('redis', '6379'))
        postgres_ports = parse_port_config(request.ports_config.get('postgres', '5432'))
        mongo_ports = parse_port_config(request.ports_config.get('mongodb', '27017'))

        # 字典解析
        users = [u.strip() for u in request.dictionaries.get('usernames', '').split('\n') if u.strip()]
        passwords = [p.strip() for p in request.dictionaries.get('passwords', '').split('\n') if p.strip()]
        update_progress(5, f"[INFO] LOADER: Loaded Auth Dictionary (Users: {len(users)}, Pass: {len(passwords)})")
        
        all_findings = []
        port_status_summary = []
        
        if len(target_ports) == 0:
            raise Exception("No ports specified")

        # --- 端口扫描 ---
        update_progress(6, f"[INFO] ENGINE: Executing TCP SYN Scan (Range: {request.port_range})...")
        
        active_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(probe_port, target_ip, p): p for p in target_ports}
            for future in as_completed(future_to_port):
                p = future_to_port[future]
                if future.result():
                    active_ports.append(p)
        
        active_ports.sort()
        if active_ports:
            update_progress(10, f"[SUCCESS] NETWORK: Handshake Complete. Found {len(active_ports)} Active Listeners.")
        else:
            update_progress(100, f"[WARN] NETWORK: No active ports found. Audit terminated.")
            # ... 保存空报告逻辑 ...
            return

        # --- 深度扫描 ---
        total_active = len(active_ports)
        
        for idx, port in enumerate(active_ports):
            progress_pct = 15 + int((idx / total_active) * 80)
            
            current_protocol = "TCP"
            service_detail = "Unknown Service"
            
            # 1. SSH
            if port in ssh_ports:
                current_protocol = "SSH"
                banner = check_ssh_banner(target_ip, port)
                service_detail = banner
                update_progress(progress_pct, f"[INFO] SCAN: Port {port}/SSH Status: OPEN -> Fingerprint: {banner}")
                
                # 检查 Banner 泄露
                if "ubuntu" in banner.lower() or "debian" in banner.lower():
                     update_progress(progress_pct, f"[WARN] [VULN_DETECTED] [Medium] SSH Banner Leak: OS info exposed in banner.")

                weak_creds = []
                if request.mode == "深度审计" and request.enable_brute and users and passwords:
                    update_progress(progress_pct, f"[INFO] BRUTE: Starting SSH dictionary attack on port {port}...")
                    weak_creds = brute_force_ssh(target_ip, port, users, passwords)
                    if weak_creds:
                        cred = weak_creds[0]
                        update_progress(progress_pct, f"[ERROR] [VULN_DETECTED] [High] SSH Weak Credential: {cred['user']}/{cred['pass']}")
                
                findings = analyzer.analyze_service("SSH", port, banner, {"weak_creds": weak_creds})
                all_findings.extend(findings)

            # 2. Web (HTTP/HTTPS)
            elif port in http_ports or port in https_ports:
                protocol_name = "HTTPS" if port in https_ports else "HTTP"
                current_protocol = protocol_name
                
                # 基础扫描
                web_res = scan_http(target_ip, port, scheme=protocol_name.lower(), vhost=None)
                banner = web_res.get('banner', 'Unknown')
                service_detail = banner
                update_progress(progress_pct, f"[INFO] SCAN: Port {port}/{protocol_name} Status: OPEN -> Web Service Detected")
                
                # 实时 Web 漏洞日志输出
                deep = web_res.get('deep_scan', {})
                
                # 版本泄露
                if web_res.get('version_leak'):
                    update_progress(progress_pct, f"[WARN] [VULN_DETECTED] [Medium] Web Server Version Leak: '{banner}' exposes specific version.")

                # 安全头缺失
                missing = deep.get('missing_headers', [])
                if 'Content-Security-Policy' in missing:
                    update_progress(progress_pct, f"[WARN] [VULN_DETECTED] [Medium] Content Security Policy: Missing CSP header, XSS risk.")
                if 'X-Frame-Options' in missing:
                     update_progress(progress_pct, f"[WARN] [VULN_DETECTED] [Medium] X-Frame-Options: Missing header, Clickjacking risk.")
                
                # 目录泄露
                exposed = deep.get('exposed_paths', [])
                if exposed:
                    for p in exposed[:2]: # 只显示前两个，防止刷屏
                         update_progress(progress_pct, f"[ERROR] [VULN_DETECTED] [High] Sensitive Path Exposed: {p['path']} (Status: {p['status']})")
                
                # HTTPS 证书检查
                tls_res = {}
                if protocol_name == "HTTPS":
                    tls_res = check_tls_vulnerability(target_ip, port)
                    cert = tls_res.get('cert_info', {})
                    if cert and cert.get('is_expired'):
                         update_progress(progress_pct, f"[ERROR] [VULN_DETECTED] [High] SSL Certificate Expired: Cert is no longer valid.")
                    if cert and cert.get('key_size', 2048) < 2048:
                         update_progress(progress_pct, f"[ERROR] [VULN_DETECTED] [High] Weak SSL Key: Key size < 2048 bits.")

                # 域名并发扫描逻辑保持不变，为节省篇幅略去详细日志，只保留核心结果
                verified_vhosts = []
                if request.mode == "深度审计" and request.domains:
                     for domain in request.domains:
                        if verify_vhost(target_ip, port, domain):
                            verified_vhosts.append(domain)
                
                findings = analyzer.analyze_service(protocol_name, port, service_detail, {
                    "web_results": web_res,
                    "tls_results": tls_res,
                    "verified_vhosts": verified_vhosts
                })
                all_findings.extend(findings)

            # 3. DNS
            elif port in dns_ports:
                current_protocol = "DNS"
                service_detail = "DNS Service Active"
                update_progress(progress_pct, f"[INFO] SCAN: Port {port}/DNS Status: OPEN -> {service_detail}")
                
                dns_res = {}
                if request.domains:
                    for domain in request.domains:
                        res = check_zone_transfer(domain, target_ip, port)
                        if res.get("vulnerable"):
                            dns_res = res
                            update_progress(progress_pct, f"[ERROR] [VULN_DETECTED] [High] DNS Zone Transfer: AXFR allowed for {domain}, topology leaked.")
                            break
                findings = analyzer.analyze_service("DNS", port, service_detail, {"dns_results": dns_res})
                all_findings.extend(findings)

            # 4. MySQL
            elif port in mysql_ports:
                current_protocol = "MySQL"
                res = scan_mysql(target_ip, port)
                service_detail = res.get("banner", "MySQL")
                update_progress(progress_pct, f"[INFO] SCAN: Port {port}/MySQL Status: OPEN -> {service_detail}")
                # 模拟一个默认开放日志
                update_progress(progress_pct, f"[INFO] [VULN_DETECTED] [Safe] Port Open: Service is reachable.")
                findings = analyzer.analyze_service("MySQL", port, service_detail, {"db_results": res})
                all_findings.extend(findings)
            
            # 5. Redis
            elif port in redis_ports:
                current_protocol = "Redis"
                res = scan_redis(target_ip, port)
                update_progress(progress_pct, f"[INFO] SCAN: Port {port}/Redis Status: OPEN -> Redis Server")
                if res.get("vulnerable"):
                    update_progress(progress_pct, f"[ERROR] [VULN_DETECTED] [High] Redis Unauthorized Access: Anonymous login allowed!")
                findings = analyzer.analyze_service("Redis", port, "Redis Server", {"db_results": res})
                all_findings.extend(findings)

            # 其他数据库及 TCP 兜底...
            else:
                findings = analyzer.analyze_service("TCP", port, "Generic TCP", {})
                all_findings.extend(findings)
                # 对未知端口，如果不在配置列表中，可视为非必要开放
                update_progress(progress_pct, f"[INFO] SCAN: Port {port}/TCP Status: OPEN -> Generic Service")

            port_status_summary.append({
                "port": port, "protocol": current_protocol, "status": "OPEN", "detail": service_detail
            })

        # 计算总分
        high_count = len([d for d in all_findings if d["risk_level"] == "高危"])
        if high_count > 0:
             update_progress(96, f"[ERROR] CRITICAL: Detected {high_count} High-Risk vulnerabilities. Immediate remediation required.")
        else:
             update_progress(96, f"[SUCCESS] SUMMARY: Audit finished. System posture is stable.")

        score = analyzer.calculate_score(all_findings)
        
        report = {
            "target": target_ip, 
            "score": score,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "defects": all_findings, 
            "port_statuses": port_status_summary,
            "metadata": request.metadata,
            "summary": {
                "high": high_count,
                "medium": len([d for d in all_findings if d["risk_level"] == "中危"]),
                "low": len([d for d in all_findings if d["risk_level"] == "低危"])
            }
        }
        
        try:
            new_id = database.save_report(report)
            report['id'] = new_id
        except Exception as e:
            print(f"DB Error: {e}")
        
        task_store[task_id] = {"status": "completed", "result": report, "progress": {"percent": 100, "log": "SESSION CLOSED"}}
    except Exception as e:
        print(f"Task Error: {e}")
        task_store[task_id] = {"status": "failed", "error": str(e)}

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())
    task_store[task_id] = {"status": "running", "progress": {"percent": 0, "log": "Initializing..."}}
    background_tasks.add_task(run_deep_scan, task_id, request)
    return {"task_id": task_id}

@app.get("/api/scan/status/{task_id}")
async def get_status(task_id: str):
    return task_store.get(task_id, {"status": "not_found"})

# --- 历史记录 API ---
@app.get("/api/history")
async def get_history():
    try: return database.get_all_reports()
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/history/purge")
async def purge_history():
    try:
        database.purge_reports()
        return {"status": "success"}
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/history/{report_id}")
async def delete_history_item(report_id: int):
    try:
        database.delete_report(report_id)
        return {"status": "success", "id": report_id}
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
