
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

# Imports
from core.analyzer import SecurityAnalyzer
from scanners.web_scan import scan_http, check_tls_vulnerability, check_sensitive_paths
from scanners.sys_scan import check_ssh_banner, brute_force_ssh
from scanners.db_scan import scan_mysql, scan_redis, scan_postgres, scan_mongodb
from scanners.dns_scan import check_zone_transfer

app = FastAPI(title="NetAudit 审计引擎 V3.2")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

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

def parse_port_config(config_str: str) -> List[int]:
    ports = []
    if not config_str: return ports
    for p in config_str.split(','):
        p = p.strip()
        if p.isdigit(): ports.append(int(p))
    return ports

def probe_port(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=0.5) as s:
            return True
    except: return False

def run_deep_scan(task_id: str, request: ScanRequest):
    try:
        def update_progress(pct, log):
            task_store[task_id]["progress"] = {"percent": pct, "log": log}

        update_progress(1, f"[*] Target: {request.target}")
        target_ip = request.target
        try:
            if any(c.isalpha() for c in target_ip): 
                target_ip = socket.gethostbyname(request.target)
        except: pass

        target_ports = parse_port_config(request.port_range)
        
        # 靶场专用端口映射
        ssh_ports = parse_port_config(request.ports_config.get('ssh', '22,2222'))
        http_ports = parse_port_config(request.ports_config.get('http', '80,8080'))
        https_ports = parse_port_config(request.ports_config.get('https', '443,8443'))
        dns_ports = parse_port_config(request.ports_config.get('dns', '53,5353'))
        mysql_ports = parse_port_config(request.ports_config.get('mysql', '3306'))

        active_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(probe_port, target_ip, p): p for p in target_ports}
            for future in as_completed(future_to_port):
                p = future_to_port[future]
                if future.result(): active_ports.append(p)
        active_ports.sort()
        
        all_findings = []
        port_status_summary = []
        
        total_active = len(active_ports)
        if total_active == 0:
            update_progress(100, "[-] No open ports.")
        
        for idx, port in enumerate(active_ports):
            progress_pct = 20 + int((idx / total_active) * 70)
            service_detail = "Unknown"
            current_protocol = "TCP"
            findings = []

            # 路由逻辑：适配 2222/8080/8443/5353 等靶场端口
            if port in ssh_ports:
                current_protocol = "SSH"
                banner = check_ssh_banner(target_ip, port)
                service_detail = banner
                weak_creds = []
                if request.mode == "深度审计" and request.enable_brute:
                    update_progress(progress_pct, f"[*] Brute-forcing SSH {port}...")
                    weak_creds = brute_force_ssh(target_ip, port, request.dictionaries.get('usernames','').split('\n'), request.dictionaries.get('passwords','').split('\n'))
                findings = analyzer.analyze_service("SSH", port, banner, {"weak_creds": weak_creds})

            elif port in http_ports or port in https_ports:
                proto_name = "HTTPS" if port in https_ports else "HTTP"
                current_protocol = proto_name
                update_progress(progress_pct, f"[*] Auditing Web {port}...")
                vhost = request.domains[0] if request.domains else None
                web_res = scan_http(target_ip, port, vhost=vhost)
                service_detail = web_res.get("banner", "Web Server")
                
                # 专项探测：敏感路径
                sensitive_paths = check_sensitive_paths(target_ip, port, vhost=vhost)
                
                tls_res = {}
                if proto_name == "HTTPS":
                    tls_res = check_tls_vulnerability(target_ip, port, vhost=vhost)
                
                findings = analyzer.analyze_service(proto_name, port, service_detail, {
                    "web_results": web_res, 
                    "tls_results": tls_res,
                    "sensitive_paths": sensitive_paths
                })

            elif port in dns_ports:
                current_protocol = "DNS"
                dns_res = {}
                if request.domains:
                    for d in request.domains:
                        res = check_zone_transfer(d, target_ip, port)
                        if res.get("vulnerable"):
                            dns_res = res
                            service_detail = "AXFR Allowed"
                            break
                findings = analyzer.analyze_service("DNS", port, service_detail, {"dns_results": dns_res})

            elif port in mysql_ports:
                current_protocol = "MySQL"
                db_res = scan_mysql(target_ip, port)
                findings = analyzer.analyze_service("MySQL", port, db_res.get("banner", "MySQL"), {"db_results": db_res})

            for f in findings:
                if f['risk_level'] != '安全':
                    update_progress(progress_pct, f"[!] Found: {f['check_item']}")
                    time.sleep(0.2)

            all_findings.extend(findings)
            port_status_summary.append({"port": port, "protocol": current_protocol, "status": "OPEN", "detail": service_detail})

        report = {
            "target": target_ip, "score": analyzer.calculate_score(all_findings),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "defects": all_findings, "port_statuses": port_status_summary,
            "summary": {
                "high": len([d for d in all_findings if d["risk_level"] == "高危"]),
                "medium": len([d for d in all_findings if d["risk_level"] == "中危"]),
                "low": len([d for d in all_findings if d["risk_level"] == "低危"])
            }
        }
        task_store[task_id] = {"status": "completed", "result": report, "progress": {"percent": 100, "log": "Audit Finished"}}
    except Exception as e:
        task_store[task_id] = {"status": "failed", "error": str(e)}

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())
    task_store[task_id] = {"status": "running", "progress": {"percent": 0, "log": "Engaging..."}}
    background_tasks.add_task(run_deep_scan, task_id, request)
    return {"task_id": task_id}

@app.get("/api/scan/status/{task_id}")
async def get_status(task_id: str):
    return task_store.get(task_id, {"status": "not_found"})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
