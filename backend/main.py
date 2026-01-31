
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import uvicorn
import time
import os
import socket
import sqlite3
import json
import uuid
from concurrent.futures import ThreadPoolExecutor

from core.analyzer import SecurityAnalyzer
from scanners.web_scan import scan_http, check_tls_vulnerability
from scanners.sys_scan import check_ssh_banner, brute_force_ssh
from scanners.dns_scan import check_zone_transfer

app = FastAPI(title="NetAudit 审计引擎")
analyzer = SecurityAnalyzer()

task_store: Dict[str, Any] = {}

DATA_DIR = "/app/data" 
DIST_DIR = "/app/dist" 

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

DB_PATH = os.path.join(DATA_DIR, "netaudit.db")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

class ScanRequest(BaseModel):
    target: str
    domains: Optional[List[str]] = []
    port_range: str
    ports_config: Dict[str, str]
    dictionaries: Dict[str, str]
    mode: str = "快速扫描"
    enable_brute: bool = False

def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.replace('，', ',').split(','):
        part = part.strip()
        if not part: continue
        try:
            if '-' in part:
                s, e = map(int, part.split('-'))
                for p in range(s, min(e + 1, s + 1000)): ports.add(p)
            else: ports.add(int(part))
        except: continue
    return sorted(list(ports))

def run_deep_scan(task_id: str, request: ScanRequest):
    try:
        def update_progress(pct, log):
            task_store[task_id]["progress"] = {"percent": pct, "log": log}

        target_ip = request.target
        domain_list = [d.strip() for d in (request.domains or []) if d.strip()]
        ports_to_scan = parse_ports(request.port_range)
        
        update_progress(10, "正在执行存活节点探测...")

        with ThreadPoolExecutor(max_workers=50) as executor:
            def check(p):
                s = socket.socket()
                s.settimeout(0.5)
                if s.connect_ex((target_ip, p)) == 0:
                    s.close()
                    return p
                return None
            results = list(executor.map(check, ports_to_scan))
            active_ports = [p for p in results if p]

        all_findings = []
        port_status_summary = []
        
        ssh_p = parse_ports(request.ports_config.get('ssh', '22'))
        http_p = parse_ports(request.ports_config.get('http', '80'))
        https_p = parse_ports(request.ports_config.get('https', '443'))
        dns_p = parse_ports(request.ports_config.get('dns', '53'))

        total_steps = len(active_ports)
        for idx, port in enumerate(active_ports):
            progress_base = 20 + int((idx / total_steps) * 60)
            update_progress(progress_base, f"正在审计端口 {port} ({idx+1}/{total_steps})...")
            
            is_scanned = False
            
            if port in ssh_p:
                banner = check_ssh_banner(target_ip, port)
                creds = []
                # 只有在深度模式且用户勾选了弱口令审计时执行
                if request.mode == "深度审计" and request.enable_brute:
                    user_list = request.dictionaries.get('usernames', 'admin').split('\n')
                    pass_list = request.dictionaries.get('passwords', '123456').split('\n')
                    total_combinations = len(user_list) * len(pass_list)
                    update_progress(progress_base, f"正在执行 SSH 弱口令爆破 (测试 {total_combinations} 组密码)...")
                    creds = brute_force_ssh(target_ip, port, user_list, pass_list)
                
                findings = analyzer.analyze_service("SSH", port, banner, {"weak_creds": creds})
                all_findings.extend(findings)
                port_status_summary.append({"port": port, "protocol": "SSH", "status": "OPEN", "detail": f"Banner: {banner}"})
                is_scanned = True
            
            if port in http_p or port in https_p:
                scan_targets = domain_list if domain_list else [None]
                for domain in scan_targets:
                    res = scan_http(target_ip, port, vhost=domain)
                    proto = "HTTPS" if port in https_p else "HTTP"
                    tls_res = check_tls_vulnerability(target_ip, port, vhost=domain) if port in https_p else {}
                    domain_findings = analyzer.analyze_service(proto, port, res.get("banner", "Unknown"), {"tls_results": tls_res})
                    for f in domain_findings:
                        if domain: f["domain"] = domain
                        all_findings.append(f)
                port_status_summary.append({"port": port, "protocol": "WEB", "status": "OPEN", "detail": "Web Service Detected"})
                is_scanned = True

            if port in dns_p:
                for domain in domain_list:
                    if domain:
                        dns_res = check_zone_transfer(domain, target_ip, port)
                        if dns_res.get("vulnerable"):
                            dns_findings = analyzer.analyze_service("DNS", port, "DNS-AXFR", {"dns_results": dns_res})
                            for f in dns_findings:
                                f["domain"] = domain
                                all_findings.append(f)
                port_status_summary.append({"port": port, "protocol": "DNS", "status": "OPEN", "detail": "DNS Service Active"})
                is_scanned = True

            if not is_scanned:
                all_findings.append({
                    "id": f"PORT-{port}", "protocol": "TCP", "check_item": "通用端口开放", 
                    "risk_level": "安全", "description": f"检测到非预设业务端口 {port} 开放。",
                    "detail_value": f"Port: {port}",
                    "suggestion": "请核查此端口是否为业务必需。", "mlps_clause": "G3-访问控制"
                })
                port_status_summary.append({"port": port, "protocol": "TCP", "status": "OPEN", "detail": "Active"})

        update_progress(95, "正在执行风险建模与评分...")
        score = analyzer.calculate_score(all_findings)
        report = {
            "target": target_ip, "score": score,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "defects": all_findings, "port_statuses": port_status_summary,
            "summary": {
                "high": len([d for d in all_findings if d["risk_level"] == "高危"]), 
                "medium": len([d for d in all_findings if d["risk_level"] == "中危"]), 
                "low": len([d for d in all_findings if d["risk_level"] == "低危"])
            }
        }
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, target TEXT, score INTEGER, report TEXT)")
        cursor.execute("INSERT INTO scans (target, score, report) VALUES (?, ?, ?)", (target_ip, score, json.dumps(report)))
        report['id'] = cursor.lastrowid
        conn.commit()
        conn.close()

        task_store[task_id] = {"status": "completed", "result": report, "progress": {"percent": 100, "log": "审计完成"}}
        
    except Exception as e:
        print(f"Task {task_id} failed: {str(e)}")
        task_store[task_id] = {"status": "failed", "error": str(e)}

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())
    task_store[task_id] = {"status": "running", "result": None, "progress": {"percent": 0, "log": "初始化审计引擎"}}
    background_tasks.add_task(run_deep_scan, task_id, request)
    return {"task_id": task_id, "status": "running"}

@app.get("/api/scan/status/{task_id}")
async def get_scan_status(task_id: str):
    status = task_store.get(task_id)
    if not status:
        raise HTTPException(status_code=404, detail="Task ID not found")
    return status

@app.get("/api/history")
async def history():
    if not os.path.exists(DB_PATH): return []
    conn = sqlite3.connect(DB_PATH)
    rows = conn.cursor().execute("SELECT id, report FROM scans ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    results = []
    for r in rows:
        item = json.loads(r[1])
        item['id'] = r[0]
        results.append(item)
    return results

@app.delete("/api/history/{scan_id}")
async def delete_scan(scan_id: int):
    if not os.path.exists(DB_PATH): 
        raise HTTPException(status_code=404, detail="Database not found")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    count = cursor.rowcount
    conn.close()
    if count == 0:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"status": "ok"}

@app.delete("/api/history/purge")
async def purge_history():
    if not os.path.exists(DB_PATH): return {"status": "ok"}
    conn = sqlite3.connect(DB_PATH)
    conn.cursor().execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return {"status": "ok"}

if os.path.exists(DIST_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(DIST_DIR, "assets")), name="assets")
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api/"): return None
        return FileResponse(os.path.join(DIST_DIR, "index.html"))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
