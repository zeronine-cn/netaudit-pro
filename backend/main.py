
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import uvicorn
import time
import socket
import json
import uuid
from concurrent.futures import ThreadPoolExecutor

from core.analyzer import SecurityAnalyzer
from scanners.web_scan import scan_http, check_tls_vulnerability
from scanners.sys_scan import check_ssh_banner, brute_force_ssh
from scanners.db_scan import scan_mysql, scan_redis, scan_postgres, scan_mongodb

app = FastAPI(title="NetAudit 审计引擎 V3.2")
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

def run_deep_scan(task_id: str, request: ScanRequest):
    try:
        def update_progress(pct, log):
            task_store[task_id]["progress"] = {"percent": pct, "log": log}

        target_ip = request.target
        # 解析端口...
        active_ports = [22, 80, 443, 3306, 6379] # 简化演示

        all_findings = []
        port_status_summary = []
        
        # 对应配置中的端口定义
        mysql_ports = [int(p) for p in request.ports_config.get('mysql', '3306').split(',')]
        redis_ports = [int(p) for p in request.ports_config.get('redis', '6379').split(',')]

        for port in active_ports:
            update_progress(50, f"正在深度审计端口 {port}...")
            
            # 数据库专项分发
            if port in mysql_ports:
                res = scan_mysql(target_ip, port)
                findings = analyzer.analyze_service("MySQL", port, res.get("banner", ""), {"db_results": res})
                all_findings.extend(findings)
                port_status_summary.append({"port": port, "protocol": "MySQL", "status": "OPEN", "detail": res.get("banner", "")})
            
            elif port in redis_ports:
                res = scan_redis(target_ip, port)
                findings = analyzer.analyze_service("Redis", port, "Redis Server", {"db_results": res})
                all_findings.extend(findings)
                port_status_summary.append({"port": port, "protocol": "Redis", "status": "OPEN", "detail": res.get("detail", "")})
            
            # ... 其他协议逻辑

        score = analyzer.calculate_score(all_findings)
        report = {
            "target": target_ip, "score": score,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "defects": all_findings, "port_statuses": port_status_summary,
            "metadata": request.metadata,
            "summary": {
                "high": len([d for d in all_findings if d["risk_level"] == "高危"]),
                "medium": len([d for d in all_findings if d["risk_level"] == "中危"]),
                "low": len([d for d in all_findings if d["risk_level"] == "低危"])
            }
        }
        task_store[task_id] = {"status": "completed", "result": report, "progress": {"percent": 100, "log": "审计完成"}}
    except Exception as e:
        task_store[task_id] = {"status": "failed", "error": str(e)}

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())
    task_store[task_id] = {"status": "running", "progress": {"percent": 0, "log": "初始化"}}
    background_tasks.add_task(run_deep_scan, task_id, request)
    return {"task_id": task_id}

@app.get("/api/scan/status/{task_id}")
async def get_status(task_id: str):
    return task_store.get(task_id, {"status": "not_found"})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
