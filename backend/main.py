
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

# 引入核心分析器
from core.analyzer import SecurityAnalyzer

# 引入所有 Scanner 模块功能
from scanners.web_scan import scan_http, check_tls_vulnerability, verify_vhost
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
    """解析端口配置字符串，如 '80, 8080' -> [80, 8080]"""
    ports = []
    if not config_str:
        return ports
    for p in config_str.split(','):
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
    return ports

def run_deep_scan(task_id: str, request: ScanRequest):
    try:
        def update_progress(pct, log):
            task_store[task_id]["progress"] = {"percent": pct, "log": log}

        target_ip = request.target
        
        # 1. 动态解析目标端口 (这是实际要扫描的端口列表)
        target_ports = parse_port_config(request.port_range)
        
        # 2. 解析协议端口配置 (用于识别端口对应的服务类型)
        ssh_ports = parse_port_config(request.ports_config.get('ssh', '22'))
        http_ports = parse_port_config(request.ports_config.get('http', '80,8080'))
        https_ports = parse_port_config(request.ports_config.get('https', '443,8443'))
        dns_ports = parse_port_config(request.ports_config.get('dns', '53'))
        mysql_ports = parse_port_config(request.ports_config.get('mysql', '3306'))
        redis_ports = parse_port_config(request.ports_config.get('redis', '6379'))
        postgres_ports = parse_port_config(request.ports_config.get('postgres', '5432'))
        mongo_ports = parse_port_config(request.ports_config.get('mongodb', '27017'))

        # 3. 解析字典
        users = [u.strip() for u in request.dictionaries.get('usernames', '').split('\n') if u.strip()]
        passwords = [p.strip() for p in request.dictionaries.get('passwords', '').split('\n') if p.strip()]
        
        all_findings = []
        port_status_summary = []
        
        total_ports = len(target_ports)
        if total_ports == 0:
            raise Exception("未指定扫描端口范围")

        for idx, port in enumerate(target_ports):
            progress_pct = int((idx / total_ports) * 90)
            update_progress(progress_pct, f"正在深度审计端口 {port}...")
            
            # --- 步骤 A: 端口存活探测 (Socket Connect) ---
            is_open = False
            try:
                # 设置较短超时，快速跳过关闭端口
                with socket.create_connection((target_ip, port), timeout=0.5) as s:
                    is_open = True
            except:
                pass

            if not is_open:
                continue

            # --- 步骤 B: 服务识别与深度扫描 ---
            current_protocol = "TCP"
            service_detail = "Unknown Service"
            
            # 1. SSH 服务审计
            if port in ssh_ports:
                current_protocol = "SSH"
                # 始终获取 Banner
                banner = check_ssh_banner(target_ip, port)
                service_detail = banner
                
                weak_creds = []
                # 【关键逻辑】仅在 "深度审计" 模式下且开启爆破时，才执行耗时的 SSH 爆破
                if request.mode == "深度审计" and request.enable_brute and users and passwords:
                    update_progress(progress_pct, f"正在对端口 {port} 进行 SSH 弱口令爆破 (深度模式)...")
                    weak_creds = brute_force_ssh(target_ip, port, users, passwords)
                elif request.enable_brute:
                    update_progress(progress_pct, f"端口 {port} 检测到 SSH，但当前非深度模式，跳过爆破。")
                
                findings = analyzer.analyze_service("SSH", port, banner, {"weak_creds": weak_creds})
                all_findings.extend(findings)

            # 2. Web 服务审计 (HTTP/HTTPS)
            elif port in http_ports or port in https_ports:
                protocol_name = "HTTPS" if port in https_ports else "HTTP"
                current_protocol = protocol_name
                
                # 确定 VHost
                primary_vhost = request.domains[0] if request.domains else None
                
                # 调用 scanners/web_scan.py
                web_res = scan_http(target_ip, port, vhost=primary_vhost)
                service_detail = web_res.get("banner", "Web Server")
                
                # VHost 碰撞 (仅深度模式或指定域名时)
                verified_vhosts = []
                if request.mode == "深度审计" and request.domains:
                    update_progress(progress_pct, f"正在对端口 {port} 进行 VHost 碰撞...")
                    for domain in request.domains:
                        if verify_vhost(target_ip, port, domain):
                            verified_vhosts.append(domain)
                
                # TLS 检测 (仅 HTTPS)
                tls_res = {}
                if protocol_name == "HTTPS":
                    tls_res = check_tls_vulnerability(target_ip, port, vhost=primary_vhost)
                
                findings = analyzer.analyze_service(protocol_name, port, service_detail, {
                    "web_results": web_res,
                    "tls_results": tls_res,
                    "verified_vhosts": verified_vhosts
                })
                all_findings.extend(findings)

            # 3. DNS 服务审计
            elif port in dns_ports:
                current_protocol = "DNS"
                service_detail = "DNS Server"
                
                dns_res = {}
                if request.domains:
                    # 尝试区域传送
                    for domain in request.domains:
                        res = check_zone_transfer(domain, target_ip, port)
                        if res.get("vulnerable"):
                            dns_res = res
                            service_detail = f"AXFR Leak ({domain})"
                            break
                        else:
                            dns_res = res
                else:
                    dns_res = {"vulnerable": False, "detail": "Skipped (No Domain Provided)"}

                findings = analyzer.analyze_service("DNS", port, service_detail, {"dns_results": dns_res})
                all_findings.extend(findings)

            # 4. MySQL 审计
            elif port in mysql_ports:
                current_protocol = "MySQL"
                # 调用 scanners/db_scan.py
                res = scan_mysql(target_ip, port)
                service_detail = res.get("banner", "MySQL Service")
                findings = analyzer.analyze_service("MySQL", port, service_detail, {"db_results": res})
                all_findings.extend(findings)
            
            # 5. Redis 审计
            elif port in redis_ports:
                current_protocol = "Redis"
                # 调用 scanners/db_scan.py
                res = scan_redis(target_ip, port)
                service_detail = res.get("detail", "Redis Service")
                findings = analyzer.analyze_service("Redis", port, "Redis Server", {"db_results": res})
                all_findings.extend(findings)

            # 6. PostgreSQL 审计
            elif port in postgres_ports:
                current_protocol = "PostgreSQL"
                # 调用 scanners/db_scan.py
                res = scan_postgres(target_ip, port)
                service_detail = res.get("banner", "PostgreSQL")
                findings = analyzer.analyze_service("PostgreSQL", port, service_detail, {"db_results": res})
                all_findings.extend(findings)

            # 7. MongoDB 审计
            elif port in mongo_ports:
                current_protocol = "MongoDB"
                # 调用 scanners/db_scan.py
                res = scan_mongodb(target_ip, port)
                service_detail = res.get("banner", "MongoDB")
                findings = analyzer.analyze_service("MongoDB", port, service_detail, {"db_results": res})
                all_findings.extend(findings)

            # 8. 通用 TCP 兜底
            else:
                findings = analyzer.analyze_service("TCP", port, "Generic TCP", {})
                all_findings.extend(findings)

            port_status_summary.append({
                "port": port, 
                "protocol": current_protocol, 
                "status": "OPEN", 
                "detail": service_detail
            })

        # 计算总分
        score = analyzer.calculate_score(all_findings)
        
        report = {
            "target": target_ip, 
            "score": score,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "defects": all_findings, 
            "port_statuses": port_status_summary,
            "metadata": request.metadata,
            "summary": {
                "high": len([d for d in all_findings if d["risk_level"] == "高危"]),
                "medium": len([d for d in all_findings if d["risk_level"] == "中危"]),
                "low": len([d for d in all_findings if d["risk_level"] == "低危"])
            }
        }
        task_store[task_id] = {"status": "completed", "result": report, "progress": {"percent": 100, "log": "审计完成"}}
    except Exception as e:
        print(f"Task Error: {e}")
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
