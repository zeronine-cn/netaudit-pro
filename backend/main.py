
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

def probe_port(ip: str, port: int) -> bool:
    """简单的 TCP 端口存活探测"""
    try:
        with socket.create_connection((ip, port), timeout=0.5) as s:
            return True
    except:
        return False

def run_deep_scan(task_id: str, request: ScanRequest):
    try:
        def update_progress(pct, log):
            task_store[task_id]["progress"] = {"percent": pct, "log": log}

        # --- 修改点 1: 域名预解析，固定 IP ---
        update_progress(1, f"[*] Target Resolution: {request.target}")
        target_ip = request.target
        try:
            if any(c.isalpha() for c in target_ip): 
                target_ip = socket.gethostbyname(request.target)
                update_progress(2, f"[+] DNS Resolved: {request.target} -> {target_ip}")
        except Exception as e:
            update_progress(2, f"[-] DNS Failed, using raw: {target_ip}")

        # 1. 动态解析目标端口
        target_ports = parse_port_config(request.port_range)
        
        # 2. 解析协议端口配置
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
        
        if len(target_ports) == 0:
            raise Exception("No port range specified")

        # --- 修改点 2: 并发端口探测 ---
        update_progress(5, f"[*] Starting Stealth SYN Scan (Ports: {len(target_ports)})...")
        
        active_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(probe_port, target_ip, p): p for p in target_ports}
            for future in as_completed(future_to_port):
                p = future_to_port[future]
                if future.result():
                    active_ports.append(p)
        
        active_ports.sort()
        
        if not active_ports:
            update_progress(100, "[-] No open ports found. Scan aborted.")
            task_store[task_id] = {
                "status": "completed", 
                "result": {
                    "target": target_ip, "score": 100, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "defects": [], "port_statuses": [], "metadata": request.metadata, "summary": {"high": 0, "medium": 0, "low": 0}
                }, 
                "progress": {"percent": 100, "log": "[-] No open ports found"}
            }
            return

        # --- 修改点 3: 深度扫描与 Nmap 风格日志 ---
        total_active = len(active_ports)
        update_progress(15, f"[+] Discovered {total_active} open ports: {active_ports}")
        time.sleep(0.5)

        for idx, port in enumerate(active_ports):
            progress_pct = 20 + int((idx / total_active) * 70)
            
            current_protocol = "TCP"
            service_detail = "Unknown"
            
            # 1. SSH 服务审计
            if port in ssh_ports:
                current_protocol = "SSH"
                update_progress(progress_pct, f"[*] Scanning {port}/tcp (SSH)...")
                
                banner = check_ssh_banner(target_ip, port)
                service_detail = banner
                
                # Nmap 风格: 发现服务
                update_progress(progress_pct, f"[+] {port}/tcp OPEN | Service: {banner}")

                weak_creds = []
                if request.mode == "深度审计" and request.enable_brute and users and passwords:
                    update_progress(progress_pct, f"[*] {port}/tcp >> Brute-forcing ({len(users)*len(passwords)} attempts)...")
                    weak_creds = brute_force_ssh(target_ip, port, users, passwords)
                
                findings = analyzer.analyze_service("SSH", port, banner, {"weak_creds": weak_creds})
                all_findings.extend(findings)

            # 2. Web 服务审计 (HTTP/HTTPS)
            elif port in http_ports or port in https_ports:
                protocol_name = "HTTPS" if port in https_ports else "HTTP"
                current_protocol = protocol_name
                update_progress(progress_pct, f"[*] Scanning {port}/tcp ({protocol_name})...")
                
                primary_vhost = request.domains[0] if request.domains else None
                
                web_res = scan_http(target_ip, port, vhost=primary_vhost)
                service_detail = web_res.get("banner", "Web Server")
                update_progress(progress_pct, f"[+] {port}/tcp OPEN | Service: {service_detail}")
                
                verified_vhosts = []
                if request.mode == "深度审计" and request.domains:
                    for domain in request.domains:
                        if verify_vhost(target_ip, port, domain):
                            verified_vhosts.append(domain)
                
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
                service_detail = "DNS"
                update_progress(progress_pct, f"[*] Scanning {port}/tcp (DNS)...")
                
                dns_res = {}
                if request.domains:
                    for domain in request.domains:
                        res = check_zone_transfer(domain, target_ip, port)
                        if res.get("vulnerable"):
                            dns_res = res
                            service_detail = "AXFR Leaked"
                            break
                        else:
                            dns_res = res
                
                findings = analyzer.analyze_service("DNS", port, service_detail, {"dns_results": dns_res})
                all_findings.extend(findings)

            # 4. MySQL
            elif port in mysql_ports:
                current_protocol = "MySQL"
                update_progress(progress_pct, f"[*] Scanning {port}/tcp (MySQL)...")
                res = scan_mysql(target_ip, port)
                service_detail = res.get("banner", "MySQL")
                update_progress(progress_pct, f"[+] {port}/tcp OPEN | Version: {service_detail}")
                findings = analyzer.analyze_service("MySQL", port, service_detail, {"db_results": res})
                all_findings.extend(findings)
            
            # 5. Redis
            elif port in redis_ports:
                current_protocol = "Redis"
                update_progress(progress_pct, f"[*] Scanning {port}/tcp (Redis)...")
                res = scan_redis(target_ip, port)
                service_detail = "Redis"
                findings = analyzer.analyze_service("Redis", port, "Redis Server", {"db_results": res})
                all_findings.extend(findings)

            # 6. 其他数据库
            elif port in postgres_ports:
                current_protocol = "PostgreSQL"
                res = scan_postgres(target_ip, port)
                service_detail = res.get("banner", "PostgreSQL")
                update_progress(progress_pct, f"[+] {port}/tcp OPEN | Service: {service_detail}")
                findings = analyzer.analyze_service("PostgreSQL", port, service_detail, {"db_results": res})
                all_findings.extend(findings)
            
            elif port in mongo_ports:
                current_protocol = "MongoDB"
                res = scan_mongodb(target_ip, port)
                service_detail = res.get("banner", "MongoDB")
                update_progress(progress_pct, f"[+] {port}/tcp OPEN | Service: {service_detail}")
                findings = analyzer.analyze_service("MongoDB", port, service_detail, {"db_results": res})
                all_findings.extend(findings)

            else:
                update_progress(progress_pct, f"[+] {port}/tcp OPEN | Service: Unknown")
                findings = analyzer.analyze_service("TCP", port, "Generic TCP", {})
                all_findings.extend(findings)

            # --- 关键逻辑：将扫描出的缺陷实时打印到日志 ---
            for f in findings:
                # 只显示非安全的项，或者你可以选择全部显示
                if f['risk_level'] == '安全': continue
                
                # 确定前缀
                prefix = "[!]" if f['risk_level'] in ['高危', '中危'] else "[-]"
                
                # 构造类似 Nmap Script 的输出，不包含 MLPS 条款
                # 格式: [!] <Check Item> detected | Detail: <Detail>
                msg = f"{prefix} {f['check_item']}"
                
                # 提取精简详情
                detail = str(f.get('detail_value', '')).strip()
                if detail and detail != "None":
                     clean_detail = detail.replace('\n', ' ').replace('\r', '')
                     if len(clean_detail) > 60: clean_detail = clean_detail[:57] + "..."
                     msg += f" | {clean_detail}"
                
                update_progress(progress_pct, msg)
                # 关键：稍微暂停一下，确保前端轮询能抓取到这条日志，形成刷屏感
                time.sleep(0.4)
            # -----------------------------------------------

            port_status_summary.append({
                "port": port, 
                "protocol": current_protocol, 
                "status": "OPEN", 
                "detail": service_detail
            })

        update_progress(95, "[*] Post-scan scripts finished. Generating report...")
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
        task_store[task_id] = {"status": "completed", "result": report, "progress": {"percent": 100, "log": "Audit Completed"}}
    except Exception as e:
        print(f"Task Error: {e}")
        task_store[task_id] = {"status": "failed", "error": str(e)}

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())
    task_store[task_id] = {"status": "running", "progress": {"percent": 0, "log": "Initializing Engine..."}}
    background_tasks.add_task(run_deep_scan, task_id, request)
    return {"task_id": task_id}

@app.get("/api/scan/status/{task_id}")
async def get_status(task_id: str):
    return task_store.get(task_id, {"status": "not_found"})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
