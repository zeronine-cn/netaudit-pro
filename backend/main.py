
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import uvicorn
import time
import socket
import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager

# 引入核心分析器
from core.analyzer import SecurityAnalyzer

# 引入数据库模块
import database

# 引入所有 Scanner 模块功能
# 注意：scan_http 已被 scan_web_service 替代用于主逻辑
from scanners.web_scan import scan_web_service, fetch_url_headers
from scanners.sys_scan import check_ssh_banner, brute_force_ssh
from scanners.db_scan import scan_mysql, scan_redis, scan_postgres, scan_mongodb, brute_force_mysql
from scanners.dns_scan import check_zone_transfer

# 引入 Word 生成器
from utils.word_generator import generate_word_report

# 使用 lifespan 替代过时的 on_event
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 初始化：连接数据库
    database.init_db()
    yield

app = FastAPI(title="NetAudit 审计引擎 V3.2", lifespan=lifespan)

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
    # 新增：爆破协议列表，用于弱口令扫描的精细化控制 (SSH, MySQL)
    brute_protocols: List[str] = ["SSH", "MySQL"]
    # 目标协议列表，用于精细化控制 (功能预留)
    target_protocols: List[str] = ["SSH", "Web", "Database", "DNS"]
    metadata: Optional[Dict[str, str]] = {}

class HeaderDebugRequest(BaseModel):
    url: str

@app.post("/api/tools/headers")
async def debug_headers(req: HeaderDebugRequest):
    """
    前端工具箱专用：获取指定 URL 的 Headers 并分析
    """
    if not req.url.startswith("http"):
        return {"error": "Invalid URL, must start with http:// or https://"}
    return fetch_url_headers(req.url)

def parse_port_config(config_str: str) -> List[int]:
    """解析端口配置字符串，支持 '80, 8080', '80-90' 及中文逗号"""
    ports = set()
    if not config_str:
        return []
    
    # 兼容中文逗号
    config_str = config_str.replace('，', ',')
    
    for p in config_str.split(','):
        p = p.strip()
        if not p: continue
        
        # 支持端口范围，例如 8000-8010
        if '-' in p:
            try:
                parts = p.split('-')
                if len(parts) == 2:
                    start = int(parts[0])
                    end = int(parts[1])
                    if start <= end:
                        ports.update(range(start, end + 1))
            except:
                pass
        elif p.isdigit():
            ports.add(int(p))
            
    return sorted(list(ports))

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

        # 为了方便传递给子模块，定义一个只接受 msg 的简单回调
        def log_callback(msg):
            # 百分比保持不变，只更新消息
            update_progress(task_store[task_id]["progress"]["percent"], msg)
            # 增加微小延时，让前端 250ms 轮询能抓到这条日志
            time.sleep(0.2)

        target_ip = request.target
        # Metasploit 风格初始化日志
        update_progress(1, f"[*] Started audit module on {request.target}")
        
        # 协议范围确认
        enabled_protos = request.target_protocols
        #update_progress(2, f"[*] Target Protocols: {', '.join(enabled_protos)}")
        
        try:
            update_progress(3, f"[*] Resolving host {request.target}...")
            if any(c.isalpha() for c in target_ip): 
                target_ip = socket.gethostbyname(request.target)
                update_progress(4, f"[+] Host resolved: {request.target} -> {target_ip}")
            else:
                update_progress(4, f"[*] Host is IP address, skipping DNS resolution")
        except Exception as e:
            update_progress(4, f"[-] DNS lookup failed: {e}. Using raw target.")

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
        
        all_findings = []
        port_status_summary = []
        
        if len(target_ports) == 0:
            raise Exception("No ports specified")

        # --- 端口扫描 ---
        update_progress(6, f"[*] Sending TCP SYN packets to {len(target_ports)} ports...")
        
        active_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(probe_port, target_ip, p): p for p in target_ports}
            for future in as_completed(future_to_port):
                p = future_to_port[future]
                if future.result():
                    active_ports.append(p)
                    # 实时发现日志
                    update_progress(8, f"[+] Discovered open port {p}/tcp")
        
        active_ports.sort()
        if active_ports:
            update_progress(10, f"[*] Scan complete. Found {len(active_ports)} open TCP ports.")
        else:
            update_progress(100, f"[-] No active ports found. Module execution aborted.")
            return

        # --- 深度扫描 ---
        total_active = len(active_ports)
        
        for idx, port in enumerate(active_ports):
            progress_pct = 15 + int((idx / total_active) * 80)
            
            # 更新进度以便 log_callback 使用正确的值
            task_store[task_id]["progress"]["percent"] = progress_pct
            
            current_protocol = "TCP"
            service_detail = "Unknown Service"
            
            # 1. SSH
            if port in ssh_ports and "SSH" in enabled_protos:
                current_protocol = "SSH"
                update_progress(progress_pct, f"[*] Running auxiliary/scanner/ssh/ssh_version on port {port}...")
                banner = check_ssh_banner(target_ip, port)
                service_detail = banner
                update_progress(progress_pct, f"[+] SSH Banner: {banner}")
                time.sleep(0.3)
                
                # 移除硬编码的 OS Info Leak 日志，交给 analyzer 统一处理

                weak_creds = []
                # 弱口令审计逻辑
                if request.mode == "深度审计" and request.enable_brute and "SSH" in request.brute_protocols and users and passwords:
                    update_progress(progress_pct, f"[*] Starting SSH brute force on {target_ip}:{port}...")
                    time.sleep(0.3)
                    weak_creds = brute_force_ssh(target_ip, port, users, passwords, callback=log_callback)
                    if weak_creds:
                        cred = weak_creds[0]
                        # 成功日志保留，因为这是过程中的高光时刻
                        update_progress(progress_pct, f"[+] Success: '{cred['user']}:{cred['pass']}'")
                        update_progress(progress_pct, f"[!] Command shell session 1 opened ({target_ip}:{port})")
                        time.sleep(1)
                
                findings = analyzer.analyze_service("SSH", port, banner, {"weak_creds": weak_creds})
                all_findings.extend(findings)

            # 2. Web (HTTP/HTTPS)
            elif (port in http_ports or port in https_ports) and "Web" in enabled_protos:
                def web_progress_callback(msg):
                    update_progress(progress_pct, msg)
                    # 关键修改：增加 Web 扫描过程日志的可见性
                    time.sleep(0.2)

                update_progress(progress_pct, f"[*] Initiating web scan on port {port}...")
                
                # 执行综合扫描
                scan_result = scan_web_service(
                    target_ip=target_ip,
                    port=port,
                    domains=request.domains,
                    is_deep_scan=(request.mode == "深度审计"),
                    update_progress_cb=web_progress_callback
                )
                
                current_protocol = scan_result["protocol"]
                service_detail = scan_result["banner"]
                extra_data = scan_result["extra"]

                # 移除硬编码的 Web 漏洞日志 (Missing headers, directories, expired certs)
                # 这些将由 analyzer 生成 findings 后统一输出

                for vhost in extra_data["verified_vhosts"]:
                     update_progress(progress_pct, f"[+] Virtual Host identified: {vhost}")
                     time.sleep(0.5)

                findings = analyzer.analyze_service(current_protocol, port, service_detail, extra_data)
                all_findings.extend(findings)

            # 3. DNS
            elif port in dns_ports and "DNS" in enabled_protos:
                current_protocol = "DNS"
                service_detail = "DNS Service Active"
                update_progress(progress_pct, f"[*] Checking DNS Zone Transfer on port {port}...")
                
                dns_res = {}
                if request.domains:
                    for domain in request.domains:
                        res = check_zone_transfer(domain, target_ip, port)
                        if res.get("vulnerable"):
                            dns_res = res
                            update_progress(progress_pct, f"[+] AXFR Zone Transfer successful for {domain}")
                            time.sleep(0.5)
                            break
                findings = analyzer.analyze_service("DNS", port, service_detail, {"dns_results": dns_res})
                all_findings.extend(findings)

            # 4. MySQL
            elif port in mysql_ports and "Database" in enabled_protos:
                current_protocol = "MySQL"
                update_progress(progress_pct, f"[*] Probing MySQL protocol on port {port}...")
                res = scan_mysql(target_ip, port)
                service_detail = res.get("banner", "MySQL")
                update_progress(progress_pct, f"[*] MySQL Version: {service_detail}")

                weak_creds = []
                db_users = [u.strip() for u in request.dictionaries.get('db_usernames', '').split('\n') if u.strip()]
                db_passwords = [p.strip() for p in request.dictionaries.get('db_passwords', '').split('\n') if p.strip()]
                
                if not db_users: db_users = users
                if not db_passwords: db_passwords = passwords

                if request.mode == "深度审计" and request.enable_brute and "MySQL" in request.brute_protocols and db_users and db_passwords:
                    update_progress(progress_pct, f"[*] Starting MySQL brute force on {target_ip}:{port}...")
                    time.sleep(0.3)
                    weak_creds = brute_force_mysql(target_ip, port, db_users, db_passwords, callback=log_callback)
                    if weak_creds:
                         cred = weak_creds[0]
                         update_progress(progress_pct, f"[+] MySQL Success: '{cred['user']}:{cred['pass']}'")
                         time.sleep(1)

                findings = analyzer.analyze_service("MySQL", port, service_detail, {"db_results": res, "weak_creds": weak_creds})
                all_findings.extend(findings)
            
            # 5. Redis
            elif port in redis_ports and "Database" in enabled_protos:
                current_protocol = "Redis"
                update_progress(progress_pct, f"[*] Checking Redis for unauthorized access...")
                res = scan_redis(target_ip, port)
                if res.get("vulnerable"):
                    update_progress(progress_pct, f"[+] Redis login successful (No Auth Required)")
                    time.sleep(0.5)
                else:
                    update_progress(progress_pct, f"[-] Redis authentication required")
                findings = analyzer.analyze_service("Redis", port, "Redis Server", {"db_results": res})
                all_findings.extend(findings)
            
            # 6. PostgreSQL
            elif port in postgres_ports and "Database" in enabled_protos:
                current_protocol = "PostgreSQL"
                update_progress(progress_pct, f"[*] Probing PostgreSQL auth on port {port}...")
                res = scan_postgres(target_ip, port)
                service_detail = res.get("banner", "PostgreSQL")
                findings = analyzer.analyze_service("PostgreSQL", port, service_detail, {"db_results": res})
                all_findings.extend(findings)

            # 7. MongoDB
            elif port in mongo_ports and "Database" in enabled_protos:
                current_protocol = "MongoDB"
                update_progress(progress_pct, f"[*] Probing MongoDB auth on port {port}...")
                res = scan_mongodb(target_ip, port)
                service_detail = res.get("banner", "MongoDB")
                if res.get("vulnerable"):
                    update_progress(progress_pct, f"[!] MongoDB Unauthorized Access detected")
                    time.sleep(0.5)
                findings = analyzer.analyze_service("MongoDB", port, service_detail, {"db_results": res})
                all_findings.extend(findings)

            else:
                findings = analyzer.analyze_service("TCP", port, "Generic TCP", {})
                all_findings.extend(findings)

            port_status_summary.append({
                "port": port, "protocol": current_protocol, "status": "OPEN", "detail": service_detail
            })

            # --- 关键情报优先策略 (Critical Intel First) ---
            # 实时输出该端口发现的中高危漏洞
            port_high_risks = 0
            port_med_risks = 0
            
            for f in findings:
                risk = f.get('risk_level', 'Info')
                if risk == '高危':
                    port_high_risks += 1
                    # 红色高亮格式
                    update_progress(progress_pct, f"[!] CRITICAL: {f.get('check_item')} - {f.get('description')[:50]}...")
                    # 关键修改：调整为 0.6 秒，配合前端 0.25 秒轮询，确保日志显示足够长的时间，又不至于卡太久
                    time.sleep(0.6) 
                elif risk == '中危':
                    port_med_risks += 1
                    # 黄色警告格式
                    update_progress(progress_pct, f"[-] WARN: {f.get('check_item')}")
                    # 关键修改：调整为 0.6 秒
                    time.sleep(0.6)
            
            # 端口扫描小结
            if port_high_risks > 0 or port_med_risks > 0:
                update_progress(progress_pct, f"[*] Port {port} analysis complete. Found {port_high_risks} Critical, {port_med_risks} Warn.")
                time.sleep(0.6) # 让小结也能被看到
            else:
                # 对于无风险端口，显示简洁信息
                update_progress(progress_pct, f"[*] Port {port} ({current_protocol}) analysis complete. Status: Clean.")
                time.sleep(0.2)

        # 计算总分
        high_count = len([d for d in all_findings if d["risk_level"] == "高危"])
        if high_count > 0:
             update_progress(96, f"[!] {high_count} critical vulnerabilities identified")
        else:
             update_progress(96, f"[*] System analysis complete. No critical issues.")

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
        
        task_store[task_id] = {"status": "completed", "result": report, "progress": {"percent": 100, "log": "[*] Auxiliary module execution completed"}}
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
async def get_scan_status(task_id: str):
    if task_id not in task_store:
        raise HTTPException(status_code=404, detail="Task not found")
    return task_store[task_id]

@app.get("/api/history")
async def get_history():
    return database.get_all_reports()

@app.delete("/api/history/{report_id}")
async def delete_history(report_id: int):
    database.delete_report(report_id)
    return {"status": "success"}

@app.delete("/api/history/purge")
async def purge_history():
    database.purge_reports()
    return {"status": "success"}

@app.post("/api/report/word/{report_id}")
async def download_word_report(report_id: int):
    """
    生成并下载 Word 格式报告
    """
    report = database.get_report_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    try:
        word_file = generate_word_report(report)
        filename = f"NetAudit_{report['target'].replace('.', '_')}_{int(time.time())}.docx"
        
        return StreamingResponse(
            word_file,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 安全配置接口：获取服务器端预设密码（如有）
@app.get("/api/config/security")
async def get_security_config():
    # 在真实场景中，这里可以从环境变量或配置文件读取
    # 为了演示，我们返回一个空对象，让前端使用默认或本地存储的密码
    return {"expected_password": None}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
