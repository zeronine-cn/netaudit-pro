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
    """
    前端工具箱专用：获取指定 URL 的 Headers 并分析
    """
    if not req.url.startswith("http"):
        return {"error": "Invalid URL, must start with http:// or https://"}
    return fetch_url_headers(req.url)

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
        target_ip = request.target
        try:
            # 简单的判断，如果包含字母则尝试解析
            if any(c.isalpha() for c in target_ip): 
                target_ip = socket.gethostbyname(request.target)
        except Exception as e:
            print(f"DNS解析失败，尝试直接使用目标: {e}")

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
        
        if len(target_ports) == 0:
            raise Exception("未指定扫描端口范围")

        # --- 修改点 2: 并发端口探测 (替换原有的 Step A) ---
        update_progress(5, f"正在对 {len(target_ports)} 个端口进行并发存活探测...")
        
        active_ports = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            # 提交所有探测任务
            future_to_port = {executor.submit(probe_port, target_ip, p): p for p in target_ports}
            for future in as_completed(future_to_port):
                p = future_to_port[future]
                if future.result():
                    active_ports.append(p)
        
        active_ports.sort() # 排序，方便查看报告
        
        if not active_ports:
            # 如果没有端口开放，直接结束
            empty_report = {
                "target": target_ip, "score": 100, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "defects": [], "port_statuses": [], "metadata": request.metadata, "summary": {"high": 0, "medium": 0, "low": 0}
            }
            # 保存空报告到数据库
            new_id = database.save_report(empty_report)
            empty_report['id'] = new_id

            task_store[task_id] = {
                "status": "completed", 
                "result": empty_report, 
                "progress": {"percent": 100, "log": "未发现开放端口"}
            }
            return

        # --- 修改点 3: 针对存活端口进行深度扫描 (Step B) ---
        total_active = len(active_ports)
        update_progress(15, f"发现 {total_active} 个存活端口，开始深度审计...")

        for idx, port in enumerate(active_ports):
            # 进度条计算：从 20% 开始，到 90% 结束
            progress_pct = 20 + int((idx / total_active) * 70)
            update_progress(progress_pct, f"正在深度审计端口 {port}...")
            
            # 由于已经是 active_ports，无需再次 socket 探测存活，直接进行服务识别
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
                
                # 2.1 基础扫描：针对 IP (强制 vhost=None)
                # 这能发现直接访问 IP 时的敏感文件泄露 (如 .git, .env)
                web_res = scan_http(target_ip, port, scheme=protocol_name.lower(), vhost=None)
                
                # 2.2 并发域名扫描：针对所有关联域名
                if request.domains:
                    update_progress(progress_pct, f"正在并发探测 {len(request.domains)} 个关联域名的 Web 漏洞...")
                    
                    def scan_domain_worker(dom):
                        return dom, scan_http(target_ip, port, scheme=protocol_name.lower(), vhost=dom)

                    # 使用线程池并发扫描所有域名
                    with ThreadPoolExecutor(max_workers=10) as web_executor:
                        futures = [web_executor.submit(scan_domain_worker, d) for d in request.domains]
                        
                        for future in as_completed(futures):
                            try:
                                domain, domain_res = future.result()
                                
                                # 如果 IP 扫描结果为空/失败（如禁止 IP 访问），直接采用域名的结果作为基准
                                if 'deep_scan' not in web_res and 'deep_scan' in domain_res:
                                    web_res = domain_res
                                    continue

                                # 结果融合逻辑
                                if 'deep_scan' in web_res and 'deep_scan' in domain_res:
                                    deep = web_res['deep_scan']
                                    dom_deep = domain_res['deep_scan']

                                    # A. 合并敏感目录
                                    # 为了保留证据，我们将域名扫描发现的所有路径都添加进去，并标记来源
                                    for p in dom_deep.get('exposed_paths', []):
                                        p_copy = p.copy()
                                        p_copy['path'] = f"{p['path']} [Domain: {domain}]"
                                        deep.setdefault('exposed_paths', []).append(p_copy)

                                    # B. 合并 CORS 问题 (只要任意域名有问题，就标记为 True)
                                    if dom_deep.get('cors_issue'):
                                        deep['cors_issue'] = True

                                    # C. 合并 Cookie 问题
                                    for c in dom_deep.get('cookie_issues', []):
                                        cookie_msg = f"{c} [Domain: {domain}]"
                                        # 简单去重
                                        if cookie_msg not in deep.get('cookie_issues', []):
                                            deep.setdefault('cookie_issues', []).append(cookie_msg)

                                    # D. 合并 Headers & Methods (取并集)
                                    deep['missing_headers'] = list(set(deep.get('missing_headers', [])) | set(dom_deep.get('missing_headers', [])))
                                    deep['unsafe_methods'] = list(set(deep.get('unsafe_methods', [])) | set(dom_deep.get('unsafe_methods', [])))
                                    
                            except Exception as e:
                                print(f"Error scanning domain {domain}: {e}")

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
                primary_vhost = request.domains[0] if request.domains else None
                if protocol_name == "HTTPS":
                    # TLS 检测依然需要 VHost 进行 SNI 握手 (使用第一个域名即可，通常证书是一样的)
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
        
        # --- 持久化存储 ---
        try:
            new_id = database.save_report(report)
            report['id'] = new_id
            update_progress(99, "正在持久化审计数据到 SQLite...")
        except Exception as e:
            print(f"Failed to save report to DB: {e}")
        
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

# --- 历史记录 API (新增) ---

@app.get("/api/history")
async def get_history():
    """获取所有历史审计报告"""
    try:
        return database.get_all_reports()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/history/purge")
async def purge_history():
    """清空所有历史记录"""
    try:
        database.purge_reports()
        return {"status": "success", "message": "All reports purged"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/history/{report_id}")
async def delete_history_item(report_id: int):
    """删除单条记录"""
    try:
        database.delete_report(report_id)
        return {"status": "success", "id": report_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
