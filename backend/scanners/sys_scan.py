
import socket
import paramiko
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置日志记录
logging.getLogger("paramiko").setLevel(logging.WARNING)

def check_ssh_banner(target: str, port: int):
    """
    获取 SSH 指纹，用于初步确认服务类型
    """
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            s.settimeout(3)
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "SSH-2.0-Generic"
    except Exception:
        return "SSH Connection Refused"

def brute_force_ssh(target: str, port: int, usernames: list, passwords: list, on_step_callback=None):
    """
    高性能并发 SSH 弱口令审计函数
    使用线程池加速验证，并支持实时进度回调
    """
    found_creds = []
    MAX_WORKERS = 5       # 建议并发数，不宜过高以防被防火墙拦截
    AUTH_TIMEOUT = 5      # 认证超时
    BANNER_TIMEOUT = 10   # Banner 响应超时

    # 构建任务队列
    tasks = []
    for u in [user.strip() for user in usernames if user.strip()]:
        for p in [pwd.strip() for pwd in passwords if pwd.strip()]:
            tasks.append((u, p))

    total_tasks = len(tasks)
    if total_tasks == 0:
        return []

    def attempt_login(user, pwd):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target,
                port=port,
                username=user,
                password=pwd,
                timeout=AUTH_TIMEOUT,
                banner_timeout=BANNER_TIMEOUT,
                look_for_keys=False,
                allow_agent=False
            )
            # 登录成功
            return {"user": user, "pass": pwd, "is_compromised": True}
        except paramiko.AuthenticationException:
            return None
        except Exception:
            return None
        finally:
            client.close()

    # 使用线程池执行并发验证
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_task = {executor.submit(attempt_login, u, p): (u, p) for u, p in tasks}
        
        completed_count = 0
        for future in as_completed(future_to_task):
            completed_count += 1
            result = future.result()
            
            # 每一步通过回调反馈进度给主进程
            if on_step_callback:
                current_pct = int((completed_count / total_tasks) * 100)
                user, pwd = future_to_task[future]
                on_step_callback(current_pct, f"正在验证凭据: {user} / {'*' * len(pwd)}")

            if result:
                # 核心逻辑：早停机制
                # 发现一个有效凭据即刻尝试取消后续任务并返回
                found_creds.append(result)
                # 停止接收新任务
                executor.shutdown(wait=False, cancel_futures=True)
                return found_creds
            
            # 短暂休眠以缓解目标系统压力
            time.sleep(0.1)
            
    return found_creds
