
import socket
import paramiko
import time
import logging

# 配置日志记录，减少 paramiko 的调试输出
logging.getLogger("paramiko").setLevel(logging.ERROR)

def check_ssh_banner(target: str, port: int):
    """获取 SSH 指纹，用于初步确认服务类型"""
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            s.settimeout(3)
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "SSH-2.0-Generic"
    except Exception:
        return "SSH Connection Refused"

def brute_force_ssh(target: str, port: int, usernames: list, passwords: list, callback=None):
    """
    SSH 弱口令审计函数 (大字典抗干扰版)：
    核心逻辑修改：遇到连接类错误（非密码错误）时，无限期（或高次数）重试当前凭据，
    直到连接成功并验证了密码为止。彻底防止因服务端 MaxStartups 限流导致的漏报。
    """
    
    # 内部登录尝试函数
    def attempt_login(user, pwd):
        user = user.strip()
        pwd = pwd.strip()
        if not user or not pwd:
            return None
        
        # 连续连接失败计数 (针对服务端限流/封禁)
        # 设置较高的重试阈值，确保在服务端解除封禁后能继续
        conn_fail_count = 0
        max_conn_fails = 20 
        
        while conn_fail_count < max_conn_fails:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=target,
                    port=port,
                    username=user,
                    password=pwd,
                    timeout=10,            # 增加 TCP 连接超时
                    banner_timeout=60,     # 大幅增加 Banner 等待时间，应对极端卡顿
                    auth_timeout=30,       # 增加认证超时
                    look_for_keys=False,
                    allow_agent=False
                )
                return {"user": user, "pass": pwd, "is_compromised": True}
            
            except paramiko.AuthenticationException:
                # 只有明确捕获到“鉴权失败”，才说明连接成功但密码错误
                # 此时应立即停止重试，返回 None 以便尝试下一个密码
                return None 
            
            except (paramiko.SSHException, socket.error, EOFError):
                # 捕获所有连接层面的异常（如 Error reading SSH protocol banner, Connection reset）
                # 这说明还没来得及验证密码就被踢了，必须重试当前密码
                conn_fail_count += 1
                
                # 智能退避策略：
                # 1-3次: 短暂抖动 (3s)
                # >3次: 可能是触发了 MaxStartups，需要较长冷却 (15s+)
                if conn_fail_count <= 3:
                    sleep_time = 3
                else:
                    sleep_time = 15 # 强制休眠15秒等待服务器恢复
                
                # 实时通知前端
                if callback:
                    callback(f"[!] SSH Connection Refused (Attempt {conn_fail_count}), Cooling down {sleep_time}s...")
                
                time.sleep(sleep_time)
                
            except Exception:
                # 其他未知错误，不再重试
                return None
            finally:
                client.close()
        
        # 如果重试次数耗尽仍无法连接（说明服务器可能彻底挂了），放弃该密码
        return None

    # 构建任务列表
    credentials_to_test = [(u, p) for u in usernames for p in passwords]
    
    # 单线程顺序执行
    for user, pwd in credentials_to_test:
        if callback:
             callback(f"[*] SSH Brute: Testing {user} / {pwd}")
             
        result = attempt_login(user, pwd)
        if result:
            return [result]
        
        # 成功完成一次密码验证（无论对错）后的常规间隔
        # 1.0秒是一个比较平衡的值，既不过快触发风控，也能保证一定效率
        time.sleep(1.0)

    return [] # 未发现弱口令
