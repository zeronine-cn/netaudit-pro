import socket
import paramiko
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置日志记录，减少 paramiko 的调试输出
logging.getLogger("paramiko").setLevel(logging.WARNING)

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
    优化后的 SSH 弱口令审计函数：
    1. 引入线程池并发验证，显著提升大字典扫描速度。
    2. 保留早停机制，一旦发现有效凭据即刻终止所有线程并返回。
    """
    
    # 内部登录尝试函数
    def attempt_login(user, pwd):
        user = user.strip()
        pwd = pwd.strip()
        if not user or not pwd:
            return None
            
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # 关键优化：禁用所有不必要的认证方法以加快速度
            client.connect(
                hostname=target,
                port=port,
                username=user,
                password=pwd,
                timeout=5,          # 认证超时
                banner_timeout=10,  # 响应超时
                look_for_keys=False,
                allow_agent=False
            )
            return {"user": user, "pass": pwd, "is_compromised": True}
        except paramiko.AuthenticationException:
            return None # 账号密码错误
        except Exception:
            return None # 网络层或协议错误
        finally:
            client.close()

    # 构建任务列表
    credentials_to_test = [(u, p) for u in usernames for p in passwords]
    
    # 使用线程池加速审计 (建议并发数 5-10，避免被目标防火墙拉黑)
    with ThreadPoolExecutor(max_workers=5) as executor:
        # 提交所有任务
        future_to_cred = {
            executor.submit(attempt_login, u, p): (u, p) 
            for u, p in credentials_to_test
        }
        
        try:
            for future in as_completed(future_to_cred):
                result = future.result()
                if result:
                    # 【核心优化：早停机制】
                    # 发现一个有效凭据后，立即强制取消所有还未开始的任务并关闭线程池
                    executor.shutdown(wait=False, cancel_futures=True)
                    return [result]
        except Exception as e:
            print(f"审计过程中出现异常: {str(e)}")

    return [] # 未发现弱口令