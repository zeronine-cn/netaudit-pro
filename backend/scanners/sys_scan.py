import socket
import paramiko
import time
import logging

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

def brute_force_ssh(target: str, port: int, usernames: list, passwords: list):
    """
    高性能、高稳定性的 SSH 弱口令审计函数
    """
    found_creds = []
    
    # 策略配置
    MAX_RETRIES = 2       # 网络错误重试次数
    AUTH_TIMEOUT = 5      # 认证超时
    BANNER_TIMEOUT = 10   # SSH Banner 响应超时 (关键)
    DELAY_BETWEEN = 0.5   # 快速扫描步长

    for user in [u.strip() for u in usernames if u.strip()]:
        for pwd in [p.strip() for p in passwords if p.strip()]:
            retry_count = 0
            while retry_count < MAX_RETRIES:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                try:
                    # 关键优化：禁用所有不必要的认证方法
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
                    found_creds.append({
                        "user": user, 
                        "pass": pwd,
                        "is_compromised": True
                    })
                    client.close()
                    return found_creds # 发现一个有效凭据即刻返回

                except paramiko.AuthenticationException:
                    # 账号密码错误，这是正常情况，继续下一个
                    client.close()
                    break 

                except (paramiko.SSHException, socket.error) as e:
                    # 网络层错误，可能是被限速或连接过多
                    retry_count += 1
                    client.close()
                    if "banner" in str(e).lower():
                        # 如果是 Banner 超时，可能是目标响应慢，增加延迟
                        time.sleep(2)
                    else:
                        time.sleep(DELAY_BETWEEN)
                    continue

                except Exception:
                    # 未知异常，跳过
                    client.close()
                    break
            
            # 账号间的小停顿，规避简单的 IDS
            time.sleep(DELAY_BETWEEN)
            
    return found_creds