
import socket
import struct
import re
import pymysql
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_socket(target, port, timeout=3):
    try:
        s = socket.create_connection((target, port), timeout=timeout)
        return s
    except:
        return None

def brute_force_mysql(target: str, port: int, usernames: list, passwords: list, callback=None):
    """
    MySQL 弱口令并发爆破逻辑
    """
    def attempt_login(user, pwd):
        conn = None
        try:
            # 优化：增加连接参数配置，提高成功率
            conn = pymysql.connect(
                host=target,
                port=port,
                user=user,
                password=pwd,
                database='mysql',    # 关键优化：尝试连接系统库，确保获取的是高权限账号
                connect_timeout=5,   # 调整：5秒超时足够，太长会拖慢整体进度
                read_timeout=5,
                charset='utf8mb4'
            )
            return {"user": user, "pass": pwd, "is_compromised": True}
        except pymysql.err.OperationalError as e:
            # 错误码 1045: Access denied (密码错误)，这是正常失败
            if e.args[0] == 1045:
                return None
            # 错误码 1040: Too many connections (并发过高)，此时应该稍作等待
            elif e.args[0] == 1040:
                time.sleep(1)
                # print(f"[MySQL] 警告: 连接数过多 (Too many connections)，请检查并发设置。")
                return None
            # 错误码 1130: Host not allowed to connect (IP被拒绝)，说明账号存在但禁止远程
            elif e.args[0] == 1130:
                # print(f"[MySQL] 失败: 目标主机配置了访问控制，禁止当前 IP 连接 (Error 1130)。")
                return None
            else:
                # print(f"[MySQL] 连接异常 ({target}:{port} - {user}): {e}")
                return None
        except Exception as e:
            # 打印其他未知错误便于调试
            # print(f"[MySQL] 未知错误: {e}")
            return None
        finally:
            try:
                if conn: conn.close()
            except: pass

    credentials_to_test = [(u, p) for u in usernames for p in passwords]
    
    # 记录总数便于计算进度
    total_creds = len(credentials_to_test)
    tested_count = 0
    
    # 调整：并发数降低至 5，MySQL 容器对并发连接非常敏感
    # 警告：如果您在 Docker 内扫描 127.0.0.1，请确保使用的是容器 IP 或 host.docker.internal，否则扫到的是扫描器容器自己
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_cred = {
            executor.submit(attempt_login, u, p): (u, p) 
            for u, p in credentials_to_test
        }
        
        try:
            for future in as_completed(future_to_cred):
                tested_count += 1
                # 每 5 个尝试汇报一次进度，避免日志刷屏太快
                if callback and tested_count % 5 == 0:
                     callback(f"[*] MySQL Brute: Checked {tested_count}/{total_creds} credentials...")
                
                result = future.result()
                if result:
                    executor.shutdown(wait=False, cancel_futures=True)
                    return [result]
        except Exception:
            pass

    return []

def scan_mysql(target, port):
    """
    MySQL 审计逻辑：
    解析 Initial Handshake Packet 获取精确版本号
    """
    s = get_socket(target, port)
    if not s: return {"status": "CLOSED"}
    
    try:
        packet = s.recv(1024)
        if not packet: return {"status": "UNKNOWN"}
        
        # MySQL Handshake / Error Packet Structure:
        # 0-2: Payload Length
        # 3  : Sequence ID
        # 4  : Protocol Version (0x0a) OR Error Marker (0xff)
        # 5...: Server Version string (null terminated) OR Error Code + Message
        
        if len(packet) > 5:
            # 1. 检查是否为错误包 (如 IP 未授权访问)
            if packet[4] == 0xff:
                # 错误包结构: Header(4) + 0xff(1) + ErrorCode(2) + Message(...)
                # 尝试提取错误信息作为 Banner，虽然不是版本号，但比 Unknown 好
                err_msg = packet[7:].decode(errors='ignore').strip()
                return {
                    "status": "OPEN",
                    "banner": f"MySQL (Blocked: {err_msg[:20]}...)",
                    "vulnerable": False,
                    "detail": f"服务端拒绝连接: {err_msg}"
                }

            # 2. 尝试提取正常版本号
            end_idx = packet.find(b'\x00', 5)
            if end_idx != -1:
                version = packet[5:end_idx].decode(errors='ignore').strip()
                # 放宽检查：只要非空即可，移除 isalnum 限制以兼容特殊版本字符串
                if len(version) > 0:
                    return {
                        "status": "OPEN", 
                        "banner": f"MySQL {version}", 
                        "vulnerable": False,
                        "detail": "服务可连接，握手正常。"
                    }
    except Exception:
        pass
    finally:
        s.close()
    
    return {"status": "OPEN", "banner": "MySQL Service", "vulnerable": False}

def scan_redis(target, port):
    """
    Redis 审计逻辑：
    1. 发送 INFO 探测未授权 (身份鉴别)
    2. 如果未授权，探测 CONFIG 指令 (入侵防范)
    """
    s = get_socket(target, port)
    if not s: return {"status": "CLOSED"}

    try:
        s.send(b"*1\r\n$4\r\nINFO\r\n")
        response = s.recv(4096).decode(errors='ignore')
        
        if "redis_version" in response:
            is_risky_config = False
            try:
                s.send(b"*2\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$1\r\n*\r\n")
                conf_resp = s.recv(4096).decode(errors='ignore')
                if "dbfilename" in conf_resp or "dir" in conf_resp:
                    is_risky_config = True
            except: pass

            detail_msg = "未授权访问：无需密码即可执行 INFO 命令。"
            if is_risky_config:
                detail_msg += " 且 CONFIG 命令未禁用 (极高危)。"

            return {
                "status": "OPEN", 
                "vulnerable": True, 
                "type": "REDIS_UNAUTH",
                "detail": detail_msg
            }
        elif "NOAUTH" in response or "Authentication required" in response:
            return {
                "status": "OPEN", 
                "vulnerable": False, 
                "detail": "已启用身份鉴别 (Requirepass Enabled)。"
            }
    except:
        pass
    finally:
        s.close()

    return {"status": "OPEN", "banner": "Redis Service", "vulnerable": False}

def scan_postgres(target, port):
    """
    PostgreSQL 审计逻辑：
    发送 StartupMessage，解析 AuthenticationRequest 类型
    识别 Trust (免密) 和 Cleartext (明文) 模式
    """
    s = get_socket(target, port)
    if not s: return {"status": "CLOSED"}

    try:
        # Protocol 3.0 (0x00030000), user=postgres, database=postgres
        protocol = b'\x00\x03\x00\x00'
        params = b'user\x00postgres\x00database\x00postgres\x00\x00'
        length = struct.pack('!I', 8 + len(params))
        
        s.send(length + protocol + params)
        
        resp_type = s.recv(1)
        if resp_type == b'R': # AuthenticationRequest
            s.recv(4) # length
            auth_type_bytes = s.recv(4)
            auth_type = struct.unpack('!I', auth_type_bytes)[0]
            
            # 0: Trust, 3: Cleartext, 5: MD5, 10: SASL
            if auth_type == 0:
                return {
                    "status": "OPEN", "vulnerable": True, "type": "PG_TRUST",
                    "detail": "Trust 模式：用户 'postgres' 无需密码即可登录 (高危)。",
                    "banner": "PostgreSQL (Trust Mode)"
                }
            elif auth_type == 3:
                return {
                    "status": "OPEN", "vulnerable": True, "type": "PG_CLEARTEXT",
                    "detail": "认证配置不安全：允许明文密码传输。",
                    "banner": "PostgreSQL (Cleartext)"
                }
            elif auth_type in [5, 10]:
                mode = "MD5" if auth_type == 5 else "SASL"
                return {
                    "status": "OPEN", "vulnerable": False, 
                    "detail": f"已启用安全的身份鉴别 ({mode})。",
                    "banner": f"PostgreSQL ({mode})"
                }
            
            return {"status": "OPEN", "banner": "PostgreSQL", "detail": f"AuthType: {auth_type}"}
            
        elif resp_type == b'E': # ErrorResponse (说明鉴权机制生效中，拒绝了直接连接)
            return {"status": "OPEN", "vulnerable": False, "detail": "鉴权机制正常生效。", "banner": "PostgreSQL"}

    except Exception:
        pass
    finally:
        s.close()

    return {"status": "OPEN", "banner": "PostgreSQL Service", "vulnerable": False}

def scan_mongodb(target, port):
    """
    MongoDB 审计逻辑：
    发送 BSON isMaster 指令，探测是否允许未授权执行管理命令
    """
    s = get_socket(target, port)
    if not s: return {"status": "CLOSED"}

    try:
        # OP_QUERY (2004) admin.$cmd { isMaster: 1 }
        header = b'\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00'
        flags_coll = b'\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00'
        bson_payload = b'\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
        
        s.send(header + flags_coll + bson_payload)
        response = s.recv(1024).decode(errors='ignore').lower()
        
        if "ismaster" in response and "ok" in response:
            if "unauthorized" in response or "authentication failed" in response or "requires authentication" in response:
                 return {
                    "status": "OPEN", "vulnerable": False, 
                    "detail": "已启用身份鉴别 (Authentication Enabled)。"
                }
            else:
                return {
                    "status": "OPEN", "vulnerable": True, "type": "MONGO_UNAUTH",
                    "detail": "未授权访问：无需认证即可执行 isMaster 管理指令。"
                }
    except:
        pass
    finally:
        s.close()
        
    return {"status": "OPEN", "banner": "MongoDB Service", "vulnerable": False}
