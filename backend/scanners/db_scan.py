
import socket
import time

def scan_mysql(target, port):
    """MySQL 协议握手探测"""
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            # MySQL 服务端连接后会主动发送一个包 (Initial Handshake Packet)
            banner = s.recv(1024)
            if len(banner) > 10:
                # 尝试提取版本号
                version = banner[5:banner.find(b'\x00', 5)].decode(errors='ignore')
                return {"status": "OPEN", "banner": f"MySQL {version}", "vulnerable": False}
    except: pass
    return {"status": "UNKNOWN"}

def scan_redis(target, port):
    """Redis 未授权访问专项探测 (等保三级核心项)"""
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            # 发送 INFO 指令测试是否需要密码
            s.send(b"*1\r\n$4\r\nINFO\r\n")
            response = s.recv(1024).decode(errors='ignore')
            
            if "redis_version" in response:
                return {
                    "status": "OPEN", 
                    "vulnerable": True, 
                    "type": "UNAUTHORIZED_ACCESS",
                    "detail": "Redis 服务器允许匿名登录并执行 INFO 操作。系统完全失控。"
                }
            elif "NOAUTH" in response:
                return {"status": "OPEN", "vulnerable": False, "detail": "Auth Required"}
    except: pass
    return {"status": "UNKNOWN"}

def scan_postgres(target, port):
    """PostgreSQL 协议探测"""
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            # 发送特定的启动包探测
            # 8 bytes: length(8), protocol(1234.5679) -> SSLRequest
            s.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            response = s.recv(1)
            if response in [b'S', b'N']:
                return {"status": "OPEN", "banner": "PostgreSQL Service", "vulnerable": False}
    except: pass
    return {"status": "UNKNOWN"}

def scan_mongodb(target, port):
    """MongoDB 协议探测"""
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            # MongoDB IsMaster 命令
            msg = b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00"
            s.send(msg)
            response = s.recv(1024)
            if len(response) > 10:
                return {"status": "OPEN", "banner": "MongoDB Service", "vulnerable": False}
    except: pass
    return {"status": "UNKNOWN"}
