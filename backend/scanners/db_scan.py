
import socket
import time

def scan_mysql(target, port):
    """MySQL 协议握手探测与版本提取"""
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            # 接收 MySQL Initial Handshake Packet
            banner_data = s.recv(1024)
            if len(banner_data) > 10:
                # 协议版本 (1 byte) + 服务版本 (null-terminated string)
                version = banner_data[1:banner_data.find(b'\x00', 1)].decode(errors='ignore')
                return {
                    "status": "OPEN", 
                    "banner": f"MySQL {version}", 
                    "vulnerable": False, # 仅指未授权访问
                    "detail": "Service responding with version banner."
                }
    except: pass
    return {"status": "UNKNOWN"}

def scan_redis(target, port):
    """Redis 未授权访问专项探测"""
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            s.send(b"*1\r\n$4\r\nINFO\r\n")
            response = s.recv(1024).decode(errors='ignore')
            if "redis_version" in response:
                return {
                    "status": "OPEN", 
                    "vulnerable": True, 
                    "type": "UNAUTHORIZED_ACCESS",
                    "detail": "Anonymous INFO command successful."
                }
            elif "NOAUTH" in response:
                return {"status": "OPEN", "vulnerable": False, "detail": "Auth Required"}
    except: pass
    return {"status": "UNKNOWN"}

def scan_postgres(target, port):
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            s.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            response = s.recv(1)
            if response in [b'S', b'N']:
                return {"status": "OPEN", "banner": "PostgreSQL Service", "vulnerable": False}
    except: pass
    return {"status": "UNKNOWN"}

def scan_mongodb(target, port):
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            msg = b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00"
            s.send(msg)
            if len(s.recv(1024)) > 10:
                return {"status": "OPEN", "banner": "MongoDB Service", "vulnerable": False}
    except: pass
    return {"status": "UNKNOWN"}
