
import socket
import time
import struct

def scan_mysql(target, port):
    """MySQL 协议握手探测与版本提取 (增强鲁棒性)"""
    try:
        with socket.create_connection((target, port), timeout=4) as s:
            # 接收 MySQL Initial Handshake Packet
            # 包结构: [3 bytes length] [1 byte sequence] [1 byte protocol version] [string server version] ...
            packet = s.recv(1024)
            if len(packet) > 5:
                # 解析包长度
                # packet_len = struct.unpack('<I', packet[0:3] + b'\x00')[0]
                
                # 获取协议版本
                proto_ver = packet[4]
                
                # 提取版本字符串 (从第5字节开始，直到遇到 0x00)
                # find(sub, start)
                null_byte_index = packet.find(b'\x00', 5)
                if null_byte_index != -1:
                    version_str = packet[5:null_byte_index].decode(errors='ignore')
                    return {
                        "status": "OPEN", 
                        "banner": f"MySQL {version_str}", 
                        "vulnerable": False, 
                        "detail": f"Version: {version_str}"
                    }
                else:
                    # 没找到 null byte，可能包截断了，但也说明端口是通的且响应了数据
                    return {"status": "OPEN", "banner": "MySQL (Unknown Version)", "vulnerable": False}
    except Exception as e:
        pass
    return {"status": "UNKNOWN"}

def scan_redis(target, port):
    """Redis 未授权访问专项探测"""
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            s.send(b"*1\r\n$4\r\nINFO\r\n")
            response = s.recv(4096).decode(errors='ignore')
            if "redis_version" in response:
                return {
                    "status": "OPEN", 
                    "vulnerable": True, 
                    "type": "UNAUTHORIZED_ACCESS",
                    "detail": "Redis Unauthorized Access Detected (INFO command)"
                }
            elif "NOAUTH" in response:
                return {"status": "OPEN", "vulnerable": False, "detail": "Redis Auth Required"}
    except: pass
    return {"status": "UNKNOWN"}

def scan_postgres(target, port):
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            # SSLRequest packet
            s.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            response = s.recv(1)
            if response in [b'S', b'N']:
                return {"status": "OPEN", "banner": "PostgreSQL", "vulnerable": False}
    except: pass
    return {"status": "UNKNOWN"}

def scan_mongodb(target, port):
    try:
        with socket.create_connection((target, port), timeout=3) as s:
            # BuildInfo command
            msg = b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00"
            s.send(msg)
            if len(s.recv(1024)) > 10:
                return {"status": "OPEN", "banner": "MongoDB", "vulnerable": False}
    except: pass
    return {"status": "UNKNOWN"}
