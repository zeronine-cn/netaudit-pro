
import requests
import ssl
import socket
import re
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def verify_vhost(target: str, port: int, vhost: str):
    """
    验证域名是否真的是该 IP 承载的有效虚拟主机
    通过 SNI 握手检查返回的证书是否包含该域名
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=vhost) as ssock:
                cert_bin = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                # 获取证书中所有的 SANs
                try:
                    ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = ext.value.get_values_for_type(x509.GeneralName)
                    # 检查域名是否匹配 (支持通配符)
                    for san in sans:
                        pattern = san.replace('.', r'\.').replace('*', r'.*')
                        if re.fullmatch(pattern, vhost, re.IGNORECASE):
                            return True
                except:
                    # 如果没有 SAN，检查 CN
                    cn = str(cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value)
                    if cn.lower() == vhost.lower():
                        return True
        return False
    except:
        # 如果是 HTTP (非加密)，尝试通过 Host 头请求判断
        try:
            r = requests.get(f"http://{target}:{port}", headers={"Host": vhost}, timeout=2, allow_redirects=False)
            # 如果返回 404 或 421 (Misdirected Request)，通常说明 VHost 不存在
            return r.status_code not in [404, 421]
        except:
            return False

def scan_http(target: str, port: int, vhost: str = None):
    try:
        url = f"http://{target}:{port}"
        if port == 443: url = f"https://{target}"
        
        headers = {}
        if vhost: headers['Host'] = vhost
            
        response = requests.get(url, headers=headers, timeout=3, allow_redirects=False, verify=False)
        server_banner = response.headers.get('Server', 'Unknown')
        return {
            "port": port,
            "status": "OPEN",
            "banner": server_banner,
            "headers": dict(response.headers),
            "vhost_matched": vhost if vhost else target
        }
    except Exception as e:
        return {"port": port, "status": "CLOSED", "error": str(e)}

def check_tls_vulnerability(target: str, port: int, vhost: str = None):
    results = {
        "weak_protocols": [],
        "cert_info": None,
        "vulnerabilities": []
    }
    
    # 1. 检测老旧协议
    for version_name, version_const in [("TLSv1.0", ssl.PROTOCOL_TLSv1), ("TLSv1.1", ssl.PROTOCOL_TLSv1_1)]:
        try:
            context = ssl.SSLContext(version_const)
            with socket.create_connection((target, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=vhost if vhost else target) as ssock:
                    results["weak_protocols"].append(version_name)
        except: pass

    # 2. 证书分析
    try:
        cert_pem = ssl.get_server_certificate((target, port))
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        
        now = datetime.utcnow()
        is_expired = now > cert.not_valid_after
        pub_key = cert.public_key()
        key_size = getattr(pub_key, 'key_size', 2048)
        
        results["cert_info"] = {
            "subject": cert.subject.rfc4514_string(),
            "expiry": cert.not_valid_after.strftime("%Y-%m-%d"),
            "key_size": key_size,
            "is_expired": is_expired
        }
        
        if is_expired: results["vulnerabilities"].append("CERT_EXPIRED")
        if key_size < 2048: results["vulnerabilities"].append("WEAK_KEY_SIZE")
    except: pass

    return results
