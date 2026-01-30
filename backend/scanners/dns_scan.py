
import dns.query
import dns.zone
import dns.resolver

def check_zone_transfer(domain: str, nameserver: str, port: int = 53):
    """
    检测 DNS 区域传送漏洞 (AXFR)
    支持自定义端口探测
    """
    try:
        # 尝试进行区域传送请求，显式指定端口
        # xfr 返回一个生成器
        xfr_query = dns.query.xfr(nameserver, domain, port=port, timeout=5)
        zone = dns.zone.from_xfr(xfr_query)
        
        if zone:
            # 提取发现的记录名称，证明泄露
            nodes = list(zone.nodes.keys())
            return {
                "vulnerable": True,
                "records_count": len(nodes),
                "detail": f"探测到敏感域: {domain}。成功获取到 {len(nodes)} 条解析记录。",
                "records": [str(n) for n in nodes[:10]] # 记录前10条作为证据
            }
    except Exception as e:
        return {
            "vulnerable": False,
            "detail": f"探测失败: {str(e)}"
        }
    return {"vulnerable": False, "detail": "Connection Refused or No Data"}
