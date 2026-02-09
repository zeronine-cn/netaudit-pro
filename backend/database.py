
import sqlite3
import json
import os
from typing import List, Dict, Any, Optional

# 确定数据库路径：位于项目根目录下的 data 文件夹内
# 在 Docker 中通常映射为 /app/data
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "netaudit.db")

def init_db():
    """初始化数据库和表结构"""
    if not os.path.exists(DATA_DIR):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except OSError:
            # 如果权限不足（如在某些只读容器中），可能会报错，打印日志
            print(f"Warning: Cannot create data directory at {DATA_DIR}")
            return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 创建报告表
    # id: 自增主键
    # target: 目标IP/域名
    # timestamp: 扫描时间
    # score: 分数
    # report_json: 完整报告的 JSON 字符串
    c.execute('''CREATE TABLE IF NOT EXISTS reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target TEXT,
                  timestamp TEXT,
                  score INTEGER,
                  report_json TEXT)''')
    conn.commit()
    conn.close()

def save_report(report: Dict[str, Any]) -> int:
    """保存扫描报告到数据库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 将字典转为 JSON 字符串存储
    report_json = json.dumps(report, ensure_ascii=False)
    
    c.execute("INSERT INTO reports (target, timestamp, score, report_json) VALUES (?, ?, ?, ?)",
              (report.get('target'),
               report.get('timestamp'),
               report.get('score', 0),
               report_json))
    
    new_id = c.lastrowid
    conn.commit()
    conn.close()
    return new_id

def get_all_reports() -> List[Dict[str, Any]]:
    """获取所有历史报告（按 ID 倒序）"""
    if not os.path.exists(DB_PATH):
        return []

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, report_json FROM reports ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        try:
            # 反序列化 JSON
            report_data = json.loads(row['report_json'])
            # 确保返回的 ID 与数据库 ID 一致
            report_data['id'] = row['id']
            results.append(report_data)
        except:
            continue
    return results

def get_report_by_id(report_id: int) -> Optional[Dict[str, Any]]:
    """根据 ID 获取单个报告"""
    if not os.path.exists(DB_PATH):
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, report_json FROM reports WHERE id=?", (report_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        try:
            report_data = json.loads(row['report_json'])
            report_data['id'] = row['id']
            return report_data
        except:
            return None
    return None

def delete_report(report_id: int):
    """删除指定 ID 的报告"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM reports WHERE id=?", (report_id,))
    conn.commit()
    conn.close()

def purge_reports():
    """清空所有报告"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM reports")
    conn.commit()
    conn.close()
