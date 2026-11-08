"""
OctoRecon SQLite Database Layer
Handles persistent scan history, indexing, retrieval, and report queries.
"""

import sqlite3
import json
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from config import DATABASE_DIR, DB_PATH

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db_sync():
    """Initializes SQLite database and tables."""
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                grade TEXT,
                total_score INTEGER DEFAULT 0,
                max_score INTEGER DEFAULT 0,
                duration REAL DEFAULT 0.0,
                status TEXT DEFAULT 'completed',
                report_json TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC)")
        conn.commit()

async def init_db():
    await asyncio.to_thread(init_db_sync)

def save_scan_sync(target: str, report_dict: Dict[str, Any], duration: float, grade: str) -> int:
    init_db_sync()
    with _get_connection() as conn:
        cursor = conn.cursor()
        now_iso = datetime.now().isoformat()
        total_score = report_dict.get("total_score", 0)
        max_score = report_dict.get("max_potential_score", 0)
        report_json = json.dumps(report_dict, default=str)
        
        cursor.execute("""
            INSERT INTO scans (target, timestamp, grade, total_score, max_score, duration, status, report_json)
            VALUES (?, ?, ?, ?, ?, ?, 'completed', ?)
        """, (target, now_iso, grade, total_score, max_score, duration, report_json))
        conn.commit()
        return cursor.lastrowid

async def save_scan(target: str, report_dict: Dict[str, Any], duration: float, grade: str) -> int:
    return await asyncio.to_thread(save_scan_sync, target, report_dict, duration, grade)

def list_scans_sync(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    init_db_sync()
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target, timestamp, grade, total_score, max_score, duration, status
            FROM scans
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

async def list_scans(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    return await asyncio.to_thread(list_scans_sync, limit, offset)

def get_scan_sync(scan_id: int) -> Optional[Dict[str, Any]]:
    init_db_sync()
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target, timestamp, grade, total_score, max_score, duration, status, report_json
            FROM scans
            WHERE id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        res = dict(row)
        try:
            res["report"] = json.loads(res["report_json"])
        except Exception:
            res["report"] = {}
        return res

async def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    return await asyncio.to_thread(get_scan_sync, scan_id)

def delete_scan_sync(scan_id: int) -> bool:
    init_db_sync()
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0

async def delete_scan(scan_id: int) -> bool:
    return await asyncio.to_thread(delete_scan_sync, scan_id)
