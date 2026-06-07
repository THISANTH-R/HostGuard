import asyncio
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Query
from pydantic import BaseModel

from .database import get_db
from .event_bus import event_bus
from .services.system_info import get_system_info
from .services.startup_manager import check_startup_status
from .services.search_service import unified_search
from .engines.ioc_engine import load_iocs

logger = logging.getLogger(__name__)

router = APIRouter()

# --- REST Endpoints ---

@router.get("/api/events")
async def get_events(
    page: int = 1, limit: int = 50, 
    severity: Optional[str] = None, 
    source: Optional[str] = None, 
    event_id: Optional[int] = None
):
    offset = (page - 1) * limit
    where_clauses = []
    params = []
    
    if severity:
        where_clauses.append("severity = ?")
        params.append(severity)
    if source:
        where_clauses.append("source = ?")
        params.append(source)
    if event_id:
        where_clauses.append("event_id = ?")
        params.append(event_id)
        
    where_str = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    
    async with get_db() as db:
        cursor = await db.execute(f"SELECT * FROM events {where_str} ORDER BY timestamp DESC LIMIT ? OFFSET ?", (*params, limit, offset))
        rows = await cursor.fetchall()
        count_cursor = await db.execute(f"SELECT COUNT(*) FROM events {where_str}", params)
        total = (await count_cursor.fetchone())[0]
        
    return {
        "data": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "limit": limit
    }

@router.get("/api/alerts")
async def get_alerts(page: int = 1, limit: int = 50, severity: Optional[str] = None, mitre: Optional[str] = None):
    offset = (page - 1) * limit
    where_clauses = []
    params = []
    
    if severity:
        where_clauses.append("severity = ?")
        params.append(severity)
    if mitre:
        where_clauses.append("mitre = ?")
        params.append(mitre)
        
    where_str = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    
    async with get_db() as db:
        cursor = await db.execute(f"SELECT * FROM alerts {where_str} ORDER BY timestamp DESC LIMIT ? OFFSET ?", (*params, limit, offset))
        rows = await cursor.fetchall()    
        count_cursor = await db.execute(f"SELECT COUNT(*) FROM alerts {where_str}", params)
        total = (await count_cursor.fetchone())[0]
        
    return {
        "data": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "limit": limit
    }

@router.post("/api/alerts/{id}/acknowledge")
async def acknowledge_alert(id: int):
    async with get_db() as db:
        await db.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (id,))
        await db.commit()
    return {"status": "success"}

@router.get("/api/process-tree")
async def get_process_tree(pid: Optional[int] = None):
    # This would ideally integrate with engines.process_tree.py
    # For now, return flat from DB as a basic implementation
    async with get_db() as db:
        if pid:
            cursor = await db.execute("SELECT * FROM process_tree WHERE pid = ?", (pid,))
        else:
            cursor = await db.execute("SELECT * FROM process_tree")
        rows = await cursor.fetchall()
    return [dict(r) for r in rows]

@router.get("/api/network")
async def get_network():
    async with get_db() as db:
        cursor = await db.execute("SELECT * FROM network_connections ORDER BY timestamp DESC LIMIT 100")
        rows = await cursor.fetchall()
    return [dict(r) for r in rows]

@router.get("/api/firewall")
async def get_firewall(page: int = 1, limit: int = 50):
    offset = (page - 1) * limit
    async with get_db() as db:
        cursor = await db.execute("SELECT * FROM firewall_events ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset))
        rows = await cursor.fetchall()
    return [dict(r) for r in rows]

@router.get("/api/history")
async def get_history(severity: Optional[str] = None, source: Optional[str] = None, pid: Optional[int] = None):
    # Basic proxy to events
    return await get_events(limit=100, severity=severity, source=source)

@router.get("/api/search")
async def search_api(q: str):
    results = await unified_search(q)
    return {"results": results}

@router.get("/api/profile")
async def get_profile():
    return get_system_info()

@router.get("/api/startup/status")
async def get_startup_status():
    return check_startup_status()

@router.get("/api/resource")
async def get_resource():
    async with get_db() as db:
        cursor = await db.execute("SELECT * FROM resource_usage ORDER BY timestamp DESC LIMIT 60")
        rows = await cursor.fetchall()
    return [dict(r) for r in rows]

@router.get("/api/stats")
async def get_stats():
    stats = {
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "action_counts": {"blocked": 0, "killed": 0, "suspended": 0, "ignored": 0}
    }
    try:
        async with get_db() as db:
            cursor = await db.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
            for row in await cursor.fetchall():
                sev = row[0].lower() if row[0] else "low"
                if sev in stats["severity_counts"]:
                    stats["severity_counts"][sev] = row[1]
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
    return stats

@router.post("/api/shutdown")
async def shutdown():
    # Will trigger graceful shutdown in main
    import os
    import signal
    os.kill(os.getpid(), signal.SIGTERM)
    return {"status": "shutting down"}

class IOCPayload(BaseModel):
    hashes: Optional[List[Dict]] = None
    ips: Optional[List[Dict]] = None
    domains: Optional[List[Dict]] = None
    urls: Optional[List[Dict]] = None

@router.post("/api/ioc/import")
async def import_iocs(payload: IOCPayload):
    load_iocs(payload.dict())
    return {"status": "success", "message": "IOCs loaded successfully"}

# --- WebSocket Endpoints ---

async def generic_ws_handler(websocket: WebSocket, channel: str):
    await websocket.accept()
    queue = asyncio.Queue()

    async def callback(data):
        await queue.put(data)

    await event_bus.subscribe(channel, callback)
    try:
        while True:
            # Check if client disconnected by waiting for any message (we don't expect any)
            # but we also need to send data
            data = await queue.get()
            await websocket.send_json(data)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error on channel {channel}: {e}")
    finally:
        await event_bus.unsubscribe(channel, callback)

@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await generic_ws_handler(websocket, "events")

@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await generic_ws_handler(websocket, "alerts")

@router.websocket("/ws/network")
async def ws_network(websocket: WebSocket):
    await generic_ws_handler(websocket, "network")

@router.websocket("/ws/firewall")
async def ws_firewall(websocket: WebSocket):
    await generic_ws_handler(websocket, "firewall")

@router.websocket("/ws/resource")
async def ws_resource(websocket: WebSocket):
    await generic_ws_handler(websocket, "resource")
