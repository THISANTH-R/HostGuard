import logging
from ..database import get_db

logger = logging.getLogger(__name__)

async def unified_search(query: str):
    """
    Search across events, alerts, network, and firewall tables.
    Supports prefixes: event:4688, severity:critical, pid:1234, ip:1.2.3.4
    """
    if not query:
        return []
        
    results = []
    
    try:
        async with get_db() as db:
            query = query.lower().strip()
            
            if query.startswith("event:"):
                val = query.split(":")[1]
                rows = await db.execute("SELECT * FROM events WHERE event_id = ? ORDER BY timestamp DESC LIMIT 50", (val,))
                for r in await rows.fetchall():
                    d = dict(r)
                    d["_type"] = "event"
                    results.append(d)
                    
            elif query.startswith("severity:"):
                val = query.split(":")[1]
                rows = await db.execute("SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT 50", (val,))
                for r in await rows.fetchall():
                    d = dict(r)
                    d["_type"] = "alert"
                    results.append(d)
                    
            elif query.startswith("pid:"):
                val = query.split(":")[1]
                rows = await db.execute("SELECT * FROM processes WHERE pid = ? ORDER BY timestamp DESC LIMIT 50", (val,))
                for r in await rows.fetchall():
                    d = dict(r)
                    d["_type"] = "process"
                    results.append(d)
                    
            elif query.startswith("ip:"):
                val = query.split(":")[1]
                val_like = f"%{val}%"
                
                # Network
                rows = await db.execute("""
                    SELECT * FROM network_connections 
                    WHERE local_ip LIKE ? OR remote_ip LIKE ? ORDER BY timestamp DESC LIMIT 25
                """, (val_like, val_like))
                for r in await rows.fetchall():
                    d = dict(r)
                    d["_type"] = "network"
                    results.append(d)
                    
                # Firewall
                rows = await db.execute("""
                    SELECT * FROM firewall_events 
                    WHERE src_ip LIKE ? OR dst_ip LIKE ? ORDER BY timestamp DESC LIMIT 25
                """, (val_like, val_like))
                for r in await rows.fetchall():
                    d = dict(r)
                    d["_type"] = "firewall"
                    results.append(d)
                    
            else:
                # General text search
                val_like = f"%{query}%"
                
                # Search events commandline/image
                rows = await db.execute("""
                    SELECT * FROM events 
                    WHERE commandline LIKE ? OR image LIKE ? ORDER BY timestamp DESC LIMIT 20
                """, (val_like, val_like))
                for r in await rows.fetchall():
                    d = dict(r)
                    d["_type"] = "event"
                    results.append(d)
                    
                # Search alerts title/details
                rows = await db.execute("""
                    SELECT * FROM alerts 
                    WHERE title LIKE ? OR details LIKE ? ORDER BY timestamp DESC LIMIT 20
                """, (val_like, val_like))
                for r in await rows.fetchall():
                    d = dict(r)
                    d["_type"] = "alert"
                    results.append(d)

    except Exception as e:
        logger.error(f"Search error: {e}")
        
    return results
