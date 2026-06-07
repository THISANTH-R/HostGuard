import asyncio
import logging
from ..database import get_database, insert_alert
from ..event_bus import event_bus
import hashlib

logger = logging.getLogger(__name__)

ioc_cache = {
    "hashes": set(),
    "ips": set(),
    "domains": set(),
    "urls": set()
}

def load_iocs(payload):
    try:
        if payload.get("hashes"):
            for h in payload["hashes"]:
                ioc_cache["hashes"].add(h["value"].lower())
        if payload.get("ips"):
            for i in payload["ips"]:
                ioc_cache["ips"].add(i["value"])
        if payload.get("domains"):
            for d in payload["domains"]:
                ioc_cache["domains"].add(d["value"].lower())
        if payload.get("urls"):
            for u in payload["urls"]:
                ioc_cache["urls"].add(u["value"])
        logger.info(f"Loaded IOCs into cache.")
    except Exception as e:
        logger.error(f"Error loading IOCs: {e}")

async def check_event_iocs(event):
    # Network check
    if event.get("source") == "network":
        remote_ip = event.get("remote_ip")
        if remote_ip and remote_ip in ioc_cache["ips"]:
            await trigger_ioc_alert(event, "IP", remote_ip)
            
    # Add hash checks for processes when hashes are available in the event

async def trigger_ioc_alert(event, ioc_type, ioc_value):
    alert = {
        "title": "Known Malicious IOC Detected",
        "severity": "critical",
        "timestamp": event.get("timestamp"),
        "mitre": "",
        "tactic": "",
        "score": 100,
        "source": "ioc_engine",
        "details": f"Matched IOC {ioc_type}: {ioc_value} in event {event.get('event_id')}"
    }
    await insert_alert(alert)

async def start_ioc_engine():
    logger.info("Starting IOC Engine...")
    queue = asyncio.Queue()
    
    async def callback(data):
        await queue.put(data)
        
    await event_bus.subscribe("network", callback)
    await event_bus.subscribe("events", callback)
    
    try:
        while True:
            event = await queue.get()
            await check_event_iocs(event)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"IOC Engine error: {e}")
    finally:
        await event_bus.unsubscribe("network", callback)
        await event_bus.unsubscribe("events", callback)
