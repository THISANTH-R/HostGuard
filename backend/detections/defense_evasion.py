import asyncio
import logging
from ..database import get_database, insert_alert
from ..event_bus import event_bus
from .mitre_mapping import get_technique

logger = logging.getLogger(__name__)

async def process_event(event):
    event_id = event.get("event_id")
    cmd = event.get("commandline", "").lower()
    image = event.get("image", "").lower()
    
    if event_id == 1102:
        await generate_alert(event, "Security Audit Log Cleared", "critical", "T1070.001", 95, "The Windows Security audit log was cleared.")
        
    elif event_id == 4688:
        if "wevtutil" in image and "cl" in cmd and "security" in cmd:
            await generate_alert(event, "Security Audit Log Cleared via wevtutil", "critical", "T1070.001", 95, f"Command: {cmd}")
            
        elif "set-mppreference" in cmd and ("disable" in cmd or "exclusionpath" in cmd):
            await generate_alert(event, "Windows Defender Tampering", "high", "T1562.001", 80, f"Command: {cmd}")
            
        elif "sc" in image and "stop" in cmd and "windefend" in cmd:
            await generate_alert(event, "Windows Defender Service Stopped", "critical", "T1562.001", 90, f"Command: {cmd}")

async def generate_alert(event, title, severity, mitre_id, score, details):
    tech = get_technique(mitre_id)
    alert = {
        "title": title,
        "severity": severity,
        "timestamp": event.get("timestamp"),
        "mitre": mitre_id,
        "tactic": tech.get("tactic", "Defense Evasion"),
        "score": score,
        "source": "defense_evasion",
        "details": details
    }
    await insert_alert(alert)

async def start_defense_evasion_detector():
    logger.info("Starting Defense Evasion Detector...")
    queue = asyncio.Queue()
    
    async def callback(data):
        await queue.put(data)
        
    await event_bus.subscribe("events", callback)
    
    try:
        while True:
            event = await queue.get()
            await process_event(event)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Defense Evasion detector error: {e}")
    finally:
        await event_bus.unsubscribe("events", callback)
