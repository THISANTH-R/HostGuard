import asyncio
import logging
import re
from ..database import insert_alert
from ..event_bus import event_bus
from .mitre_mapping import get_technique

logger = logging.getLogger(__name__)

async def process_event(event):
    if event.get("event_id") == 4688:
        cmd = event.get("commandline", "").lower()
        image = event.get("image", "").lower()
        
        # LSASS Dump indicators
        if "procdump" in image and "lsass" in cmd:
            await generate_alert(event, "LSASS Memory Dump Attempt (ProcDump)", "critical", "T1003.001", 90)
            
        elif "comsvcs.dll" in cmd and "minidump" in cmd:
            await generate_alert(event, "LSASS Memory Dump Attempt (comsvcs.dll)", "critical", "T1003.001", 95)
            
        # SAM/NTDS Dumping
        elif "reg.exe" in image and "save" in cmd and "hklm\\sam" in cmd:
            await generate_alert(event, "SAM Registry Hive Dump Attempt", "critical", "T1003.002", 90)
            
        elif "ntdsutil" in image and "ac i ntds" in cmd:
            await generate_alert(event, "NTDS.dit Extraction Attempt", "critical", "T1003.003", 95)

async def generate_alert(event, title, severity, mitre_id, score):
    tech = get_technique(mitre_id)
    alert = {
        "title": title,
        "severity": severity,
        "timestamp": event.get("timestamp"),
        "mitre": mitre_id,
        "tactic": tech.get("tactic", "Credential Access"),
        "score": score,
        "source": "credential_access",
        "details": f"Process {event.get('image')} executed suspicious command: {event.get('commandline')}"
    }
    await insert_alert(alert)

async def start_credential_detector():
    logger.info("Starting Credential Access Detector...")
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
        logger.error(f"Credential detector error: {e}")
    finally:
        await event_bus.unsubscribe("events", callback)
