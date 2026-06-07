import asyncio
import logging
from ..database import get_database, insert_alert
from ..event_bus import event_bus
from .mitre_mapping import get_technique

logger = logging.getLogger(__name__)

# Basic correlation state
ransomware_state = {
    "high_cpu": False,
    "high_disk": False,
    "shadow_deleted": False,
    "recovery_disabled": False,
    "score": 0
}

async def process_event(event):
    cmd = event.get("commandline", "").lower()
    image = event.get("image", "").lower()
    source = event.get("source")
    
    # 1. Resource spikes
    if source == "resource":
        cpu = event.get("cpu_percent", 0)
        disk_write = event.get("disk_write_bytes", 0)
        
        if cpu > 85:
            ransomware_state["high_cpu"] = True
            ransomware_state["score"] += 10
        else:
            ransomware_state["high_cpu"] = False
            
        if disk_write > 50_000_000: # 50MB/s
            ransomware_state["high_disk"] = True
            ransomware_state["score"] += 20
        else:
            ransomware_state["high_disk"] = False
            
    # 2. Command analysis
    elif event.get("event_id") == 4688:
        if "vssadmin" in image and "delete" in cmd and "shadows" in cmd:
            ransomware_state["shadow_deleted"] = True
            ransomware_state["score"] += 60
            await generate_alert(event, "Shadow Copies Deleted", "critical", "T1490", 85, f"Command: {cmd}")
            
        elif "wmic" in image and "shadowcopy" in cmd and "delete" in cmd:
            ransomware_state["shadow_deleted"] = True
            ransomware_state["score"] += 60
            await generate_alert(event, "Shadow Copies Deleted (WMIC)", "critical", "T1490", 85, f"Command: {cmd}")
            
        elif "bcdedit" in image and "recoveryenabled" in cmd and "no" in cmd:
            ransomware_state["recovery_disabled"] = True
            ransomware_state["score"] += 50
            await generate_alert(event, "System Recovery Disabled", "critical", "T1490", 80, f"Command: {cmd}")
            
    # Correlation Check
    if ransomware_state["score"] > 80:
        await generate_alert(event, "Possible Ransomware Activity Detected", "critical", "T1486", ransomware_state["score"], "Correlated ransomware indicators observed.")
        ransomware_state["score"] = 0 # Reset after alert

async def generate_alert(event, title, severity, mitre_id, score, details):
    tech = get_technique(mitre_id)
    alert = {
        "title": title,
        "severity": severity,
        "timestamp": event.get("timestamp"),
        "mitre": mitre_id,
        "tactic": tech.get("tactic", "Impact"),
        "score": score,
        "source": "ransomware_correlation",
        "details": details
    }
    await insert_alert(alert)

async def start_ransomware_detector():
    logger.info("Starting Ransomware Correlation Detector...")
    queue = asyncio.Queue()
    
    async def callback(data):
        await queue.put(data)
        
    await event_bus.subscribe("events", callback)
    await event_bus.subscribe("resource", callback)
    
    try:
        while True:
            event = await queue.get()
            await process_event(event)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Ransomware detector error: {e}")
    finally:
        await event_bus.unsubscribe("events", callback)
        await event_bus.unsubscribe("resource", callback)
