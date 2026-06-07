import asyncio
import logging
from ..database import get_database, insert_alert
from ..event_bus import event_bus
from .mitre_mapping import get_technique

logger = logging.getLogger(__name__)

async def process_event(event):
    event_id = event.get("event_id")
    
    if event_id == 4720:
        await generate_alert(event, "New User Account Created", "high", "T1136.001", 60, "A user account was created.")
    elif event_id == 4728:
        await generate_alert(event, "User Added to Privileged Group", "critical", "T1078.002", 85, "A user was added to a privileged security-enabled global group.")
    elif event_id == 4672:
        # Filter noise, focus on non-SYSTEM special privileges
        username = event.get("username", "").lower()
        if username and not username.endswith("$") and username != "system":
            await generate_alert(event, "Special Privileges Assigned to New Logon", "medium", "T1078", 50, f"Special privileges assigned to user {username}.")

async def generate_alert(event, title, severity, mitre_id, score, details):
    tech = get_technique(mitre_id)
    alert = {
        "title": title,
        "severity": severity,
        "timestamp": event.get("timestamp"),
        "mitre": mitre_id,
        "tactic": tech.get("tactic", "Privilege Escalation"),
        "score": score,
        "source": "privilege_escalation",
        "details": details
    }
    await insert_alert(alert)

async def start_privesc_detector():
    logger.info("Starting Privilege Escalation Detector...")
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
        logger.error(f"PrivEsc detector error: {e}")
    finally:
        await event_bus.unsubscribe("events", callback)
