"""
Persistence Threat Detection Module.
Detects common persistence mechanisms such as scheduled tasks, service installs, registry run key additions, and startup items.
"""

import asyncio
import logging
import re
from ..database import insert_alert
from ..event_bus import event_bus
from .mitre_mapping import get_technique

logger = logging.getLogger(__name__)

# Monitored persistence events:
# Event ID 4697 - New Service Created
# Event ID 7045 - New Service Installed
# Event ID 4698 - Scheduled Task Created
async def analyze_persistence_event(event: dict):
    event_id = event.get("event_id")
    cmd = event.get("commandline", "").lower()
    image = event.get("image", "").lower()
    
    # 1. Windows Service Installations
    if event_id in [4697, 7045]:
        service_name = event.get("raw_data", {}).get("service_name", "Unknown Service")
        tech = get_technique("T1543.003")
        alert = {
            "title": f"New Windows Service Installed ({service_name})",
            "severity": "high",
            "timestamp": event.get("timestamp"),
            "mitre": "T1543.003",
            "tactic": tech.get("tactic", "Persistence"),
            "score": 70,
            "source": "persistence_detection",
            "details": f"A new service '{service_name}' was installed on the system. Service file path: {event.get('image') or 'unknown'}"
        }
        await insert_alert(alert)
        await event_bus.publish("alerts", alert)
        logger.info(f"Persistence Alert: Service Installed '{service_name}'")
        
    # 2. Command Line Detections (schtasks or registry modifications)
    elif event_id == 4688 or (event.get("source") == "sysmon" and event_id == 1):
        filename = image.split("\\")[-1]
        
        # Scheduled Task Creation commands
        if filename == "schtasks.exe" and "create" in cmd:
            task_name = "unknown"
            match = re.search(r"/tn\s+([^\s]+)", cmd)
            if match:
                task_name = match.group(1).strip('"\'')
                
            tech = get_technique("T1053.005")
            alert = {
                "title": f"Scheduled Task Created via Command Line ({task_name})",
                "severity": "medium",
                "timestamp": event.get("timestamp"),
                "mitre": "T1053.005",
                "tactic": tech.get("tactic", "Persistence"),
                "score": 50,
                "source": "persistence_detection",
                "details": f"Process {image} executed a scheduled task creation command: {event.get('commandline')}"
            }
            await insert_alert(alert)
            await event_bus.publish("alerts", alert)
            logger.info(f"Persistence Alert: Scheduled Task Command '{task_name}'")
            
        # Registry Run Key Modification commands
        elif filename == "reg.exe" and "add" in cmd and "run" in cmd:
            tech = get_technique("T1547.001")
            alert = {
                "title": "Registry Startup Run Key Modified (Reg.exe)",
                "severity": "high",
                "timestamp": event.get("timestamp"),
                "mitre": "T1547.001",
                "tactic": tech.get("tactic", "Persistence"),
                "score": 75,
                "source": "persistence_detection",
                "details": f"Process {image} executed registry run modification command: {event.get('commandline')}"
            }
            await insert_alert(alert)
            await event_bus.publish("alerts", alert)
            logger.info("Persistence Alert: Registry Run modification detected.")
            
        # Startup Folder Modifications
        elif "appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup" in cmd or "programdata\\microsoft\\windows\\start menu\\programs\\startup" in cmd:
            tech = get_technique("T1547.001")
            alert = {
                "title": "File Copied to Startup Folder",
                "severity": "high",
                "timestamp": event.get("timestamp"),
                "mitre": "T1547.001",
                "tactic": tech.get("tactic", "Persistence"),
                "score": 80,
                "source": "persistence_detection",
                "details": f"Process {image} modified the startup folder via command: {event.get('commandline')}"
            }
            await insert_alert(alert)
            await event_bus.publish("alerts", alert)
            logger.info("Persistence Alert: Startup folder modification detected.")

async def start_persistence_detector():
    """Starts the persistence detection module."""
    logger.info("Starting Persistence Mechanism Detector...")
    queue = asyncio.Queue()
    
    async def callback(data):
        await queue.put(data)
        
    await event_bus.subscribe("events", callback)
    
    try:
        while True:
            event = await queue.get()
            await analyze_persistence_event(event)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Error in persistence detector: {e}")
    finally:
        await event_bus.unsubscribe("events", callback)
