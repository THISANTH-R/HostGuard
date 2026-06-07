import asyncio
import logging
from ..database import insert_alert
from ..event_bus import event_bus
from .mitre_mapping import get_technique

logger = logging.getLogger(__name__)

# Known suspicious ports
SUSPICIOUS_PORTS = {4444, 5555, 8888, 1337, 31337, 666, 6667}

async def process_event(event):
    remote_port = event.get("remote_port")
    remote_ip = event.get("remote_ip")
    process = event.get("process", "").lower()
    
    if remote_port in SUSPICIOUS_PORTS:
        await generate_alert(event, f"Connection to Suspicious Port ({remote_port})", "high", "T1071", 65, f"Process {process} connected to {remote_ip}:{remote_port}")

    if process in ["powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe"]:
        # Only alert if connecting to public IP
        if remote_ip and not remote_ip.startswith(("10.", "192.168.", "172.", "127.", "::1", "fe80:")):
            await generate_alert(event, f"Suspicious Process Making External Connection", "high", "T1071.001", 70, f"Process {process} connected to {remote_ip}:{remote_port}")

async def generate_alert(event, title, severity, mitre_id, score, details):
    tech = get_technique(mitre_id)
    alert = {
        "title": title,
        "severity": severity,
        "timestamp": event.get("timestamp"),
        "mitre": mitre_id,
        "tactic": tech.get("tactic", "Command and Control"),
        "score": score,
        "source": "network_anomalies",
        "details": details
    }
    await insert_alert(alert)

async def start_network_anomaly_detector():
    logger.info("Starting Network Anomaly Detector...")
    queue = asyncio.Queue()
    
    async def callback(data):
        await queue.put(data)
        
    await event_bus.subscribe("network", callback)
    
    try:
        while True:
            event = await queue.get()
            await process_event(event)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Network anomaly detector error: {e}")
    finally:
        await event_bus.unsubscribe("network", callback)
