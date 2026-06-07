"""
LOLBin Abuse Detection Module.
Monitors process execution events for suspicious patterns involving dual-use Windows binaries (LOLBins).
"""

import asyncio
import logging
from ..database import insert_alert
from ..event_bus import event_bus
from .mitre_mapping import get_technique

logger = logging.getLogger(__name__)

# Dictionary of LOLBin processes and their monitored command-line patterns
LOLBIN_RULES = {
    "certutil.exe": [
        (r"-urlcache", "Certutil URL Cache Download Attempt", "medium", "T1105"),
        (r"-decode", "Certutil Base64 Decoding Attempt", "medium", "T1140"),
        (r"-encode", "Certutil Base64 Encoding Attempt", "low", "T1027")
    ],
    "mshta.exe": [
        (r"http[s]?://", "Mshta Remote HTML Application Execution", "high", "T1218.005"),
        (r"\.hta", "Mshta Local HTA File Execution", "medium", "T1218.005"),
        (r"javascript:", "Mshta Inline JavaScript Execution", "high", "T1218.005")
    ],
    "rundll32.exe": [
        (r"javascript:", "Rundll32 Inline Script Execution", "high", "T1218.011"),
        (r"urldownload", "Rundll32 Remote DLL Download Execution", "high", "T1218.011"),
        (r"pcwutl.dll,launchapplication", "Rundll32 Application Launch Bypass", "high", "T1218.011"),
        (r"AppData|Temp|Downloads", "Rundll32 Execution from User Directory", "medium", "T1218.011")
    ],
    "regsvr32.exe": [
        (r"/i:http[s]?://", "Regsvr32 Remote Scriptlet Execution (Squiblydoo)", "critical", "T1218.010"),
        (r"scrobj\.dll", "Regsvr32 Scriptlet Object Load", "high", "T1218.010"),
        (r"AppData|Temp|Downloads", "Regsvr32 DLL Execution from User Directory", "medium", "T1218.010")
    ],
    "bitsadmin.exe": [
        (r"/transfer", "Bitsadmin File Transfer Job Created", "medium", "T1197"),
        (r"/create", "Bitsadmin Job Creation", "low", "T1197")
    ],
    "hh.exe": [
        (r"http[s]?://", "Hh.exe Help Compiler Remote Payload Execution", "high", "T1218.001"),
        (r"\.chm", "Hh.exe Help Compiler Execution", "medium", "T1218.001")
    ],
    "makecab.exe": [
        (r"\.cab", "Makecab Compressed Archive Creation", "low", "T1560.001")
    ],
    "certreq.exe": [
        (r"-post", "Certreq Remote Web Request", "medium", "T1105")
    ],
    "curl.exe": [
        (r"-o|-O|--output", "Curl File Download Command", "low", "T1105")
    ],
    "schtasks.exe": [
        (r"/create", "Scheduled Task Creation via CommandLine", "medium", "T1053.005"),
        (r"/change", "Scheduled Task Modification", "medium", "T1053.005")
    ],
    "sc.exe": [
        (r"create", "New Service Creation via CommandLine", "high", "T1543.003"),
        (r"config", "Service Configuration Change", "medium", "T1543.003")
    ],
    "reg.exe": [
        (r"add.*run", "Registry Run Key Modification (Reg.exe)", "high", "T1547.001"),
        (r"save", "Registry Hive Export Attempt", "critical", "T1003")
    ],
    "wmic.exe": [
        (r"shadowcopy.*delete", "Shadow Copy Deletion (WMIC)", "critical", "T1490"),
        (r"process.*call.*create", "Process Spawning via WMIC", "high", "T1047")
    ],
    "vssadmin.exe": [
        (r"delete.*shadows", "Shadow Copy Deletion (Vssadmin)", "critical", "T1490")
    ],
    "bcdedit.exe": [
        (r"recoveryenabled.*no", "System Recovery Disabled (Bcdedit)", "critical", "T1490")
    ]
}

async def analyze_process_event(event: dict):
    """Inspects a process event for LOLBin abuse patterns."""
    if event.get("event_id") != 4688:
        return
        
    image = event.get("image", "").lower()
    cmd = event.get("commandline", "").lower()
    
    # Extract filename from image path
    filename = image.split("\\")[-1]
    
    if filename in LOLBIN_RULES:
        rules = LOLBIN_RULES[filename]
        for pattern, title, severity, mitre_id in rules:
            import re
            if re.search(pattern, cmd, re.IGNORECASE):
                # Calculate initial risk score based on severity
                score_map = {"low": 20, "medium": 45, "high": 75, "critical": 95}
                score = score_map.get(severity, 30)
                
                tech = get_technique(mitre_id)
                alert = {
                    "title": title,
                    "severity": severity,
                    "timestamp": event.get("timestamp"),
                    "mitre": mitre_id,
                    "tactic": tech.get("tactic", "Defense Evasion"),
                    "score": score,
                    "source": "lolbins",
                    "details": f"Process {image} executed with suspicious command: '{event.get('commandline')}' matching pattern '{pattern}'"
                }
                
                await insert_alert(alert)
                # Publish the detection alert to the event bus
                await event_bus.publish("alerts", alert)
                logger.info(f"LOLBin Alert Generated: {title} ({mitre_id})")

async def start_lolbin_detector():
    """Subscribes the LOLBin detector to the event bus."""
    logger.info("Starting LOLBin Abuse Detector...")
    queue = asyncio.Queue()
    
    async def callback(data):
        await queue.put(data)
        
    await event_bus.subscribe("events", callback)
    
    try:
        while True:
            event = await queue.get()
            await analyze_process_event(event)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Error in LOLBin detector: {e}")
    finally:
        await event_bus.unsubscribe("events", callback)
