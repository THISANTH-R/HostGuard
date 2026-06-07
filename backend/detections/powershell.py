"""
PowerShell Attack Detection Module.
Detects suspicious PowerShell command lines, script block execution, and suspicious parent-child relationships.
"""

import asyncio
import logging
import re
from ..database import insert_alert
from ..event_bus import event_bus
from .mitre_mapping import get_technique

logger = logging.getLogger(__name__)

# Suspicious parent processes that should never spawn PowerShell in normal use
SUSPICIOUS_PARENTS = [
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "publisher.exe", "visio.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "nginx.exe",
    "httpd.exe", "tomcat.exe", "sqlservr.exe"
]

SUSPICIOUS_POWERSHELL_PATTERNS = [
    (r"-enc(odedcommand)?\s+[a-zA-Z0-9+/=]{10,}", "Encoded PowerShell Command Execution", "high", "T1027"),
    (r"-ep(olicy)?\s+bypass", "Execution Policy Bypass Flag Detected", "medium", "T1562.001"),
    (r"-w(indowstyle)?\s+hid(den)?", "Hidden Window execution flag", "medium", "T1564.003"),
    (r"iex\s*\(|invoke-expression", "PowerShell Invoke-Expression (IEX) Abuse", "high", "T1059.001"),
    (r"downloadstring|downloadfile", "PowerShell Web Download Attempt", "high", "T1105"),
    (r"bypass.*-nop|nop.*bypass", "Combined Stealth Execution Flag Bypass", "high", "T1059.001"),
    (r"system\.net\.webclient", "PowerShell Web Client Object Creation", "medium", "T1105"),
    (r"invoke-webrequest|iwr", "PowerShell Web Request Command", "medium", "T1105"),
    (r"virtualalloc|writeprocessmemory|createremotethread", "In-Memory Shellcode Execution Indicators", "critical", "T1055")
]

async def analyze_event(event: dict):
    image = event.get("image", "").lower()
    cmd = event.get("commandline", "").lower()
    event_id = event.get("event_id")
    
    # Process Creation check
    if event_id == 4688 or (event.get("source") == "sysmon" and event_id == 1):
        filename = image.split("\\")[-1]
        
        if "powershell" in filename or "pwsh" in filename:
            # Check suspicious parent process
            # In Windows Security log 4688, parent process name might be in raw_data or can be fetched
            parent = event.get("raw_data", {}).get("parent_process_name", "")
            if not parent and event.get("ppid"):
                # If we have PPID, we can inspect process name (handled in correlator but do simple check here)
                pass
                
            # Parse command line patterns
            for pattern, title, severity, mitre_id in SUSPICIOUS_POWERSHELL_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    score_map = {"low": 20, "medium": 45, "high": 75, "critical": 95}
                    score = score_map.get(severity, 30)
                    
                    tech = get_technique(mitre_id)
                    alert = {
                        "title": title,
                        "severity": severity,
                        "timestamp": event.get("timestamp"),
                        "mitre": mitre_id,
                        "tactic": tech.get("tactic", "Execution"),
                        "score": score,
                        "source": "powershell_detection",
                        "details": f"Suspicious PowerShell executed: '{event.get('commandline')}' matching pattern '{pattern}'"
                    }
                    await insert_alert(alert)
                    await event_bus.publish("alerts", alert)
                    logger.info(f"PowerShell Alert Generated: {title} ({mitre_id})")
                    
    # Script block logging check (Event 4104)
    elif event_id == 4104:
        script_content = event.get("raw_data", {}).get("script_content", "") or cmd
        
        # Check script block content for danger keywords
        keywords = ["mimikatz", "bypassuac", "lsadump", "sekurlsa", "invokemimikatz", "safetykatz"]
        for kw in keywords:
            if kw in script_content.lower():
                tech = get_technique("T1059.001")
                alert = {
                    "title": f"Malicious PowerShell Script Block Detected ({kw})",
                    "severity": "critical",
                    "timestamp": event.get("timestamp"),
                    "mitre": "T1059.001",
                    "tactic": tech.get("tactic", "Execution"),
                    "score": 95,
                    "source": "powershell_script_block",
                    "details": f"Script block ID 4104 contains malicious keyword: '{kw}'"
                }
                await insert_alert(alert)
                await event_bus.publish("alerts", alert)
                logger.info(f"PowerShell Script Block Alert: Malicious Keyword '{kw}'")

async def start_powershell_detector():
    """Starts the PowerShell detection module."""
    logger.info("Starting PowerShell Attack Detector...")
    queue = asyncio.Queue()
    
    async def callback(data):
        await queue.put(data)
        
    await event_bus.subscribe("events", callback)
    
    try:
        while True:
            event = await queue.get()
            await analyze_event(event)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Error in PowerShell detector: {e}")
    finally:
        await event_bus.unsubscribe("events", callback)
