"""
Windows Security Event Log Collector.
Collects security events from the Windows Security event log channel.
Includes a graceful mock fallback if run without admin rights or on non-Windows systems.
"""

import asyncio
import logging
from datetime import datetime, timezone
import os
import socket

# Try to import pywin32
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import pywintypes
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

from ..database import insert_event, insert_process
from ..event_bus import event_bus

logger = logging.getLogger(__name__)

MONITORED_EVENT_IDS = {
    4688: "Process Creation",
    4689: "Process Termination",
    4624: "Successful Logon",
    4625: "Failed Logon",
    4672: "Special Privileges Assigned",
    4697: "Service Installation",
    7045: "New Service Installed",
    1102: "Audit Log Cleared",
    4720: "User Account Created",
    4728: "Member Added to Security Group",
    5156: "WFP Connection Allowed",
    5157: "WFP Connection Blocked",
    4103: "PowerShell Module Logging",
    4104: "PowerShell Script Block Logging",
}

SEVERITY_MAP = {
    4688: "low",
    4689: "low",
    4624: "low",
    4625: "medium",
    4672: "medium",
    4697: "high",
    7045: "high",
    1102: "critical",
    4720: "medium",
    4728: "medium",
    5156: "low",
    5157: "medium",
    4103: "medium",
    4104: "medium",
}

async def process_normalized_event(event: dict):
    """Save to DB, handle process creation specially, and publish to event bus."""
    # Insert event into database
    await insert_event(event)
    
    # If Process Creation (4688), insert process into processes table
    if event["event_id"] == 4688:
        proc_data = {
            "pid": event["pid"],
            "ppid": event["ppid"],
            "image": event["image"],
            "commandline": event["commandline"],
            "username": event["username"],
            "timestamp": event["timestamp"],
            "status": "running"
        }
        await insert_process(proc_data)
        
    # Publish to event bus
    await event_bus.publish("events", event)

async def run_mock_collector():
    """Generates mock Windows Security events for fallback and testing."""
    logger.info("Running Winlogs Collector in Mock Fallback mode.")
    import random
    
    users = ["SYSTEM", "Administrator", "thisuser", "Guest"]
    images = [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\svchost.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    ]
    
    while True:
        try:
            await asyncio.sleep(random.uniform(3.0, 8.0))
            
            event_id = random.choice(list(MONITORED_EVENT_IDS.keys()))
            username = random.choice(users)
            pid = random.randint(1000, 20000)
            ppid = random.randint(500, 1000)
            image = random.choice(images) if event_id in [4688, 4689] else ""
            cmd = f"{image} /c echo Hello" if image and "powershell" not in image else f"{image} -ExecutionPolicy Bypass" if image else ""
            
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "winlog",
                "event_id": event_id,
                "severity": SEVERITY_MAP.get(event_id, "low"),
                "pid": pid,
                "ppid": ppid,
                "image": image,
                "commandline": cmd,
                "username": username,
                "host": socket.gethostname(),
                "raw_data": {"description": MONITORED_EVENT_IDS[event_id]}
            }
            
            await process_normalized_event(event)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in mock winlogs collector: {e}")

async def run_real_collector():
    """Polls real Windows Security Event logs."""
    logger.info("Starting real Winlogs Collector.")
    
    # Open Security event log
    try:
        hand = win32evtlog.OpenEventLog(None, "Security")
    except Exception as e:
        logger.warning(f"Failed to open Windows Security Event Log: {e}. Switching to mock fallback.")
        await run_mock_collector()
        return

    # To read from the end, we record the total count first
    try:
        total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
    except Exception as e:
        logger.warning(f"Failed to query event log metadata: {e}. Switching to mock fallback.")
        await run_mock_collector()
        return
        
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    # Position at the end of the log
    # We do a fast backwards read first to discard past events
    discard_flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    win32evtlog.ReadEventLog(hand, discard_flags, 0)
    
    logger.info("Winlogs Collector is actively listening for new events.")
    
    while True:
        try:
            # Sleep between polls
            await asyncio.sleep(2.0)
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                continue
                
            for ev in events:
                event_id = ev.EventID & 0xFFFF  # Map down to actual EventID
                
                if event_id in MONITORED_EVENT_IDS:
                    # Parse Event data
                    strings = ev.StringInserts
                    username = ev.SourceName
                    
                    pid = None
                    ppid = None
                    image = ""
                    cmd = ""
                    
                    # Custom parsing for process creation (4688)
                    if event_id == 4688 and strings and len(strings) > 5:
                        # String index 1: New Process Name, index 5: Process Command Line
                        image = strings[5] if len(strings) > 5 else ""
                        cmd = strings[8] if len(strings) > 8 else ""
                        try:
                            pid = int(strings[4], 16) if len(strings) > 4 else None
                            ppid = int(strings[7], 16) if len(strings) > 7 else None
                        except:
                            pass
                    
                    # Normalize
                    normalized = {
                        "timestamp": ev.TimeGenerated.replace(tzinfo=timezone.utc).isoformat() if ev.TimeGenerated else datetime.now(timezone.utc).isoformat(),
                        "source": "winlog",
                        "event_id": event_id,
                        "severity": SEVERITY_MAP.get(event_id, "low"),
                        "pid": pid,
                        "ppid": ppid,
                        "image": image,
                        "commandline": cmd,
                        "username": username or "SYSTEM",
                        "host": socket.gethostname(),
                        "raw_data": {
                            "source_name": ev.SourceName,
                            "event_category": ev.EventCategory,
                            "description": MONITORED_EVENT_IDS[event_id]
                        }
                    }
                    
                    await process_normalized_event(normalized)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error reading Windows event logs: {e}")
            await asyncio.sleep(5.0)

async def start_winlog_collector():
    """Starts the Windows Event Log collector."""
    logger.info("Initializing Winlogs Collector...")
    if HAS_PYWIN32:
        asyncio.create_task(run_real_collector())
    else:
        logger.warning("pywin32 not available. Running mock winlogs collector instead.")
        asyncio.create_task(run_mock_collector())
