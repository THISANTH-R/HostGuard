"""
Windows Firewall Log Collector.
Monitors pfirewall.log incrementally. Fallback to mock firewall logs if not available.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
import random

from ..database import insert_firewall_event
from ..event_bus import event_bus

logger = logging.getLogger(__name__)

async def process_firewall_log_line(line: str):
    """Parses a single line from the Windows Firewall log and inserts it."""
    # Format of pfirewall.log lines:
    # 2026-06-07 12:00:00 ALLOW TCP 192.168.1.10 8.8.8.8 51234 443 0 - - - - - - - SEND
    # Fields: date, time, action, protocol, src-ip, dst-ip, src-port, dst-port, ...
    if line.startswith("#") or not line.strip():
        return
        
    parts = line.split()
    if len(parts) < 8:
        return
        
    try:
        date_str, time_str, action, protocol, src_ip, dst_ip, src_port_str, dst_port_str = parts[:8]
        
        # Parse ports
        try:
            src_port = int(src_port_str)
        except:
            src_port = 0
        try:
            dst_port = int(dst_port_str)
        except:
            dst_port = 0
            
        timestamp = f"{date_str}T{time_str}"
        # Direction extraction (best effort based on standard log ending)
        direction = "RECEIVE"
        if len(parts) >= 17:
            direction = parts[16] # e.g. SEND/RECEIVE
            
        firewall_evt = {
            "timestamp": timestamp,
            "action": action,
            "protocol": protocol.lower(),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "direction": direction
        }
        
        await insert_firewall_event(firewall_evt)
        await event_bus.publish("firewall", firewall_evt)
    except Exception as e:
        logger.debug(f"Failed to parse firewall line: {line}. Error: {e}")

async def run_mock_firewall():
    """Generates mock firewall logs if real logging is unavailable."""
    logger.info("Running Firewall Collector in Mock Fallback mode.")
    ips_internal = ["192.168.1.15", "192.168.1.100", "192.168.1.50"]
    ips_external = ["8.8.8.8", "1.1.1.1", "185.190.140.10", "44.228.249.3", "104.244.42.1"]
    protocols = ["TCP", "UDP", "ICMP"]
    
    while True:
        try:
            await asyncio.sleep(random.uniform(1.0, 4.0))
            
            action = "ALLOW" if random.random() > 0.15 else "DROP"
            protocol = random.choice(protocols)
            direction = "SEND" if random.random() > 0.4 else "RECEIVE"
            
            src_ip = random.choice(ips_internal) if direction == "SEND" else random.choice(ips_external)
            dst_ip = random.choice(ips_external) if direction == "SEND" else random.choice(ips_internal)
            
            src_port = random.randint(49152, 65535) if protocol != "ICMP" else 0
            dst_port = random.choice([80, 443, 8080, 22, 3389]) if protocol != "ICMP" else 0
            
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "protocol": protocol.lower(),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "direction": direction
            }
            
            await insert_firewall_event(event)
            await event_bus.publish("firewall", event)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in mock firewall collector: {e}")

async def tail_firewall_log(path: str):
    """Tails the firewall log file and parses lines incrementally."""
    logger.info(f"Tailing firewall log: {path}")
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            # Go to end of file
            f.seek(0, os.SEEK_END)
            
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(1.0)
                    continue
                await process_firewall_log_line(line)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Error tailing firewall log: {e}. Switching to mock.")
        await run_mock_firewall()

async def start_firewall_collector():
    """Starts the Windows Firewall log collector."""
    logger.info("Initializing Firewall Collector...")
    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    log_path = os.path.join(system_root, "System32", "LogFiles", "Firewall", "pfirewall.log")
    
    if os.path.exists(log_path):
        asyncio.create_task(tail_firewall_log(log_path))
    else:
        logger.warning(f"Firewall log not found at {log_path}. Running mock firewall collector instead.")
        asyncio.create_task(run_mock_firewall())
