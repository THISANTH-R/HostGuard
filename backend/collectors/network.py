"""
Active Network Connections Collector.
Uses psutil to enumerate TCP and UDP connections, resolves PIDs, and stores them.
"""

import asyncio
import logging
from datetime import datetime, timezone
import psutil
import socket
import random

from ..database import insert_network_connection
from ..event_bus import event_bus

logger = logging.getLogger(__name__)

# Cache process names to avoid repeatedly instantiating psutil.Process
process_name_cache = {}

def get_process_name(pid: int) -> str:
    if pid is None or pid == 0:
        return "System"
    if pid in process_name_cache:
        return process_name_cache[pid]
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        process_name_cache[pid] = name
        return name
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"

async def run_network_collector():
    """Periodically queries system network connections."""
    logger.info("Starting Network Connections Collector loop.")
    
    last_connections = set()
    
    while True:
        try:
            # Enumerate connections
            conns = psutil.net_connections(kind='all')
            current_connections = set()
            
            for conn in conns:
                # Filter out connections without remote address (listening sockets)
                if not conn.raddr:
                    continue
                    
                r_ip, r_port = conn.raddr
                l_ip, l_port = conn.laddr
                
                # Create a unique key for tracking state changes
                conn_key = (conn.pid, l_ip, l_port, r_ip, r_port, conn.status)
                current_connections.add(conn_key)
                
                # If this is a new connection or status changed, log it
                if conn_key not in last_connections:
                    proc_name = get_process_name(conn.pid)
                    
                    network_evt = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "pid": conn.pid,
                        "process": proc_name,
                        "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                        "local_ip": l_ip,
                        "local_port": l_port,
                        "remote_ip": r_ip,
                        "remote_port": r_port,
                        "status": conn.status
                    }
                    
                    await insert_network_connection(network_evt)
                    await event_bus.publish("network", network_evt)
            
            last_connections = current_connections
            
            # Clean up process cache periodically to prevent leaks
            if len(process_name_cache) > 200:
                process_name_cache.clear()
                
            await asyncio.sleep(5.0)
            
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in Network Connections Collector: {e}")
            # Generate mock fallback network events if psutil fails or connection fails
            await asyncio.sleep(5.0)

async def start_network_collector():
    """Starts the network connections collector."""
    logger.info("Initializing Network Collector...")
    asyncio.create_task(run_network_collector())
