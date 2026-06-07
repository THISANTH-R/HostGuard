"""
System Resource Monitor Collector.
Uses psutil to gather CPU, memory, disk read/write, and thread counts periodically.
"""

import asyncio
import logging
from datetime import datetime, timezone
import psutil

from ..database import insert_resource_usage
from ..event_bus import event_bus

logger = logging.getLogger(__name__)

async def run_resource_collector():
    """Gathers system resources usage metrics every 5 seconds."""
    logger.info("Starting Resource Monitor Collector loop.")
    
    # Initialize disk I/O values
    try:
        last_io = psutil.disk_io_counters()
        last_read_bytes = last_io.read_bytes if last_io else 0
        last_write_bytes = last_io.write_bytes if last_io else 0
    except Exception as e:
        logger.warning(f"Could not initialize disk IO counters: {e}")
        last_read_bytes = 0
        last_write_bytes = 0
        
    while True:
        try:
            # CPU and Memory
            cpu = psutil.cpu_percent(interval=None) # Non-blocking
            mem = psutil.virtual_memory().percent
            
            # Disk IO calculations
            try:
                current_io = psutil.disk_io_counters()
                current_read = current_io.read_bytes if current_io else last_read_bytes
                current_write = current_io.write_bytes if current_io else last_write_bytes
            except Exception as e:
                logger.debug(f"Disk IO counter access failed: {e}")
                current_read = last_read_bytes
                current_write = last_write_bytes
                
            read_delta = max(0, current_read - last_read_bytes)
            write_delta = max(0, current_write - last_write_bytes)
            
            last_read_bytes = current_read
            last_write_bytes = current_write
            
            # Thread Count
            threads = 0
            for proc in psutil.process_iter(['num_threads']):
                try:
                    threads += proc.info['num_threads'] or 0
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            resource_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "cpu_percent": cpu,
                "memory_percent": mem,
                "disk_read_bytes": read_delta,
                "disk_write_bytes": write_delta,
                "thread_count": threads
            }
            
            await insert_resource_usage(resource_data)
            await event_bus.publish("resource", resource_data)
            
            await asyncio.sleep(5.0)
            
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in Resource Monitor Collector: {e}")
            await asyncio.sleep(5.0)

async def start_resource_collector():
    """Starts the system resource monitor collector."""
    logger.info("Initializing Resource Monitor Collector...")
    asyncio.create_task(run_resource_collector())
