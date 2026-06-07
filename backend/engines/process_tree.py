import asyncio
import logging
from ..database import insert_process_tree_node
from ..event_bus import event_bus

logger = logging.getLogger(__name__)

async def process_event(event):
    if event.get("event_id") == 4688 or (event.get("source") == "sysmon" and event.get("event_id") == 1):
        try:
            node = {
                "pid": event.get("pid"),
                "ppid": event.get("ppid"),
                "image": event.get("image"),
                "commandline": event.get("commandline", ""),
                "timestamp": event.get("timestamp"),
                "depth": 0
            }
            await insert_process_tree_node(node)
        except Exception as e:
            logger.error(f"Error adding to process tree: {e}")

async def start_process_tree_engine():
    logger.info("Starting Process Tree Engine...")
    
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
        logger.error(f"Process tree engine error: {e}")
    finally:
        await event_bus.unsubscribe("events", callback)
