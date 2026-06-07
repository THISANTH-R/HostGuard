import asyncio
import ctypes
import os
import sys
import logging
from pathlib import Path
import winreg

from .database import get_db
from .collectors.winlogs import start_winlog_collector
from .collectors.sysmon import start_sysmon_collector
from .collectors.firewall import start_firewall_collector
from .collectors.network import start_network_collector
from .collectors.resource_monitor import start_resource_collector
from .engines.process_tree import start_process_tree_engine
from .engines.correlator import start_correlator
from .engines.yara_engine import start_yara_engine
from .engines.ioc_engine import start_ioc_engine
from .engines.threat_scoring import start_scoring_engine
from .detections.lolbins import start_lolbin_detector
from .detections.powershell import start_powershell_detector
from .detections.persistence import start_persistence_detector
from .detections.credential_access import start_credential_detector
from .detections.privilege_escalation import start_privesc_detector
from .detections.defense_evasion import start_defense_evasion_detector
from .detections.ransomware import start_ransomware_detector
from .detections.network_anomalies import start_network_anomaly_detector

logger = logging.getLogger(__name__)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

async def initialize_system():
    logger.info("Initializing system...")
    
    # Check Admin Privileges
    admin_mode = is_admin()
    if not admin_mode:
        logger.warning("Application is NOT running with Administrator privileges. Some collectors (like Security Event Logs) may fail.")
    
    # Initialize Database
    db_path = Path(os.getenv("DATABASE_PATH", "backend/database.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # The database initialization actually happens on the first get_database() call implicitly if we just run a basic query.
    
    # Record startup status in DB
    try:
        async with get_db() as db:
            await db.upsert_setting('admin_mode', str(admin_mode))
    except Exception as e:
        logger.error(f"Failed to record admin status: {e}")

async def start_all_services():
    await initialize_system()
    
    # List of all background tasks
    tasks = [
        # Collectors
        asyncio.create_task(start_winlog_collector(), name="winlog_collector"),
        asyncio.create_task(start_sysmon_collector(), name="sysmon_collector"),
        asyncio.create_task(start_firewall_collector(), name="firewall_collector"),
        asyncio.create_task(start_network_collector(), name="network_collector"),
        asyncio.create_task(start_resource_collector(), name="resource_collector"),
        
        # Engines
        asyncio.create_task(start_process_tree_engine(), name="process_tree_engine"),
        asyncio.create_task(start_correlator(), name="correlator_engine"),
        asyncio.create_task(start_yara_engine(), name="yara_engine"),
        asyncio.create_task(start_ioc_engine(), name="ioc_engine"),
        asyncio.create_task(start_scoring_engine(), name="scoring_engine"),
        
        # Detections
        asyncio.create_task(start_lolbin_detector(), name="lolbin_detector"),
        asyncio.create_task(start_powershell_detector(), name="powershell_detector"),
        asyncio.create_task(start_persistence_detector(), name="persistence_detector"),
        asyncio.create_task(start_credential_detector(), name="credential_detector"),
        asyncio.create_task(start_privesc_detector(), name="privesc_detector"),
        asyncio.create_task(start_defense_evasion_detector(), name="defense_evasion_detector"),
        asyncio.create_task(start_ransomware_detector(), name="ransomware_detector"),
        asyncio.create_task(start_network_anomaly_detector(), name="network_anomaly_detector")
    ]
    
    return tasks
