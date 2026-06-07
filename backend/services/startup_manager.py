import winreg
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def check_startup_status():
    status = {
        "registry_run": "Disabled",
        "startup_folder": "Disabled",
        "scheduled_task": "Disabled"
    }
    
    # 1. Check HKCU Run
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
        try:
            winreg.QueryValueEx(key, "HostGuard")
            status["registry_run"] = "Enabled"
        except FileNotFoundError:
            pass
        finally:
            winreg.CloseKey(key)
    except Exception as e:
        logger.error(f"Error checking registry startup: {e}")
        
    # 2. Check Startup Folder
    try:
        startup_path = Path(os.getenv("APPDATA")) / r"Microsoft\Windows\Start Menu\Programs\Startup\HostGuard.lnk"
        if startup_path.exists():
            status["startup_folder"] = "Enabled"
    except Exception as e:
        logger.error(f"Error checking startup folder: {e}")
        
    # 3. Check Scheduled Task (Simplified check)
    # Ideally would use schtasks query or win32com.client
    # For now, we'll leave it as Disabled unless specifically registered by our installer
        
    return status

def register_startup():
    # Example placeholder for enable functionality
    pass

def unregister_startup():
    # Example placeholder for disable functionality
    pass
