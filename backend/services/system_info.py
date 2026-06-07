import platform
import psutil
import socket
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def get_system_info():
    try:
        # Platform info
        uname = platform.uname()
        hostname = uname.node
        os_version = f"{uname.system} {uname.release}"
        windows_build = uname.version
        
        # CPU info
        cpu_info = platform.processor()
        
        # RAM info
        mem = psutil.virtual_memory()
        ram_total = f"{mem.total / (1024 ** 3):.2f} GB"
        ram_used = f"{mem.used / (1024 ** 3):.2f} GB"
        
        # Disk info
        disk = psutil.disk_usage('/')
        disk_total = f"{disk.total / (1024 ** 3):.2f} GB"
        disk_used = f"{disk.used / (1024 ** 3):.2f} GB"
        disk_percent = disk.percent
        
        # Uptime
        boot_time_timestamp = psutil.boot_time()
        bt = datetime.fromtimestamp(boot_time_timestamp)
        uptime = f"Booted {bt.strftime('%Y-%m-%d %H:%M:%S')}"
        
        # IP and MAC (Primary interface)
        ip_address = "Unknown"
        mac_address = "Unknown"
        
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        
        # Get MAC
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac_address = addr.address
                    break
            if mac_address != "Unknown":
                break

        return {
            "hostname": hostname,
            "os_version": os_version,
            "windows_build": windows_build,
            "cpu_info": cpu_info,
            "ram_total": ram_total,
            "ram_used": ram_used,
            "disk_total": disk_total,
            "disk_used": disk_used,
            "disk_percent": disk_percent,
            "uptime": uptime,
            "ip_address": ip_address,
            "mac_address": mac_address
        }
    except Exception as e:
        logger.error(f"Error gathering system info: {e}")
        return {}
