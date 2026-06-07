"""
Centralized MITRE ATT&CK technique registry.

Provides a comprehensive mapping of MITRE ATT&CK technique IDs to their
metadata including name, tactic, description, and severity boost values.
Used by all detection modules to enrich alerts with ATT&CK context.

Usage:
    from detections.mitre_mapping import get_technique, get_techniques_by_tactic

    technique = get_technique("T1059.001")
    execution_techniques = get_techniques_by_tactic("Execution")
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Technique Registry
# ──────────────────────────────────────────────────────────────────────────────
MITRE_TECHNIQUES: dict[str, dict] = {
    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse PowerShell commands and scripts for execution. "
            "PowerShell is a powerful interactive command-line interface and "
            "scripting environment included in the Windows operating system."
        ),
        "severity_boost": 2,
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse the Windows command shell (cmd.exe) for "
            "execution. The Windows command shell is the primary command prompt "
            "on Windows systems."
        ),
        "severity_boost": 1,
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse Windows Management Instrumentation (WMI) to "
            "execute malicious commands and payloads."
        ),
        "severity_boost": 2,
    },

    # ── Defense Evasion / Execution (Signed Binary Proxy Execution) ───────────
    "T1218.001": {
        "name": "Compiled HTML File",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may abuse Compiled HTML (.chm) files to conceal "
            "malicious code. CHM files are commonly distributed as part of the "
            "Microsoft HTML Help system."
        ),
        "severity_boost": 2,
    },
    "T1218.002": {
        "name": "Control Panel",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may abuse control.exe to proxy execution of malicious "
            "payloads. The Windows Control Panel process binary handles execution "
            "of Control Panel items (.cpl files)."
        ),
        "severity_boost": 2,
    },
    "T1218.004": {
        "name": "InstallUtil",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may use InstallUtil to proxy execution of code through "
            "a trusted Windows utility."
        ),
        "severity_boost": 2,
    },
    "T1218.005": {
        "name": "Mshta",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may abuse mshta.exe to proxy execution of malicious "
            ".hta files and Javascript or VBScript through a trusted Windows "
            "utility."
        ),
        "severity_boost": 3,
    },
    "T1218.010": {
        "name": "Regsvr32",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may abuse Regsvr32.exe to proxy execution of malicious "
            "code by using it to load COM scriptlets (SCT) that execute DLLs."
        ),
        "severity_boost": 3,
    },
    "T1218.011": {
        "name": "Rundll32",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may abuse rundll32.exe to proxy execution of malicious "
            "code. Rundll32.exe can be used to execute arbitrary DLLs."
        ),
        "severity_boost": 2,
    },

    # ── Defense Evasion ───────────────────────────────────────────────────────
    "T1197": {
        "name": "BITS Jobs",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may abuse BITS jobs to persistently execute code and "
            "perform various background tasks. BITS is a low-bandwidth, "
            "asynchronous file transfer mechanism."
        ),
        "severity_boost": 2,
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may use obfuscated files or information to hide "
            "artifacts of an intrusion from analysis."
        ),
        "severity_boost": 1,
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may clear Windows Event Logs to hide the activity of an "
            "intrusion."
        ),
        "severity_boost": 3,
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may modify and/or disable security tools to avoid "
            "possible detection of their malware/tools and activities."
        ),
        "severity_boost": 3,
    },
    "T1070.004": {
        "name": "File Deletion",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may delete files left behind by the actions of their "
            "intrusion activity."
        ),
        "severity_boost": 1,
    },
    "T1036.005": {
        "name": "Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may match or approximate the name or location of "
            "legitimate files or resources when naming/placing malicious ones."
        ),
        "severity_boost": 2,
    },

    # ── Persistence ───────────────────────────────────────────────────────────
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": (
            "Adversaries may achieve persistence by adding a program to a "
            "startup folder or referencing it with a Registry run key."
        ),
        "severity_boost": 2,
    },
    "T1547.009": {
        "name": "Shortcut Modification",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create or modify shortcuts that can execute a "
            "program during system boot or user login."
        ),
        "severity_boost": 2,
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "description": (
            "Adversaries may abuse the Windows Task Scheduler to perform task "
            "scheduling for initial or recurring execution of malicious code."
        ),
        "severity_boost": 2,
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create or modify Windows services to repeatedly "
            "execute malicious payloads as part of persistence."
        ),
        "severity_boost": 2,
    },
    "T1546.003": {
        "name": "WMI Event Subscription",
        "tactic": "Persistence",
        "description": (
            "Adversaries may establish persistence and elevate privileges by "
            "executing malicious content triggered by a WMI event subscription."
        ),
        "severity_boost": 3,
    },

    # ── Credential Access ────────────────────────────────────────────────────
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to dump credentials to obtain account "
            "login and credential material from the operating system and "
            "software."
        ),
        "severity_boost": 3,
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to access credential material stored in "
            "the process memory of the Local Security Authority Subsystem "
            "Service (LSASS)."
        ),
        "severity_boost": 4,
    },
    "T1003.002": {
        "name": "Security Account Manager",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to extract credential material from the "
            "Security Account Manager (SAM) database."
        ),
        "severity_boost": 3,
    },
    "T1003.003": {
        "name": "NTDS",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to access or create a copy of the Active "
            "Directory domain database (NTDS.dit)."
        ),
        "severity_boost": 4,
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to "
            "accounts when passwords are unknown or when password hashes are "
            "obtained."
        ),
        "severity_boost": 2,
    },

    # ── Privilege Escalation ─────────────────────────────────────────────────
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts "
            "as a means of gaining Initial Access, Persistence, Privilege "
            "Escalation, or Defense Evasion."
        ),
        "severity_boost": 2,
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may modify access tokens to operate under a different "
            "user or system security context to perform actions and bypass "
            "access controls."
        ),
        "severity_boost": 3,
    },

    # ── Lateral Movement ─────────────────────────────────────────────────────
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use Valid Accounts to log into a computer using "
            "the Remote Desktop Protocol (RDP)."
        ),
        "severity_boost": 1,
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use Valid Accounts to interact with a remote "
            "network share using Server Message Block (SMB)."
        ),
        "severity_boost": 1,
    },

    # ── Command and Control ──────────────────────────────────────────────────
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using application layer protocols "
            "associated with web traffic to avoid detection."
        ),
        "severity_boost": 2,
    },
    "T1071.004": {
        "name": "DNS",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using the Domain Name System (DNS) "
            "application layer protocol to avoid detection."
        ),
        "severity_boost": 2,
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may tunnel network communications to and from a victim "
            "system within a separate protocol to avoid detection."
        ),
        "severity_boost": 3,
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may employ an encryption algorithm to conceal command "
            "and control traffic."
        ),
        "severity_boost": 1,
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may use a non-application layer protocol for "
            "communication between host and C2 server or among infected hosts."
        ),
        "severity_boost": 2,
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data by exfiltrating it over an existing "
            "command and control channel."
        ),
        "severity_boost": 3,
    },

    # ── Impact ────────────────────────────────────────────────────────────────
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": (
            "Adversaries may encrypt data on target systems to interrupt "
            "availability to system and network resources. This is commonly "
            "associated with ransomware."
        ),
        "severity_boost": 4,
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": (
            "Adversaries may delete or remove built-in data and turn off "
            "services designed to aid in the recovery of a corrupted system."
        ),
        "severity_boost": 4,
    },
    "T1489": {
        "name": "Service Stop",
        "tactic": "Impact",
        "description": (
            "Adversaries may stop or disable services on a system to render "
            "those services unavailable to legitimate users."
        ),
        "severity_boost": 2,
    },

    # ── Collection ────────────────────────────────────────────────────────────
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": (
            "Adversaries may search local system sources, such as file systems "
            "and configuration files, to find files of interest and sensitive "
            "data prior to exfiltration."
        ),
        "severity_boost": 1,
    },

    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of accounts on a system "
            "or within an environment."
        ),
        "severity_boost": 1,
    },
}


def get_technique(technique_id: str) -> Optional[dict]:
    """
    Retrieve MITRE ATT&CK technique metadata by technique ID.

    Args:
        technique_id: The MITRE ATT&CK technique ID (e.g., "T1059.001").

    Returns:
        A dictionary containing 'name', 'tactic', 'description', and
        'severity_boost' for the given technique, or ``None`` if the
        technique ID is not found.

    Example::

        >>> get_technique("T1059.001")
        {'name': 'PowerShell', 'tactic': 'Execution', ...}
    """
    technique = MITRE_TECHNIQUES.get(technique_id)
    if technique is None:
        logger.warning("Unknown MITRE technique requested: %s", technique_id)
        return {}
    return {
        "id": technique_id,
        **technique,
    }


def get_techniques_by_tactic(tactic: str) -> list[dict]:
    """
    Retrieve all registered MITRE ATT&CK techniques for a given tactic.

    Args:
        tactic: The tactic name (e.g., "Execution", "Persistence").
                Case-insensitive comparison is performed.

    Returns:
        A list of technique dictionaries matching the given tactic.

    Example::

        >>> get_techniques_by_tactic("Execution")
        [{'id': 'T1059.001', 'name': 'PowerShell', ...}, ...]
    """
    tactic_lower = tactic.lower()
    results = []
    for tid, info in MITRE_TECHNIQUES.items():
        if info["tactic"].lower() == tactic_lower:
            results.append({"id": tid, **info})
    if not results:
        logger.warning("No techniques found for tactic: %s", tactic)
    return results


def get_all_techniques() -> list[dict]:
    """
    Retrieve all registered MITRE ATT&CK techniques.

    Returns:
        A list of all technique dictionaries.
    """
    return [{"id": tid, **info} for tid, info in MITRE_TECHNIQUES.items()]


def get_all_tactics() -> list[str]:
    """
    Retrieve a sorted list of all unique tactics in the registry.

    Returns:
        A sorted list of tactic name strings.
    """
    return sorted({info["tactic"] for info in MITRE_TECHNIQUES.values()})
