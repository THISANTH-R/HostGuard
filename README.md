HOST SECURITY MONITORING PLATFORM

PROJECT OVERVIEW

The Host Security Monitoring Platform is a Windows host-based security monitoring, detection, and investigation platform designed for local deployment. It combines endpoint telemetry collection, event correlation, threat detection, and real-time visualization into a unified dashboard.

The platform continuously collects and analyzes telemetry from Windows Security Logs, Sysmon, Windows Firewall logs, network activity, and host resource utilization. Collected events are normalized into a common format, correlated across multiple data sources, and evaluated against detection rules, threat intelligence indicators, YARA signatures, and MITRE ATT&CK mappings.

The primary goal of the platform is to provide security visibility, threat detection, alerting, and investigation capabilities for Windows environments while keeping data processing local to the host.

FEATURES

Telemetry Collection

• Windows Security Event Logs
• Sysmon Event Collection
• Windows Firewall Log Monitoring
• Network Connection Monitoring
• Resource Usage Monitoring
• Process Creation Tracking
• Process Tree Reconstruction

Detection Capabilities

• LOLBin Detection
• PowerShell Abuse Detection
• Persistence Detection
• Privilege Escalation Detection
• Defense Evasion Detection
• Credential Access Detection
• Network Anomaly Detection
• Ransomware Correlation Detection

Threat Intelligence

• MITRE ATT&CK Mapping
• IOC Matching
• YARA Rule Integration
• Threat Scoring Engine
• Alert Severity Classification

Frontend Dashboard

• Real-Time Event Streaming
• Live Alert Feed
• Process Tree Visualization
• Severity Metrics
• Search and Filtering
• Historical Event Investigation
• System Profile Page

ARCHITECTURE

Backend

• Python
• FastAPI
• SQLite
• WebSockets

Frontend

• React
• Vite
• TypeScript
• TailwindCSS
• Zustand
• React Query
• Recharts
• React Flow

PREREQUISITES

Operating System

• Windows 10 or Windows 11
• Administrator privileges recommended

Python

Recommended Version:
Python 3.12

Note:
Some Windows security libraries may not yet fully support the newest Python releases. If installation issues occur with pywin32, wmi, or yara-python, use Python 3.12.

Node.js

Recommended:
Node.js 18 or newer

WINDOWS CONFIGURATION

Enable Process Creation Auditing

Run Command Prompt as Administrator:

auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

This enables Event ID 4688 collection.

Enable PowerShell Logging

Open:

gpedit.msc

Navigate to:

Computer Configuration
→ Administrative Templates
→ Windows Components
→ Windows PowerShell

Enable:

• Turn on Module Logging
• Turn on PowerShell Script Block Logging

This enables Event IDs 4103 and 4104.

Enable Firewall Logging

Open:

Windows Defender Firewall with Advanced Security

Enable logging for allowed and blocked connections.

SYSMON SETUP

Sysmon provides enhanced telemetry beyond native Windows auditing.

Install Sysmon:

Sysmon.exe -accepteula -i

Verify Installation:

sc query Sysmon

Verify Event Log:

Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational

The platform automatically detects Sysmon and collects supported Sysmon events when available.

If Sysmon is not installed, the platform automatically falls back to native Windows Security Event Logs.

PSSUSPEND SETUP

PsSuspend is optional and is only used for process suspension actions.

Verify Installation:

pssuspend

If the command executes successfully, no additional configuration is required.

The platform can invoke PsSuspend through the system PATH.

INSTALLATION

Backend

Navigate to:

backend/

Create Virtual Environment:

py -3.12 -m venv venv

Activate:

venv\Scripts\activate

Install Dependencies:

pip install -r requirements.txt

Run Backend:

python main.py

Frontend

Navigate to:

frontend/

Install Dependencies:

npm install

Start Development Server:

npm run dev

Default Frontend URL:

http://localhost:5173

Default Backend URL:

http://localhost:8000

AVAILABLE DATA SOURCES

Windows Security Events

4688 Process Creation
4689 Process Exit
4624 Successful Logon
4625 Failed Logon
4672 Special Privileges Assigned
4697 Service Installed
7045 Service Creation
1102 Audit Log Cleared
4720 User Creation
4728 Privileged Group Membership
5156 Allowed Connection
5157 Blocked Connection
4103 PowerShell Module Logging
4104 PowerShell Script Block Logging

Sysmon Events

1 Process Creation
3 Network Connection
7 DLL Load
11 File Creation

SEARCH EXAMPLES

certutil
powershell
event:4688
severity:critical
pid:1234
ip:8.8.8.8

API ENDPOINTS

/api/events
/api/alerts
/api/process-tree
/api/network
/api/firewall
/api/history
/api/search
/api/profile
/api/startup/status
/api/shutdown

DISCLAIMER

This project is intended for security monitoring, research, learning, lab environments, and defensive security operations. Detection accuracy depends on system configuration, enabled logging sources, installed telemetry providers, and rule quality. Automated response actions should be reviewed carefully before use in production environments.
