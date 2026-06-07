export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface SecurityEvent {
  id: number;
  timestamp: string;
  source: string;
  event_id: number;
  severity: Severity;
  pid: number;
  ppid: number;
  image: string;
  commandline: string;
  username: string;
  host: string;
}

export interface Alert {
  id: number;
  title: string;
  severity: Severity;
  timestamp: string;
  mitre: string;
  tactic: string;
  score: number;
  source: string;
  details: string;
  acknowledged: boolean;
}

export interface ProcessNode {
  pid: number;
  ppid: number;
  image: string;
  commandline: string;
  timestamp: string;
  children?: ProcessNode[];
}

export interface NetworkConnection {
  id: number;
  timestamp: string;
  pid: number;
  process: string;
  protocol: string;
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  status: string;
}

export interface FirewallEvent {
  id: number;
  timestamp: string;
  action: string;
  protocol: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  direction: string;
}

export interface ResourceUsage {
  id: number;
  timestamp: string;
  cpu_percent: number;
  memory_percent: number;
  disk_read_bytes: number;
  disk_write_bytes: number;
  thread_count: number;
}

export interface SystemInfo {
  hostname: string;
  os_version: string;
  windows_build: string;
  cpu_info: string;
  ram_total: string;
  ram_used: string;
  disk_total: string;
  disk_used: string;
  disk_percent: number;
  uptime: string;
  ip_address: string;
  mac_address: string;
}

export interface DashboardStats {
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  action_counts: {
    blocked: number;
    killed: number;
    suspended: number;
    ignored: number;
  };
}
