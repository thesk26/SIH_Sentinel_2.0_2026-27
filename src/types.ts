export interface Device {
  device_id: string;
  hostname: string;
  operating_system: string;
  os_version: string;
  architecture: string;
  cpu_cores: number;
  total_memory_bytes: number;
  total_disk_bytes: number;
  collector_version: string;
  registered_at: number;
  authorization_status: 'PENDING' | 'AUTHORIZED' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  last_heartbeat: number;
  last_telemetry_timestamp: number;
  is_simulated: number;
}

export interface TelemetryRecord {
  id: number;
  device_id: string;
  timestamp: number;
  is_simulated: number;
  cpu_percent: number;
  memory_percent: number;
  memory_used_bytes: number;
  disk_percent: number;
  uptime_seconds: number;
  network_bytes_sent: number;
  network_bytes_recv: number;
  active_connections_count: number;
  active_processes_count: number;
  evidence_hash: string;
  raw_json: string;
}

export interface NetworkConnectionRecord {
  id: number;
  device_id: string;
  telemetry_id: number;
  timestamp: number;
  protocol: string;
  local_address: string;
  local_port: number;
  remote_address: string;
  remote_port: number;
  state: string;
}

export interface ProcessRecord {
  id: number;
  device_id: string;
  telemetry_id: number;
  timestamp: number;
  pid: number;
  ppid: number;
  name: string;
  exe_path: string;
  cmdline: string;
  memory_rss_bytes: number;
  thread_count: number;
}

export interface BehaviourBaseline {
  device_id: string;
  last_updated: number;
  total_telemetry_windows: number;
  cpu_mean: number;
  cpu_stddev: number;
  cpu_p95: number;
  mem_mean: number;
  mem_stddev: number;
  net_conn_mean: number;
  net_conn_stddev: number;
  known_remote_ips: string;
  known_processes: string;
}

export interface AnomalyRecord {
  id: string;
  device_id: string;
  timestamp: number;
  anomaly_score: number;
  anomaly_level: 'NORMAL' | 'LOW_ANOMALY' | 'MEDIUM_ANOMALY' | 'HIGH_ANOMALY';
  contributing_factors: string;
  summary_reasons: string;
  is_simulated: number;
}

export interface PredictionRecord {
  id: string;
  device_id: string;
  timestamp: number;
  current_stage: string;
  predicted_next_stage: string;
  confidence: number;
  attack_risk_probability: number;
  forecast_hypothesis: string;
  supporting_evidence: string;
  recommended_mitigations: string;
  is_simulated: number;
}

export interface RiskRecord {
  id: string;
  device_id: string;
  timestamp: number;
  risk_score: number;
  risk_level: 'LOW' | 'GUARDED' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  classification: 'NORMAL' | 'ANOMALY' | 'POTENTIAL THREAT' | 'VERIFIED THREAT';
  confidence: number;
  key_reasons: string;
  primary_evidence: string;
  recommended_response: string;
  is_simulated: number;
}

export interface IncidentRecord {
  id: string;
  device_id: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
  risk_score: number;
  explanation: string;
  evidence: string;
  recommended_actions: string;
  created_at: number;
  updated_at: number;
  is_simulated: number;
}

export interface BlockchainRecord {
  tx_id: string;
  evidence_hash: string;
  device_id: string;
  incident_id?: string;
  timestamp: number;
  block_index: number;
  previous_block_hash: string;
  merkle_root: string;
  signature: string;
  canonical_data: string;
}

export interface DashboardOverview {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  active_threats: number;
  open_incidents: number;
  average_risk: number | null;
  cyber_health_score: number | null;
  recent_alerts: RiskRecord[];
  top_risk_devices: Array<RiskRecord & { hostname: string }>;
}
