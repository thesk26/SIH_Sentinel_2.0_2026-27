import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';

const dbPath = path.join(process.env.SENTINEL_DATA_DIR ?? path.join(process.cwd(), 'data'), 'sentinel.db');
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

export const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// Initialize normalized tables according to Section 20 of requirements
export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('ADMIN', 'ANALYST', 'VIEWER')),
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS devices (
      device_id TEXT PRIMARY KEY,
      hostname TEXT NOT NULL,
      operating_system TEXT NOT NULL,
      os_version TEXT NOT NULL,
      architecture TEXT NOT NULL,
      mac_address TEXT,
      ip_addresses TEXT,
      cpu_cores INTEGER DEFAULT 1,
      total_memory_bytes INTEGER DEFAULT 0,
      total_disk_bytes INTEGER DEFAULT 0,
      collector_version TEXT,
      registered_at INTEGER NOT NULL,
      authorization_status TEXT NOT NULL CHECK(authorization_status IN ('PENDING', 'AUTHORIZED', 'ACTIVE', 'REVOKED', 'EXPIRED')),
      last_heartbeat INTEGER,
      last_telemetry_timestamp INTEGER,
      is_simulated INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS device_authorizations (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      authorized_by TEXT NOT NULL,
      authorized_at INTEGER NOT NULL,
      status TEXT NOT NULL,
      revoked_at INTEGER,
      revocation_reason TEXT,
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );

    CREATE TABLE IF NOT EXISTS telemetry (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      is_simulated INTEGER DEFAULT 0,
      cpu_percent REAL NOT NULL,
      memory_percent REAL NOT NULL,
      memory_used_bytes INTEGER NOT NULL,
      disk_percent REAL NOT NULL,
      uptime_seconds INTEGER NOT NULL,
      network_bytes_sent INTEGER NOT NULL,
      network_bytes_recv INTEGER NOT NULL,
      active_connections_count INTEGER NOT NULL,
      active_processes_count INTEGER NOT NULL,
      evidence_hash TEXT NOT NULL,
      raw_json TEXT NOT NULL,
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );
    CREATE INDEX IF NOT EXISTS idx_telemetry_device_time ON telemetry(device_id, timestamp);

    CREATE TABLE IF NOT EXISTS network_connections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      telemetry_id INTEGER,
      timestamp INTEGER NOT NULL,
      protocol TEXT NOT NULL,
      local_address TEXT NOT NULL,
      local_port INTEGER NOT NULL,
      remote_address TEXT NOT NULL,
      remote_port INTEGER NOT NULL,
      state TEXT NOT NULL,
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );
    CREATE INDEX IF NOT EXISTS idx_net_conn_dev ON network_connections(device_id, timestamp);

    CREATE TABLE IF NOT EXISTS processes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      telemetry_id INTEGER,
      timestamp INTEGER NOT NULL,
      pid INTEGER NOT NULL,
      ppid INTEGER NOT NULL,
      name TEXT NOT NULL,
      exe_path TEXT,
      cmdline TEXT,
      memory_rss_bytes INTEGER,
      thread_count INTEGER,
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );

    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      source TEXT NOT NULL,
      description TEXT NOT NULL,
      raw_event TEXT,
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );

    CREATE TABLE IF NOT EXISTS behaviour_baselines (
      device_id TEXT PRIMARY KEY,
      last_updated INTEGER NOT NULL,
      total_telemetry_windows INTEGER NOT NULL,
      cpu_mean REAL DEFAULT 0,
      cpu_stddev REAL DEFAULT 0,
      cpu_p95 REAL DEFAULT 0,
      mem_mean REAL DEFAULT 0,
      mem_stddev REAL DEFAULT 0,
      net_conn_mean REAL DEFAULT 0,
      net_conn_stddev REAL DEFAULT 0,
      known_remote_ips TEXT DEFAULT '[]',
      known_processes TEXT DEFAULT '[]',
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );

    CREATE TABLE IF NOT EXISTS anomalies (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      anomaly_score REAL NOT NULL,
      anomaly_level TEXT NOT NULL,
      contributing_factors TEXT NOT NULL,
      summary_reasons TEXT NOT NULL,
      is_simulated INTEGER DEFAULT 0,
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );
    CREATE INDEX IF NOT EXISTS idx_anomalies_dev ON anomalies(device_id, timestamp);

    CREATE TABLE IF NOT EXISTS predictions (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      current_stage TEXT NOT NULL,
      predicted_next_stage TEXT NOT NULL,
      confidence REAL NOT NULL,
      attack_risk_probability REAL NOT NULL,
      forecast_hypothesis TEXT NOT NULL,
      supporting_evidence TEXT NOT NULL,
      recommended_mitigations TEXT NOT NULL,
      is_simulated INTEGER DEFAULT 0,
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );

    CREATE TABLE IF NOT EXISTS risk_scores (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      risk_score REAL NOT NULL,
      risk_level TEXT NOT NULL,
      classification TEXT NOT NULL,
      confidence REAL NOT NULL,
      key_reasons TEXT NOT NULL,
      primary_evidence TEXT NOT NULL,
      recommended_response TEXT NOT NULL,
      is_simulated INTEGER DEFAULT 0,
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );
    CREATE INDEX IF NOT EXISTS idx_risk_dev ON risk_scores(device_id, timestamp);

    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      status TEXT NOT NULL CHECK(status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')),
      risk_score REAL NOT NULL,
      explanation TEXT NOT NULL,
      evidence TEXT NOT NULL,
      recommended_actions TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      is_simulated INTEGER DEFAULT 0,
      FOREIGN KEY(device_id) REFERENCES devices(device_id)
    );

    CREATE TABLE IF NOT EXISTS blockchain_records (
      tx_id TEXT PRIMARY KEY,
      evidence_hash TEXT NOT NULL,
      device_id TEXT NOT NULL,
      incident_id TEXT,
      timestamp INTEGER NOT NULL,
      block_index INTEGER NOT NULL,
      previous_block_hash TEXT NOT NULL,
      merkle_root TEXT NOT NULL,
      signature TEXT NOT NULL,
      canonical_data TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS response_actions (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      incident_id TEXT,
      action_type TEXT NOT NULL,
      mode TEXT NOT NULL CHECK(mode IN ('RECOMMENDATION', 'SIMULATION', 'EXECUTED')),
      details TEXT NOT NULL,
      initiated_by TEXT NOT NULL,
      executed_at INTEGER NOT NULL,
      status TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      details TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      signature TEXT NOT NULL
    );
  `);

  // Seed default admin user if not exists
  const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (!existingUser) {
    db.prepare(`
      INSERT INTO users (id, username, password_hash, role, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run('USR-ADMIN-1', 'admin', 'sentinel_sha256_admin_hash', 'ADMIN', Date.now());
  }
}
