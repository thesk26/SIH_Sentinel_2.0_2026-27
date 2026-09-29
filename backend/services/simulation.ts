import { TelemetryPipeline, TelemetryPayload } from './telemetry_pipeline.js';
import { db } from '../database/schema.js';

export class SimulationEngine {
  public static generateSimulatedDevice(scenario: 'BENIGN' | 'BRUTE_FORCE' | 'C2_BEACON' | 'CRYPTO_MINER') {
    const deviceId = `SIM-NODE-${scenario.toLowerCase()}-01`;
    const now = Date.now();

    // Base telemetry template
    const payload: TelemetryPayload = {
      device_id: deviceId,
      collector_version: '1.4.0-cpp20-sim',
      timestamp: now,
      is_simulated: true,
      system: {
        hostname: `simulated-endpoint-${scenario.toLowerCase()}`,
        os_name: 'Linux',
        os_version: '5.15.0-generic-sim',
        architecture: 'x86_64',
        cpu_percent: 18.5,
        memory_percent: 32.0,
        memory_total_bytes: 8589934592,
        memory_used_bytes: 2748779069,
        disk_percent: 41.2,
        disk_total_bytes: 256000000000,
        disk_used_bytes: 105472000000,
        uptime_seconds: 43200,
        load_avg_1m: 0.25,
        load_avg_5m: 0.30,
        load_avg_15m: 0.28
      },
      processes: [
        { pid: 1, ppid: 0, name: 'systemd', exe_path: '/usr/lib/systemd/systemd', cmdline: '/sbin/init', memory_rss_bytes: 8400000, thread_count: 1 },
        { pid: 402, ppid: 1, name: 'sshd', exe_path: '/usr/sbin/sshd', cmdline: '/usr/sbin/sshd -D', memory_rss_bytes: 6500000, thread_count: 1 },
        { pid: 810, ppid: 1, name: 'nginx', exe_path: '/usr/sbin/nginx', cmdline: 'nginx: master', memory_rss_bytes: 12000000, thread_count: 4 }
      ],
      network_connections: [
        { protocol: 'tcp', local_address: '10.0.1.45', local_port: 22, remote_address: '10.0.1.1', remote_port: 52140, state: 'ESTABLISHED' },
        { protocol: 'tcp', local_address: '10.0.1.45', local_port: 443, remote_address: '10.0.1.200', remote_port: 48920, state: 'ESTABLISHED' }
      ],
      security_events: [],
      network_io: {
        bytes_received: 10485760,
        bytes_sent: 5242880
      },
      evidence_hash: 'SIM_EVIDENCE_' + now
    };

    if (scenario === 'BENIGN') {
      // Normal stable baseline
      payload.system.cpu_percent = 22.4;
      payload.system.memory_percent = 34.1;
    } else if (scenario === 'BRUTE_FORCE') {
      // Authentication Spray Attack
      payload.system.cpu_percent = 45.0;
      payload.security_events = [
        { event_id: `EV-SIM-${now}-1`, event_type: 'AUTH_FAILURE', severity: 'HIGH', source: '/var/log/auth.log', description: 'Failed SSH login for invalid user admin from 198.51.100.23 port 41200', timestamp: now - 2000 },
        { event_id: `EV-SIM-${now}-2`, event_type: 'AUTH_FAILURE', severity: 'HIGH', source: '/var/log/auth.log', description: 'Failed SSH login for root from 198.51.100.23 port 41202', timestamp: now - 1000 },
        { event_id: `EV-SIM-${now}-3`, event_type: 'AUTH_FAILURE', severity: 'HIGH', source: '/var/log/auth.log', description: 'Repeated authentication failure: 14 invalid attempts in 60s', timestamp: now }
      ];
    } else if (scenario === 'C2_BEACON') {
      // C2 communication to external IP with unusual port
      payload.system.cpu_percent = 28.0;
      payload.network_connections.push(
        { protocol: 'tcp', local_address: '10.0.1.45', local_port: 55432, remote_address: '185.220.101.5', remote_port: 4444, state: 'ESTABLISHED' },
        { protocol: 'tcp', local_address: '10.0.1.45', local_port: 55433, remote_address: '185.220.101.5', remote_port: 4444, state: 'SYN_SENT' },
        { protocol: 'tcp', local_address: '10.0.1.45', local_port: 55434, remote_address: '185.220.101.5', remote_port: 4444, state: 'ESTABLISHED' }
      );
      payload.network_io.bytes_sent = 85940000;
    } else if (scenario === 'CRYPTO_MINER') {
      // High CPU sustained spike
      payload.system.cpu_percent = 97.8;
      payload.processes.push({
        pid: 9482,
        ppid: 1,
        name: 'xmrig_worker',
        exe_path: '/tmp/.kworker',
        cmdline: './.kworker --algo rx/0 --url pool.minexmr.com:4444',
        memory_rss_bytes: 524288000,
        thread_count: 8
      });
    }

    // Ingest simulated device
    return TelemetryPipeline.ingestTelemetry(payload);
  }

  public static clearSimulatedData() {
    db.prepare('DELETE FROM telemetry WHERE is_simulated = 1').run();
    db.prepare('DELETE FROM anomalies WHERE is_simulated = 1').run();
    db.prepare('DELETE FROM predictions WHERE is_simulated = 1').run();
    db.prepare('DELETE FROM risk_scores WHERE is_simulated = 1').run();
    db.prepare('DELETE FROM incidents WHERE is_simulated = 1').run();
    db.prepare('DELETE FROM devices WHERE is_simulated = 1').run();
    return { success: true };
  }
}
