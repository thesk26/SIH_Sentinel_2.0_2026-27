import { execSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import { db } from '../database/schema.js';
import { BlockchainEvidenceService } from './blockchain.js';

export interface TelemetryPayload {
  device_id: string;
  collector_version: string;
  timestamp: number;
  is_simulated: boolean;
  system: {
    hostname: string;
    os_name: string;
    os_version: string;
    architecture: string;
    cpu_percent: number;
    memory_percent: number;
    memory_total_bytes: number;
    memory_used_bytes: number;
    disk_percent: number;
    disk_total_bytes: number;
    disk_used_bytes: number;
    uptime_seconds: number;
    load_avg_1m: number;
    load_avg_5m: number;
    load_avg_15m: number;
  };
  processes: Array<{
    pid: number;
    ppid: number;
    name: string;
    exe_path: string;
    cmdline: string;
    memory_rss_bytes: number;
    thread_count: number;
  }>;
  network_connections: Array<{
    protocol: string;
    local_address: string;
    local_port: number;
    remote_address: string;
    remote_port: number;
    state: string;
  }>;
  security_events: Array<{
    event_id: string;
    event_type: string;
    severity: string;
    source: string;
    description: string;
    timestamp: number;
  }>;
  network_io: {
    bytes_received: number;
    bytes_sent: number;
  };
  evidence_hash?: string;
}

export class TelemetryPipeline {
  // Execute native C++ collector binary to harvest real-time OS telemetry
  public static collectFromHost(deviceId = 'SENTINEL-PRIMARY-NODE'): TelemetryPayload {
    const appRoot = process.env.SENTINEL_APP_ROOT ?? process.cwd();
    const collectorName = process.platform === 'win32' ? 'sentinel_collector.exe' : 'sentinel_collector';
    const collectorBin = path.join(appRoot, 'build', collectorName);
    if (!fs.existsSync(collectorBin)) {
      throw new Error(`Native C++ collector binary not found at ${collectorBin}. Build project first.`);
    }

    try {
      const output = execSync(`"${collectorBin}" "${deviceId}"`, { encoding: 'utf-8', timeout: 5000 });
      // Find JSON block from output
      const jsonStart = output.indexOf('{');
      const jsonEnd = output.lastIndexOf('}');
      if (jsonStart === -1 || jsonEnd === -1) {
        throw new Error('Failed to parse JSON output from C++ collector');
      }
      const rawJson = output.substring(jsonStart, jsonEnd + 1);
      const parsed: TelemetryPayload = JSON.parse(rawJson);
      return parsed;
    } catch (err: any) {
      console.error('Error invoking native C++ collector:', err.message);
      throw err;
    }
  }

  // Ingest & Process Telemetry (Real or Simulation)
  public static ingestTelemetry(payload: TelemetryPayload) {
    const now = Date.now();
    const isSimulated = payload.is_simulated ? 1 : 0;

    // 1. Ensure Device Record Exists
    let device = db.prepare('SELECT * FROM devices WHERE device_id = ?').get(payload.device_id) as any;
    if (!device) {
      // First registration -> auto PENDING or AUTHORIZED for PRIMARY NODE
      const status = payload.device_id === 'SENTINEL-PRIMARY-NODE' ? 'AUTHORIZED' : 'PENDING';
      db.prepare(`
        INSERT INTO devices (
          device_id, hostname, operating_system, os_version, architecture,
          cpu_cores, total_memory_bytes, total_disk_bytes, collector_version,
          registered_at, authorization_status, last_heartbeat, last_telemetry_timestamp, is_simulated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        payload.device_id,
        payload.system.hostname,
        payload.system.os_name,
        payload.system.os_version,
        payload.system.architecture,
        2,
        payload.system.memory_total_bytes,
        payload.system.disk_total_bytes,
        payload.collector_version,
        now,
        status,
        now,
        payload.timestamp || now,
        isSimulated
      );
      device = db.prepare('SELECT * FROM devices WHERE device_id = ?').get(payload.device_id);
    } else {
      // Update heartbeat & specs
      db.prepare(`
        UPDATE devices
        SET last_heartbeat = ?, last_telemetry_timestamp = ?,
            total_memory_bytes = ?, total_disk_bytes = ?,
            hostname = ?, os_version = ?
        WHERE device_id = ?
      `).run(
        now,
        payload.timestamp || now,
        payload.system.memory_total_bytes,
        payload.system.disk_total_bytes,
        payload.system.hostname,
        payload.system.os_version,
        payload.device_id
      );
    }

    // 2. Persist Telemetry Record
    const rawJsonStr = JSON.stringify(payload);
    const evidenceHash = payload.evidence_hash || 'SHA256_UNSET';

    const insertTelem = db.prepare(`
      INSERT INTO telemetry (
        device_id, timestamp, is_simulated, cpu_percent, memory_percent,
        memory_used_bytes, disk_percent, uptime_seconds, network_bytes_sent,
        network_bytes_recv, active_connections_count, active_processes_count,
        evidence_hash, raw_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      payload.device_id,
      payload.timestamp || now,
      isSimulated,
      payload.system.cpu_percent,
      payload.system.memory_percent,
      payload.system.memory_used_bytes,
      payload.system.disk_percent,
      payload.system.uptime_seconds,
      payload.network_io.bytes_sent,
      payload.network_io.bytes_received,
      payload.network_connections.length,
      payload.processes.length,
      evidenceHash,
      rawJsonStr
    );
    const telemetryId = insertTelem.lastInsertRowid;

    // 3. Persist Network Connections
    const insertConn = db.prepare(`
      INSERT INTO network_connections (device_id, telemetry_id, timestamp, protocol, local_address, local_port, remote_address, remote_port, state)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const c of payload.network_connections) {
      insertConn.run(
        payload.device_id,
        telemetryId,
        payload.timestamp || now,
        c.protocol,
        c.local_address,
        c.local_port,
        c.remote_address,
        c.remote_port,
        c.state
      );
    }

    // 4. Persist Security Events
    const insertSecEvent = db.prepare(`
      INSERT OR REPLACE INTO security_events (id, device_id, timestamp, event_type, severity, source, description, raw_event)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const ev of payload.security_events) {
      insertSecEvent.run(
        ev.event_id,
        payload.device_id,
        ev.timestamp || now,
        ev.event_type,
        ev.severity,
        ev.source,
        ev.description,
        ev.description
      );
    }

    // 5. Update Behavioural Baseline
    const baseline = this.updateBaseline(payload.device_id, payload);

    // 6. Anomaly Detection
    const anomaly = this.detectAnomalies(payload, baseline);

    // 7. Temporal Attack Forecasting
    const forecast = this.forecastAttack(payload, anomaly);

    // 8. Explainable Risk Score
    const risk = this.computeRisk(payload, anomaly, forecast, device.authorization_status);

    // 9. Incident Trigger if Risk is High/Critical
    if (risk.risk_score >= 60 || anomaly.anomaly_score >= 70) {
      const incidentId = 'INC-' + Math.floor(Math.random() * 90000 + 10000);
      const severity = risk.risk_score >= 80 ? 'CRITICAL' : 'HIGH';
      
      db.prepare(`
        INSERT INTO incidents (
          id, device_id, title, severity, status, risk_score, explanation, evidence, recommended_actions, created_at, updated_at, is_simulated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        incidentId,
        payload.device_id,
        `${risk.classification}: ${forecast.current_stage}`,
        severity,
        'OPEN',
        risk.risk_score,
        risk.key_reasons.join(' | '),
        risk.primary_evidence,
        risk.recommended_response,
        now,
        now,
        isSimulated
      );

      // 10. Record Forensic Evidence to Blockchain
      BlockchainEvidenceService.recordEvidence(
        payload.device_id,
        {
          incident_id: incidentId,
          device_id: payload.device_id,
          telemetry_evidence_hash: evidenceHash,
          risk_score: risk.risk_score,
          forecast_stage: forecast.current_stage,
          reasons: risk.key_reasons,
          timestamp: now
        },
        incidentId
      );
    }

    return {
      device,
      baseline,
      anomaly,
      forecast,
      risk
    };
  }

  private static updateBaseline(deviceId: string, payload: TelemetryPayload) {
    const history = db.prepare(`
      SELECT cpu_percent, memory_percent, active_connections_count, active_processes_count
      FROM telemetry
      WHERE device_id = ?
      ORDER BY timestamp DESC
      LIMIT 50
    `).all(deviceId) as Array<{ cpu_percent: number; memory_percent: number; active_connections_count: number; active_processes_count: number }>;

    const cpuVals = history.map(h => h.cpu_percent);
    const memVals = history.map(h => h.memory_percent);
    const connVals = history.map(h => h.active_connections_count);

    const calcMean = (arr: number[]) => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
    const calcStd = (arr: number[], mean: number) => arr.length > 1 ? Math.sqrt(arr.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / (arr.length - 1)) : 0;

    const cpuMean = calcMean(cpuVals);
    const cpuStd = calcStd(cpuVals, cpuMean);
    const memMean = calcMean(memVals);
    const memStd = calcStd(memVals, memMean);
    const connMean = calcMean(connVals);
    const connStd = calcStd(connVals, connMean);

    // Existing baseline
    const existing = db.prepare('SELECT * FROM behaviour_baselines WHERE device_id = ?').get(deviceId) as any;
    const knownIps: Set<string> = existing ? new Set(JSON.parse(existing.known_remote_ips || '[]')) : new Set();
    const knownProcs: Set<string> = existing ? new Set(JSON.parse(existing.known_processes || '[]')) : new Set();

    for (const c of payload.network_connections) {
      if (c.remote_address && c.remote_address !== '0.0.0.0' && c.remote_address !== '127.0.0.1') {
        knownIps.add(c.remote_address);
      }
    }
    for (const p of payload.processes) {
      if (p.name) knownProcs.add(p.name);
    }

    const baselineData = {
      device_id: deviceId,
      last_updated: Date.now(),
      total_telemetry_windows: history.length,
      cpu_mean: cpuMean,
      cpu_stddev: cpuStd,
      cpu_p95: cpuMean + (1.645 * cpuStd),
      mem_mean: memMean,
      mem_stddev: memStd,
      net_conn_mean: connMean,
      net_conn_stddev: connStd,
      known_remote_ips: JSON.stringify(Array.from(knownIps).slice(-100)),
      known_processes: JSON.stringify(Array.from(knownProcs).slice(-100))
    };

    db.prepare(`
      INSERT OR REPLACE INTO behaviour_baselines (
        device_id, last_updated, total_telemetry_windows, cpu_mean, cpu_stddev, cpu_p95,
        mem_mean, mem_stddev, net_conn_mean, net_conn_stddev, known_remote_ips, known_processes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      baselineData.device_id,
      baselineData.last_updated,
      baselineData.total_telemetry_windows,
      baselineData.cpu_mean,
      baselineData.cpu_stddev,
      baselineData.cpu_p95,
      baselineData.mem_mean,
      baselineData.mem_stddev,
      baselineData.net_conn_mean,
      baselineData.net_conn_stddev,
      baselineData.known_remote_ips,
      baselineData.known_processes
    );

    return baselineData;
  }

  private static detectAnomalies(payload: TelemetryPayload, baseline: any) {
    const isSimulated = payload.is_simulated ? 1 : 0;
    const contributing_factors: any[] = [];
    const summary_reasons: string[] = [];
    let anomalyScore = 0;

    if (baseline.total_telemetry_windows < 3) {
      summary_reasons.push('Baseline actively learning (insufficient historical observation windows).');
    } else {
      // CPU anomaly
      const cpuZ = baseline.cpu_stddev > 0.1 ? (payload.system.cpu_percent - baseline.cpu_mean) / baseline.cpu_stddev : 0;
      if (cpuZ > 2.0 && payload.system.cpu_percent > 65.0) {
        const impact = Math.min(25, (cpuZ - 2.0) * 8.0);
        anomalyScore += impact;
        contributing_factors.push({
          feature_name: 'CPU Utilization',
          baseline_value: baseline.cpu_mean,
          current_value: payload.system.cpu_percent,
          deviation_ratio: baseline.cpu_mean > 0 ? (payload.system.cpu_percent / baseline.cpu_mean) : 1.0,
          contribution_weight: impact / 100,
          explanation: `CPU usage (${payload.system.cpu_percent.toFixed(1)}%) is ${(payload.system.cpu_percent / (baseline.cpu_mean || 1)).toFixed(1)}x above baseline expectation.`
        });
        summary_reasons.push(contributing_factors[contributing_factors.length - 1].explanation);
      }

      // Connection anomaly
      const connCount = payload.network_connections.length;
      const connZ = baseline.net_conn_stddev > 0.1 ? (connCount - baseline.net_conn_mean) / baseline.net_conn_stddev : 0;
      if (connZ > 2.5 || (baseline.net_conn_mean > 0 && connCount > baseline.net_conn_mean * 3)) {
        const impact = Math.min(30, Math.max(10, connZ * 7.0));
        anomalyScore += impact;
        contributing_factors.push({
          feature_name: 'Network Connection Frequency',
          baseline_value: baseline.net_conn_mean,
          current_value: connCount,
          deviation_ratio: baseline.net_conn_mean > 0 ? (connCount / baseline.net_conn_mean) : 2.0,
          contribution_weight: impact / 100,
          explanation: `Network connection count (${connCount}) rose ${(connCount / (baseline.net_conn_mean || 1)).toFixed(1)}x compared to historical mean.`
        });
        summary_reasons.push(contributing_factors[contributing_factors.length - 1].explanation);
      }

      // Unseen remote IPs
      const knownIps: string[] = JSON.parse(baseline.known_remote_ips || '[]');
      const novelIps = payload.network_connections
        .map(c => c.remote_address)
        .filter(ip => ip && ip !== '0.0.0.0' && ip !== '127.0.0.1' && !knownIps.includes(ip));
      
      const uniqueNovelIps = Array.from(new Set(novelIps));
      if (uniqueNovelIps.length > 0) {
        const impact = Math.min(35, uniqueNovelIps.length * 12);
        anomalyScore += impact;
        contributing_factors.push({
          feature_name: 'Novel Destination IP Interaction',
          baseline_value: knownIps.length,
          current_value: uniqueNovelIps.length,
          deviation_ratio: uniqueNovelIps.length,
          contribution_weight: impact / 100,
          explanation: `Observed communication with ${uniqueNovelIps.length} unverified external destination(s) [e.g. ${uniqueNovelIps[0]}].`
        });
        summary_reasons.push(contributing_factors[contributing_factors.length - 1].explanation);
      }

      // Security / Auth failures
      const authFails = payload.security_events.filter(e => e.event_type === 'AUTH_FAILURE').length;
      if (authFails > 0) {
        const impact = Math.min(40, authFails * 15);
        anomalyScore += impact;
        contributing_factors.push({
          feature_name: 'Authentication Security Events',
          baseline_value: 0,
          current_value: authFails,
          deviation_ratio: authFails,
          contribution_weight: impact / 100,
          explanation: `Recorded ${authFails} authentication failure / brute-force events.`
        });
        summary_reasons.push(contributing_factors[contributing_factors.length - 1].explanation);
      }
    }

    anomalyScore = Math.min(100, Math.max(0, anomalyScore));
    let level = 'NORMAL';
    if (anomalyScore >= 75) level = 'HIGH_ANOMALY';
    else if (anomalyScore >= 50) level = 'MEDIUM_ANOMALY';
    else if (anomalyScore >= 25) level = 'LOW_ANOMALY';

    if (!summary_reasons.length) {
      summary_reasons.push('Telemetry aligned with historical baseline profiles.');
    }

    const anomalyId = 'ANOM-' + Date.now();
    db.prepare(`
      INSERT INTO anomalies (id, device_id, timestamp, anomaly_score, anomaly_level, contributing_factors, summary_reasons, is_simulated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      anomalyId,
      payload.device_id,
      payload.timestamp || Date.now(),
      anomalyScore,
      level,
      JSON.stringify(contributing_factors),
      JSON.stringify(summary_reasons),
      isSimulated
    );

    return {
      anomaly_score: anomalyScore,
      anomaly_level: level,
      contributing_factors,
      summary_reasons
    };
  }

  private static forecastAttack(payload: TelemetryPayload, anomaly: any) {
    const isSimulated = payload.is_simulated ? 1 : 0;
    const authFails = payload.security_events.filter(e => e.event_type === 'AUTH_FAILURE').length;
    const hasSuspiciousPort = payload.network_connections.some(c => [4444, 1337, 6667, 8080, 9001].includes(c.remote_port));
    const novelIpFactor = anomaly.contributing_factors.some((f: any) => f.feature_name === 'Novel Destination IP Interaction');

    let current_stage = 'Benign / Normal Operations';
    let predicted_next_stage = 'Benign / Normal Operations';
    let confidence = 0.95;
    let attack_risk_probability = 0.05;
    let forecast_hypothesis = 'Continuous temporal sequence exhibits benign baseline behavior.';
    const supporting_evidence: string[] = ['Telemetry variance strictly matches nominal operating bounds.'];
    const recommended_mitigations: string[] = ['Maintain continuous behavioral telemetry collection.'];

    if (authFails >= 2) {
      current_stage = 'Credential Access (TA0006)';
      predicted_next_stage = 'Privilege Escalation (TA0004)';
      confidence = 0.85;
      attack_risk_probability = 0.82;
      forecast_hypothesis = 'Sequential authentication failures indicate active credential spraying. High probability of subsequent sudo token manipulation or local privilege escalation.';
      supporting_evidence.push(`${authFails} authentication failures detected in session logs.`);
      supporting_evidence.push(`Anomaly score elevated to ${anomaly.anomaly_score.toFixed(0)}/100.`);
      recommended_mitigations.push('Invalidate current user session tokens and require MFA verification.');
      recommended_mitigations.push('Enable auditd syscall monitoring on /etc/sudoers and /etc/shadow.');
    } else if ((hasSuspiciousPort || novelIpFactor) && anomaly.anomaly_score > 35) {
      current_stage = 'Command and Control (TA0011)';
      predicted_next_stage = 'Exfiltration (TA0010)';
      confidence = 0.88;
      attack_risk_probability = 0.86;
      forecast_hypothesis = 'High-frequency telemetry egress to unverified remote destination aligns with beaconing sequence. Next phase anticipates outbound data staging and exfiltration.';
      supporting_evidence.push('Outbound connection established to unverified external IP.');
      supporting_evidence.push('Network connection frequency deviates from baseline.');
      recommended_mitigations.push('Temporarily apply egress filtering to target destination port.');
      recommended_mitigations.push('Preserve socket tables and memory state for chain-of-custody verification.');
    } else if (payload.system.cpu_percent > 85 && anomaly.anomaly_score > 30) {
      current_stage = 'Execution (TA0002)';
      predicted_next_stage = 'Persistence (TA0003)';
      confidence = 0.72;
      attack_risk_probability = 0.68;
      forecast_hypothesis = 'Sustained compute spike accompanied by new binary process tree. Progression pattern suggests staging persistence through systemd or cron services.';
      supporting_evidence.push(`CPU sustained at ${payload.system.cpu_percent.toFixed(1)}%.`);
      recommended_mitigations.push('Inspect binary sha256 checksum and verify against threat intelligence feeds.');
    }

    const predictionId = 'PRED-' + Date.now();
    db.prepare(`
      INSERT INTO predictions (
        id, device_id, timestamp, current_stage, predicted_next_stage,
        confidence, attack_risk_probability, forecast_hypothesis, supporting_evidence, recommended_mitigations, is_simulated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      predictionId,
      payload.device_id,
      payload.timestamp || Date.now(),
      current_stage,
      predicted_next_stage,
      confidence,
      attack_risk_probability,
      forecast_hypothesis,
      JSON.stringify(supporting_evidence),
      JSON.stringify(recommended_mitigations),
      isSimulated
    );

    return {
      current_stage,
      predicted_next_stage,
      confidence,
      attack_risk_probability,
      forecast_hypothesis,
      supporting_evidence,
      recommended_mitigations
    };
  }

  private static computeRisk(payload: TelemetryPayload, anomaly: any, forecast: any, authStatus: string) {
    const isSimulated = payload.is_simulated ? 1 : 0;
    let authPenalty = 0;
    const reasons: string[] = [];

    if (authStatus === 'REVOKED') {
      authPenalty = 100;
      reasons.push('Device authorization has been revoked by SOC admin.');
    } else if (authStatus === 'PENDING') {
      authPenalty = 50;
      reasons.push('Device status is pending administrative approval.');
    } else if (authStatus === 'EXPIRED') {
      authPenalty = 70;
      reasons.push('Device identity certificate has expired.');
    }

    const anomalyComp = anomaly.anomaly_score;
    const forecastComp = forecast.attack_risk_probability * 100;
    const authFails = payload.security_events.filter(e => e.event_type === 'AUTH_FAILURE').length;
    const secEventComp = Math.min(100, authFails * 35);

    const riskScore = Math.min(100, Math.max(0, 
      (authPenalty * 0.20) +
      (anomalyComp * 0.35) +
      (forecastComp * 0.30) +
      (secEventComp * 0.15)
    ));

    let riskLevel = 'LOW';
    let classification = 'NORMAL';
    let recommendedResponse = 'MONITOR';

    if (riskScore <= 20) {
      riskLevel = 'LOW';
      classification = 'NORMAL';
      recommendedResponse = 'MONITOR';
    } else if (riskScore <= 40) {
      riskLevel = 'GUARDED';
      classification = anomalyComp > 30 ? 'ANOMALY' : 'NORMAL';
      recommendedResponse = 'MONITOR';
    } else if (riskScore <= 60) {
      riskLevel = 'MEDIUM';
      classification = 'POTENTIAL THREAT';
      recommendedResponse = 'INVESTIGATE';
    } else if (riskScore <= 80) {
      riskLevel = 'HIGH';
      classification = (authFails > 1 || forecast.confidence > 0.8) ? 'VERIFIED THREAT' : 'POTENTIAL THREAT';
      recommendedResponse = 'CHALLENGE';
    } else {
      riskLevel = 'CRITICAL';
      classification = 'VERIFIED THREAT';
      recommendedResponse = 'PRESERVE_EVIDENCE_AND_ISOLATE';
    }

    for (const r of anomaly.summary_reasons) {
      if (!r.includes('insufficient') && !r.includes('aligned')) {
        reasons.push(r);
      }
    }
    if (forecast.forecast_hypothesis && forecast.attack_risk_probability > 0.3) {
      reasons.push(forecast.forecast_hypothesis);
    }
    if (!reasons.length) {
      reasons.push('Telemetry baseline confirms nominal security posture.');
    }

    const primaryEvidence = `Telemetry timestamp: ${payload.timestamp} | CPU: ${payload.system.cpu_percent.toFixed(1)}% | RAM: ${payload.system.memory_percent.toFixed(1)}% | Connections: ${payload.network_connections.length}`;

    const riskId = 'RISK-' + Date.now();
    db.prepare(`
      INSERT INTO risk_scores (
        id, device_id, timestamp, risk_score, risk_level, classification,
        confidence, key_reasons, primary_evidence, recommended_response, is_simulated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      riskId,
      payload.device_id,
      payload.timestamp || Date.now(),
      riskScore,
      riskLevel,
      classification,
      forecast.confidence,
      JSON.stringify(reasons),
      primaryEvidence,
      recommendedResponse,
      isSimulated
    );

    return {
      risk_score: riskScore,
      risk_level: riskLevel,
      classification,
      confidence: forecast.confidence,
      key_reasons: reasons,
      primary_evidence: primaryEvidence,
      recommended_response: recommendedResponse
    };
  }
}
