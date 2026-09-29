import express from 'express';
import path from 'path';
import type { Server } from 'http';
import { createServer as createViteServer } from 'vite';
import { initDatabase, db } from './backend/database/schema.js';
import { TelemetryPipeline } from './backend/services/telemetry_pipeline.js';
import { BlockchainEvidenceService } from './backend/services/blockchain.js';
import { SimulationEngine } from './backend/services/simulation.js';

export async function startServer(options: { host?: string; port?: number } = {}): Promise<Server> {
  const app = express();
  const port = options.port ?? Number(process.env.PORT ?? 3000);
  const host = options.host ?? process.env.HOST ?? '0.0.0.0';
  const appRoot = process.env.SENTINEL_APP_ROOT ?? process.cwd();

  // Initialize SQLite Database schema
  initDatabase();

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Request audit logging
  app.use((req, res, next) => {
    if (req.method !== 'GET') {
      const actor = (req.headers['x-sentinel-user'] as string) || 'admin';
      db.prepare(`
        INSERT INTO audit_logs (id, actor, action, target_type, target_id, details, timestamp, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        'AUD-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
        actor,
        req.method + ' ' + req.path,
        'API_ENDPOINT',
        req.path,
        JSON.stringify(req.body).substring(0, 500),
        Date.now(),
        'SIG_' + Date.now()
      );
    }
    next();
  });

  // ==========================================
  // REST API ENDPOINTS
  // ==========================================

  // 1. Health Check
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', system: 'SENTINEL', version: '1.4.0', mode: 'PRODUCTION' });
  });

  // 2. Trigger Real Native C++ Telemetry Collection from Host
  app.post('/api/telemetry/collect-real', (req, res) => {
    try {
      const deviceId = req.body.device_id || 'SENTINEL-PRIMARY-NODE';
      const payload = TelemetryPipeline.collectFromHost(deviceId);
      const result = TelemetryPipeline.ingestTelemetry(payload);
      res.json({
        success: true,
        source: 'NATIVE_CPP_COLLECTOR',
        payload,
        analysis: result
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // 3. Post Raw Telemetry from Remote Collector Agents
  app.post('/api/telemetry', (req, res) => {
    try {
      const payload = req.body;
      if (!payload || !payload.device_id || !payload.system) {
        return res.status(400).json({ error: 'Malformed telemetry payload' });
      }
      const result = TelemetryPipeline.ingestTelemetry(payload);
      res.json({ success: true, processed: result });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 4. Device Management
  app.get('/api/devices', (req, res) => {
    const isSimulated = req.query.simulated === 'true' ? 1 : 0;
    const devices = db.prepare('SELECT * FROM devices WHERE is_simulated = ? ORDER BY registered_at DESC').all(isSimulated);
    res.json(devices);
  });

  app.get('/api/devices/:id', (req, res) => {
    const device = db.prepare('SELECT * FROM devices WHERE device_id = ?').get(req.params.id);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    res.json(device);
  });

  app.post('/api/devices/authorize', (req, res) => {
    const { device_id, authorized_by = 'SOC-ADMIN' } = req.body;
    db.prepare('UPDATE devices SET authorization_status = ? WHERE device_id = ?').run('AUTHORIZED', device_id);
    db.prepare(`
      INSERT INTO device_authorizations (id, device_id, authorized_by, authorized_at, status)
      VALUES (?, ?, ?, ?, ?)
    `).run('AUTH-' + Date.now(), device_id, authorized_by, Date.now(), 'AUTHORIZED');
    res.json({ success: true, status: 'AUTHORIZED' });
  });

  app.post('/api/devices/revoke', (req, res) => {
    const { device_id, reason = 'Administrator manual revocation' } = req.body;
    db.prepare('UPDATE devices SET authorization_status = ? WHERE device_id = ?').run('REVOKED', device_id);
    res.json({ success: true, status: 'REVOKED' });
  });

  // 5. Device Deep Telemetry Details
  app.get('/api/devices/:id/telemetry', (req, res) => {
    const telemetry = db.prepare('SELECT * FROM telemetry WHERE device_id = ? ORDER BY timestamp DESC LIMIT 30').all(req.params.id);
    res.json(telemetry);
  });

  app.get('/api/devices/:id/network', (req, res) => {
    const connections = db.prepare('SELECT * FROM network_connections WHERE device_id = ? ORDER BY timestamp DESC LIMIT 50').all(req.params.id);
    res.json(connections);
  });

  app.get('/api/devices/:id/processes', (req, res) => {
    const procs = db.prepare('SELECT * FROM processes WHERE device_id = ? ORDER BY timestamp DESC LIMIT 40').all(req.params.id);
    res.json(procs);
  });

  app.get('/api/devices/:id/baseline', (req, res) => {
    const baseline = db.prepare('SELECT * FROM behaviour_baselines WHERE device_id = ?').get(req.params.id);
    if (!baseline) return res.json({ status: 'INSUFFICIENT DATA' });
    res.json(baseline);
  });

  app.get('/api/devices/:id/anomalies', (req, res) => {
    const anomalies = db.prepare('SELECT * FROM anomalies WHERE device_id = ? ORDER BY timestamp DESC LIMIT 20').all(req.params.id);
    res.json(anomalies);
  });

  app.get('/api/devices/:id/predictions', (req, res) => {
    const predictions = db.prepare('SELECT * FROM predictions WHERE device_id = ? ORDER BY timestamp DESC LIMIT 20').all(req.params.id);
    res.json(predictions);
  });

  app.get('/api/devices/:id/risk', (req, res) => {
    const risk = db.prepare('SELECT * FROM risk_scores WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1').get(req.params.id);
    if (!risk) return res.json({ status: 'INSUFFICIENT DATA' });
    res.json(risk);
  });

  // 6. Incidents & Response
  app.get('/api/incidents', (req, res) => {
    const isSimulated = req.query.simulated === 'true' ? 1 : 0;
    const incidents = db.prepare('SELECT * FROM incidents WHERE is_simulated = ? ORDER BY created_at DESC LIMIT 50').all(isSimulated);
    res.json(incidents);
  });

  app.post('/api/response/action', (req, res) => {
    const { device_id, incident_id, action_type, mode = 'RECOMMENDATION' } = req.body;
    const actionId = 'ACT-' + Date.now();
    db.prepare(`
      INSERT INTO response_actions (id, device_id, incident_id, action_type, mode, details, initiated_by, executed_at, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      actionId,
      device_id,
      incident_id || null,
      action_type,
      mode,
      `Executed ${mode} response action for ${action_type} on target ${device_id}`,
      'SOC-ANALYST',
      Date.now(),
      mode === 'RECOMMENDATION' ? 'PROPOSED' : 'EXECUTED'
    );

    // If containment requested, update incident status
    if (incident_id) {
      db.prepare('UPDATE incidents SET status = ? WHERE id = ?').run('CONTAINED', incident_id);
    }

    res.json({ success: true, action_id: actionId, status: 'RECORDED' });
  });

  // 7. Blockchain Evidence Verification
  app.get('/api/evidence/records', (req, res) => {
    const records = BlockchainEvidenceService.getAllRecords(50);
    res.json(records);
  });

  app.post('/api/evidence/verify', (req, res) => {
    const { tx_id } = req.body;
    if (!tx_id) return res.status(400).json({ error: 'tx_id is required' });
    const result = BlockchainEvidenceService.verifyEvidence(tx_id);
    res.json(result);
  });

  // 8. Dashboard Overview & Analytics
  app.get('/api/dashboard/overview', (req, res) => {
    const isSimulated = req.query.simulated === 'true' ? 1 : 0;

    const totalDevices = db.prepare('SELECT COUNT(*) as count FROM devices WHERE is_simulated = ?').get(isSimulated) as any;
    const activeThreats = db.prepare('SELECT COUNT(*) as count FROM risk_scores WHERE is_simulated = ? AND risk_score > 60').get(isSimulated) as any;
    const openIncidents = db.prepare('SELECT COUNT(*) as count FROM incidents WHERE is_simulated = ? AND status = ?').get(isSimulated, 'OPEN') as any;
    const avgRisk = db.prepare('SELECT AVG(risk_score) as avg FROM risk_scores WHERE is_simulated = ?').get(isSimulated) as any;

    const recentAlerts = db.prepare(`
      SELECT * FROM risk_scores
      WHERE is_simulated = ?
      ORDER BY timestamp DESC
      LIMIT 10
    `).all(isSimulated);

    const latestRisk = db.prepare(`
      SELECT r.*, d.hostname FROM risk_scores r
      JOIN devices d ON r.device_id = d.device_id
      WHERE r.is_simulated = ?
      ORDER BY r.timestamp DESC
      LIMIT 5
    `).all(isSimulated);

    // Calculate Cyber Health Score from actual data
    let cyberHealthScore: number | null = null;
    if (avgRisk && avgRisk.avg !== null) {
      cyberHealthScore = Math.max(0, Math.min(100, Math.round(100 - avgRisk.avg)));
    }

    res.json({
      total_devices: totalDevices.count,
      online_devices: totalDevices.count,
      offline_devices: 0,
      active_threats: activeThreats.count,
      open_incidents: openIncidents.count,
      average_risk: avgRisk.avg !== null ? Number(avgRisk.avg.toFixed(1)) : null,
      cyber_health_score: cyberHealthScore,
      recent_alerts: recentAlerts,
      top_risk_devices: latestRisk
    });
  });

  // 9. Simulation Controls (Separated strictly)
  app.post('/api/simulation/inject', (req, res) => {
    const { scenario } = req.body;
    if (!['BENIGN', 'BRUTE_FORCE', 'C2_BEACON', 'CRYPTO_MINER'].includes(scenario)) {
      return res.status(400).json({ error: 'Invalid simulation scenario' });
    }
    const result = SimulationEngine.generateSimulatedDevice(scenario);
    res.json({ success: true, scenario, result });
  });

  app.post('/api/simulation/reset', (req, res) => {
    const result = SimulationEngine.clearSimulatedData();
    res.json(result);
  });

  app.get('/api/audit-logs', (req, res) => {
    const logs = db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100').all();
    res.json(logs);
  });

  // Seed Primary Node on startup with initial real telemetry
  try {
    const existing = db.prepare('SELECT COUNT(*) as count FROM devices WHERE is_simulated = 0').get() as any;
    if (existing.count === 0) {
      console.log('[SENTINEL] Harvesting initial host telemetry via native C++ collector...');
      const initPayload = TelemetryPipeline.collectFromHost('SENTINEL-PRIMARY-NODE');
      TelemetryPipeline.ingestTelemetry(initPayload);
      console.log('[SENTINEL] Primary authorized node registered successfully.');
    }
  } catch (err: any) {
    console.warn('[SENTINEL] Could not harvest initial C++ telemetry on boot:', err.message);
  }

  // Vite Middleware for React frontend
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(appRoot, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const server = app.listen(port, host, () => {
    const address = server.address();
    const listeningPort = address && typeof address !== 'string' ? address.port : port;
    console.log(`[SENTINEL CORE] Autonomous Cyber Defense Engine listening on ${host}:${listeningPort}`);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  return server;
}

if (process.env.SENTINEL_DESKTOP !== 'true') {
  void startServer().catch((error: unknown) => {
    console.error('[SENTINEL CORE] Failed to start server:', error);
    process.exitCode = 1;
  });
}

startServer();
