/**
 * ECHO Canary Beacon v2.0.0
 * Commander Bobby Don McWilliams II — Authority 11.0
 *
 * Canary deployment monitoring for the ECHO OMEGA PRIME fleet.
 * Tracks new deployments, monitors health during rollout period,
 * and triggers automatic rollback if error/latency thresholds are breached.
 *
 * Crons:
 *   Every 2 min    — Check all active canary deployments
 *   Daily 3am UTC  — Cleanup old check data (>30 days)
 *   Weekly Monday 6am UTC — Post deployment summary to SWARM_BRAIN MoltBook
 */

// ─── Environment ────────────────────────────────────────────────────────────

export interface Env {
  DB: D1Database;
  HITS: KVNamespace;
  CACHE: KVNamespace;
  SWARM_BRAIN: Fetcher;
  ADMIN_KEY: string;
  WORKER_VERSION: string;
  ECHO_API_KEY: string;
}

// ─── Types ──────────────────────────────────────────────────────────────────

type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal';

interface CanaryDeployment {
  id: string;
  worker_name: string;
  old_version: string;
  new_version: string;
  deploy_source: 'manual' | 'ci' | 'auto';
  status: 'active' | 'healthy' | 'rolled_back' | 'promoted' | 'failed';
  started_at: string;
  promoted_at: string | null;
  rolled_back_at: string | null;
  health_checks_passed: number;
  health_checks_failed: number;
  error_threshold: number;
  latency_threshold_ms: number;
  min_duration_minutes: number;
  created_at: string;
}

interface CanaryCheck {
  id: string;
  deployment_id: string;
  check_type: 'health' | 'latency' | 'error_rate' | 'response_validation';
  result: 'pass' | 'fail' | 'warn';
  value: number;
  threshold: number;
  details: string;
  checked_at: string;
}

interface DeploymentHistory {
  id: string;
  worker_name: string;
  version: string;
  deployed_at: string;
  deployed_by: string;
  commit_sha: string;
  status: 'active' | 'superseded' | 'rolled_back';
  rollback_reason: string | null;
  created_at: string;
}

interface DeployRequest {
  worker_name: string;
  old_version?: string;
  new_version: string;
  deploy_source?: 'manual' | 'ci' | 'auto';
  worker_url?: string;
  error_threshold?: number;
  latency_threshold_ms?: number;
  min_duration_minutes?: number;
  commit_sha?: string;
  deployed_by?: string;
}

interface HealthCheckResult {
  reachable: boolean;
  status_code: number;
  latency_ms: number;
  body: Record<string, unknown> | null;
  error: string | null;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const SERVICE_NAME = 'echo-canary-beacon';
// API_KEY pulled from env at runtime — never hardcoded
const DEFAULT_ERROR_THRESHOLD = 0.05;
const DEFAULT_LATENCY_THRESHOLD_MS = 5000;
const DEFAULT_MIN_DURATION_MINUTES = 30;
const MAX_CONSECUTIVE_FAILURES = 5;
const CHECK_DATA_RETENTION_DAYS = 30;

// ─── Structured Logging ─────────────────────────────────────────────────────

function log(level: LogLevel, message: string, meta: Record<string, unknown> = {}): void {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    service: SERVICE_NAME,
    message,
    ...meta,
  };
  if (level === 'error' || level === 'fatal') {
    console.error(JSON.stringify(entry));
  } else if (level === 'warn') {
    console.warn(JSON.stringify(entry));
  } else {
    console.log(JSON.stringify(entry));
  }
}

// ─── Utilities ──────────────────────────────────────────────────────────────

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  });
}

function cors(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Echo-API-Key, Authorization',
      'Access-Control-Max-Age': '86400',
    },
  });
}

function checkAuth(request: Request, env: Env): boolean {
  const key = request.headers.get('X-Echo-API-Key');
  return key === (env.ECHO_API_KEY || '');
}

function generateId(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const segments = [8, 4, 4, 12];
  return segments
    .map((len) => {
      let s = '';
      for (let i = 0; i < len; i++) {
        s += chars[Math.floor(Math.random() * chars.length)];
      }
      return s;
    })
    .join('-');
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function minutesSince(isoDate: string): number {
  return (Date.now() - new Date(isoDate).getTime()) / 60000;
}

// ─── D1 Schema ──────────────────────────────────────────────────────────────

async function ensureSchema(db: D1Database): Promise<void> {
  const statements = [
    `CREATE TABLE IF NOT EXISTS canary_deployments (
      id TEXT PRIMARY KEY,
      worker_name TEXT NOT NULL,
      old_version TEXT NOT NULL DEFAULT '',
      new_version TEXT NOT NULL,
      deploy_source TEXT NOT NULL DEFAULT 'manual',
      status TEXT NOT NULL DEFAULT 'active',
      started_at TEXT NOT NULL,
      promoted_at TEXT,
      rolled_back_at TEXT,
      health_checks_passed INTEGER NOT NULL DEFAULT 0,
      health_checks_failed INTEGER NOT NULL DEFAULT 0,
      error_threshold REAL DEFAULT 0.05,
      latency_threshold_ms INTEGER DEFAULT 5000,
      min_duration_minutes INTEGER DEFAULT 30,
      created_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS canary_checks (
      id TEXT PRIMARY KEY,
      deployment_id TEXT NOT NULL,
      check_type TEXT NOT NULL,
      result TEXT NOT NULL,
      value REAL,
      threshold REAL,
      details TEXT,
      checked_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS deployment_history (
      id TEXT PRIMARY KEY,
      worker_name TEXT NOT NULL,
      version TEXT NOT NULL,
      deployed_at TEXT NOT NULL,
      deployed_by TEXT NOT NULL DEFAULT 'system',
      commit_sha TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active',
      rollback_reason TEXT,
      created_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS rollback_log (
      id TEXT PRIMARY KEY,
      deployment_id TEXT NOT NULL,
      worker_name TEXT NOT NULL,
      from_version TEXT NOT NULL,
      to_version TEXT NOT NULL,
      reason TEXT NOT NULL,
      initiated_by TEXT NOT NULL DEFAULT 'auto',
      result TEXT NOT NULL DEFAULT 'success',
      error TEXT,
      created_at TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS idx_canary_deployments_status ON canary_deployments(status)`,
    `CREATE INDEX IF NOT EXISTS idx_canary_deployments_worker ON canary_deployments(worker_name)`,
    `CREATE INDEX IF NOT EXISTS idx_canary_checks_deployment ON canary_checks(deployment_id)`,
    `CREATE INDEX IF NOT EXISTS idx_canary_checks_checked_at ON canary_checks(checked_at)`,
    `CREATE INDEX IF NOT EXISTS idx_deployment_history_worker ON deployment_history(worker_name)`,
    `CREATE INDEX IF NOT EXISTS idx_deployment_history_status ON deployment_history(status)`,
    `CREATE INDEX IF NOT EXISTS idx_rollback_log_deployment ON rollback_log(deployment_id)`,
    `CREATE INDEX IF NOT EXISTS idx_rollback_log_worker ON rollback_log(worker_name)`,
  ];

  for (const sql of statements) {
    try {
      await db.prepare(sql).run();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes('already exists')) {
        log('error', 'schema_init_failed', { sql: sql.substring(0, 80), error: msg });
      }
    }
  }
  log('info', 'schema_initialized');
}

// ─── Health Check Engine ────────────────────────────────────────────────────

async function performHealthCheck(workerName: string): Promise<HealthCheckResult> {
  const url = `https://${workerName}.bmcii1976.workers.dev/health`;
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'echo-canary-beacon/2.0.0' },
    });

    clearTimeout(timeout);
    const latency = Date.now() - start;

    let body: Record<string, unknown> | null = null;
    try {
      body = (await resp.json()) as Record<string, unknown>;
    } catch {
      // non-JSON response is acceptable for health endpoint
    }

    return {
      reachable: true,
      status_code: resp.status,
      latency_ms: latency,
      body,
      error: null,
    };
  } catch (err: unknown) {
    const latency = Date.now() - start;
    const msg = err instanceof Error ? err.message : String(err);
    return {
      reachable: false,
      status_code: 0,
      latency_ms: latency,
      body: null,
      error: msg,
    };
  }
}

async function recordCheck(
  db: D1Database,
  deploymentId: string,
  checkType: CanaryCheck['check_type'],
  result: CanaryCheck['result'],
  value: number,
  threshold: number,
  details: string,
): Promise<void> {
  const id = generateId();
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO canary_checks (id, deployment_id, check_type, result, value, threshold, details, checked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(id, deploymentId, checkType, result, value, threshold, details, now)
    .run();
}

// ─── Canary Evaluation Logic ────────────────────────────────────────────────

async function evaluateCanary(
  db: D1Database,
  deployment: CanaryDeployment,
  env: Env,
): Promise<'continue' | 'promote' | 'rollback'> {
  const healthResult = await performHealthCheck(deployment.worker_name);

  // --- Health Check ---
  if (!healthResult.reachable || healthResult.status_code >= 500) {
    await recordCheck(
      db,
      deployment.id,
      'health',
      'fail',
      healthResult.status_code,
      200,
      healthResult.error || `HTTP ${healthResult.status_code}`,
    );
    await db
      .prepare(
        `UPDATE canary_deployments SET health_checks_failed = health_checks_failed + 1 WHERE id = ?`,
      )
      .bind(deployment.id)
      .run();
    log('warn', 'canary_health_check_failed', {
      deployment_id: deployment.id,
      worker: deployment.worker_name,
      status_code: healthResult.status_code,
      error: healthResult.error,
    });
  } else {
    await recordCheck(
      db,
      deployment.id,
      'health',
      'pass',
      healthResult.status_code,
      200,
      `HTTP ${healthResult.status_code} OK`,
    );
    await db
      .prepare(
        `UPDATE canary_deployments SET health_checks_passed = health_checks_passed + 1 WHERE id = ?`,
      )
      .bind(deployment.id)
      .run();
  }

  // --- Latency Check ---
  const latencyResult: CanaryCheck['result'] =
    healthResult.latency_ms > deployment.latency_threshold_ms ? 'fail' : 'pass';
  await recordCheck(
    db,
    deployment.id,
    'latency',
    latencyResult,
    healthResult.latency_ms,
    deployment.latency_threshold_ms,
    `${healthResult.latency_ms}ms (threshold: ${deployment.latency_threshold_ms}ms)`,
  );

  if (latencyResult === 'fail') {
    log('warn', 'canary_latency_exceeded', {
      deployment_id: deployment.id,
      worker: deployment.worker_name,
      latency_ms: healthResult.latency_ms,
      threshold_ms: deployment.latency_threshold_ms,
    });
  }

  // --- Response Validation ---
  if (healthResult.body) {
    const hasStatus = 'status' in healthResult.body;
    const statusOk =
      hasStatus &&
      (healthResult.body['status'] === 'ok' || healthResult.body['status'] === 'healthy');
    const validationResult: CanaryCheck['result'] = statusOk ? 'pass' : 'warn';
    await recordCheck(
      db,
      deployment.id,
      'response_validation',
      validationResult,
      statusOk ? 1 : 0,
      1,
      statusOk
        ? 'Health response contains valid status'
        : `Health status: ${String(healthResult.body['status'] ?? 'missing')}`,
    );
  }

  // --- Re-fetch updated deployment for accurate counts ---
  const updated = await db
    .prepare(`SELECT * FROM canary_deployments WHERE id = ?`)
    .bind(deployment.id)
    .first<CanaryDeployment>();

  if (!updated) return 'continue';

  const totalChecks = updated.health_checks_passed + updated.health_checks_failed;
  const failRate = totalChecks > 0 ? updated.health_checks_failed / totalChecks : 0;

  // --- Error Rate Check ---
  await recordCheck(
    db,
    deployment.id,
    'error_rate',
    failRate > deployment.error_threshold ? 'fail' : 'pass',
    failRate,
    deployment.error_threshold,
    `Error rate: ${(failRate * 100).toFixed(2)}% (threshold: ${(deployment.error_threshold * 100).toFixed(1)}%)`,
  );

  // --- Decision: Rollback if error rate exceeded and enough checks ---
  if (totalChecks >= 3 && failRate > deployment.error_threshold) {
    log('error', 'canary_threshold_breached_rollback', {
      deployment_id: deployment.id,
      worker: deployment.worker_name,
      fail_rate: failRate,
      threshold: deployment.error_threshold,
      total_checks: totalChecks,
    });
    return 'rollback';
  }

  // --- Decision: Rollback if too many consecutive failures ---
  const recentChecks = await db
    .prepare(
      `SELECT result FROM canary_checks
       WHERE deployment_id = ? AND check_type = 'health'
       ORDER BY checked_at DESC LIMIT ?`,
    )
    .bind(deployment.id, MAX_CONSECUTIVE_FAILURES)
    .all<{ result: string }>();

  if (
    recentChecks.results.length >= MAX_CONSECUTIVE_FAILURES &&
    recentChecks.results.every((c) => c.result === 'fail')
  ) {
    log('error', 'canary_consecutive_failures_rollback', {
      deployment_id: deployment.id,
      worker: deployment.worker_name,
      consecutive_failures: MAX_CONSECUTIVE_FAILURES,
    });
    return 'rollback';
  }

  // --- Decision: Promote if monitoring period passed and healthy ---
  const elapsed = minutesSince(deployment.started_at);
  if (elapsed >= deployment.min_duration_minutes && failRate <= deployment.error_threshold) {
    log('info', 'canary_promotion_eligible', {
      deployment_id: deployment.id,
      worker: deployment.worker_name,
      elapsed_minutes: Math.round(elapsed),
      pass_rate: ((1 - failRate) * 100).toFixed(1),
    });
    return 'promote';
  }

  return 'continue';
}

// ─── Promotion & Rollback ───────────────────────────────────────────────────

async function promoteDeployment(db: D1Database, deployment: CanaryDeployment): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(`UPDATE canary_deployments SET status = 'promoted', promoted_at = ? WHERE id = ?`)
    .bind(now, deployment.id)
    .run();

  // Mark in deployment history
  await db
    .prepare(
      `INSERT INTO deployment_history (id, worker_name, version, deployed_at, deployed_by, commit_sha, status, created_at)
       VALUES (?, ?, ?, ?, 'canary-beacon', '', 'active', ?)`,
    )
    .bind(generateId(), deployment.worker_name, deployment.new_version, now, now)
    .run();

  // Supersede old version
  await db
    .prepare(
      `UPDATE deployment_history SET status = 'superseded'
       WHERE worker_name = ? AND version = ? AND status = 'active'`,
    )
    .bind(deployment.worker_name, deployment.old_version)
    .run();

  log('info', 'canary_promoted', {
    deployment_id: deployment.id,
    worker: deployment.worker_name,
    version: deployment.new_version,
    passed: deployment.health_checks_passed,
    failed: deployment.health_checks_failed,
  });
}

async function rollbackDeployment(
  db: D1Database,
  deployment: CanaryDeployment,
  reason: string,
  initiatedBy: 'auto' | 'manual',
): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(`UPDATE canary_deployments SET status = 'rolled_back', rolled_back_at = ? WHERE id = ?`)
    .bind(now, deployment.id)
    .run();

  // Log rollback
  const rollbackId = generateId();
  await db
    .prepare(
      `INSERT INTO rollback_log (id, deployment_id, worker_name, from_version, to_version, reason, initiated_by, result, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'success', ?)`,
    )
    .bind(
      rollbackId,
      deployment.id,
      deployment.worker_name,
      deployment.new_version,
      deployment.old_version,
      reason,
      initiatedBy,
      now,
    )
    .run();

  // Mark in deployment history
  await db
    .prepare(
      `INSERT INTO deployment_history (id, worker_name, version, deployed_at, deployed_by, commit_sha, status, rollback_reason, created_at)
       VALUES (?, ?, ?, ?, 'canary-beacon', '', 'rolled_back', ?, ?)`,
    )
    .bind(
      generateId(),
      deployment.worker_name,
      deployment.new_version,
      now,
      reason,
      now,
    )
    .run();

  log('warn', 'canary_rolled_back', {
    deployment_id: deployment.id,
    worker: deployment.worker_name,
    from_version: deployment.new_version,
    to_version: deployment.old_version,
    reason,
    initiated_by: initiatedBy,
  });
}

// ─── Cron: Check Active Canaries ────────────────────────────────────────────

async function cronCheckCanaries(env: Env): Promise<void> {
  const db = env.DB;
  log('info', 'cron_check_canaries_start');

  const active = await db
    .prepare(`SELECT * FROM canary_deployments WHERE status = 'active' ORDER BY started_at ASC`)
    .all<CanaryDeployment>();

  if (active.results.length === 0) {
    log('info', 'cron_check_canaries_no_active');
    return;
  }

  log('info', 'cron_checking_active_canaries', { count: active.results.length });

  for (const deployment of active.results) {
    try {
      const decision = await evaluateCanary(db, deployment, env);

      if (decision === 'promote') {
        await promoteDeployment(db, deployment);
      } else if (decision === 'rollback') {
        const totalChecks = deployment.health_checks_passed + deployment.health_checks_failed;
        const failRate = totalChecks > 0 ? deployment.health_checks_failed / totalChecks : 1;
        await rollbackDeployment(
          db,
          deployment,
          `Auto-rollback: error rate ${(failRate * 100).toFixed(1)}% exceeds threshold ${(deployment.error_threshold * 100).toFixed(1)}%`,
          'auto',
        );

        // Alert via KV for quick lookup
        await env.HITS.put(
          `alert:rollback:${deployment.worker_name}`,
          JSON.stringify({
            deployment_id: deployment.id,
            worker: deployment.worker_name,
            from_version: deployment.new_version,
            to_version: deployment.old_version,
            reason: 'auto-rollback',
            timestamp: new Date().toISOString(),
          }),
          { expirationTtl: 86400 * 7 },
        );
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      log('error', 'canary_evaluation_error', {
        deployment_id: deployment.id,
        worker: deployment.worker_name,
        error: msg,
      });
    }
  }

  log('info', 'cron_check_canaries_complete', { checked: active.results.length });
}

// ─── Cron: Cleanup Old Data ─────────────────────────────────────────────────

async function cronCleanup(env: Env): Promise<void> {
  const db = env.DB;
  const cutoff = new Date(Date.now() - CHECK_DATA_RETENTION_DAYS * 86400000).toISOString();
  log('info', 'cron_cleanup_start', { cutoff });

  const result = await db
    .prepare(`DELETE FROM canary_checks WHERE checked_at < ?`)
    .bind(cutoff)
    .run();

  // Also clean up old completed deployments (>90 days)
  const deploymentCutoff = new Date(Date.now() - 90 * 86400000).toISOString();
  const deployResult = await db
    .prepare(
      `DELETE FROM canary_deployments WHERE status IN ('promoted', 'rolled_back', 'failed') AND created_at < ?`,
    )
    .bind(deploymentCutoff)
    .run();

  log('info', 'cron_cleanup_complete', {
    checks_deleted: result.meta?.changes ?? 0,
    deployments_deleted: deployResult.meta?.changes ?? 0,
  });
}

// ─── Cron: Weekly Summary ───────────────────────────────────────────────────

async function cronWeeklySummary(env: Env): Promise<void> {
  const db = env.DB;
  const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString();
  log('info', 'cron_weekly_summary_start');

  const promoted = await db
    .prepare(
      `SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'promoted' AND promoted_at > ?`,
    )
    .bind(weekAgo)
    .first<{ cnt: number }>();

  const rolledBack = await db
    .prepare(
      `SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'rolled_back' AND rolled_back_at > ?`,
    )
    .bind(weekAgo)
    .first<{ cnt: number }>();

  const active = await db
    .prepare(`SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'active'`)
    .first<{ cnt: number }>();

  const totalChecks = await db
    .prepare(`SELECT COUNT(*) as cnt FROM canary_checks WHERE checked_at > ?`)
    .bind(weekAgo)
    .first<{ cnt: number }>();

  const rollbacks = await db
    .prepare(`SELECT worker_name, from_version, to_version, reason FROM rollback_log WHERE created_at > ? ORDER BY created_at DESC LIMIT 10`)
    .bind(weekAgo)
    .all<{ worker_name: string; from_version: string; to_version: string; reason: string }>();

  const summary = {
    period: 'weekly',
    promoted: promoted?.cnt ?? 0,
    rolled_back: rolledBack?.cnt ?? 0,
    active: active?.cnt ?? 0,
    total_checks: totalChecks?.cnt ?? 0,
    recent_rollbacks: rollbacks.results,
    generated_at: new Date().toISOString(),
  };

  // Post to MoltBook via SWARM_BRAIN
  try {
    const moltContent = [
      `CANARY BEACON Weekly Report:`,
      `Promoted: ${summary.promoted} | Rolled Back: ${summary.rolled_back} | Active: ${summary.active}`,
      `Total Checks: ${summary.total_checks}`,
      summary.recent_rollbacks.length > 0
        ? `Recent Rollbacks: ${summary.recent_rollbacks.map((r) => `${r.worker_name} (${r.from_version} -> ${r.to_version})`).join(', ')}`
        : 'No rollbacks this week.',
    ].join('\n');

    await env.SWARM_BRAIN.fetch('https://echo-swarm-brain.bmcii1976.workers.dev/moltbook/post', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Echo-API-Key': env.ECHO_API_KEY || '',
      },
      body: JSON.stringify({
        author_id: 'canary-beacon',
        author_name: 'Canary Beacon',
        author_type: 'agent',
        content: moltContent,
        mood: summary.rolled_back > 0 ? 'alert' : 'operational',
        tags: ['canary', 'deployment', 'weekly-report'],
      }),
    });
    log('info', 'moltbook_weekly_summary_posted', summary);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    log('error', 'moltbook_post_failed', { error: msg });
  }

  // Cache summary in KV
  await env.CACHE.put('weekly_summary', JSON.stringify(summary), { expirationTtl: 86400 * 8 });

  log('info', 'cron_weekly_summary_complete', summary);
}

// ─── API Handlers ───────────────────────────────────────────────────────────

async function handleHealth(env: Env): Promise<Response> {
  const active = await env.DB
    .prepare(`SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'active'`)
    .first<{ cnt: number }>();

  const totalHits = await env.HITS.get('total_hits');

  return jsonResponse({
    status: 'ok',
    service: SERVICE_NAME,
    version: env.WORKER_VERSION,
    active_canaries: active?.cnt ?? 0,
    total_hits: parseInt(totalHits || '0'),
    timestamp: new Date().toISOString(),
  });
}

async function handleStats(env: Env): Promise<Response> {
  const db = env.DB;

  const [active, promoted, rolledBack, failed, totalChecks, recentRollbacks] = await Promise.all([
    db.prepare(`SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'active'`).first<{ cnt: number }>(),
    db.prepare(`SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'promoted'`).first<{ cnt: number }>(),
    db.prepare(`SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'rolled_back'`).first<{ cnt: number }>(),
    db.prepare(`SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'failed'`).first<{ cnt: number }>(),
    db.prepare(`SELECT COUNT(*) as cnt FROM canary_checks`).first<{ cnt: number }>(),
    db.prepare(`SELECT COUNT(*) as cnt FROM rollback_log`).first<{ cnt: number }>(),
  ]);

  const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString();
  const weekPromoted = await db
    .prepare(`SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'promoted' AND promoted_at > ?`)
    .bind(weekAgo)
    .first<{ cnt: number }>();
  const weekRolledBack = await db
    .prepare(`SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = 'rolled_back' AND rolled_back_at > ?`)
    .bind(weekAgo)
    .first<{ cnt: number }>();

  return jsonResponse({
    deployments: {
      active: active?.cnt ?? 0,
      promoted: promoted?.cnt ?? 0,
      rolled_back: rolledBack?.cnt ?? 0,
      failed: failed?.cnt ?? 0,
    },
    total_checks: totalChecks?.cnt ?? 0,
    total_rollbacks: recentRollbacks?.cnt ?? 0,
    last_7_days: {
      promoted: weekPromoted?.cnt ?? 0,
      rolled_back: weekRolledBack?.cnt ?? 0,
    },
    timestamp: new Date().toISOString(),
  });
}

async function handleDeploy(request: Request, env: Env): Promise<Response> {
  let body: DeployRequest;
  try {
    body = (await request.json()) as DeployRequest;
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }

  if (!body.worker_name || !body.new_version) {
    return jsonResponse({ error: 'worker_name and new_version are required' }, 400);
  }

  const db = env.DB;
  const now = new Date().toISOString();
  const id = generateId();

  // Check for existing active canary for this worker
  const existing = await db
    .prepare(
      `SELECT id FROM canary_deployments WHERE worker_name = ? AND status = 'active'`,
    )
    .bind(body.worker_name)
    .first<{ id: string }>();

  if (existing) {
    return jsonResponse(
      {
        error: 'Active canary already exists for this worker',
        existing_deployment_id: existing.id,
        hint: 'Promote or rollback the existing canary first',
      },
      409,
    );
  }

  await db
    .prepare(
      `INSERT INTO canary_deployments
       (id, worker_name, old_version, new_version, deploy_source, status, started_at,
        error_threshold, latency_threshold_ms, min_duration_minutes, created_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)`,
    )
    .bind(
      id,
      body.worker_name,
      body.old_version || '',
      body.new_version,
      body.deploy_source || 'manual',
      now,
      body.error_threshold ?? DEFAULT_ERROR_THRESHOLD,
      body.latency_threshold_ms ?? DEFAULT_LATENCY_THRESHOLD_MS,
      body.min_duration_minutes ?? DEFAULT_MIN_DURATION_MINUTES,
      now,
    )
    .run();

  // Also log in deployment history
  await db
    .prepare(
      `INSERT INTO deployment_history
       (id, worker_name, version, deployed_at, deployed_by, commit_sha, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
    )
    .bind(
      generateId(),
      body.worker_name,
      body.new_version,
      now,
      body.deployed_by || 'manual',
      body.commit_sha || '',
      now,
    )
    .run();

  // Store worker URL in KV for health checks (if custom)
  if (body.worker_url) {
    await env.CACHE.put(`worker_url:${body.worker_name}`, body.worker_url);
  }

  // Increment hit counter
  const hits = parseInt((await env.HITS.get('total_hits')) || '0');
  await env.HITS.put('total_hits', String(hits + 1));

  log('info', 'canary_deployment_registered', {
    deployment_id: id,
    worker: body.worker_name,
    old_version: body.old_version || '',
    new_version: body.new_version,
    deploy_source: body.deploy_source || 'manual',
    error_threshold: body.error_threshold ?? DEFAULT_ERROR_THRESHOLD,
    latency_threshold_ms: body.latency_threshold_ms ?? DEFAULT_LATENCY_THRESHOLD_MS,
    min_duration_minutes: body.min_duration_minutes ?? DEFAULT_MIN_DURATION_MINUTES,
  });

  return jsonResponse(
    {
      deployment_id: id,
      worker_name: body.worker_name,
      new_version: body.new_version,
      status: 'active',
      monitoring_started: now,
      min_duration_minutes: body.min_duration_minutes ?? DEFAULT_MIN_DURATION_MINUTES,
      estimated_promotion: new Date(
        Date.now() + (body.min_duration_minutes ?? DEFAULT_MIN_DURATION_MINUTES) * 60000,
      ).toISOString(),
    },
    201,
  );
}

async function handleListDeployments(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  let query: string;
  let binds: unknown[];

  if (status) {
    query = `SELECT * FROM canary_deployments WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    binds = [status, limit, offset];
  } else {
    query = `SELECT * FROM canary_deployments ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    binds = [limit, offset];
  }

  const stmt = env.DB.prepare(query);
  const result = await (binds.length === 3
    ? stmt.bind(binds[0], binds[1], binds[2])
    : stmt.bind(binds[0], binds[1])
  ).all<CanaryDeployment>();

  const total = await env.DB
    .prepare(
      status
        ? `SELECT COUNT(*) as cnt FROM canary_deployments WHERE status = ?`
        : `SELECT COUNT(*) as cnt FROM canary_deployments`,
    )
    .bind(...(status ? [status] : []))
    .first<{ cnt: number }>();

  return jsonResponse({
    deployments: result.results,
    total: total?.cnt ?? 0,
    limit,
    offset,
  });
}

async function handleDeploymentDetail(deploymentId: string, env: Env): Promise<Response> {
  const db = env.DB;

  const deployment = await db
    .prepare(`SELECT * FROM canary_deployments WHERE id = ?`)
    .bind(deploymentId)
    .first<CanaryDeployment>();

  if (!deployment) {
    return jsonResponse({ error: 'Deployment not found' }, 404);
  }

  const checks = await db
    .prepare(
      `SELECT * FROM canary_checks WHERE deployment_id = ? ORDER BY checked_at DESC LIMIT 100`,
    )
    .bind(deploymentId)
    .all<CanaryCheck>();

  const rollbacks = await db
    .prepare(`SELECT * FROM rollback_log WHERE deployment_id = ? ORDER BY created_at DESC`)
    .bind(deploymentId)
    .all();

  const totalChecks = deployment.health_checks_passed + deployment.health_checks_failed;
  const failRate = totalChecks > 0 ? deployment.health_checks_failed / totalChecks : 0;
  const elapsed = minutesSince(deployment.started_at);

  return jsonResponse({
    deployment,
    metrics: {
      total_checks: totalChecks,
      pass_rate: totalChecks > 0 ? ((1 - failRate) * 100).toFixed(2) + '%' : 'N/A',
      fail_rate: totalChecks > 0 ? (failRate * 100).toFixed(2) + '%' : 'N/A',
      elapsed_minutes: Math.round(elapsed),
      remaining_minutes: Math.max(0, Math.round(deployment.min_duration_minutes - elapsed)),
    },
    recent_checks: checks.results,
    rollbacks: rollbacks.results,
  });
}

async function handleForcePromote(deploymentId: string, env: Env): Promise<Response> {
  const db = env.DB;

  const deployment = await db
    .prepare(`SELECT * FROM canary_deployments WHERE id = ?`)
    .bind(deploymentId)
    .first<CanaryDeployment>();

  if (!deployment) {
    return jsonResponse({ error: 'Deployment not found' }, 404);
  }

  if (deployment.status !== 'active') {
    return jsonResponse(
      { error: `Cannot promote: deployment status is '${deployment.status}'` },
      400,
    );
  }

  await promoteDeployment(db, deployment);
  log('info', 'canary_force_promoted', {
    deployment_id: deploymentId,
    worker: deployment.worker_name,
  });

  return jsonResponse({
    message: 'Deployment promoted successfully',
    deployment_id: deploymentId,
    worker: deployment.worker_name,
    version: deployment.new_version,
  });
}

async function handleForceRollback(
  deploymentId: string,
  request: Request,
  env: Env,
): Promise<Response> {
  const db = env.DB;

  const deployment = await db
    .prepare(`SELECT * FROM canary_deployments WHERE id = ?`)
    .bind(deploymentId)
    .first<CanaryDeployment>();

  if (!deployment) {
    return jsonResponse({ error: 'Deployment not found' }, 404);
  }

  if (deployment.status !== 'active') {
    return jsonResponse(
      { error: `Cannot rollback: deployment status is '${deployment.status}'` },
      400,
    );
  }

  let reason = 'Manual rollback';
  try {
    const body = (await request.json()) as { reason?: string };
    if (body.reason) reason = body.reason;
  } catch {
    // body is optional
  }

  await rollbackDeployment(db, deployment, reason, 'manual');

  return jsonResponse({
    message: 'Deployment rolled back successfully',
    deployment_id: deploymentId,
    worker: deployment.worker_name,
    from_version: deployment.new_version,
    to_version: deployment.old_version,
    reason,
  });
}

async function handleHistory(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 500);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  const result = await env.DB
    .prepare(
      `SELECT * FROM deployment_history ORDER BY deployed_at DESC LIMIT ? OFFSET ?`,
    )
    .bind(limit, offset)
    .all<DeploymentHistory>();

  const total = await env.DB
    .prepare(`SELECT COUNT(*) as cnt FROM deployment_history`)
    .first<{ cnt: number }>();

  return jsonResponse({
    history: result.results,
    total: total?.cnt ?? 0,
    limit,
    offset,
  });
}

async function handleWorkerHistory(workerName: string, env: Env): Promise<Response> {
  const deployments = await env.DB
    .prepare(
      `SELECT * FROM canary_deployments WHERE worker_name = ? ORDER BY created_at DESC LIMIT 50`,
    )
    .bind(workerName)
    .all<CanaryDeployment>();

  const history = await env.DB
    .prepare(
      `SELECT * FROM deployment_history WHERE worker_name = ? ORDER BY deployed_at DESC LIMIT 50`,
    )
    .bind(workerName)
    .all<DeploymentHistory>();

  const rollbacks = await env.DB
    .prepare(
      `SELECT * FROM rollback_log WHERE worker_name = ? ORDER BY created_at DESC LIMIT 20`,
    )
    .bind(workerName)
    .all();

  return jsonResponse({
    worker_name: workerName,
    canary_deployments: deployments.results,
    deployment_history: history.results,
    rollbacks: rollbacks.results,
  });
}

// ─── HTML Dashboard ─────────────────────────────────────────────────────────

async function handleDashboard(env: Env): Promise<Response> {
  const db = env.DB;

  const [activeCanaries, recentDeployments, recentRollbacks, stats] = await Promise.all([
    db
      .prepare(`SELECT * FROM canary_deployments WHERE status = 'active' ORDER BY started_at ASC`)
      .all<CanaryDeployment>(),
    db
      .prepare(
        `SELECT * FROM canary_deployments ORDER BY created_at DESC LIMIT 20`,
      )
      .all<CanaryDeployment>(),
    db
      .prepare(`SELECT * FROM rollback_log ORDER BY created_at DESC LIMIT 15`)
      .all<{
        id: string;
        deployment_id: string;
        worker_name: string;
        from_version: string;
        to_version: string;
        reason: string;
        initiated_by: string;
        result: string;
        created_at: string;
      }>(),
    db
      .prepare(
        `SELECT
          (SELECT COUNT(*) FROM canary_deployments WHERE status = 'active') as active,
          (SELECT COUNT(*) FROM canary_deployments WHERE status = 'promoted') as promoted,
          (SELECT COUNT(*) FROM canary_deployments WHERE status = 'rolled_back') as rolled_back,
          (SELECT COUNT(*) FROM canary_deployments WHERE status = 'failed') as failed,
          (SELECT COUNT(*) FROM canary_checks) as total_checks,
          (SELECT COUNT(*) FROM rollback_log) as total_rollbacks`,
      )
      .first<{
        active: number;
        promoted: number;
        rolled_back: number;
        failed: number;
        total_checks: number;
        total_rollbacks: number;
      }>(),
  ]);

  // Build fleet version map from deployment history
  const fleetVersions = await db
    .prepare(
      `SELECT worker_name, version, deployed_at FROM deployment_history
       WHERE status = 'active' ORDER BY worker_name ASC`,
    )
    .all<{ worker_name: string; version: string; deployed_at: string }>();

  const activeRows = activeCanaries.results
    .map((d) => {
      const total = d.health_checks_passed + d.health_checks_failed;
      const failRate = total > 0 ? d.health_checks_failed / total : 0;
      const elapsed = minutesSince(d.started_at);
      const remaining = Math.max(0, d.min_duration_minutes - elapsed);
      const healthClass = failRate > d.error_threshold ? 'status-fail' : 'status-pass';
      const progressPct = Math.min(100, (elapsed / d.min_duration_minutes) * 100);
      return `<tr>
        <td><span class="${healthClass}">${escapeHtml(d.worker_name)}</span></td>
        <td>${escapeHtml(d.old_version || '-')} &rarr; ${escapeHtml(d.new_version)}</td>
        <td>${d.deploy_source}</td>
        <td>${d.health_checks_passed}/${total}</td>
        <td class="${failRate > d.error_threshold ? 'text-red' : 'text-green'}">${(failRate * 100).toFixed(1)}%</td>
        <td>
          <div class="progress-bar"><div class="progress-fill" style="width:${progressPct.toFixed(0)}%"></div></div>
          <small>${Math.round(elapsed)}m / ${d.min_duration_minutes}m (${Math.round(remaining)}m left)</small>
        </td>
        <td>
          <button onclick="forceAction('${d.id}','promote')" class="btn btn-green">Promote</button>
          <button onclick="forceAction('${d.id}','rollback')" class="btn btn-red">Rollback</button>
        </td>
      </tr>`;
    })
    .join('');

  const recentRows = recentDeployments.results
    .map((d) => {
      const statusClass =
        d.status === 'promoted'
          ? 'badge-green'
          : d.status === 'rolled_back'
            ? 'badge-red'
            : d.status === 'active'
              ? 'badge-blue'
              : 'badge-gray';
      return `<tr>
        <td>${escapeHtml(d.worker_name)}</td>
        <td>${escapeHtml(d.new_version)}</td>
        <td><span class="badge ${statusClass}">${d.status}</span></td>
        <td>${d.health_checks_passed} / ${d.health_checks_passed + d.health_checks_failed}</td>
        <td>${d.created_at.replace('T', ' ').substring(0, 19)}</td>
      </tr>`;
    })
    .join('');

  const rollbackRows = recentRollbacks.results
    .map((r) => {
      return `<tr>
        <td>${escapeHtml(r.worker_name)}</td>
        <td>${escapeHtml(r.from_version)} &rarr; ${escapeHtml(r.to_version)}</td>
        <td>${escapeHtml(r.reason)}</td>
        <td><span class="badge ${r.initiated_by === 'auto' ? 'badge-red' : 'badge-yellow'}">${r.initiated_by}</span></td>
        <td><span class="badge ${r.result === 'success' ? 'badge-green' : 'badge-red'}">${r.result}</span></td>
        <td>${r.created_at.replace('T', ' ').substring(0, 19)}</td>
      </tr>`;
    })
    .join('');

  const fleetRows = fleetVersions.results
    .map((f) => {
      return `<tr>
        <td>${escapeHtml(f.worker_name)}</td>
        <td>${escapeHtml(f.version)}</td>
        <td>${f.deployed_at.replace('T', ' ').substring(0, 19)}</td>
      </tr>`;
    })
    .join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Echo Canary Beacon</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#0a0e1a;color:#c8cdd8;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.5}
  .container{max-width:1400px;margin:0 auto;padding:20px}
  header{display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid #1e2740;margin-bottom:24px}
  header h1{font-size:22px;color:#e2e8f0;letter-spacing:0.5px}
  header h1 span{color:#f59e0b}
  .meta{color:#64748b;font-size:12px}
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:28px}
  .stat-card{background:#111827;border:1px solid #1e2740;border-radius:8px;padding:16px;text-align:center}
  .stat-card .value{font-size:28px;font-weight:700;color:#e2e8f0}
  .stat-card .label{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-top:4px}
  .stat-card.active .value{color:#3b82f6}
  .stat-card.promoted .value{color:#22c55e}
  .stat-card.rolled-back .value{color:#ef4444}
  .stat-card.failed .value{color:#f59e0b}
  .section{margin-bottom:28px}
  .section h2{font-size:16px;color:#e2e8f0;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #1e2740;display:flex;align-items:center;gap:8px}
  .section h2 .count{background:#1e2740;color:#94a3b8;font-size:11px;padding:2px 8px;border-radius:10px}
  table{width:100%;border-collapse:collapse;background:#111827;border:1px solid #1e2740;border-radius:8px;overflow:hidden}
  th{background:#0f1629;color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:1px;padding:10px 12px;text-align:left;border-bottom:1px solid #1e2740}
  td{padding:10px 12px;border-bottom:1px solid #1a2035;font-size:13px}
  tr:last-child td{border-bottom:none}
  tr:hover{background:#0f1629}
  .status-pass{color:#22c55e}
  .status-fail{color:#ef4444}
  .text-red{color:#ef4444}
  .text-green{color:#22c55e}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase}
  .badge-green{background:#052e16;color:#22c55e;border:1px solid #166534}
  .badge-red{background:#350a0a;color:#ef4444;border:1px solid #991b1b}
  .badge-blue{background:#0a1e3d;color:#3b82f6;border:1px solid #1e40af}
  .badge-yellow{background:#3d2e0a;color:#f59e0b;border:1px solid #a16207}
  .badge-gray{background:#1e2740;color:#94a3b8;border:1px solid #334155}
  .btn{padding:4px 10px;border:none;border-radius:4px;font-size:11px;font-weight:600;cursor:pointer;text-transform:uppercase;letter-spacing:0.5px}
  .btn-green{background:#166534;color:#22c55e}
  .btn-green:hover{background:#15803d}
  .btn-red{background:#7f1d1d;color:#ef4444}
  .btn-red:hover{background:#991b1b}
  .progress-bar{width:100%;height:6px;background:#1e2740;border-radius:3px;margin-bottom:4px;overflow:hidden}
  .progress-fill{height:100%;background:linear-gradient(90deg,#3b82f6,#22c55e);border-radius:3px;transition:width 0.3s}
  .empty{text-align:center;padding:24px;color:#475569;font-style:italic}
  footer{text-align:center;padding:16px 0;color:#475569;font-size:11px;border-top:1px solid #1e2740;margin-top:32px}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>ECHO</span> Canary Beacon</h1>
    <div class="meta">v${escapeHtml(env.WORKER_VERSION)} | ${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC</div>
  </header>

  <div class="stats-grid">
    <div class="stat-card active"><div class="value">${stats?.active ?? 0}</div><div class="label">Active Canaries</div></div>
    <div class="stat-card promoted"><div class="value">${stats?.promoted ?? 0}</div><div class="label">Promoted</div></div>
    <div class="stat-card rolled-back"><div class="value">${stats?.rolled_back ?? 0}</div><div class="label">Rolled Back</div></div>
    <div class="stat-card failed"><div class="value">${stats?.failed ?? 0}</div><div class="label">Failed</div></div>
    <div class="stat-card"><div class="value">${stats?.total_checks ?? 0}</div><div class="label">Total Checks</div></div>
    <div class="stat-card"><div class="value">${stats?.total_rollbacks ?? 0}</div><div class="label">Total Rollbacks</div></div>
  </div>

  <div class="section">
    <h2>Active Canaries <span class="count">${activeCanaries.results.length}</span></h2>
    ${
      activeCanaries.results.length > 0
        ? `<table>
      <thead><tr><th>Worker</th><th>Version</th><th>Source</th><th>Passed/Total</th><th>Fail Rate</th><th>Progress</th><th>Actions</th></tr></thead>
      <tbody>${activeRows}</tbody>
    </table>`
        : '<div class="empty">No active canary deployments. All workers are stable.</div>'
    }
  </div>

  <div class="section">
    <h2>Recent Deployments <span class="count">${recentDeployments.results.length}</span></h2>
    ${
      recentDeployments.results.length > 0
        ? `<table>
      <thead><tr><th>Worker</th><th>Version</th><th>Status</th><th>Checks</th><th>Created</th></tr></thead>
      <tbody>${recentRows}</tbody>
    </table>`
        : '<div class="empty">No deployment records yet.</div>'
    }
  </div>

  <div class="section">
    <h2>Rollback History <span class="count">${recentRollbacks.results.length}</span></h2>
    ${
      recentRollbacks.results.length > 0
        ? `<table>
      <thead><tr><th>Worker</th><th>Version Change</th><th>Reason</th><th>Initiated By</th><th>Result</th><th>When</th></tr></thead>
      <tbody>${rollbackRows}</tbody>
    </table>`
        : '<div class="empty">No rollbacks recorded. Fleet stability is excellent.</div>'
    }
  </div>

  <div class="section">
    <h2>Fleet Version Map <span class="count">${fleetVersions.results.length}</span></h2>
    ${
      fleetVersions.results.length > 0
        ? `<table>
      <thead><tr><th>Worker</th><th>Active Version</th><th>Deployed At</th></tr></thead>
      <tbody>${fleetRows}</tbody>
    </table>`
        : '<div class="empty">No version map data yet. Register deployments to build the map.</div>'
    }
  </div>
</div>

<footer>Echo Canary Beacon v${escapeHtml(env.WORKER_VERSION)} | Echo Omega Prime Fleet Intelligence | Commander Bobby Don McWilliams II</footer>

<script>
async function forceAction(id, action) {
  if (!confirm('Confirm ' + action + ' for deployment ' + id + '?')) return;
  const key = prompt('Enter API key:');
  if (!key) return;
  try {
    const resp = await fetch('/deployments/' + id + '/' + action, {
      method: 'POST',
      headers: { 'X-Echo-API-Key': key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: 'Manual ' + action + ' from dashboard' })
    });
    const data = await resp.json();
    if (resp.ok) {
      alert(action.charAt(0).toUpperCase() + action.slice(1) + ' successful');
      location.reload();
    } else {
      alert('Error: ' + (data.error || 'Unknown'));
    }
  } catch (e) {
    alert('Request failed: ' + e.message);
  }
}
</script>
</body>
</html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

// ─── Router ─────────────────────────────────────────────────────────────────

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    return cors();
  }

  // Public endpoints (no auth)
  if (path === '/health' && method === 'GET') {
    return handleHealth(env);
  }

  // Dashboard (no auth — read only visual)
  if (path === '/' && method === 'GET') {
    return handleDashboard(env);
  }

  // All other endpoints require auth
  if (!checkAuth(request, env)) {
    log('warn', 'auth_rejected', {
      path,
      method,
      ip: request.headers.get('cf-connecting-ip') || 'unknown',
    });
    return jsonResponse({ error: 'Unauthorized', hint: 'Provide X-Echo-API-Key header' }, 401);
  }

  // GET /stats
  if (path === '/stats' && method === 'GET') {
    return handleStats(env);
  }

  // POST /deploy
  if (path === '/deploy' && method === 'POST') {
    return handleDeploy(request, env);
  }

  // GET /deployments
  if (path === '/deployments' && method === 'GET') {
    return handleListDeployments(request, env);
  }

  // GET /deployments/:id
  const deployDetailMatch = path.match(/^\/deployments\/([a-z0-9-]+)$/);
  if (deployDetailMatch && method === 'GET') {
    return handleDeploymentDetail(deployDetailMatch[1], env);
  }

  // POST /deployments/:id/promote
  const promoteMatch = path.match(/^\/deployments\/([a-z0-9-]+)\/promote$/);
  if (promoteMatch && method === 'POST') {
    return handleForcePromote(promoteMatch[1], env);
  }

  // POST /deployments/:id/rollback
  const rollbackMatch = path.match(/^\/deployments\/([a-z0-9-]+)\/rollback$/);
  if (rollbackMatch && method === 'POST') {
    return handleForceRollback(rollbackMatch[1], request, env);
  }

  // GET /history
  if (path === '/history' && method === 'GET') {
    return handleHistory(request, env);
  }

  // GET /history/:worker
  const historyWorkerMatch = path.match(/^\/history\/([a-z0-9_-]+)$/);
  if (historyWorkerMatch && method === 'GET') {
    return handleWorkerHistory(historyWorkerMatch[1], env);
  }

  // 404
  log('info', 'not_found', { path, method });
  return jsonResponse({ error: 'Not found', path, endpoints: [
    'GET  /              — Dashboard',
    'GET  /health        — Health check',
    'GET  /stats         — Deployment stats',
    'POST /deploy        — Register new canary',
    'GET  /deployments   — List deployments',
    'GET  /deployments/:id — Deployment detail',
    'POST /deployments/:id/promote  — Force promote',
    'POST /deployments/:id/rollback — Force rollback',
    'GET  /history       — Full deployment history',
    'GET  /history/:worker — Worker history',
  ]}, 404);
}

// ─── Cron Dispatcher ────────────────────────────────────────────────────────

async function handleScheduled(
  event: ScheduledEvent,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  const cron = event.cron;
  log('info', 'cron_triggered', { cron });

  try {
    await ensureSchema(env.DB);

    if (cron === '*/2 * * * *') {
      await cronCheckCanaries(env);
    } else if (cron === '0 3 * * *') {
      await cronCleanup(env);
    } else if (cron === '0 6 * * 1') {
      await cronWeeklySummary(env);
    } else {
      log('warn', 'unknown_cron', { cron });
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    log('fatal', 'cron_fatal_error', { cron, error: msg });
  }
}

// ─── Worker Export ──────────────────────────────────────────────────────────

let schemaInitialized = false;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const start = Date.now();

    try {
      // Ensure schema on first request
      if (!schemaInitialized) {
        await ensureSchema(env.DB);
        schemaInitialized = true;
      }

      const response = await handleRequest(request, env);
      const elapsed = Date.now() - start;

      log('info', 'request_handled', {
        method: request.method,
        path: new URL(request.url).pathname,
        status: response.status,
        latency_ms: elapsed,
        ip: request.headers.get('cf-connecting-ip') || 'unknown',
      });

      return response;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      const stack = err instanceof Error ? err.stack : undefined;
      log('fatal', 'unhandled_error', {
        error: msg,
        stack,
        method: request.method,
        path: new URL(request.url).pathname,
      });
      return jsonResponse(
        { error: 'Internal server error', message: msg, service: SERVICE_NAME },
        500,
      );
    }
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(handleScheduled(event, env, ctx));
  },
};
