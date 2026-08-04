#!/usr/bin/env python3
"""Echo Canary Beacon — FORGE migration of the legacy CF worker `echo-canary-beacon`.

Canary deployment monitoring for the ECHO OMEGA PRIME fleet.
Tracks new deployments, monitors health during rollout period,
and triggers automatic rollback if error/latency thresholds are breached.

Follows the ShadowGlass/echo-coin-rewards template exactly (NO CLOUDFLARE:
D1/KV -> Postgres schema `canary_beacon`, R2 n/a, crons -> scheduler endpoints,
SWARM_BRAIN -> http or log). Faithful reconstruction of all routes, handlers,
health check engine, evaluate logic, promote/rollback, scheduled crons.

Run: uvicorn app:app --host 0.0.0.0 --port 8094   (systemd: echo-canary-beacon)
"""
from __future__ import annotations
import re
import socket
import ipaddress
from fastapi import Request
from fastapi.responses import JSONResponse
import hmac

import json
import logging
import os

from credential_config import required_env
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [canary-beacon] %(levelname)s %(message)s"
)
logger = logging.getLogger("canary_beacon")

PG = dict(
    host=os.environ.get("PGHOST", "localhost"),
    user=os.environ.get("PGUSER", "echo"),
    password=required_env("PGPASSWORD"),
    dbname=os.environ.get("PGDATABASE", "echo"),
)
SWARM_BRAIN_URL = os.environ.get("SWARM_BRAIN_URL", "")  # optional http target for summaries
DEFAULT_ERROR_THRESHOLD = 0.05
DEFAULT_LATENCY_THRESHOLD_MS = 5000
DEFAULT_MIN_DURATION_MINUTES = 30
MAX_CONSECUTIVE_FAILURES = 5
SERVICE_NAME = "echo-canary-beacon"
WORKER_VERSION = "2.0.0-forged"

SCHEMA = """
CREATE SCHEMA IF NOT EXISTS canary_beacon;
CREATE TABLE IF NOT EXISTS canary_beacon.canary_deployments (
    id TEXT PRIMARY KEY,
    worker_name TEXT NOT NULL,
    old_version TEXT NOT NULL DEFAULT '',
    new_version TEXT NOT NULL,
    deploy_source TEXT NOT NULL DEFAULT 'manual',
    status TEXT NOT NULL DEFAULT 'active',
    started_at TIMESTAMPTZ NOT NULL,
    promoted_at TIMESTAMPTZ,
    rolled_back_at TIMESTAMPTZ,
    health_checks_passed INTEGER NOT NULL DEFAULT 0,
    health_checks_failed INTEGER NOT NULL DEFAULT 0,
    error_threshold REAL DEFAULT 0.05,
    latency_threshold_ms INTEGER DEFAULT 5000,
    min_duration_minutes INTEGER DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS canary_beacon.canary_checks (
    id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    check_type TEXT NOT NULL,
    result TEXT NOT NULL,
    value REAL,
    threshold REAL,
    details TEXT,
    checked_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS canary_beacon.deployment_history (
    id TEXT PRIMARY KEY,
    worker_name TEXT NOT NULL,
    version TEXT NOT NULL,
    deployed_at TIMESTAMPTZ NOT NULL,
    deployed_by TEXT NOT NULL DEFAULT 'system',
    commit_sha TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    rollback_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS canary_beacon.rollback_log (
    id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    worker_name TEXT NOT NULL,
    from_version TEXT NOT NULL,
    to_version TEXT NOT NULL,
    reason TEXT NOT NULL,
    initiated_by TEXT NOT NULL DEFAULT 'auto',
    result TEXT NOT NULL DEFAULT 'success',
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS canary_beacon.counters (
    key TEXT PRIMARY KEY,
    value BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS canary_beacon.cache (
    key TEXT PRIMARY KEY,
    value TEXT,
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_cb_deploy_status ON canary_beacon.canary_deployments(status);
CREATE INDEX IF NOT EXISTS idx_cb_deploy_worker ON canary_beacon.canary_deployments(worker_name);
CREATE INDEX IF NOT EXISTS idx_cb_checks_deployment ON canary_beacon.canary_checks(deployment_id);
CREATE INDEX IF NOT EXISTS idx_cb_checks_checked_at ON canary_beacon.canary_checks(checked_at);
CREATE INDEX IF NOT EXISTS idx_cb_history_worker ON canary_beacon.deployment_history(worker_name);
CREATE INDEX IF NOT EXISTS idx_cb_history_status ON canary_beacon.deployment_history(status);
CREATE INDEX IF NOT EXISTS idx_cb_rollback_deployment ON canary_beacon.rollback_log(deployment_id);
CREATE INDEX IF NOT EXISTS idx_cb_rollback_worker ON canary_beacon.rollback_log(worker_name);
"""

@contextmanager
def _db():
    con = psycopg2.connect(**PG)
    try:
        yield con
        con.commit()
    finally:
        con.close()

def _generate_id() -> str:
    return str(uuid.uuid4())

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _minutes_since(ts: str) -> float:
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 60.0
    except Exception:
        return 0.0

def _json_response(data: dict, status: int = 200) -> dict:
    # FastAPI returns dict; status via HTTPException or responses in real
    return data

def _inc_counter(cur, key: str, delta: int = 1) -> int:
    cur.execute(
        "INSERT INTO canary_beacon.counters(key, value) VALUES(%s, %s) "
        "ON CONFLICT (key) DO UPDATE SET value = canary_beacon.counters.value + %s RETURNING value",
        (key, delta, delta)
    )
    return int(cur.fetchone()[0])

def _get_counter(cur, key: str) -> int:
    cur.execute("SELECT value FROM canary_beacon.counters WHERE key=%s", (key,))
    row = cur.fetchone()
    return int(row[0]) if row else 0

def _cache_put(cur, key: str, value: str, ttl_seconds: int = 86400 * 7) -> None:
    expires = datetime.now(timezone.utc).timestamp() + ttl_seconds
    cur.execute(
        "INSERT INTO canary_beacon.cache(key, value, expires_at) VALUES(%s, %s, to_timestamp(%s)) "
        "ON CONFLICT (key) DO UPDATE SET value=%s, expires_at=to_timestamp(%s)",
        (key, value, expires, value, expires)
    )

def _cache_get(cur, key: str) -> Optional[str]:
    cur.execute("SELECT value FROM canary_beacon.cache WHERE key=%s AND (expires_at IS NULL OR expires_at > now())", (key,))
    row = cur.fetchone()
    return row[0] if row else None

def _ensure_schema() -> None:
    with _db() as con, con.cursor() as cur:
        cur.execute(SCHEMA)
    logger.info("canary_beacon schema ready")

# --- SSRF controls for the worker health check -----------------------------
#
# worker_name reaches this module from a request body. Interpolating it into a
# URL unvalidated let a caller aim our outbound fetch at an arbitrary host.
# Four controls, because each has a known bypass on its own: allowlist the name,
# re-parse what was actually built, resolve DNS and reject private space, and
# refuse redirects.

WORKER_HOST_SUFFIX = ".bmcii1976.workers.dev"

#: Cloudflare worker-name shape. Excludes / @ # ? : . and credential separators,
#: so nothing that could restructure the URL survives.
_WORKER_NAME_RX = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse 3xx. A compliant first hop must not be able to hand the request
    to an internal address after every other control has already passed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, f"redirect refused to {newurl}", headers, fp
        )


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _reject_private(host: str) -> None:
    """Reject a host that resolves into loopback, private or link-local space.

    A name can pass the allowlist and the suffix check and still be a public DNS
    record pointing at 127.0.0.1 or 169.254.169.254. Resolution is the only
    place that shows up.
    """

    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve {host}") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast):
            raise ValueError(f"{host} resolves to non-public address {address}")


def _safe_worker_health_url(worker_name: str) -> str:
    """Build the worker /health URL, or raise. Never returns an unvalidated URL."""

    name = (worker_name or "").strip().lower()
    if not _WORKER_NAME_RX.fullmatch(name):
        raise ValueError(f"invalid worker name: {worker_name!r}")

    url = f"https://{name}{WORKER_HOST_SUFFIX}/health"

    # Re-parse what was actually built rather than trusting the inputs: this is
    # what a fetch will act on.
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host.endswith(WORKER_HOST_SUFFIX):
        raise ValueError(f"refusing non-worker URL: {url!r}")
    if parsed.port not in (None, 443) or "@" in (parsed.netloc or ""):
        raise ValueError(f"refusing URL with port or credentials: {url!r}")

    _reject_private(host)
    return url


def _perform_health_check(worker_name: str) -> dict[str, Any]:
    """Port of performHealthCheck: ping /health on worker (prefer cached worker_url)."""
    url = _safe_worker_health_url(worker_name)
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"{SERVICE_NAME}/{WORKER_VERSION}"})
        with _NO_REDIRECT_OPENER.open(req, timeout=10) as resp:
            latency = int((time.time() - start) * 1000)
            body = None
            try:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
            except Exception:
                pass
            return {
                "reachable": True,
                "status_code": resp.status,
                "latency_ms": latency,
                "body": body,
                "error": None,
            }
    except urllib.error.URLError as e:
        latency = int((time.time() - start) * 1000)
        return {
            "reachable": False,
            "status_code": 0,
            "latency_ms": latency,
            "body": None,
            "error": str(e)[:200],
        }
    except Exception as e:
        latency = int((time.time() - start) * 1000)
        return {
            "reachable": False,
            "status_code": 0,
            "latency_ms": latency,
            "body": None,
            "error": str(e)[:200],
        }

def _record_check(cur, deployment_id: str, check_type: str, result: str, value: float, threshold: float, details: str) -> None:
    cid = _generate_id()
    now = _now()
    cur.execute(
        "INSERT INTO canary_beacon.canary_checks (id, deployment_id, check_type, result, value, threshold, details, checked_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (cid, deployment_id, check_type, result, value, threshold, details, now)
    )

def _evaluate_canary(cur, deployment: dict) -> str:
    """Port of evaluateCanary + decision: returns 'continue' | 'promote' | 'rollback'."""
    health = _perform_health_check(deployment["worker_name"])

    # Health check
    if not health["reachable"] or health["status_code"] >= 500:
        _record_check(cur, deployment["id"], "health", "fail", float(health["status_code"]), 200.0,
                      health["error"] or f"HTTP {health['status_code']}")
        cur.execute(
            "UPDATE canary_beacon.canary_deployments SET health_checks_failed = health_checks_failed + 1 WHERE id = %s",
            (deployment["id"],)
        )
        logger.warning(f"canary_health_check_failed: {deployment['id']} {deployment['worker_name']}")
    else:
        _record_check(cur, deployment["id"], "health", "pass", float(health["status_code"]), 200.0, "HTTP OK")
        cur.execute(
            "UPDATE canary_beacon.canary_deployments SET health_checks_passed = health_checks_passed + 1 WHERE id = %s",
            (deployment["id"],)
        )

    # Latency
    latency_result = "fail" if health["latency_ms"] > deployment["latency_threshold_ms"] else "pass"
    _record_check(cur, deployment["id"], "latency", latency_result, float(health["latency_ms"]),
                  float(deployment["latency_threshold_ms"]),
                  f"{health['latency_ms']}ms (threshold: {deployment['latency_threshold_ms']}ms)")
    if latency_result == "fail":
        logger.warning(f"canary_latency_exceeded: {deployment['id']} {health['latency_ms']}ms")

    # Response validation
    body_ok = False
    if health.get("body"):
        b = health["body"]
        has_status = "status" in b or "ok" in b or "healthy" in str(b).lower()
        body_ok = has_status
        res = "pass" if body_ok else "warn"
        _record_check(cur, deployment["id"], "response_validation", res, 1.0 if body_ok else 0.0, 1.0,
                      f"body status/healthy present: {body_ok}")
    else:
        _record_check(cur, deployment["id"], "response_validation", "warn", 0.0, 1.0, "no json body")

    # Decision
    total_checks = deployment["health_checks_passed"] + deployment["health_checks_failed"] + 1
    fail_rate = (deployment["health_checks_failed"] + (0 if health["reachable"] and health["status_code"] < 500 else 1)) / max(1, total_checks)
    elapsed = _minutes_since(deployment["started_at"])
    consecutive_fails = deployment["health_checks_failed"] + (0 if health["reachable"] and health["status_code"] < 500 else 1)

    if consecutive_fails >= MAX_CONSECUTIVE_FAILURES:
        logger.warning(f"canary_rollback_triggered: {deployment['id']} consecutive_fails={consecutive_fails}")
        return "rollback"

    if elapsed >= deployment["min_duration_minutes"]:
        if fail_rate > deployment["error_threshold"]:
            logger.warning(f"canary_rollback_triggered: {deployment['id']} fail_rate={fail_rate:.2%}")
            return "rollback"
        if health["reachable"] and health["status_code"] < 500 and latency_result == "pass" and body_ok:
            logger.info(f"canary_promote_triggered: {deployment['id']}")
            return "promote"

    return "continue"

def _promote_deployment(cur, deployment: dict) -> None:
    now = _now()
    cur.execute(
        "UPDATE canary_beacon.canary_deployments SET status='promoted', promoted_at=%s WHERE id=%s",
        (now, deployment["id"])
    )
    cur.execute(
        "INSERT INTO canary_beacon.deployment_history (id, worker_name, version, deployed_at, deployed_by, commit_sha, status, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, 'promoted', %s)",
        (_generate_id(), deployment["worker_name"], deployment["new_version"], now, "auto-promote", "", now)
    )
    logger.info(f"canary_promoted: {deployment['id']} {deployment['worker_name']} -> {deployment['new_version']}")

def _rollback_deployment(cur, deployment: dict, reason: str, initiated_by: str = "auto") -> None:
    now = _now()
    cur.execute(
        "UPDATE canary_beacon.canary_deployments SET status='rolled_back', rolled_back_at=%s WHERE id=%s",
        (now, deployment["id"])
    )
    cur.execute(
        "INSERT INTO canary_beacon.rollback_log (id, deployment_id, worker_name, from_version, to_version, reason, initiated_by, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (_generate_id(), deployment["id"], deployment["worker_name"], deployment["new_version"],
         deployment["old_version"] or deployment["new_version"], reason, initiated_by, now)
    )
    cur.execute(
        "UPDATE canary_beacon.deployment_history SET status='rolled_back', rollback_reason=%s WHERE worker_name=%s AND version=%s AND status='active'",
        (reason, deployment["worker_name"], deployment["new_version"])
    )
    logger.info(f"canary_rolled_back: {deployment['id']} {deployment['worker_name']} reason={reason}")

def _cron_check_canaries() -> dict:
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM canary_beacon.canary_deployments WHERE status='active'")
        actives = cur.fetchall()
        results = []
        for d in actives:
            elapsed = _minutes_since(d["started_at"])
            if elapsed < d["min_duration_minutes"]:
                results.append({"id": d["id"], "action": "continue", "reason": "min_duration_not_met"})
                continue
            decision = _evaluate_canary(cur, dict(d))
            if decision == "rollback":
                _rollback_deployment(cur, dict(d), "auto: health/latency/fail thresholds breached")
                results.append({"id": d["id"], "action": "rollback"})
            elif decision == "promote":
                _promote_deployment(cur, dict(d))
                results.append({"id": d["id"], "action": "promote"})
            else:
                results.append({"id": d["id"], "action": "continue"})
        return {"checked": len(actives), "results": results}

def _cron_cleanup() -> dict:
    cutoff = datetime.now(timezone.utc).timestamp() - (86400 * 30)
    with _db() as con, con.cursor() as cur:
        for tbl in ["canary_checks", "canary_deployments", "deployment_history", "rollback_log"]:
            cur.execute(f"DELETE FROM canary_beacon.{tbl} WHERE created_at < to_timestamp(%s)", (cutoff,))
        logger.info("cron_cleanup_complete")
        return {"cleaned_before": datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()}

def _cron_weekly_summary() -> dict:
    week_ago = datetime.now(timezone.utc).timestamp() - (86400 * 7)
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT COUNT(*) as cnt FROM canary_beacon.canary_deployments WHERE status='promoted' AND promoted_at > to_timestamp(%s)", (week_ago,))
        promoted = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) as cnt FROM canary_beacon.canary_deployments WHERE status='rolled_back' AND rolled_back_at > to_timestamp(%s)", (week_ago,))
        rolled = cur.fetchone()["cnt"]
        summary = {
            "week_promoted": promoted,
            "week_rolled_back": rolled,
            "generated_at": _now(),
            "service": SERVICE_NAME,
        }
        # Cache
        _cache_put(cur, "weekly_summary", json.dumps(summary), 86400 * 8)
        # SWARM_BRAIN (best effort, no hard dep)
        if SWARM_BRAIN_URL:
            try:
                data = json.dumps(summary).encode("utf-8")
                req = urllib.request.Request(SWARM_BRAIN_URL, data=data, headers={"Content-Type": "application/json"}, method="POST")
                urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                logger.warning(f"swarm_brain_post_failed: {e}")
        else:
            logger.info(f"weekly_summary (no SWARM_BRAIN_URL): {summary}")
        return summary

app = FastAPI(title="Echo Canary Beacon", version=WORKER_VERSION)

@app.on_event("startup")
def _startup() -> None:
    _ensure_schema()
    logger.info("canary_beacon ready")

class DeployBody(BaseModel):
    worker_name: str
    old_version: Optional[str] = ""
    new_version: str
    deploy_source: Optional[str] = "manual"
    worker_url: Optional[str] = None
    error_threshold: Optional[float] = None
    latency_threshold_ms: Optional[int] = None
    min_duration_minutes: Optional[int] = None
    commit_sha: Optional[str] = ""
    deployed_by: Optional[str] = "manual"

@app.get("/health")
def health():
    try:
        with _db() as con, con.cursor() as cur:
            cur.execute("SELECT 1")
            active = _get_counter(cur, "active_canaries")  # computed on fly below
            cur.execute("SELECT COUNT(*) FROM canary_beacon.canary_deployments WHERE status='active'")
            active = cur.fetchone()[0]
            hits = _get_counter(cur, "total_hits")
        return {"status": "ok", "service": SERVICE_NAME, "version": WORKER_VERSION,
                "active_canaries": active, "total_hits": hits, "timestamp": _now()}
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}

@app.get("/stats")
def stats():
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT COUNT(*) as cnt FROM canary_beacon.canary_deployments WHERE status='active'")
        active = cur.fetchone()["cnt"]
        _dc = {}
        for st in ["promoted", "rolled_back", "failed"]:
            cur.execute(f"SELECT COUNT(*) as cnt FROM canary_beacon.canary_deployments WHERE status=%s", (st,))
            _dc[st] = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) as cnt FROM canary_beacon.canary_checks")
        total_checks = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) as cnt FROM canary_beacon.rollback_log")
        total_rollbacks = cur.fetchone()["cnt"]
        week_ago = datetime.now(timezone.utc).timestamp() - (86400 * 7)
        cur.execute("SELECT COUNT(*) as cnt FROM canary_beacon.canary_deployments WHERE status='promoted' AND promoted_at > to_timestamp(%s)", (week_ago,))
        week_prom = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) as cnt FROM canary_beacon.canary_deployments WHERE status='rolled_back' AND rolled_back_at > to_timestamp(%s)", (week_ago,))
        week_roll = cur.fetchone()["cnt"]
    return {
        "deployments": {"active": active, "promoted": _dc["promoted"], "rolled_back": _dc["rolled_back"], "failed": _dc["failed"]},
        "total_checks": total_checks,
        "total_rollbacks": total_rollbacks,
        "last_7_days": {"promoted": week_prom, "rolled_back": week_roll},
        "timestamp": _now(),
    }

@app.post("/deploy")
def deploy(b: DeployBody):
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id FROM canary_beacon.canary_deployments WHERE worker_name=%s AND status='active'",
            (b.worker_name,)
        )
        existing = cur.fetchone()
        if existing:
            raise HTTPException(409, {"error": "Active canary already exists", "existing_deployment_id": existing["id"]})
        now = _now()
        did = _generate_id()
        cur.execute(
            "INSERT INTO canary_beacon.canary_deployments (id, worker_name, old_version, new_version, deploy_source, status, started_at, "
            "error_threshold, latency_threshold_ms, min_duration_minutes, created_at) "
            "VALUES (%s,%s,%s,%s,%s,'active',%s,%s,%s,%s,%s)",
            (did, b.worker_name, b.old_version or "", b.new_version, b.deploy_source or "manual", now,
             b.error_threshold or DEFAULT_ERROR_THRESHOLD, b.latency_threshold_ms or DEFAULT_LATENCY_THRESHOLD_MS,
             b.min_duration_minutes or DEFAULT_MIN_DURATION_MINUTES, now)
        )
        cur.execute(
            "INSERT INTO canary_beacon.deployment_history (id, worker_name, version, deployed_at, deployed_by, commit_sha, status, created_at) "
            "VALUES (%s,%s,%s,%s,%s,%s,'active',%s)",
            (_generate_id(), b.worker_name, b.new_version, now, b.deployed_by or "manual", b.commit_sha or "", now)
        )
        if b.worker_url:
            _cache_put(cur, f"worker_url:{b.worker_name}", b.worker_url)
        hits = _inc_counter(cur, "total_hits")
        logger.info(f"canary_deployment_registered: {did} {b.worker_name} v={b.new_version}")
        return {
            "deployment_id": did,
            "worker_name": b.worker_name,
            "new_version": b.new_version,
            "status": "active",
            "monitoring_started": now,
            "min_duration_minutes": b.min_duration_minutes or DEFAULT_MIN_DURATION_MINUTES,
            "estimated_promotion": (datetime.now(timezone.utc).timestamp() + (b.min_duration_minutes or 30) * 60),
        }

@app.get("/deployments")
def list_deployments(status: Optional[str] = None, limit: int = 50, offset: int = 0):
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        if status:
            cur.execute(
                "SELECT * FROM canary_beacon.canary_deployments WHERE status=%s ORDER BY created_at DESC LIMIT %s OFFSET %s",
                (status, limit, offset)
            )
            total_q = "SELECT COUNT(*) FROM canary_beacon.canary_deployments WHERE status=%s"
            total_args = (status,)
        else:
            cur.execute(
                "SELECT * FROM canary_beacon.canary_deployments ORDER BY created_at DESC LIMIT %s OFFSET %s",
                (limit, offset)
            )
            total_q = "SELECT COUNT(*) FROM canary_beacon.canary_deployments"
            total_args = ()
        rows = cur.fetchall()
        cur.execute(total_q, total_args)
        total = cur.fetchone()[0]
    return {"deployments": rows, "total": total, "limit": limit, "offset": offset}

@app.get("/deployments/{deployment_id}")
def deployment_detail(deployment_id: str):
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM canary_beacon.canary_deployments WHERE id=%s", (deployment_id,))
        dep = cur.fetchone()
        if not dep:
            raise HTTPException(404, "Deployment not found")
        cur.execute(
            "SELECT * FROM canary_beacon.canary_checks WHERE deployment_id=%s ORDER BY checked_at DESC LIMIT 100",
            (deployment_id,)
        )
        checks = cur.fetchall()
        cur.execute("SELECT * FROM canary_beacon.rollback_log WHERE deployment_id=%s ORDER BY created_at DESC", (deployment_id,))
        rollbacks = cur.fetchall()
    total_checks = dep["health_checks_passed"] + dep["health_checks_failed"]
    fail_rate = (dep["health_checks_failed"] / total_checks * 100) if total_checks > 0 else 0.0
    elapsed = _minutes_since(dep["started_at"])
    return {
        "deployment": dep,
        "metrics": {
            "total_checks": total_checks,
            "pass_rate": f"{(100 - fail_rate):.2f}%",
            "fail_rate": f"{fail_rate:.2f}%",
            "elapsed_minutes": round(elapsed),
            "remaining_minutes": max(0, round(dep["min_duration_minutes"] - elapsed)),
        },
        "recent_checks": checks,
        "rollbacks": rollbacks,
    }

@app.post("/deployments/{deployment_id}/promote")
def force_promote(deployment_id: str):
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM canary_beacon.canary_deployments WHERE id=%s", (deployment_id,))
        dep = cur.fetchone()
        if not dep:
            raise HTTPException(404, "Deployment not found")
        if dep["status"] != "active":
            raise HTTPException(400, f"Cannot promote: status {dep['status']}")
        _promote_deployment(cur, dict(dep))
    return {"message": "promoted", "deployment_id": deployment_id}

@app.post("/deployments/{deployment_id}/rollback")
def force_rollback(deployment_id: str, reason: Optional[str] = None):
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM canary_beacon.canary_deployments WHERE id=%s", (deployment_id,))
        dep = cur.fetchone()
        if not dep:
            raise HTTPException(404, "Deployment not found")
        if dep["status"] != "active":
            raise HTTPException(400, f"Cannot rollback: status {dep['status']}")
        _rollback_deployment(cur, dict(dep), reason or "Manual rollback", "manual")
    return {"message": "rolled_back", "deployment_id": deployment_id}

@app.get("/history")
def history(limit: int = 100, offset: int = 0):
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM canary_beacon.deployment_history ORDER BY deployed_at DESC LIMIT %s OFFSET %s",
            (limit, offset)
        )
        rows = cur.fetchall()
    return {"history": rows, "limit": limit, "offset": offset}

@app.get("/history/{worker_name}")
def worker_history(worker_name: str, limit: int = 50):
    with _db() as con, con.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM canary_beacon.deployment_history WHERE worker_name=%s ORDER BY deployed_at DESC LIMIT %s",
            (worker_name, limit)
        )
        rows = cur.fetchall()
    return {"worker": worker_name, "history": rows}

@app.get("/")
def dashboard():
    return {
        "service": SERVICE_NAME,
        "version": WORKER_VERSION,
        "endpoints": [
            "GET  /health",
            "GET  /stats",
            "POST /deploy",
            "GET  /deployments",
            "GET  /deployments/:id",
            "POST /deployments/:id/promote",
            "POST /deployments/:id/rollback",
            "GET  /history",
            "GET  /history/:worker",
            "POST /internal/cron/check|cleanup|weekly",
        ],
        "note": "Canary deployment monitoring + auto rollback. See /stats for live state.",
    }

@app.post("/internal/cron/check")
def internal_cron_check():
    return _cron_check_canaries()

@app.post("/internal/cron/cleanup")
def internal_cron_cleanup():
    return _cron_cleanup()

@app.post("/internal/cron/weekly")
def internal_cron_weekly():
    return _cron_weekly_summary()


# --- authentication boundary (P0 #26871) ---------------------------------
#
# This service had none: sensitive routes answered anything that could reach
# the port. Default-deny middleware; the allowlist below is the whole public
# surface.

CANARY_API_TOKEN = os.environ.get("CANARY_API_TOKEN", "").strip()

_PUBLIC_PATHS = frozenset(['/docs', '/health', '/healthz', '/openapi.json', '/ready', '/redoc'])
_PUBLIC_PREFIXES = ("/public/",)


def _path_is_public(path: str) -> bool:
    return path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES)


@app.middleware("http")
async def _require_service_auth(request: Request, call_next):
    if request.method == "OPTIONS" or _path_is_public(request.url.path):
        return await call_next(request)

    if not CANARY_API_TOKEN:
        return JSONResponse({"detail": "Auth not configured"}, status_code=503)

    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        presented = authorization[7:].strip()
        # compare_digest, not ==, so the check does not leak the token prefix
        # through timing.
        if presented and hmac.compare_digest(presented, CANARY_API_TOKEN):
            return await call_next(request)

    return JSONResponse({"detail": "Unauthorized"}, status_code=401)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8094)
