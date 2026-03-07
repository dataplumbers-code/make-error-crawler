#!/usr/bin/env python3
"""Make.com scenario failure monitor with incident dedupe and lifecycle tracking."""

from __future__ import annotations

import hashlib
import json
import os
import re
import smtplib
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests


DEFAULT_STATE_FILE = ".monitor/state.json"
DEFAULT_CONFIG_FILE = "monitor_config.json"
DEFAULT_API_BASE = "https://eu2.make.com/api/v2"
DEFAULT_AIRTABLE_ENDPOINT = "https://api.airtable.com/v0"
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_INITIAL_LOOKBACK_SECONDS = 600
DEFAULT_OVERLAP_SECONDS = 120
DEFAULT_RESOLVE_GRACE_SECONDS = 180
DEFAULT_STILL_FAILING_SUPPRESSION_SECONDS = 1800
DEFAULT_SEEN_EXECUTION_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_MAX_PER_PAGE = 50
DEFAULT_MAX_PAGES_PER_SCENARIO = 10
MAKE_MAX_PAGE_LIMIT = 50
DEFAULT_MAKE_MIN_INTERVAL_MS = 1200
DEFAULT_MAX_MAKE_CALLS_PER_RUN = 40
DEFAULT_MAX_SCENARIOS_PER_RUN = 25

STATUS_SUCCESS = 1
STATUS_WARNING = 2
STATUS_ERROR = 3


@dataclass
class MonitorConfig:
    base_url: str
    api_token: str
    team_id: int

    alert_webhook_url: Optional[str]

    airtable_api_token: Optional[str]
    airtable_base_id: Optional[str]
    airtable_table_id: Optional[str]
    airtable_table_name: Optional[str]
    airtable_endpoint: str
    airtable_field_scenario_name: str
    airtable_field_module_name: str
    airtable_field_error_message: str
    airtable_field_error_code: str
    airtable_field_timestamp: str
    airtable_field_execution_id: str

    smtp_host: Optional[str]
    smtp_port: int
    smtp_username: Optional[str]
    smtp_password: Optional[str]
    smtp_use_tls: bool
    email_from: Optional[str]
    email_to: List[str]

    include_warnings: bool
    initial_lookback_seconds: int
    overlap_seconds: int
    resolve_grace_seconds: int
    still_failing_suppression_seconds: int
    seen_execution_ttl_seconds: int
    timeout_seconds: int
    max_per_page: int
    max_pages_per_scenario: int
    scenario_allowlist: List[int]
    scenario_blocklist: List[int]
    scenario_folder_id: Optional[int]
    make_min_interval_ms: int
    max_make_calls_per_run: int
    max_scenarios_per_run: int
    fetch_execution_details: bool
    airtable_skip_prefetch_dedupe: bool


def now_ms() -> int:
    return int(time.time() * 1000)


def iso_utc(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


def iso_utc_z(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def load_json_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
    temp_path.replace(path)


def parse_csv_ints(value: Optional[str]) -> List[int]:
    if not value:
        return []
    out: List[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        out.append(int(item))
    return out


def parse_csv_strings(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def load_config() -> MonitorConfig:
    cfg_path = Path(os.environ.get("MONITOR_CONFIG_PATH", DEFAULT_CONFIG_FILE))
    file_cfg = load_json_file(cfg_path) if cfg_path.exists() else {}

    def get(name: str, default: Any = None) -> Any:
        if name in os.environ:
            return os.environ[name]
        return file_cfg.get(name, default)

    def get_str(name: str, default: str = "") -> str:
        raw = get(name, default)
        if raw is None:
            return default
        text = str(raw).strip()
        if not text:
            return default
        return text

    def get_int(name: str, default: int) -> int:
        raw = get(name, default)
        if raw is None:
            return int(default)
        if isinstance(raw, int):
            return raw
        text = str(raw).strip()
        if not text:
            return int(default)
        return int(text)

    def get_bool(name: str, default: bool) -> bool:
        raw = get(name, "true" if default else "false")
        text = str(raw).strip().lower()
        if not text:
            return default
        return text in ("1", "true", "yes", "y", "on")

    api_token = get_str("MAKE_API_TOKEN", "")
    if not api_token:
        raise ValueError("MAKE_API_TOKEN is required")

    team_id_raw = get("MAKE_TEAM_ID", None)
    if team_id_raw is None or not str(team_id_raw).strip():
        raise ValueError("MAKE_TEAM_ID is required")

    email_to = parse_csv_strings(str(get("EMAIL_TO", "")).strip())

    return MonitorConfig(
        base_url=get_str("MAKE_BASE_URL", DEFAULT_API_BASE).rstrip("/"),
        api_token=api_token,
        team_id=int(str(team_id_raw).strip()),
        alert_webhook_url=get_str("ALERT_WEBHOOK_URL", "") or None,
        airtable_api_token=get_str("AIRTABLE_API_TOKEN", "") or None,
        airtable_base_id=get_str("AIRTABLE_BASE_ID", "") or None,
        airtable_table_id=get_str("AIRTABLE_TABLE_ID", "") or None,
        airtable_table_name=get_str("AIRTABLE_TABLE_NAME", "") or None,
        airtable_endpoint=get_str("AIRTABLE_ENDPOINT", DEFAULT_AIRTABLE_ENDPOINT).rstrip("/"),
        airtable_field_scenario_name=get_str("AIRTABLE_FIELD_SCENARIO_NAME", "fldQUxFUQeQGXPWpf"),
        airtable_field_module_name=get_str("AIRTABLE_FIELD_MODULE_NAME", "fldKovncPBvCr6kWc"),
        airtable_field_error_message=get_str("AIRTABLE_FIELD_ERROR_MESSAGE", "fld3S36GeS9l5dj9o"),
        airtable_field_error_code=get_str("AIRTABLE_FIELD_ERROR_CODE", "fldcK6pp2AG4dV4BA"),
        airtable_field_timestamp=get_str("AIRTABLE_FIELD_TIMESTAMP", "fldXakRHe5xVEBZ0O"),
        airtable_field_execution_id=get_str("AIRTABLE_FIELD_EXECUTION_ID", "fldW7Hf90ljWjCpdX"),
        smtp_host=get_str("EMAIL_SMTP_HOST", "") or None,
        smtp_port=get_int("EMAIL_SMTP_PORT", 587),
        smtp_username=get_str("EMAIL_SMTP_USERNAME", "") or None,
        smtp_password=get_str("EMAIL_SMTP_PASSWORD", "") or None,
        smtp_use_tls=get_str("EMAIL_SMTP_USE_TLS", "true").lower() == "true",
        email_from=get_str("EMAIL_FROM", "") or None,
        email_to=email_to,
        include_warnings=get_bool("INCLUDE_WARNINGS", False),
        initial_lookback_seconds=get_int("INITIAL_LOOKBACK_SECONDS", DEFAULT_INITIAL_LOOKBACK_SECONDS),
        overlap_seconds=get_int("OVERLAP_SECONDS", DEFAULT_OVERLAP_SECONDS),
        resolve_grace_seconds=get_int("RESOLVE_GRACE_SECONDS", DEFAULT_RESOLVE_GRACE_SECONDS),
        still_failing_suppression_seconds=get_int(
            "STILL_FAILING_SUPPRESSION_SECONDS", DEFAULT_STILL_FAILING_SUPPRESSION_SECONDS
        ),
        seen_execution_ttl_seconds=get_int("SEEN_EXECUTION_TTL_SECONDS", DEFAULT_SEEN_EXECUTION_TTL_SECONDS),
        timeout_seconds=get_int("HTTP_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS),
        max_per_page=max(1, min(get_int("MAX_PER_PAGE", DEFAULT_MAX_PER_PAGE), MAKE_MAX_PAGE_LIMIT)),
        max_pages_per_scenario=get_int("MAX_PAGES_PER_SCENARIO", DEFAULT_MAX_PAGES_PER_SCENARIO),
        scenario_allowlist=parse_csv_ints(get("SCENARIO_ALLOWLIST", "")),
        scenario_blocklist=parse_csv_ints(get("SCENARIO_BLOCKLIST", "")),
        scenario_folder_id=(
            get_int("SCENARIO_FOLDER_ID", 0) if str(get("SCENARIO_FOLDER_ID", "")).strip() else None
        ),
        make_min_interval_ms=max(0, get_int("MAKE_MIN_INTERVAL_MS", DEFAULT_MAKE_MIN_INTERVAL_MS)),
        max_make_calls_per_run=max(1, get_int("MAX_MAKE_CALLS_PER_RUN", DEFAULT_MAX_MAKE_CALLS_PER_RUN)),
        max_scenarios_per_run=max(1, get_int("MAX_SCENARIOS_PER_RUN", DEFAULT_MAX_SCENARIOS_PER_RUN)),
        fetch_execution_details=get_bool("FETCH_EXECUTION_DETAILS", False),
        airtable_skip_prefetch_dedupe=get_bool("AIRTABLE_SKIP_PREFETCH_DEDUPE", True),
    )


class MakeApiClient:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.call_count = 0
        self.last_request_mono = 0.0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token {config.api_token}",
                "Content-Type": "application/json",
                "User-Agent": "make-error-monitor/1.0",
            }
        )

    def _acquire_budget_slot(self) -> None:
        if self.call_count >= self.config.max_make_calls_per_run:
            raise RuntimeError(
                f"Make call budget exhausted ({self.config.max_make_calls_per_run} calls/run)"
            )
        if self.config.make_min_interval_ms > 0 and self.last_request_mono > 0:
            elapsed_ms = (time.monotonic() - self.last_request_mono) * 1000
            sleep_ms = self.config.make_min_interval_ms - elapsed_ms
            if sleep_ms > 0:
                time.sleep(sleep_ms / 1000)

    def _request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.config.base_url}{path}"
        max_attempts = 5
        base_delay = 1.0

        for attempt in range(1, max_attempts + 1):
            self._acquire_budget_slot()
            self.call_count += 1
            self.last_request_mono = time.monotonic()
            try:
                resp = self.session.request(
                    method,
                    url,
                    params=params,
                    timeout=self.config.timeout_seconds,
                )
            except requests.RequestException as exc:
                if attempt == max_attempts:
                    raise RuntimeError(f"request failed {method} {path}: {exc}") from exc
                time.sleep(base_delay * attempt)
                continue

            if resp.status_code in (429, 500, 502, 503, 504):
                if attempt == max_attempts:
                    raise RuntimeError(
                        f"request failed {method} {path}: HTTP {resp.status_code} body={resp.text[:500]}"
                    )
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    sleep_seconds = float(retry_after)
                else:
                    sleep_seconds = base_delay * attempt
                time.sleep(sleep_seconds)
                continue

            if resp.status_code >= 400:
                raise RuntimeError(f"request failed {method} {path}: HTTP {resp.status_code} body={resp.text[:500]}")

            try:
                return resp.json()
            except ValueError as exc:
                raise RuntimeError(f"invalid json for {method} {path}: {resp.text[:500]}") from exc

        raise RuntimeError(f"unexpected retry exhaustion for {method} {path}")

    def list_scenarios(self) -> List[Dict[str, Any]]:
        data = self._request("GET", "/scenarios", params={"teamId": self.config.team_id})
        scenarios = data.get("scenarios")
        if not isinstance(scenarios, list):
            raise RuntimeError("Unexpected response shape for /scenarios")
        return scenarios

    def list_scenario_logs(
        self,
        scenario_id: int,
        from_ms: int,
        to_ms: int,
        max_per_page: int,
        max_pages: int,
    ) -> List[Dict[str, Any]]:
        all_logs: List[Dict[str, Any]] = []
        offset = 0

        for _ in range(max_pages):
            params = {
                "teamId": self.config.team_id,
                "from": from_ms,
                "to": to_ms,
                "pg[offset]": offset,
                "pg[limit]": max_per_page,
            }
            data = self._request("GET", f"/scenarios/{scenario_id}/logs", params=params)
            logs = data.get("scenarioLogs")
            if not isinstance(logs, list):
                raise RuntimeError(f"Unexpected response shape for /scenarios/{scenario_id}/logs")
            all_logs.extend(logs)
            if len(logs) < max_per_page:
                break
            offset += max_per_page

        return all_logs

    def get_execution(self, scenario_id: int, execution_id: str) -> Dict[str, Any]:
        return self._request(
            "GET",
            f"/scenarios/{scenario_id}/executions/{execution_id}",
            params={"teamId": self.config.team_id},
        )


class Notifier:
    def __init__(self, cfg: MonitorConfig):
        self.cfg = cfg
        self.session = requests.Session()

    def _request_with_retry(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        max_attempts = 5
        base_delay = 1.0

        for attempt in range(1, max_attempts + 1):
            try:
                resp = self.session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                    timeout=self.cfg.timeout_seconds,
                )
            except requests.RequestException as exc:
                if attempt == max_attempts:
                    raise RuntimeError(f"notify request failed {method} {url}: {exc}") from exc
                time.sleep(base_delay * attempt)
                continue

            if resp.status_code in (429, 500, 502, 503, 504):
                if attempt == max_attempts:
                    raise RuntimeError(f"notify request failed {method} {url}: HTTP {resp.status_code} {resp.text[:500]}")
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    sleep_seconds = float(retry_after)
                else:
                    sleep_seconds = base_delay * attempt
                time.sleep(sleep_seconds)
                continue

            if resp.status_code >= 400:
                raise RuntimeError(f"notify request failed {method} {url}: HTTP {resp.status_code} {resp.text[:500]}")

            return resp

        raise RuntimeError(f"unexpected retry exhaustion for notify {method} {url}")

    def send_webhook(self, payload: Dict[str, Any]) -> None:
        if not self.cfg.alert_webhook_url:
            return
        self._request_with_retry("POST", self.cfg.alert_webhook_url, json_body=payload)

    @staticmethod
    def _airtable_formula_escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def upsert_airtable_event(self, payload: Dict[str, Any]) -> None:
        table_ref = self.cfg.airtable_table_id or self.cfg.airtable_table_name
        if not (self.cfg.airtable_api_token and self.cfg.airtable_base_id and table_ref):
            return

        token = self.cfg.airtable_api_token
        table_url = f"{self.cfg.airtable_endpoint}/{self.cfg.airtable_base_id}/{table_ref}"
        dedupe_field = self.cfg.airtable_field_execution_id
        dedupe_value = str(payload.get("last_execution_id") or payload["idempotency_key"]).strip()

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        if not self.cfg.airtable_skip_prefetch_dedupe:
            esc = self._airtable_formula_escape(dedupe_value)
            formula = f"{{{dedupe_field}}}='{esc}'"
            find_resp = self._request_with_retry(
                "GET",
                table_url,
                headers=headers,
                params={"maxRecords": 1, "filterByFormula": formula},
            )
            try:
                find_data = find_resp.json()
            except ValueError as exc:
                raise RuntimeError("airtable list response was not valid json") from exc

            if isinstance(find_data.get("records"), list) and len(find_data["records"]) > 0:
                return

        error_message = str(payload.get("error_message") or "").strip()
        if not error_message:
            error_message = str(payload.get("signature") or "")

        fields = {
            self.cfg.airtable_field_scenario_name: str(payload.get("scenario_name") or payload.get("scenario_id")),
            self.cfg.airtable_field_module_name: str(payload.get("module_name") or ""),
            self.cfg.airtable_field_error_message: error_message[:99000],
            self.cfg.airtable_field_error_code: str(payload.get("error_code") or ""),
            self.cfg.airtable_field_timestamp: str(payload.get("detected_at") or ""),
            self.cfg.airtable_field_execution_id: dedupe_value,
        }

        self._request_with_retry(
            "POST",
            table_url,
            headers=headers,
            json_body={"records": [{"fields": fields}]},
        )

    def send_email(self, payload: Dict[str, Any]) -> None:
        if not (self.cfg.smtp_host and self.cfg.email_from and self.cfg.email_to):
            return

        subject = (
            f"[Make Monitor] {payload['event_type']} | "
            f"scenario={payload.get('scenario_name') or payload['scenario_id']} | incident={payload['incident_key']}"
        )
        body = json.dumps(payload, indent=2, sort_keys=True)

        msg = EmailMessage()
        msg["From"] = self.cfg.email_from
        msg["To"] = ", ".join(self.cfg.email_to)
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port, timeout=self.cfg.timeout_seconds) as server:
            if self.cfg.smtp_use_tls:
                server.starttls()
            if self.cfg.smtp_username and self.cfg.smtp_password:
                server.login(self.cfg.smtp_username, self.cfg.smtp_password)
            server.send_message(msg)

    def notify_all(self, payload: Dict[str, Any]) -> None:
        self.send_webhook(payload)
        self.upsert_airtable_event(payload)
        self.send_email(payload)


def parse_ms(value: Any) -> Optional[int]:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        v = int(value)
        if v > 10**12:
            return v
        if v > 10**9:
            return v * 1000
        return None

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit():
            return parse_ms(int(text))
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return int(parsed.timestamp() * 1000)
        except ValueError:
            return None

    return None


def normalize_message(msg: str) -> str:
    msg = msg.strip().lower()
    msg = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", msg)
    msg = re.sub(r"\b\d{4,}\b", "<num>", msg)
    msg = re.sub(r"https?://\S+", "<url>", msg)
    msg = re.sub(r"\s+", " ", msg)
    return msg[:400]


def stable_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:20]


def _iter_nodes(value: Any):
    stack = [value]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, dict):
            for child in node.values():
                stack.append(child)
        elif isinstance(node, list):
            for child in node:
                stack.append(child)


def find_first_string(value: Any, keys: Tuple[str, ...]) -> str:
    keyset = set(keys)
    for node in _iter_nodes(value):
        if not isinstance(node, dict):
            continue
        for key in keys:
            candidate = node.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    # Fallback in case keys differ in case.
    for node in _iter_nodes(value):
        if not isinstance(node, dict):
            continue
        for key, candidate in node.items():
            if str(key) in keyset and isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return ""


def find_first_scalar(value: Any, keys: Tuple[str, ...]) -> str:
    for node in _iter_nodes(value):
        if not isinstance(node, dict):
            continue
        for key in keys:
            candidate = node.get(key)
            if isinstance(candidate, (str, int, float)) and str(candidate).strip():
                return str(candidate).strip()
    return ""


def prettify_module_name(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    # Common Make style: provider:module-action
    if ":" in text:
        text = text.split(":", 1)[0]
    text = text.replace("_", " ").replace("-", " ").strip()
    return " ".join(part.capitalize() for part in text.split())


def derive_error_signature(log_item: Dict[str, Any], execution_detail: Optional[Dict[str, Any]]) -> Tuple[str, Dict[str, Any]]:
    parts: List[str] = []
    debug: Dict[str, Any] = {}

    direct_candidates = [
        ("errorMessage", log_item.get("errorMessage")),
        ("message", log_item.get("message")),
        ("error", log_item.get("error")),
        ("moduleName", log_item.get("moduleName")),
    ]
    for key, val in direct_candidates:
        if isinstance(val, str) and val.strip():
            normalized = normalize_message(val)
            parts.append(f"{key}:{normalized}")
            debug[key] = val[:300]

    if execution_detail:
        execution = execution_detail.get("execution") if isinstance(execution_detail, dict) else None
        if isinstance(execution, dict):
            maybe_error = execution.get("error")
            if isinstance(maybe_error, dict):
                for key in ("type", "message", "code", "module", "moduleName"):
                    val = maybe_error.get(key)
                    if isinstance(val, str) and val.strip():
                        norm = normalize_message(val)
                        parts.append(f"exec.error.{key}:{norm}")
                        debug[f"exec_error_{key}"] = val[:300]

    if not parts:
        status_val = log_item.get("status") or log_item.get("statusId")
        if isinstance(status_val, (int, str)):
            parts.append(f"status:{status_val}")
        parts.append("fallback:unknown")

    signature_basis = "|".join(sorted(set(parts)))
    return stable_hash(signature_basis), debug


def extract_error_fields(log_item: Dict[str, Any], execution_detail: Optional[Dict[str, Any]]) -> Dict[str, str]:
    source: Dict[str, Any] = {"log": log_item}
    if isinstance(execution_detail, dict):
        source["execution_detail"] = execution_detail
        execution = execution_detail.get("execution")
        if isinstance(execution, dict):
            source["execution"] = execution
            maybe_error = execution.get("error")
            if isinstance(maybe_error, dict):
                source["execution_error"] = maybe_error

    module_name = find_first_string(source, ("moduleName", "module", "appName", "app", "provider", "service"))
    error_message = find_first_string(
        source,
        ("errorMessage", "message", "detail", "description", "reason", "type"),
    )
    error_code = find_first_scalar(
        source,
        ("code", "errorCode", "statusCode", "httpCode", "status"),
    )
    if not error_code and error_message:
        match = re.search(r"\[(\\d{3})\]", error_message)
        if match:
            error_code = match.group(1)

    if module_name:
        module_name = prettify_module_name(module_name)

    return {
        "module_name": module_name,
        "error_message": error_message,
        "error_code": error_code,
    }


def classify_status(log_item: Dict[str, Any]) -> Optional[int]:
    for key in ("status", "statusId", "status_id"):
        value = log_item.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def log_timestamp_ms(log_item: Dict[str, Any]) -> Optional[int]:
    for key in ("createdAt", "startedAt", "finishedAt", "timestamp", "date", "imtUpdated"):
        parsed = parse_ms(log_item.get(key))
        if parsed is not None:
            return parsed
    return None


def log_execution_id(log_item: Dict[str, Any]) -> Optional[str]:
    for key in ("executionId", "id", "imtId"):
        value = log_item.get(key)
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def load_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {
            "version": 1,
            "last_poll_ms": 0,
            "seen_executions": {},
            "incidents": {},
            "scenario_health": {},
            "emitted_event_ids": {},
        }
    return load_json_file(path)


def prune_ttl_map(source: Dict[str, Any], older_than_ms: int) -> Dict[str, int]:
    pruned: Dict[str, int] = {}
    for key, value in source.items():
        if isinstance(value, int) and value >= older_than_ms:
            pruned[key] = value
    return pruned


def incident_key(scenario_id: int, signature: str) -> str:
    return f"{scenario_id}:{signature}"


def event_id(event_type: str, inc_key: str, marker: str) -> str:
    return stable_hash(f"{event_type}|{inc_key}|{marker}")


def scenario_name(scenario: Dict[str, Any]) -> str:
    for key in ("name", "label"):
        val = scenario.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return f"scenario-{scenario.get('id', 'unknown')}"


def scenario_folder_id(scenario: Dict[str, Any]) -> Optional[int]:
    direct = scenario.get("folderId") or scenario.get("folder_id") or scenario.get("imtFolderId")
    if isinstance(direct, int):
        return direct
    if isinstance(direct, str) and direct.strip().isdigit():
        return int(direct.strip())
    folder_obj = scenario.get("folder")
    if isinstance(folder_obj, dict):
        val = folder_obj.get("id")
        if isinstance(val, int):
            return val
        if isinstance(val, str) and val.strip().isdigit():
            return int(val.strip())
    return None


def ui_base_url(api_base_url: str) -> str:
    # e.g. https://eu2.make.com/api/v2 -> https://eu2.make.com
    return re.sub(r"/api(?:/v\\d+)?/?$", "", api_base_url.rstrip("/"))


def make_execution_url(api_base_url: str, team_id: int, scenario_id: int, execution_id: str) -> str:
    if not execution_id or execution_id.startswith("fallback-"):
        return ""
    return f"{ui_base_url(api_base_url)}/{team_id}/scenarios/{scenario_id}/logs/{execution_id}"


def alert_payload(event_type: str, incident: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "event_type": event_type,
        "incident_key": incident["incident_key"],
        "scenario_id": incident["scenario_id"],
        "scenario_name": incident.get("scenario_name"),
        "signature": incident["signature"],
        "status": incident["status"],
        "first_seen": iso_utc(incident["first_seen_ms"]),
        "last_seen": iso_utc(incident["last_seen_ms"]),
        "occurrences": incident.get("occurrences", 0),
        "reopen_count": incident.get("reopen_count", 0),
        "module_name": incident.get("last_module_name", ""),
        "error_message": incident.get("last_error_message", ""),
        "error_code": incident.get("last_error_code", ""),
        "detected_at": iso_utc_z(now_ms()),
        "execution_url": incident.get("last_execution_url", ""),
    }
    payload.update(extra)
    return payload


def should_track_scenario(scenario: Dict[str, Any], cfg: MonitorConfig) -> bool:
    scenario_id = int(scenario["id"])
    if cfg.scenario_allowlist and scenario_id not in cfg.scenario_allowlist:
        return False
    if scenario_id in cfg.scenario_blocklist:
        return False
    if cfg.scenario_folder_id is not None:
        sid_folder = scenario_folder_id(scenario)
        if sid_folder != cfg.scenario_folder_id:
            return False
    return True


def process() -> int:
    cfg = load_config()
    state_path = Path(os.environ.get("MONITOR_STATE_FILE", DEFAULT_STATE_FILE))
    state = load_state(state_path)

    state.setdefault("seen_executions", {})
    state.setdefault("incidents", {})
    state.setdefault("scenario_health", {})
    state.setdefault("emitted_event_ids", {})

    current_ms = now_ms()
    last_poll_ms = int(state.get("last_poll_ms") or 0)
    if last_poll_ms <= 0:
        from_ms = current_ms - (cfg.initial_lookback_seconds * 1000)
    else:
        from_ms = max(0, last_poll_ms - (cfg.overlap_seconds * 1000))

    client = MakeApiClient(cfg)
    notifier = Notifier(cfg)

    scenarios = client.list_scenarios()
    tracked_scenarios_all = [s for s in scenarios if should_track_scenario(s, cfg)]
    tracked_scenarios = tracked_scenarios_all[: cfg.max_scenarios_per_run]
    budget_exhausted = False

    alerts: List[Tuple[str, Dict[str, Any], str]] = []

    scenarios_scanned_count = 0
    for scenario in tracked_scenarios:
        sid = int(scenario["id"])
        sname = scenario_name(scenario)
        scenarios_scanned_count += 1
        scenario_state = state["scenario_health"].setdefault(str(sid), {"last_success_ms": 0})
        try:
            logs = client.list_scenario_logs(
                scenario_id=sid,
                from_ms=from_ms,
                to_ms=current_ms,
                max_per_page=cfg.max_per_page,
                max_pages=cfg.max_pages_per_scenario,
            )
        except RuntimeError as exc:
            if "Make call budget exhausted" in str(exc):
                print("WARN Make call budget exhausted while fetching logs; ending scenario scan early")
                budget_exhausted = True
                break
            raise

        parsed_logs: List[Tuple[int, int, Dict[str, Any]]] = []
        for raw in logs:
            ts = log_timestamp_ms(raw)
            st = classify_status(raw)
            if ts is None or st is None:
                continue
            parsed_logs.append((ts, st, raw))

        parsed_logs.sort(key=lambda x: x[0])

        for ts, st, raw in parsed_logs:
            exec_id = log_execution_id(raw)
            if st == STATUS_SUCCESS:
                scenario_state["last_success_ms"] = max(int(scenario_state.get("last_success_ms", 0)), ts)
                continue

            if st == STATUS_WARNING and not cfg.include_warnings:
                continue

            if st not in (STATUS_WARNING, STATUS_ERROR):
                continue

            if exec_id is None:
                exec_id = f"fallback-{sid}-{ts}"

            exec_key = str(exec_id)
            if exec_key in state["seen_executions"]:
                continue

            state["seen_executions"][exec_key] = ts

            execution_detail: Optional[Dict[str, Any]] = None
            if cfg.fetch_execution_details and exec_id and not exec_id.startswith("fallback-"):
                try:
                    execution_detail = client.get_execution(sid, exec_id)
                except Exception as exc:  # noqa: BLE001
                    if "Make call budget exhausted" in str(exc):
                        budget_exhausted = True
                        print("WARN Make call budget exhausted while fetching execution detail")
                        execution_detail = None
                    else:
                        print(f"WARN execution detail fetch failed exec_id={exec_id}: {exc}")
                if budget_exhausted:
                    break

            signature, _signature_debug = derive_error_signature(raw, execution_detail)
            error_fields = extract_error_fields(raw, execution_detail)
            inc_key = incident_key(sid, signature)

            incident = state["incidents"].get(inc_key)
            if not incident:
                incident = {
                    "incident_key": inc_key,
                    "scenario_id": sid,
                    "scenario_name": sname,
                    "signature": signature,
                    "status": "open",
                    "first_seen_ms": ts,
                    "last_seen_ms": ts,
                    "last_alert_ms": 0,
                    "last_execution_id": exec_id,
                    "last_execution_url": make_execution_url(cfg.base_url, cfg.team_id, sid, exec_id),
                    "occurrences": 1,
                    "reopen_count": 0,
                    "last_module_name": error_fields.get("module_name", ""),
                    "last_error_message": error_fields.get("error_message", ""),
                    "last_error_code": error_fields.get("error_code", ""),
                }
                state["incidents"][inc_key] = incident
                alerts.append(("new_error", incident, str(exec_id)))
                continue

            prev_status = incident.get("status")
            incident["scenario_name"] = sname
            incident["last_seen_ms"] = max(int(incident.get("last_seen_ms", 0)), ts)
            incident["last_execution_id"] = exec_id
            incident["last_execution_url"] = make_execution_url(cfg.base_url, cfg.team_id, sid, exec_id)
            incident["occurrences"] = int(incident.get("occurrences", 0)) + 1
            incident["last_module_name"] = error_fields.get("module_name", "")
            incident["last_error_message"] = error_fields.get("error_message", "")
            incident["last_error_code"] = error_fields.get("error_code", "")

            if prev_status == "resolved":
                incident["status"] = "open"
                incident["reopen_count"] = int(incident.get("reopen_count", 0)) + 1
                alerts.append(("failed_again", incident, str(exec_id)))
                continue

            incident["status"] = "open"
            last_alert_ms = int(incident.get("last_alert_ms", 0))
            if current_ms - last_alert_ms >= cfg.still_failing_suppression_seconds * 1000:
                alerts.append(("still_failing", incident, str(exec_id)))

        if budget_exhausted:
            break

    for incident in state["incidents"].values():
        if incident.get("status") != "open":
            continue

        sid = int(incident["scenario_id"])
        scenario_state = state["scenario_health"].get(str(sid), {})
        last_success_ms = int(scenario_state.get("last_success_ms", 0))
        last_seen_ms = int(incident.get("last_seen_ms", 0))

        if last_success_ms <= last_seen_ms:
            continue

        if current_ms - last_seen_ms < cfg.resolve_grace_seconds * 1000:
            continue

        incident["status"] = "resolved"
        incident["resolved_at_ms"] = current_ms
        alerts.append(("resolved", incident, str(current_ms)))

    cutoff_events_ms = current_ms - (cfg.seen_execution_ttl_seconds * 1000)
    state["seen_executions"] = prune_ttl_map(state["seen_executions"], cutoff_events_ms)
    state["emitted_event_ids"] = prune_ttl_map(state["emitted_event_ids"], cutoff_events_ms)

    sent_count = 0
    for event_type, incident, marker in alerts:
        eid = event_id(event_type, incident["incident_key"], marker)
        if eid in state["emitted_event_ids"]:
            continue

        payload = alert_payload(
            event_type,
            incident,
            {
                "idempotency_key": eid,
                "last_execution_id": incident.get("last_execution_id"),
            },
        )

        notifier.notify_all(payload)

        state["emitted_event_ids"][eid] = current_ms
        incident["last_alert_ms"] = current_ms
        sent_count += 1

        # Useful fallback log line even when external notifications are configured.
        print(json.dumps(payload, sort_keys=True))

    state["last_poll_ms"] = current_ms
    write_json_atomic(state_path, state)

    open_count = sum(1 for i in state["incidents"].values() if i.get("status") == "open")
    print(
        json.dumps(
            {
                "scenarios_total": len(scenarios),
                "scenarios_tracked_total": len(tracked_scenarios_all),
                "scenarios_scanned_this_run": scenarios_scanned_count,
                "alerts_sent": sent_count,
                "incidents_open": open_count,
                "make_call_count": client.call_count,
                "make_call_budget": cfg.max_make_calls_per_run,
                "make_budget_exhausted": budget_exhausted,
                "poll_window_from": iso_utc(from_ms),
                "poll_window_to": iso_utc(current_ms),
                "state_file": str(state_path),
            },
            sort_keys=True,
        )
    )

    return 0


def main() -> None:
    try:
        code = process()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR monitor failed: {exc}", file=sys.stderr)
        sys.exit(2)

    sys.exit(code)


if __name__ == "__main__":
    main()
