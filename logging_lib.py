import json
import logging
import time
import re
from typing import Any, Callable, Dict, Optional
from uuid import uuid4
from urllib.parse import urlencode

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import Message


class MinimalJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "asctime": self.formatTime(record, self.datefmt),
            "levelname": record.levelname,
        }
        if isinstance(record.msg, dict):
            base.update(record.msg)
        else:
            base["message"] = record.getMessage()
        return json.dumps(base, ensure_ascii=False)


def get_json_logger(name: str = "main", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
    handler = logging.StreamHandler()
    handler.setFormatter(MinimalJsonFormatter())
    logger.addHandler(handler)
    return logger


class AsyncIteratorWrapper:
    def __init__(self, obj):
        self._it = iter(obj)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            value = next(self._it)
        except StopIteration:
            raise StopAsyncIteration
        return value


def _client_ip_from(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for") or ""
    ip = (xff.split(",")[0].strip() if xff else "") or request.client.host
    return ip


REDACTED = "***REDACTED***"
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"pass(word)?", re.I),
    re.compile(r"token", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"api[-_]?key", re.I),
    re.compile(r"auth", re.I),
    re.compile(r"cookie", re.I),
    re.compile(r"cred", re.I),
    re.compile(r"senha", re.I),
]

JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
BEARER_RE = re.compile(r"^\s*Bearer\s+.+", re.I)


def _is_sensitive_key(key: str) -> bool:
    k = key or ""
    return any(p.search(k) for p in SENSITIVE_KEY_PATTERNS)


def _mask_string(s: str) -> str:
    if not s:
        return s
    if BEARER_RE.match(s) or JWT_RE.search(s):
        return "Bearer " + REDACTED if s.strip().lower().startswith("bearer ") else REDACTED
    return s


def sanitize_data(data):
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            if _is_sensitive_key(str(k)):
                out[k] = REDACTED
            else:
                out[k] = sanitize_data(v)
        return out
    if isinstance(data, list):
        return [sanitize_data(v) for v in data]
    if isinstance(data, str):
        return _mask_string(data)
    return data


def sanitize_query_params(request: Request) -> str:
    if not request.query_params:
        return request.url.path
    items = []
    for k, v in request.query_params.multi_items():
        v_sanitized = REDACTED if _is_sensitive_key(k) else _mask_string(v)
        items.append((k, v_sanitized))
    return f"{request.url.path}?{urlencode(items)}"

def sanitize_headers(headers) -> Dict[str, str]:
    items = headers.items() if hasattr(headers, "items") else list(headers or [])
    out: Dict[str, str] = {}
    for k, v in items:
        k_str = k.decode("latin1") if isinstance(k, (bytes, bytearray)) else str(k)
        v_str = v.decode("latin1") if isinstance(v, (bytes, bytearray)) else str(v)
        k_lower = k_str.lower()
        out[k_lower] = REDACTED if _is_sensitive_key(k_lower) else _mask_string(v_str)
    return out

class RouterLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: FastAPI,
        *,
        logger: logging.Logger,
        level_success: int = logging.INFO,
        level_client_error: int = logging.WARNING,
        level_server_error: int = logging.ERROR,
        status_level_map: Optional[Dict[int, int]] = None,
    ) -> None:
        self._logger = logger
        self._level_success = level_success
        self._level_client_error = level_client_error
        self._level_server_error = level_server_error
        self._status_level_map = status_level_map or {}
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        incoming = (
            request.headers.get("x-api-trace-id")
            or request.headers.get("x-trace-id")
            or request.headers.get("x-correlation-id")
        )
        request_id: str = incoming or str(uuid4())
        request.state.request_id = request_id

        await self._cache_request_body(request)
        response, response_dict = await self._log_response(call_next, request, request_id)
        request_dict = await self._log_request(request)

        log_payload = {
            "X-API-TRACE-ID": request_id,
            "request": request_dict,
            "response": response_dict,
        }

        level = self._level_for_status(response_dict["status_code"])
        self._logger.log(level, log_payload)
        return response

    def _level_for_status(self, status_code: int) -> int:
        if status_code in self._status_level_map:
            return self._status_level_map[status_code]
        if status_code >= 500:
            return self._level_server_error
        if 400 <= status_code < 500:
            return self._level_client_error
        return self._level_success

    async def _cache_request_body(self, request: Request) -> None:
        received = await request._receive()

        async def receive() -> Message:
            return received

        request._receive = receive  # type: ignore[attr-defined]

    async def _log_request(self, request: Request) -> Dict[str, Any]:
        path = sanitize_query_params(request)
        request_logging: Dict[str, Any] = {
            "method": request.method,
            "path": path,
            "ip": _client_ip_from(request),
            "headers": sanitize_headers(request.headers),
        }
        try:
            body = await request.json()
            request_logging["body"] = sanitize_data(body)
        except Exception:
            pass
        return request_logging

    async def _log_response(
        self, call_next: Callable, request: Request, request_id: str
    ) -> tuple[Response, Dict[str, Any]]:
        start_time = time.perf_counter()
        response: Response = await self._execute_request(call_next, request, request_id)
        finish_time = time.perf_counter()

        status = "successful" if response.status_code < 400 else "failed"
        elapsed = f"{(finish_time - start_time):0.4f}s"

        response_logging: Dict[str, Any] = {
            "status": status,
            "status_code": response.status_code,
            "time_taken": elapsed,
        }

        try:
            chunks = [section async for section in response.__dict__["body_iterator"]]
            response.__setattr__("body_iterator", AsyncIteratorWrapper(chunks))
            raw_bytes = b"".join(chunks) if chunks else b""
            if raw_bytes:
                try:
                    parsed = json.loads(raw_bytes.decode())
                    response_logging["body"] = sanitize_data(parsed)
                except Exception:
                    response_logging["body"] = _mask_string(raw_bytes.decode(errors="replace"))
        except Exception:
            pass

        return response, response_logging

    async def _execute_request(
        self, call_next: Callable, request: Request, request_id: str
    ) -> Response:
        try:
            response: Response = await call_next(request)
            response.headers["X-API-TRACE-ID"] = request_id
            return response
        except Exception as exc:
            self._logger.exception(
                {
                    "X-API-TRACE-ID": request_id,
                    "path": request.url.path,
                    "method": request.method,
                    "reason": str(exc),
                }
            )
            raise
