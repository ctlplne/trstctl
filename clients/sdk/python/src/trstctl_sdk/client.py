"""Dependency-free Python runtime for the trstctl served OpenAPI contract.

The resource shapes are generated into :mod:`trstctl_sdk.types` from
``clients/sdk/openapi.json``. This runtime adds the behavior every caller needs:
bearer auth, optional tenant hint, stable Idempotency-Key on mutations, RFC 7807
problem parsing, and bounded retries that honor Retry-After.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Mapping, MutableMapping, Optional, Union
from urllib import error, parse, request

DEFAULT_USER_AGENT = "trstctl-python-sdk/1"


@dataclass(frozen=True)
class RetryPolicy:
    """Retry behavior for request and mutation calls."""

    max_attempts: int = 4
    base_delay_seconds: float = 0.2
    max_delay_seconds: float = 5.0

    @classmethod
    def from_value(cls, value: Optional[Union["RetryPolicy", Mapping[str, Any]]]) -> "RetryPolicy":
        if value is None:
            return DEFAULT_RETRY
        if isinstance(value, RetryPolicy):
            return value
        return cls(
            max_attempts=int(value.get("max_attempts", DEFAULT_RETRY.max_attempts)),
            base_delay_seconds=float(value.get("base_delay_seconds", DEFAULT_RETRY.base_delay_seconds)),
            max_delay_seconds=float(value.get("max_delay_seconds", DEFAULT_RETRY.max_delay_seconds)),
        ).with_defaults()

    def with_defaults(self) -> "RetryPolicy":
        return RetryPolicy(
            max_attempts=self.max_attempts if self.max_attempts >= 1 else DEFAULT_RETRY.max_attempts,
            base_delay_seconds=self.base_delay_seconds if self.base_delay_seconds > 0 else DEFAULT_RETRY.base_delay_seconds,
            max_delay_seconds=self.max_delay_seconds if self.max_delay_seconds > 0 else DEFAULT_RETRY.max_delay_seconds,
        )


DEFAULT_RETRY = RetryPolicy()


class ProblemError(Exception):
    """RFC 7807 problem+json error returned by the trstctl API."""

    def __init__(self, http_status: int, body: Optional[Mapping[str, Any]] = None, retry_after_seconds: Optional[int] = None):
        body = dict(body or {})
        self.http_status = http_status
        self.type = body.get("type") if isinstance(body.get("type"), str) else None
        self.title = body.get("title") if isinstance(body.get("title"), str) else None
        self.status = body.get("status") if isinstance(body.get("status"), int) else None
        self.detail = body.get("detail") if isinstance(body.get("detail"), str) else None
        self.instance = body.get("instance") if isinstance(body.get("instance"), str) else None
        self.retry_after_seconds = retry_after_seconds
        self.extensions = {k: v for k, v in body.items() if k not in {"type", "title", "status", "detail", "instance"}}
        label = self.title or ""
        if self.detail:
            label = f"{label}: {self.detail}" if label else self.detail
        super().__init__(f"trstctl: {http_status} {label}".strip())

    @property
    def is_rate_limited(self) -> bool:
        return self.http_status == 429


def is_problem(err: BaseException) -> bool:
    return isinstance(err, ProblemError)


def new_idempotency_key() -> str:
    return str(uuid.uuid4())


_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
_RETRYABLE = {429, 502, 503, 504}


class TrstctlClient:
    """SDK entry point for a trstctl control plane."""

    def __init__(
        self,
        *,
        base_url: str,
        token: Optional[str] = None,
        tenant: Optional[str] = None,
        timeout: float = 30.0,
        retry: Optional[Union[RetryPolicy, Mapping[str, Any]]] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        opener: Optional[request.OpenerDirector] = None,
    ) -> None:
        if not base_url:
            raise ValueError("trstctl: base_url is required")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.tenant = tenant
        self.timeout = timeout
        self.retry = RetryPolicy.from_value(retry)
        self.user_agent = user_agent
        self.opener = opener or request.build_opener()

    @classmethod
    def from_env(cls, **kwargs: Any) -> "TrstctlClient":
        """Build a client from TRSTCTL_SERVER, TRSTCTL_TOKEN, and TRSTCTL_TENANT."""

        base_url = os.environ.get("TRSTCTL_SERVER") or os.environ.get("TRSTCTL_ENDPOINT")
        if not base_url:
            raise ValueError("TRSTCTL_SERVER is required")
        return cls(
            base_url=base_url,
            token=os.environ.get("TRSTCTL_TOKEN"),
            tenant=os.environ.get("TRSTCTL_TENANT"),
            **kwargs,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Any] = None,
        query: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Any:
        method = method.upper()
        url = self._url(path, query)
        headers: MutableMapping[str, str] = {
            "Accept": "application/json, application/problem+json",
            "User-Agent": self.user_agent,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.tenant:
            headers["X-Tenant-ID"] = self.tenant
        if method in _MUTATING:
            headers["Idempotency-Key"] = idempotency_key or new_idempotency_key()

        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"

        last_error: Optional[BaseException] = None
        for attempt in range(1, self.retry.max_attempts + 1):
            req = request.Request(url, data=data, headers=dict(headers), method=method)
            try:
                with self.opener.open(req, timeout=self.timeout) as resp:
                    return self._decode_success(resp.status, resp.read())
            except error.HTTPError as exc:
                retry_after = _parse_retry_after(exc.headers.get("Retry-After"))
                problem = self._problem(exc.code, exc.read(), retry_after)
                last_error = problem
                if exc.code in _RETRYABLE and attempt < self.retry.max_attempts:
                    time.sleep(self._backoff(attempt, retry_after))
                    continue
                raise problem from None
            except error.URLError as exc:
                last_error = exc
                if attempt < self.retry.max_attempts:
                    time.sleep(self._backoff(attempt, None))
                    continue
                raise
        assert last_error is not None
        raise last_error

    def create_profile(self, name: str, spec: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Any:
        return self.request("POST", "/api/v1/profiles", body={"name": name, "spec": dict(spec)}, idempotency_key=idempotency_key)

    def issue_pki_secret(self, common_name: str, *, ttl_seconds: int = 3600, idempotency_key: Optional[str] = None) -> Any:
        return self.request(
            "POST",
            "/api/v1/secrets/pki",
            body={"common_name": common_name, "ttl_seconds": ttl_seconds},
            idempotency_key=idempotency_key,
        )

    def create_secret(self, name: str, value: str, *, idempotency_key: Optional[str] = None) -> Any:
        return self.request("POST", "/api/v1/secrets/store", body={"name": name, "value": value}, idempotency_key=idempotency_key)

    def list_secrets(self, *, limit: Optional[int] = None, cursor: Optional[str] = None) -> Any:
        return self.request("GET", "/api/v1/secrets/store", query={"limit": limit, "cursor": cursor})

    def get_secret(self, name: str, *, resolve: bool = False) -> Any:
        return self.request("GET", f"/api/v1/secrets/store/{_secret_path(name)}", query={"resolve": "true" if resolve else None})

    def rotate_secret(self, name: str, value: str, *, idempotency_key: Optional[str] = None) -> Any:
        return self.request("PUT", f"/api/v1/secrets/store/{_secret_path(name)}", body={"value": value}, idempotency_key=idempotency_key)

    def delete_secret(self, name: str, *, idempotency_key: Optional[str] = None) -> None:
        self.request("DELETE", f"/api/v1/secrets/store/{_secret_path(name)}", idempotency_key=idempotency_key)

    def _url(self, path: str, query: Optional[Mapping[str, Any]]) -> str:
        url = self.base_url + path
        if not query:
            return url
        pairs = [(k, str(v).lower() if isinstance(v, bool) else str(v)) for k, v in query.items() if v not in (None, "")]
        if not pairs:
            return url
        return url + "?" + parse.urlencode(pairs)

    def _backoff(self, attempt: int, retry_after_seconds: Optional[int]) -> float:
        if retry_after_seconds is not None:
            return min(float(retry_after_seconds), self.retry.max_delay_seconds)
        delay = self.retry.base_delay_seconds * (2 ** max(0, attempt - 1))
        return min(delay, self.retry.max_delay_seconds)

    @staticmethod
    def _decode_success(status: int, data: bytes) -> Any:
        if status == 204:
            return None
        if not data:
            return None
        return json.loads(data.decode("utf-8"))

    @staticmethod
    def _problem(status: int, data: bytes, retry_after: Optional[int]) -> ProblemError:
        try:
            parsed = json.loads(data.decode("utf-8")) if data else {}
        except json.JSONDecodeError:
            parsed = {"detail": data.decode("utf-8", errors="replace")}
        if not isinstance(parsed, Mapping):
            parsed = {"detail": str(parsed)}
        return ProblemError(status, parsed, retry_after)


def _parse_retry_after(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return max(0, int(float(value)))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return max(0, int(when.timestamp() - time.time()))


def _secret_path(name: str) -> str:
    return "/".join(parse.quote(part, safe="") for part in name.split("/"))
