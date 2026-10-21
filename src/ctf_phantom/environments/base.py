"""Challenge environment lifecycle. One environment instance == one fresh run (reset by design)."""

from __future__ import annotations

import abc
import socket
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ctf_phantom.challenges.spec import Challenge


@dataclass
class EnvironmentInfo:
    backend: str
    base_url: str
    startup_s: float
    details: dict[str, Any] = field(default_factory=dict)


class EnvironmentError_(RuntimeError):
    """Environment failed to start or respond (treated as transient / recoverable)."""


class BackendUnavailableError(EnvironmentError_):
    """The backend itself is unusable (e.g. Docker daemon down). Irrecoverable for the experiment."""


class IsolationError(EnvironmentError_):
    """The isolation guarantees could not be verified. Irrecoverable: never run an agent."""


class CleanupError(EnvironmentError_):
    """Teardown failed; the reset guarantee between runs no longer holds. Irrecoverable."""


class ChallengeEnvironment(abc.ABC):
    backend: str

    def __init__(self, challenge: Challenge, *, startup_timeout_s: float = 90.0) -> None:
        self.challenge = challenge
        self.startup_timeout_s = startup_timeout_s

    @abc.abstractmethod
    def start(self, *, flag: str, slots: dict[str, Any], session_secret: str) -> EnvironmentInfo: ...

    @abc.abstractmethod
    def stop(self) -> None: ...

    def server_logs(self) -> list[str]:
        return []

    def __enter__(self) -> ChallengeEnvironment:
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def wait_healthy(self, base_url: str) -> None:
        url = base_url.rstrip("/") + self.challenge.spec.app.healthcheck_path
        deadline = time.monotonic() + self.startup_timeout_s
        last: Exception | str | None = None
        with httpx.Client(timeout=2.0, trust_env=False) as client:
            while time.monotonic() < deadline:
                try:
                    if client.get(url).status_code == 200:
                        return
                    last = "non-200 healthcheck"
                except httpx.HTTPError as exc:
                    last = exc
                time.sleep(0.25)
        raise EnvironmentError_(f"environment not healthy at {url} after {self.startup_timeout_s}s: {last}")


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
