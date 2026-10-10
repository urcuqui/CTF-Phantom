"""In-process backend: serves the challenge app on 127.0.0.1 in a background thread.

For development, tests and CI where Docker is unavailable. It provides loopback-only binding and a
fresh app per run, but NOT container isolation; use the docker backend for reported experiments.
"""

from __future__ import annotations

import importlib.util
import logging
import threading
import time
from types import ModuleType
from typing import Any

from werkzeug.serving import BaseWSGIServer, make_server

from ctf_phantom.environments.base import ChallengeEnvironment, EnvironmentError_, EnvironmentInfo


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def load_app_module(path: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise EnvironmentError_(f"cannot load challenge app from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LocalEnvironment(ChallengeEnvironment):
    backend = "local"

    _server: BaseWSGIServer | None = None
    _thread: threading.Thread | None = None
    _handler: _ListHandler | None = None
    _logger: logging.Logger | None = None

    def start(self, *, flag: str, slots: dict[str, Any], session_secret: str) -> EnvironmentInfo:
        t0 = time.monotonic()
        module_path = self.challenge.root / self.challenge.spec.app.module
        module = load_app_module(str(module_path), f"_ctf_phantom_app_{self.challenge.id}")
        app = module.create_app(flag=flag, slots=slots, session_secret=session_secret)

        self._logger = logging.getLogger(module.ACCESS_LOGGER)
        self._handler = _ListHandler()
        self._logger.addHandler(self._handler)
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        self._server = make_server("127.0.0.1", 0, app, threaded=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        base_url = f"http://127.0.0.1:{self._server.server_port}"
        self.wait_healthy(base_url)
        return EnvironmentInfo(
            backend=self.backend,
            base_url=base_url,
            startup_s=round(time.monotonic() - t0, 3),
            details={"isolation": "loopback-only, in-process (no container isolation)"},
        )

    def server_logs(self) -> list[str]:
        return list(self._handler.lines) if self._handler else []

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._logger is not None and self._handler is not None:
            self._logger.removeHandler(self._handler)
