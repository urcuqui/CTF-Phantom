"""Docker Compose backend: a fresh, network-isolated compose project per run.

Lifecycle per run: ``up --build --wait`` (new project name) -> agent episode -> collect logs ->
``down -v --remove-orphans``. The challenge container sits on an ``internal`` network with no
egress; an nginx gateway publishes it on 127.0.0.1 only. An egress probe from inside the
challenge container is executed and recorded as evidence of isolation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from typing import Any

from ctf_phantom.environments.base import (
    ChallengeEnvironment,
    EnvironmentError_,
    EnvironmentInfo,
    free_local_port,
)

_EGRESS_PROBE = (
    "import socket,sys\n"
    "try:\n"
    "    socket.create_connection(('1.1.1.1', 443), timeout=3); sys.exit(1)\n"
    "except OSError:\n"
    "    sys.exit(0)\n"
)


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class DockerComposeEnvironment(ChallengeEnvironment):
    backend = "docker"

    def __init__(self, *args: Any, build: bool = True, verify_isolation: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.build = build
        self.verify_isolation = verify_isolation
        self.project = f"phantom_{self.challenge.id}_{uuid.uuid4().hex[:8]}"
        self.compose_file = self.challenge.root / self.challenge.spec.app.compose_file
        self._env: dict[str, str] | None = None
        self._logs: list[str] = []

    def _compose(self, *args: str, check: bool = True, timeout: float = 300) -> subprocess.CompletedProcess[str]:
        cmd = ["docker", "compose", "-f", str(self.compose_file), "-p", self.project, *args]
        proc = subprocess.run(cmd, env=self._env, capture_output=True, text=True, timeout=timeout)
        if check and proc.returncode != 0:
            raise EnvironmentError_(f"{' '.join(cmd)} failed ({proc.returncode}):\n{proc.stderr.strip()}")
        return proc

    def start(self, *, flag: str, slots: dict[str, Any], session_secret: str) -> EnvironmentInfo:
        import json

        if not docker_available():
            raise EnvironmentError_("Docker daemon not reachable. Start Docker or use --backend local.")
        t0 = time.monotonic()
        port = free_local_port()
        self._env = {
            **os.environ,
            "PHANTOM_FLAG": flag,
            "PHANTOM_SLOTS": json.dumps(slots),
            "PHANTOM_SESSION_SECRET": session_secret,
            "PHANTOM_HOST_PORT": str(port),
        }
        up = ["up", "-d", "--wait", "--wait-timeout", str(int(self.startup_timeout_s))]
        if self.build:
            up.append("--build")
        try:
            self._compose(*up, timeout=self.startup_timeout_s + 600)
            base_url = f"http://127.0.0.1:{port}"
            self.wait_healthy(base_url)
            details: dict[str, Any] = {
                "project": self.project,
                "images": self._image_ids(),
                "network": "challenge on internal-only network; gateway on 127.0.0.1",
            }
            if self.verify_isolation:
                details["egress_blocked"] = self._egress_blocked()
                if not details["egress_blocked"]:
                    raise EnvironmentError_("isolation check failed: challenge container has egress")
        except Exception:
            self.stop()
            raise
        return EnvironmentInfo(self.backend, base_url, round(time.monotonic() - t0, 3), details)

    def _image_ids(self) -> dict[str, str]:
        proc = self._compose("images", "--format", "json", check=False)
        if proc.returncode != 0:
            return {}
        import json

        try:
            rows = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            return {}
        return {r.get("ContainerName", "?"): r.get("ID", "?") for r in rows if isinstance(r, dict)}

    def _egress_blocked(self) -> bool:
        proc = self._compose("exec", "-T", "challenge", "python", "-c", _EGRESS_PROBE, check=False, timeout=30)
        return proc.returncode == 0

    def server_logs(self) -> list[str]:
        if self._env is None:
            return self._logs
        proc = self._compose("logs", "--no-color", "--no-log-prefix", "challenge", check=False, timeout=60)
        self._logs = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        return self._logs

    def stop(self) -> None:
        if self._env is None:
            return
        try:
            self._compose("down", "-v", "--remove-orphans", "--timeout", "5", check=False, timeout=120)
        finally:
            self._env = None
