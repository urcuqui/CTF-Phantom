"""Docker Compose backend: a fresh, network-isolated compose project per run.

Lifecycle per run: ``up --build --wait`` (new project name) -> agent episode -> collect logs ->
``down -v --remove-orphans``. The challenge container sits on an ``internal`` network with no
egress; an nginx gateway publishes it on 127.0.0.1 only. An egress probe from inside the
challenge container is executed and recorded as evidence of isolation.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from typing import Any

from ctf_phantom.environments.base import (
    BackendUnavailableError,
    ChallengeEnvironment,
    CleanupError,
    EnvironmentError_,
    EnvironmentInfo,
    IsolationError,
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


_BUILD_ENV = {"PHANTOM_FLAG": "PHANTOM{000000000000000000000000}", "PHANTOM_HOST_PORT": "0"}


def prepare_images(challenge: Any, *, timeout: float = 900) -> dict[str, str]:
    """Pull + build the challenge's images ONCE per experiment and return {image_ref: image_id}.

    Runs then start with ``build=False`` so every run of an experiment uses byte-identical images
    (compose labels images with the project name, so per-run builds would yield new image IDs).
    """
    if not docker_available():
        raise BackendUnavailableError("Docker daemon not reachable. Start Docker or use --backend local.")
    compose = str(challenge.root / challenge.spec.app.compose_file)
    base = ["docker", "compose", "-f", compose, "-p", f"phantom_build_{challenge.id}"]
    env = {**os.environ, **_BUILD_ENV}

    def run(*args: str) -> str:
        try:
            proc = subprocess.run([*base, *args], env=env, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise EnvironmentError_(f"compose {' '.join(args)} timed out") from exc
        if proc.returncode != 0:
            raise EnvironmentError_(f"compose {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc.stdout

    run("pull", "--ignore-buildable", "--quiet")
    run("build", "--quiet")
    images: dict[str, str] = {}
    for ref in run("config", "--images").split():
        proc = subprocess.run(["docker", "image", "inspect", ref, "--format", "{{.Id}}"],
                              capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            raise EnvironmentError_(f"image {ref} missing after build: {proc.stderr.strip()}")
        images[ref] = proc.stdout.strip()
    return images


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
        try:
            proc = subprocess.run(cmd, env=self._env, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            if args and args[0] == "down":
                raise CleanupError(f"compose down timed out for project {self.project}") from exc
            raise EnvironmentError_(f"{' '.join(cmd)} timed out after {timeout}s") from exc
        if check and proc.returncode != 0:
            raise EnvironmentError_(f"{' '.join(cmd)} failed ({proc.returncode}):\n{proc.stderr.strip()}")
        return proc

    def start(self, *, flag: str, slots: dict[str, Any], session_secret: str) -> EnvironmentInfo:
        if not docker_available():
            raise BackendUnavailableError("Docker daemon not reachable. Start Docker or use --backend local.")
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
        # No teardown here on failure: callers always call stop() (the runner does so in a
        # `finally`), which surfaces CleanupError instead of masking it.
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
                raise IsolationError("isolation check failed: challenge container has egress")
        return EnvironmentInfo(self.backend, base_url, round(time.monotonic() - t0, 3), details)

    def _image_ids(self) -> dict[str, str]:
        proc = self._compose("images", "--format", "json", check=False)
        if proc.returncode != 0:
            return {}
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
            proc = self._compose("down", "-v", "--remove-orphans", "--timeout", "5", check=False, timeout=120)
        finally:
            self._env = None
        if proc.returncode != 0:
            raise CleanupError(f"compose down failed for project {self.project}: {proc.stderr.strip()}")
