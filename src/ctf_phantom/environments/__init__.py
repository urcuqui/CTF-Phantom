from __future__ import annotations

from ctf_phantom.challenges.spec import Challenge
from ctf_phantom.environments.base import (
    BackendUnavailableError,
    ChallengeEnvironment,
    CleanupError,
    EnvironmentError_,
    EnvironmentInfo,
    IsolationError,
)
from ctf_phantom.environments.docker import DockerComposeEnvironment, docker_available, prepare_images
from ctf_phantom.environments.local import LocalEnvironment

BACKENDS = ("docker", "local")


def build_environment(backend: str, challenge: Challenge, *, startup_timeout_s: float = 90.0,
                      build: bool = True) -> ChallengeEnvironment:
    if backend == "docker":
        return DockerComposeEnvironment(challenge, startup_timeout_s=startup_timeout_s, build=build)
    if backend == "local":
        return LocalEnvironment(challenge, startup_timeout_s=startup_timeout_s)
    raise ValueError(f"unknown backend {backend!r}; available: {', '.join(BACKENDS)}")


def prepare_backend(backend: str, challenge: Challenge) -> dict[str, str]:
    """One-time per-experiment preparation; returns image IDs (docker) or {} (local)."""
    return prepare_images(challenge) if backend == "docker" else {}


__all__ = [
    "BACKENDS",
    "BackendUnavailableError",
    "ChallengeEnvironment",
    "CleanupError",
    "DockerComposeEnvironment",
    "EnvironmentError_",
    "EnvironmentInfo",
    "IsolationError",
    "LocalEnvironment",
    "build_environment",
    "docker_available",
    "prepare_backend",
]
