"""Docker A4 validation end to end: build, run isolated, compare immutable image IDs, clean up.

Requires a running Docker daemon (skipped otherwise; run in CI by .github/workflows/docker.yml).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ctf_phantom import runner as runner_mod
from ctf_phantom.config import ExperimentConfig, PinsConfig
from ctf_phantom.environments import docker_available
from ctf_phantom.environments.docker import DockerComposeEnvironment, prepare_images
from ctf_phantom.evaluation import check_acceptance
from ctf_phantom.images import normalize_image_id
from ctf_phantom.runner import current_pins, execute_experiment, preflight
from ctf_phantom.tracing import EventType, read_trace

pytestmark = [pytest.mark.docker, pytest.mark.integration,
              pytest.mark.skipif(not docker_available(), reason="Docker daemon not available")]


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=True, timeout=120).stdout


def _phantom_resources() -> tuple[list[str], list[str]]:
    containers = [c for c in _docker("ps", "-a", "--format", '{{.Label "com.docker.compose.project"}}').split()
                  if c.startswith("phantom_")]
    networks = [n for n in _docker("network", "ls", "--format", "{{.Name}}").split() if n.startswith("phantom_")]
    return containers, networks


@pytest.fixture(scope="module")
def prepared(challenge) -> tuple[dict[str, str], dict[str, str]]:  # type: ignore[no-untyped-def]
    return prepare_images(challenge)


@pytest.fixture(scope="module")
def expected_content(prepared: tuple[dict[str, str], dict[str, str]]) -> dict[str, str]:
    return prepared[1]


def test_prepare_images_reports_immutable_ids_per_service(prepared: tuple[dict[str, str], dict[str, str]]) -> None:
    ids, content = prepared
    assert set(ids) == set(content) == {"challenge", "gateway"}
    for value in (*ids.values(), *content.values()):
        assert normalize_image_id(value) == value  # full sha256:<64 hex>, never a short ID
    tagged = _docker("image", "inspect", "ctf-phantom/phantom_001:latest", "--format", "{{.Id}}")
    assert normalize_image_id(tagged) == ids["challenge"]


def test_content_ids_are_stable_across_rebuilds(challenge, expected_content: dict[str, str]) -> None:  # type: ignore[no-untyped-def]
    _, again = prepare_images(challenge)  # full rebuild; engine IDs may change on containerd stores
    assert again == expected_content


def test_isolated_environment_uses_expected_images_and_cleans_up(challenge, expected_content) -> None:  # type: ignore[no-untyped-def]
    env = DockerComposeEnvironment(challenge, build=False)
    try:
        info = env.start(flag="PHANTOM{" + "0" * 24 + "}", slots=dict(challenge.variant("baseline").slots),
                         session_secret="s" * 32)
        assert info.details["egress_blocked"] is True
        assert info.details["image_content"] == expected_content  # identical services AND content
        tagged = _docker("image", "inspect", "ctf-phantom/phantom_001:latest", "--format", "{{.Id}}")
        assert info.details["images"]["challenge"] == normalize_image_id(tagged)  # the image actually run
        ids = _docker("ps", "-q", "--filter", f"label=com.docker.compose.project={env.project}").split()
        by_service = {}
        for cid in ids:
            data = json.loads(_docker("inspect", cid))[0]
            by_service[data["Config"]["Labels"]["com.docker.compose.service"]] = data
        # challenge: only on internal networks, publishes nothing
        nets = by_service["challenge"]["NetworkSettings"]["Networks"]
        for name in nets:
            assert json.loads(_docker("network", "inspect", name))[0]["Internal"] is True, name
        assert not by_service["challenge"]["HostConfig"]["PortBindings"]
        # gateway: published on loopback only
        bindings = [b for v in by_service["gateway"]["HostConfig"]["PortBindings"].values() for b in v]
        assert bindings and all(b["HostIp"] == "127.0.0.1" for b in bindings)
    finally:
        env.stop()
    containers, networks = _phantom_resources()
    assert env.project not in containers and not any(n.startswith(env.project) for n in networks)


def test_reference_run_passes_a4_and_tampered_images_fail(tmp_path: Path, challenge, expected_content,  # type: ignore[no-untyped-def]
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "git_state", lambda: {"commit": "test", "dirty": False})
    cfg = ExperimentConfig.model_validate({
        "name": "a4", "challenge": "phantom_001", "variants": ["baseline", "prompt_injection"], "seed": 21,
        "shuffle_variants": False, "environment": {"backend": "docker", "startup_timeout_s": 120},
        "provider": {"name": "scripted", "model": "reference", "script": "reference"},
        "output_dir": str(tmp_path / "results"),
    })
    _, secret = preflight(cfg)
    cfg = cfg.model_copy(update={"pins": PinsConfig.model_validate(current_pins(cfg, challenge, secret))})
    report = execute_experiment(cfg)
    exp = report.out_dir
    assert report.status == "completed" and all(r.metrics.challenge_completed for r in report.results)

    meta = json.loads((exp / "experiment.json").read_text())
    # The experiment rebuilt the images itself; content IDs still equal the earlier build.
    assert meta["environment_image_content"] == expected_content
    for r in report.results:
        ready = next(e for e in read_trace(r.run_dir / "trace.jsonl") if e.type is EventType.ENVIRONMENT_READY)
        assert ready.data["backend"] == "docker" and ready.data["details"]["egress_blocked"] is True
        assert ready.data["details"]["images"] == meta["environment_images"]  # built once, used by every run
        assert ready.data["details"]["image_content"] == expected_content

    def a4(directory: Path) -> dict[str, Any]:
        return next(c for c in check_acceptance(directory)["criteria"] if c["id"] == "A4")

    assert a4(exp)["status"] == "pass", a4(exp)["detail"]

    def tampered(name: str, images: dict[str, str], key: str = "environment_image_content") -> Path:
        copy = tmp_path / name
        shutil.copytree(exp, copy)
        data = json.loads((copy / "experiment.json").read_text())
        data[key] = images
        (copy / "experiment.json").write_text(json.dumps(data))
        return copy

    c = expected_content
    other = {"challenge": c["gateway"], "gateway": c["gateway"]}
    swapped = {"challenge": c["gateway"], "gateway": c["challenge"]}
    short = {k: v.removeprefix("sha256:")[:12] for k, v in c.items()}
    # A different engine ID for byte-identical content is NOT a false mismatch.
    rebuilt = {k: "sha256:" + "f" * 64 for k in meta["environment_images"]}
    assert a4(tampered("rebuilt", rebuilt, key="environment_images"))["status"] == "pass"
    for name, images, problem in [("other", other, "images_differ_from_experiment"),
                                  ("swapped", swapped, "images_differ_from_experiment"),
                                  ("short", short, "image_id_not_immutable")]:
        result = a4(tampered(name, images))
        assert result["status"] == "fail" and problem in result["detail"], (name, result)

    containers, networks = _phantom_resources()
    assert not containers and not networks, (containers, networks)
