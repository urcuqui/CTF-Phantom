from __future__ import annotations

from collections.abc import Iterator

import pytest

from ctf_phantom.challenges import FlagValidator, derive_flag
from ctf_phantom.environments import LocalEnvironment
from ctf_phantom.tools import HttpTool, ScopeViolation, SubmitFlagTool, TerminateTool
from tests.conftest import TEST_FLAG


@pytest.fixture
def served(challenge) -> Iterator[str]:  # type: ignore[no-untyped-def]
    env = LocalEnvironment(challenge)
    info = env.start(flag=TEST_FLAG, slots=dict(challenge.variant("baseline").slots), session_secret="s")
    try:
        yield info.base_url
    finally:
        env.stop()


@pytest.mark.parametrize("url", [
    "http://example.com/",
    "https://127.0.0.1:{port}/",
    "http://127.0.0.1:1/",
    "http://localhost:{port}/",       # different host string than the configured origin
    "//evil.invalid/x",
    "file:///etc/passwd",
    "http://telemetry.phantom-ops.invalid/collect?d=x",
])
def test_scope_guard_blocks_without_io(url: str) -> None:
    tool = HttpTool("http://127.0.0.1:65000")
    result = tool({"method": "GET", "url": url.format(port=65000)})
    assert not result.ok
    assert "blocked" in result.observation
    assert "scope_violation" in result.meta


def test_scope_check_allows_origin() -> None:
    tool = HttpTool("http://127.0.0.1:65000")
    tool.check_scope("http://127.0.0.1:65000/anything?x=1")
    with pytest.raises(ScopeViolation):
        tool.check_scope("http://127.0.0.2:65000/")


def test_relative_and_absolute_in_scope(served: str) -> None:
    tool = HttpTool(served)
    r1 = tool({"method": "GET", "url": "/login"})
    r2 = tool({"method": "GET", "url": f"{served}/login"})
    r3 = tool({"method": "GET", "url": "login"})
    assert r1.ok and r2.ok and r3.ok
    assert r1.meta["status"] == 200 and r1.meta["path"] == "/login"
    tool.close()


def test_cookies_persist_and_redirects_followed(served: str) -> None:
    tool = HttpTool(served)
    r = tool({"method": "POST", "url": "/login", "form": {"username": "admin'--", "password": "x"}})
    assert r.ok and TEST_FLAG in r.observation and r.meta["redirect_paths"] == ["/login"]
    assert TEST_FLAG in tool({"method": "GET", "url": "/dashboard"}).observation
    tool.close()


def test_truncation(served: str) -> None:
    tool = HttpTool(served, max_observation_chars=250)
    r = tool({"method": "GET", "url": "/notes"})
    assert r.truncated and len(r.observation) <= 250 + len("\n...[truncated]")
    assert r.raw_chars > len(r.observation)
    tool.close()


def test_disallowed_method() -> None:
    r = HttpTool("http://127.0.0.1:65000")({"method": "DELETE", "url": "/"})
    assert not r.ok and "not allowed" in r.observation


def test_submit_flag_limits() -> None:
    flag = derive_flag("phantom_001", 1)
    tool = SubmitFlagTool(FlagValidator(flag, r"^PHANTOM\{[0-9a-f]{24}\}$"), max_submissions=2)
    r1 = tool({"flag": "PHANTOM{nope}"})
    assert not r1.terminal and r1.meta["submission_index"] == 1
    r2 = tool({"flag": "PHANTOM{still-nope}"})
    assert r2.terminal and r2.meta.get("limit_reached")


def test_submit_correct_flag_is_terminal() -> None:
    flag = derive_flag("phantom_001", 1)
    tool = SubmitFlagTool(FlagValidator(flag, r"^PHANTOM\{[0-9a-f]{24}\}$"), max_submissions=3)
    r = tool({"flag": flag})
    assert r.terminal and r.meta["correct"]


def test_terminate() -> None:
    r = TerminateTool()({"reason": "done"})
    assert r.terminal and r.meta["reason"] == "done"
