"""Image-ID normalization and per-service comparison (acceptance A4)."""

from __future__ import annotations

import pytest

from ctf_phantom.images import compare_image_maps, normalize_image_id

A, B, C = "a" * 64, "b" * 64, "c" * 64


@pytest.mark.parametrize("raw", [f"sha256:{A}", A, f"SHA256:{A.upper()}", f"  sha256:{A}\n"])
def test_full_ids_normalize_identically(raw: str) -> None:
    assert normalize_image_id(raw) == f"sha256:{A}"


@pytest.mark.parametrize("raw", ["", "aaaaaaaaaaaa", f"sha256:{A[:12]}", "sha256:xyz", f"sha512:{A}",
                                 "ctf-phantom/phantom_001:latest"])
def test_short_or_non_ids_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_image_id(raw)


def test_same_images_in_different_formats_match() -> None:
    assert compare_image_maps({"challenge": f"sha256:{A}", "gateway": f"sha256:{B}"},
                              {"challenge": A.upper(), "gateway": f"sha256:{B}"}) is None


def test_container_names_never_enter_the_comparison() -> None:
    # legacy maps keyed by image ref (experiment) and container name (run): values compared as sets
    assert compare_image_maps({"ctf-phantom/phantom_001:latest": f"sha256:{A}", "nginx@sha256:x": f"sha256:{B}"},
                              {"phantom_x_1a2b-challenge-1": A, "phantom_x_1a2b-gateway-1": B}) is None


@pytest.mark.parametrize(("expected", "used", "problem"), [
    ({"challenge": A, "gateway": B}, {"challenge": C, "gateway": B}, "images_differ_from_experiment"),
    ({"challenge": A, "gateway": B}, {"challenge": B, "gateway": A}, "images_differ_from_experiment"),  # swapped
    ({"challenge": A, "gateway": B}, {"challenge": A}, "images_differ_from_experiment"),               # missing
    ({"challenge": A}, {"challenge": A, "extra": C}, "images_differ_from_experiment"),                 # extra
    ({"challenge": A}, {"challenge": A[:12]}, "image_id_not_immutable"),
    ({}, {"challenge": A}, "experiment_images_not_recorded"),
    ({"challenge": A}, {}, "run_images_not_recorded"),
])
def test_mismatches_are_detected(expected: dict[str, str], used: dict[str, str], problem: str) -> None:
    assert compare_image_maps(expected, used) == problem


def _inspect(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "Id": f"sha256:{A}", "Os": "linux", "Architecture": "arm64",
        "RootFS": {"Layers": [f"sha256:{B}", f"sha256:{C}"]},
        "Config": {"Cmd": ["gunicorn"], "User": "10001", "Env": ["X=1"],
                   "Labels": {"com.docker.compose.project": "p1", "com.docker.compose.version": "2.39.2"}},
    }
    return base | over


def test_content_id_ignores_engine_id_and_compose_labels() -> None:
    from ctf_phantom.images import content_id

    a = content_id(_inspect())
    b = content_id(_inspect(Id=f"sha256:{C}", Config={"Cmd": ["gunicorn"], "User": "10001", "Env": ["X=1"],
                                                       "Labels": {"com.docker.compose.project": "p2"}}))
    assert a == b and normalize_image_id(a) == a


@pytest.mark.parametrize("change", [
    {"RootFS": {"Layers": [f"sha256:{B}"]}},
    {"Architecture": "amd64"},
    {"Config": {"Cmd": ["python"], "User": "10001", "Env": ["X=1"]}},
    {"Config": {"Cmd": ["gunicorn"], "User": "0", "Env": ["X=1"]}},
    {"Config": {"Cmd": ["gunicorn"], "User": "10001", "Env": ["X=1"], "Labels": {"custom": "1"}}},
])
def test_content_id_changes_with_behavioural_content(change: dict[str, object]) -> None:
    from ctf_phantom.images import content_id

    assert content_id(_inspect(**change)) != content_id(_inspect())


def test_content_id_requires_layers() -> None:
    from ctf_phantom.images import content_id

    with pytest.raises(ValueError):
        content_id(_inspect(RootFS={"Layers": []}))


def test_run_comparison_prefers_content_ids() -> None:
    from ctf_phantom.images import compare_run_images

    ids_exp, ids_run = {"challenge": A}, {"challenge": B}           # engine IDs differ (rebuild)
    assert compare_run_images(ids_exp, ids_run, {"challenge": C}, {"challenge": C}) is None
    assert compare_run_images(ids_exp, ids_run, {"challenge": C}, {"challenge": A}) == "images_differ_from_experiment"
    assert compare_run_images(ids_exp, ids_run) == "images_differ_from_experiment"  # legacy: engine IDs only
