from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from ctf_phantom.challenges import (
    ChallengeValidationError,
    list_challenges,
    load_challenge,
    slot_texts,
)
from tests.conftest import CHALLENGES

EXPECTED_VARIANTS = {"baseline", "benign_control", "deception", "prompt_injection"}


def test_lists_phantom_001() -> None:
    assert "phantom_001" in list_challenges(CHALLENGES)


def test_loads_all_four_variants(challenge) -> None:  # type: ignore[no-untyped-def]
    assert set(challenge.variants) == EXPECTED_VARIANTS
    assert challenge.variant("baseline").condition == "control"
    assert challenge.variant("benign_control").condition == "control"
    assert challenge.variant("deception").condition == "treatment"
    assert challenge.variant("prompt_injection").condition == "treatment"


def test_controls_have_no_indicators_and_treatments_have_action_indicators(challenge) -> None:  # type: ignore[no-untyped-def]
    for v in challenge.variants.values():
        if v.condition == "control":
            assert v.indicators == []
        else:
            assert any(i.kind == "action" for i in v.indicators)


def test_hashes_are_stable_and_distinct(challenge) -> None:  # type: ignore[no-untyped-def]
    again = load_challenge("phantom_001", CHALLENGES)
    assert again.challenge_hash == challenge.challenge_hash
    assert again.variant_hashes == challenge.variant_hashes
    assert len(set(challenge.variant_hashes.values())) == 4
    for vid, hashes in challenge.payload_hashes.items():
        assert set(hashes) == set(challenge.spec.content_slots), vid


def test_unknown_variant_raises(challenge) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(KeyError):
        challenge.variant("nope")


def test_objective_renders_base_url(challenge) -> None:  # type: ignore[no-untyped-def]
    text = challenge.spec.render_objective("http://127.0.0.1:9999")
    assert "http://127.0.0.1:9999" in text and "PHANTOM{...}" in text


def _copy_challenge(tmp_path: Path) -> Path:
    dst = tmp_path / "challenges"
    shutil.copytree(CHALLENGES / "phantom_001", dst / "phantom_001")
    return dst


def _mutate_variant(root: Path, vid: str, fn) -> None:  # type: ignore[no-untyped-def]
    path = root / "phantom_001" / "variants" / f"{vid}.yaml"
    data = yaml.safe_load(path.read_text())
    fn(data)
    path.write_text(yaml.safe_dump(data))


def test_rejects_undeclared_slot(tmp_path: Path) -> None:
    root = _copy_challenge(tmp_path)
    _mutate_variant(root, "deception", lambda d: d["slots"].update({"page_title": "x"}))
    with pytest.raises(ChallengeValidationError, match="declared slots"):
        load_challenge("phantom_001", root)


def test_rejects_oversized_slot(tmp_path: Path) -> None:
    root = _copy_challenge(tmp_path)
    _mutate_variant(root, "prompt_injection", lambda d: d["slots"].update({"login_html_comment": "A" * 5000}))
    with pytest.raises(ChallengeValidationError, match="max"):
        load_challenge("phantom_001", root)


def test_rejects_marker_absent_from_payload(tmp_path: Path) -> None:
    root = _copy_challenge(tmp_path)
    _mutate_variant(root, "baseline", lambda d: d.update({"exposure_markers": ["not in content"]}))
    with pytest.raises(ChallengeValidationError, match="exposure marker"):
        load_challenge("phantom_001", root)


def test_benign_control_is_length_matched_to_treatments(challenge) -> None:  # type: ignore[no-untyped-def]
    def size(vid: str) -> int:
        return sum(len(t) for t in slot_texts(challenge.spec, challenge.variant(vid).slots).values())

    control = size("benign_control")
    for treatment in ("deception", "prompt_injection"):
        assert abs(control - size(treatment)) / size(treatment) <= 0.2, treatment


def test_exposure_markers_are_unique_to_their_variant(challenge) -> None:  # type: ignore[no-untyped-def]
    for vid, v in challenge.variants.items():
        for other_id, other in challenge.variants.items():
            if other_id == vid:
                continue
            other_text = "\n".join(slot_texts(challenge.spec, other.slots).values())
            for marker in v.exposure_markers:
                assert marker not in other_text, (vid, other_id, marker)
