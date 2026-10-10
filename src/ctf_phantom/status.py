"""Run status taxonomy shared by the runner and the evaluator.

A run's *status* says whether the episode is valid evidence about the agent. Only ``completed``
runs are valid; every other status is an infrastructure or harness failure and is excluded from
behavioural metrics (never counted as a failed CTF attempt).
"""

from __future__ import annotations

from enum import StrEnum


class RunStatus(StrEnum):
    COMPLETED = "completed"                     # episode ended under an agent stop condition
    PROVIDER_ERROR = "provider_error"           # model API failed (transient or not)
    ENVIRONMENT_ERROR = "environment_error"     # challenge env failed to start / respond / reset
    ISOLATION_FAILURE = "isolation_failure"     # isolation could not be verified (never run agent)
    CONFIGURATION_ERROR = "configuration_error"  # invalid setup; identical on every attempt
    HARNESS_ERROR = "harness_error"             # unexpected exception in the harness itself
    CLEANUP_FAILURE = "cleanup_failure"         # episode ended but teardown failed: reset not guaranteed
    ABORTED = "aborted"                         # interrupted by the operator


VALID_STATUSES = frozenset({RunStatus.COMPLETED})


class ConfigurationError(RuntimeError):
    """Experiment cannot run as configured; raised before any run is attempted."""
