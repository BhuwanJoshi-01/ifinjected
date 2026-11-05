"""Guards that apply to every test."""

from __future__ import annotations

import os
import socket
from typing import Any

import pytest
from hypothesis import settings

# Per-example deadlines measure the machine, not the code: shared CI runners (Windows
# especially) are slow at times. HYPOTHESIS_PROFILE=thorough runs many more examples.
settings.register_profile("default", deadline=None)
settings.register_profile("thorough", deadline=None, max_examples=2000)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

_LOCAL_FAMILIES = {getattr(socket, "AF_UNIX", None)} - {None}


class NetworkAccessError(AssertionError):
    """Code under test tried to open a network connection."""


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any test whose code opens an internet socket.

    The tool promises no network access during normal use; this makes the whole suite
    enforce it. Local UNIX sockets stay allowed.
    """
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded(original: Any) -> Any:
        def connect(self: socket.socket, address: Any) -> Any:
            if self.family in _LOCAL_FAMILIES:
                return original(self, address)
            raise NetworkAccessError(f"network access attempted: {address!r}")

        return connect

    monkeypatch.setattr(socket.socket, "connect", guarded(original_connect))
    monkeypatch.setattr(socket.socket, "connect_ex", guarded(original_connect_ex))
