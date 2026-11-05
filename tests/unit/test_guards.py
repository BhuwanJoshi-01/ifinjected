"""The suite-wide guards in conftest.py really guard."""

from __future__ import annotations

import socket

import pytest

from tests.conftest import NetworkAccessError


def test_an_internet_connection_fails_the_test() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(NetworkAccessError),
    ):
        sock.connect(("192.0.2.1", 443))  # TEST-NET-1: never routed


def test_connect_ex_is_guarded_too() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(NetworkAccessError),
    ):
        sock.connect_ex(("192.0.2.1", 443))
