from ifinjected.exit_codes import ExitCode


def test_exit_codes_are_stable() -> None:
    assert {code.name: code.value for code in ExitCode} == {
        "OK": 0,
        "STRICT_FAILURE": 1,
        "ERROR": 2,
        "CONTEXT_UNAVAILABLE": 3,
        "INTERRUPTED": 130,
    }
