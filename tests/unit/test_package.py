from importlib.metadata import version

import ifinjected


def test_version_comes_from_installed_metadata() -> None:
    assert ifinjected.__version__ == version("ifinjected")
