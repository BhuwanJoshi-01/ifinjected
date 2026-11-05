"""ifinjected: what could a prompt-injected coding agent reach on this machine?"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ifinjected")
except PackageNotFoundError:  # imported from a source tree that was never installed
    __version__ = "0+unknown"
