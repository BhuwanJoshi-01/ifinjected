"""The probe: a fixed program that opens paths and closes them, and never reads.

It is passed to the interpreter with ``-I -c`` (isolated: no user site, no current
directory on ``sys.path``), runs under the sandbox being tested, and prints one JSON
document between markers. For each path it calls ``os.open(path, O_RDONLY | O_NONBLOCK)``
and ``os.close``: whether the open succeeds is the whole answer. Not one byte of a file
is read. With ``--network`` it makes one TCP connection to the target it is given and
closes it at once; nothing is sent.

A test walks this program's syntax tree and fails if it calls anything else.
"""

from __future__ import annotations

BEGIN = "IFINJECTED-PROBE-BEGIN"
END = "IFINJECTED-PROBE-END"

PROGRAM = """
import json, os, socket, sys
flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
args = sys.argv[1:]
target = None
if args and args[0] == "--connect":
    target = args[1]
    args = args[2:]
results = {}
for path in args:
    try:
        fd = os.open(path, flags)
    except OSError as error:
        results[path] = error.errno
    else:
        os.close(fd)
        results[path] = 0
network = None
if target is not None:
    host, port = target.rsplit(":", 1)
    try:
        connection = socket.create_connection((host, int(port)), timeout=5)
    except OSError as error:
        network = error.errno or -1
    else:
        connection.close()
        network = 0
answer = json.dumps({"protocol": 1, "open": results, "connect": network})
sys.stdout.write("IFINJECTED-PROBE-BEGIN" + answer + "IFINJECTED-PROBE-END")
"""
