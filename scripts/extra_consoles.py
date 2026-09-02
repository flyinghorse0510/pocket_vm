#!/usr/bin/env python3
"""Drive a run's extra serial lines and report what an operator observes.

A line that exists is not a line that works: the descriptor has to survive
into the guest, the device node has to be reachable from the workload's own
/dev, and the pseudo-terminal the operator was told to attach to has to
outlive the launch. Each is separately observable only by using the line, so
this attaches to one and talks over it in both directions.

Prints one `key=value` line per property; the calling script owns the verdict.
"""

import os
import re
import select
import subprocess
import sys
import time

POCKET = os.environ["POCKET_BIN"]
BUNDLE = os.environ["PROFILE_BUNDLE"]
STORE = os.environ["STORE"]
RUNTIME_ROOT = os.environ["RUNTIME_ROOT"]
ALIAS = os.environ.get("CONSOLE_ALIAS", "base:latest")

# The workload does nothing to the lines. A shell on each is the runtime's
# job now, so a workload that mentions them would not be testing that.
WORKLOAD = "ls -l /dev/ttyS4 /dev/ttyS5 >/dev/null 2>&1 && echo NODES_OK; sleep 25; echo MAIN_DONE"


def drain(fd, seconds):
    got = b""
    end = time.time() + seconds
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                got += os.read(fd, 65536)
            except OSError:
                pass
    return got.decode("utf-8", "replace")


def main():
    argv = [
        POCKET, "run",
        "--profile-bundle", BUNDLE, "--store", STORE,
        "--runtime-root", RUNTIME_ROOT, "--rm",
        "--consoles", "2", "--timeout", "180s",
        ALIAS, "--", "/bin/sh", "-c", WORKLOAD,
    ]
    process = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    paths = []
    for _ in range(80):
        line = process.stderr.readline()
        if not line:
            break
        match = re.search(r"guest (/dev/ttyS\d+) is attachable at (\S+)", line)
        if match:
            paths.append(match.group(2))
        if len(paths) == 2:
            break
    print(f"published_lines={len(paths)}")
    if len(paths) != 2:
        process.kill()
        return 1

    # The path must still be there once the launch has returned: the run, not
    # the launch, is what the operator attaches during.
    print(f"path_present={'1' if os.path.exists(paths[0]) else '0'}")

    time.sleep(10)
    fd = os.open(paths[0], os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    os.write(fd, b"echo SECOND_SHELL_OK; hostname; id\n")
    seen = drain(fd, 10)
    print(f"second_shell={'1' if 'SECOND_SHELL_OK' in seen else '0'}")
    print(f"guest_hostname={'1' if 'pocket' in seen else '0'}")
    print(f"shell_is_root={'1' if 'uid=0(root)' in seen else '0'}")
    os.close(fd)

    # The second line must be independently usable, not just the first.
    other = os.open(paths[1], os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    os.write(other, b"echo OTHER_LINE_OK\n")
    seen_other = drain(other, 8)
    print(f"second_line={'1' if 'OTHER_LINE_OK' in seen_other else '0'}")
    os.close(other)

    stdout, _ = process.communicate(timeout=180)
    print(f"nodes_present={'1' if 'NODES_OK' in stdout else '0'}")
    print(f"main_workload={'1' if 'MAIN_DONE' in stdout else '0'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
