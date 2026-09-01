#!/usr/bin/env python3
"""Drive one `pocket run -t` session through a real PTY and report the facts.

`-t` needs a terminal on both descriptors, so a pipe cannot exercise it. This
allocates a PTY, types into the session, and prints one `key=value` line per
observed property for the calling script to assert. It asserts nothing itself:
the shell script owns the verdict.
"""

import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

POCKET = os.environ["POCKET_BIN"]
BUNDLE = os.environ["PROFILE_BUNDLE"]
STORE = os.environ["STORE"]
RUNTIME_ROOT = os.environ["RUNTIME_ROOT"]
ALIAS = os.environ.get("SESSION_ALIAS", "session:latest")

START_ROWS, START_COLUMNS = 40, 132
RESIZE_ROWS, RESIZE_COLUMNS = 24, 100
BOOT_TIMEOUT = 180
IDLE_TIMEOUT = 30

MARKER = "PKVM"


def set_size(fd, rows, columns):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))


def main():
    argv = [
        POCKET, "run", "-t",
        "--profile-bundle", BUNDLE,
        "--store", STORE,
        "--runtime-root", RUNTIME_ROOT,
        "--timeout", "600s",
        ALIAS, "--", "/bin/sh",
    ]
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        try:
            os.execv(argv[0], argv)
        finally:
            os._exit(127)

    set_size(fd, START_ROWS, START_COLUMNS)
    transcript = bytearray()

    def pump(seconds):
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return False
            if not chunk:
                return False
            transcript.extend(chunk)
        return True

    def send(line):
        os.write(fd, line.encode() + b"\n")

    def wait_for(pattern, timeout):
        end = time.time() + timeout
        expression = re.compile(pattern)
        while time.time() < end:
            match = expression.search(transcript.decode("utf-8", "replace"))
            if match:
                return match
            if not pump(0.5):
                break
        return None

    # The guest boots, mounts its image and starts a shell; wait for a prompt
    # rather than a fixed delay.
    send(f"echo {MARKER}-ready")
    if wait_for(rf"{MARKER}-ready\r?\n", BOOT_TIMEOUT) is None:
        print("the guest never reached a shell prompt", file=sys.stderr)
        sys.stderr.write(transcript.decode("utf-8", "replace"))
        return 1

    # The guest's line discipline echoes what is typed, so a naive search finds
    # the command rather than its answer. Turn the echo off, and additionally
    # assemble each result prefix in the guest so the literal being searched
    # for never appears in the command that produces it.
    send("stty -echo")
    time.sleep(1)
    send("P=R; Q=ES")

    facts = {}

    def ask(command, key, pattern, timeout=IDLE_TIMEOUT):
        send(command)
        match = wait_for(rf"RES{pattern}\r?\n", timeout)
        return match

    match = ask("[ -t 0 ] && echo ${P}${Q}_ISATTY=1 || echo ${P}${Q}_ISATTY=0",
                "isatty", r"_ISATTY=(\d)")
    facts["isatty"] = match.group(1) if match else "?"

    match = ask("echo ${P}${Q}_SIZE=$(stty size | tr '\\n' ' ')",
                "size", r"_SIZE=(\d+) (\d+)")
    facts["size"] = f"{match.group(1)} {match.group(2)}" if match else "?"

    # Resize the operator's window; the guest should learn its new size.
    set_size(fd, RESIZE_ROWS, RESIZE_COLUMNS)
    time.sleep(3)
    match = ask("echo ${P}${Q}_RESIZED=$(stty size | tr '\\n' ' ')",
                "resized", r"_RESIZED=(\d+) (\d+)")
    facts["resized"] = f"{match.group(1)} {match.group(2)}" if match else "?"

    match = ask("echo ${P}${Q}_TTYNAME=$(tty)", "ttyname", r"_TTYNAME=(\S+)")
    facts["ttyname"] = match.group(1) if match else "?"

    match = ask("echo ${P}${Q}_TERMIS=$TERM", "term", r"_TERMIS=(\S+)")
    facts["term"] = match.group(1) if match else "?"

    # The host terminal is raw, so ^C is a byte the guest's line discipline
    # turns into SIGINT for the foreground process group. The effect is
    # measured by whether the shell becomes responsive again long before the
    # sleep would have ended: a shell discards the rest of a command list it
    # was interrupted in, so asking the interrupted command to report its own
    # status would measure nothing.
    send("sleep 60")
    time.sleep(3)
    os.write(fd, b"\x03")
    time.sleep(1)
    send("echo ${P}${Q}_WOKE=1")
    match = wait_for(r"RES_WOKE=1\r?\n", 20)
    facts["ctrl_c"] = "interrupted" if match else "not-interrupted"

    send("exit 7")
    pump(10)
    _, status = os.waitpid(pid, 0)
    facts["exit"] = str(os.waitstatus_to_exitcode(status))
    os.close(fd)

    # `-t` must refuse a pipe rather than quietly degrading to buffered
    # streams. This is the same binary with the same arguments, run without a
    # terminal on either side.
    refused = subprocess.run(
        argv + [],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    facts["no_terminal_refused"] = (
        "1"
        if refused.returncode != 0 and b"not a terminal" in refused.stderr
        else "0"
    )

    for key, value in facts.items():
        print(f"{key}={value}")
    if os.environ.get("POCKET_TERMINAL_TRANSCRIPT"):
        sys.stderr.write(transcript.decode("utf-8", "replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
