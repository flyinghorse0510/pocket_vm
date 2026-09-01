# pocket-guard

`pocket-guard` is the deliberately single-threaded lifetime anchor for one
Pocket operation. It is the direct parent and Linux child subreaper for exactly
one executed program. It uses no shell, namespace, cgroup, capability, or
privileged helper.

~~~text
pocket-guard \
  --supervisor-pid PID \
  [--liveness-fd FD] \
  [--lease-fd FD] \
  [--inherit-fd FD]... \
  [--term-timeout-ms MS] \
  [--uml-personality] \
  -- PROGRAM [ARG]...
~~~

The liveness FD is guard-only; EOF requests SIGTERM followed by bounded
SIGKILL escalation. The lease FD is held by the guard and is also guard-only.
Standard input, output, and error are inherited automatically. Every other FD
must be named with `--inherit-fd`; after a successful spawn the guard closes
its copy so pipe and socket EOF semantics remain correct.

The guard arms `PR_SET_PDEATHSIG=SIGKILL`, immediately verifies its creating
supervisor, and applies the same contract to its child before exec. The child
becomes a process-group leader before exec. This deliberately prevents UML's
later `setsid()` from moving it out of the guard-owned group. The guard also
uses pidfd readiness when available, `waitpid` as the status/reaping authority,
and `/proc/.../children` to terminate adopted descendants that escaped the
original process group.

The pre-exec closure is isolated in `linux::prepare_command_child`. It invokes
only async-signal-safe Linux operations and does not allocate or lock. A
`close_range(..., CLOSE_RANGE_CLOEXEC)` sweep preserves Rust's exec-error pipe
until exec while closing all unintended descriptors on successful exec.
For a UML child, `--uml-personality` also establishes and verifies
`PER_LINUX|ADDR_NO_RANDOMIZE` before exec. This is mandatory when UML is
invoked through a bundled dynamic loader: `/proc/self/exe` then names the
loader, so UML's normal personality-triggered self-reexec would otherwise lose
the target executable and loader arguments.

Exit codes follow the conventional exact mapping: a normal child exit is
returned unchanged, and signal death is returned as `128 + signal`. Guard
configuration or lifecycle failures return 125 after owned children have been
terminated and reaped. A fatal supervision error after spawn triggers an
immediate SIGKILL-and-reap fallback; any failure of that fallback is reported.

`PR_SET_PDEATHSIG` kills the direct child if the guard itself is abruptly
killed. It cannot generically propagate through an arbitrary descendant tree.
Pocket's UML artifact must independently arm and recheck parent-death handling
for its per-address-space stubs; this guard does not claim cgroup-like kill
atomicity.
