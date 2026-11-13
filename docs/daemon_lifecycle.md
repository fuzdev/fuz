# Daemon Lifecycle

How `fuzd` starts, stops, and is observed. The `fuzd` CLI orchestrates; the
running daemon is passive.

```
                       UDS ~/.fuz/run/socket
[fuzd CLI]             ───────────────────► [fuzd] ──► workloads: observer (process/network/services)
[fuz workload observe] ───────────────────►                       watcher  (filesystem, notify/inotify)
                                                                  sidecar* (dormant)
```

The socket is mode `0600` and the daemon accepts same-uid peers only, by
`SO_PEERCRED` — no TCP port, no bearer token. `fuzd`'s lifecycle subcommands and
`fuz workload observe` speak the wire protocol over it, both through
`fuz_client`. The rest of `fuz` runs without the daemon; `fuz self status` and
`fuz tool install|upgrade fuzd` only test whether the socket accepts a
connection (../crates/fuz/src/fuzd.rs).

`*` the Deno/Python sidecar workload, built only with `--features sidecar`
(./sidecars.md).

## Principles

**The health check is truth; `daemon.json` is a hint.** A daemon answering the
health check outranks whatever `daemon.json` says, and stale files are cleaned
automatically. One exception: a recorded daemon that doesn't answer but still
holds the socket lock (§ Socket ownership) keeps its `daemon.json`, since that
pid is the only handle `fuzd stop --force` has on it.

**The daemon never reads, writes, or references `daemon.json`.** It writes only
its socket and the socket lock, and creates `run/` (and `~/.fuz` itself, if
missing) at `0700`. Who owns what under `~/.fuz/`: ./fuz_home.md § Ownership.

## Who does what

- `fuzd` CLI (`start` / `stop` / `restart` / `status` / `logs`) — the
  lifecycle: spawns the bare daemon, owns `daemon.json` and the log. `start`
  spawns the `fuzd` beside its own executable, else the one on `PATH`.
- bare `fuzd` — the daemon: owns `run/socket` and `run/socket.lock`, never
  touches `daemon.json`, and takes no configuration beyond `FUZ_HOME` (and
  `RUST_LOG`).
- `cargo xtask install` — installs the fuz artifact and the fuzd tool, then
  runs `fuzd restart`.
- `fuz` — no lifecycle; probes the socket (`fuz self status`) and consumes
  workloads (`fuz workload observe`). Without fuzd installed, `fuz self status`
  reports `fuzd: not installed` with a `fuz tool install fuzd` hint.
- `fuz_client` — the RPCs: `check_health` (Hello), `daemon_status`,
  `shutdown`, `observe_subscribe`, `watch_subscribe`.

## States

The CLI derives the state on every command from `daemon.json`, a Hello probe,
and the socket lock (`fuz_daemon::DaemonState`):

- **Running** — `daemon.json` names a daemon that answers Hello.
- **Unresponsive** — `daemon.json` names a live fuzd that holds the socket lock
  but fails Hello: hung, stopped, or speaking another protocol version (the
  probe is one bit). Only `--force` acts on it.
- **Stale** — `daemon.json` names a daemon that neither answers nor holds the
  lock (crashed, killed, or past its lock release); the command warns and
  deletes the file.
- **Stopped** — no readable `daemon.json`. A daemon may still answer (a
  foreground `fuzd`, an orphan, a start not yet recorded); each command's rows
  below say what happens then.

Starting and stopping are transitions, not states. `start` spawns, then polls
until Hello answers while the lock body names its child. A shutdown (SIGINT,
SIGTERM, or the shutdown RPC) unlinks the socket and releases the lock before
draining, so clients see Running go straight to Stopped or Stale.

Health is one bit: `fuz_client::check_health` is `true` exactly when the daemon
answers Hello with a matching `PROTOCOL_VERSION`; connect, write, and read
each get `HEALTH_CHECK_TIMEOUT` (`fuz_client`). The socket lock's body (a pid,
checked for liveness) decides whose answer a starting daemon's is and when a
stopping one has let go of the path.

## Behavior Matrix

Lifecycle commands exit `0` when the desired state is reached, `1` when not,
and `2` when the invocation or the fuz home is wrong — an unparseable command
line, an unusable `HOME` with `FUZ_HOME` unset, a relative `FUZ_HOME`, a
`FUZ_HOME` too long for the socket under it, a world-writable home where
`start` writes under it (fix it, don't retry as-is); `logs` exits
`0` when its output is complete, `1` when there is no log or it is refused,
unreadable, or unwritable, and dies by the signal when a SIGINT or SIGTERM ends
a follow (`130` / `143`); bare `fuzd` exits 75 when another fuzd holds the lock.

Messages name the pid from `daemon.json` when the daemon is recorded, else from
the socket lock's body. With no pid in the body the suffix is omitted, and bare
`fuzd` prints `(pid unknown)` instead.

**start**

| Situation | Result | Exit |
| --- | --- | --- |
| nothing running | spawn, poll, write `daemon.json` | 0 |
| already running (recorded, or a daemon with no `daemon.json` such as a foreground `fuzd`) | "already running at <socket> (pid M)"; spawns nothing, writes nothing | 0 |
| spawned child exits 75 and the lock holder answers (another start won the race) | "already running …"; writes no `daemon.json` | 0 |
| spawned child exits 75 and the holder doesn't answer (another protocol version, still starting or stopping, or slow) | "another fuzd is already running on <socket>"; hint: `fuzd stop` can't reach it, `kill <pid>` | 1 |
| unresponsive | "fuzd (pid M) holds <socket> but does not answer this fuzd's health check"; hint `fuzd restart --force`; keeps `daemon.json` | 1 |
| not ready within `HEALTH_POLL_TIMEOUT_SECS` | the child is killed and reaped (a late binder would be an orphan recorded nowhere) | 1 |
| a fuz home that can't be used as configured (an unusable `HOME` with `FUZ_HOME` unset, a relative `FUZ_HOME`, a `FUZ_HOME` too long for the socket, a world-writable home) | the home's error and hint; spawns nothing, creates nothing | 2 |
| the spawned child exits 2 (it refused its configuration) | "daemon exited with code 2"; hint `fuzd logs` | 2 |
| daemon up but `daemon.json` can't be written (e.g. a symlink at its temp path) | the child is killed and reaped | 1 |
| stale `daemon.json` (neither answers nor holds the lock) | warn, clean, start | 0 |
| `daemon.json` in a schema this fuzd can't read, naming a live fuzd (version skew) | error naming the schema version and pid; hint `kill <pid>`; keeps `daemon.json`. No `--force` path: another version's wire protocol isn't this fuzd's to speak | 1 |
| leftover socket file | the new daemon takes the lock, then unlinks and binds fresh (a live daemon's socket is never reached — it holds the lock) | 0 |

**stop**

| Situation | Result | Exit |
| --- | --- | --- |
| running | shutdown RPC, wait for the lock release, clean, "stopped" | 0 |
| not running, stale `daemon.json`, or a daemon with no `daemon.json` | "not running" (warn and clean a stale file; an unrecorded daemon is untouched) | 0 |
| unresponsive | start's error, hint `fuzd stop --force`; kills nothing | 1 |
| answered, then didn't shut down in time | error, hint `fuzd stop --force` | 1 |
| `--force` (unresponsive or timed out) | SIGTERM, then SIGKILL if still there (no RPC); waits for the lock release, "stopped" | 0 |
| `--force`, lock still held `FORCE_KILL_TIMEOUT_SECS` after SIGKILL (e.g. blocked in the kernel) | error naming the pid; `daemon.json` left for the next command | 1 |
| `FUZ_HOME` too long for the socket (e.g. the home renamed under a running daemon), `--force` or not | the home's error and hint, naming the pid `daemon.json` records if any; signals nothing, leaves `daemon.json` as it is | 2 |

**restart** is stop then start, with start's output. Stop waits for the old
daemon to release the socket lock, not just close its listener, so the new one
isn't refused.

| Situation | Result | Exit |
| --- | --- | --- |
| stop fails | bails without starting; on a timeout the hint names `fuzd restart --force` | 1 |
| unresponsive | start's error, hint `fuzd restart --force`; touches nothing | 1 |
| `--force` | kills as `stop --force` does (bailing the same way if the lock stays held), then starts | 0 |
| a daemon answers with no `daemon.json` (foreground `fuzd`, orphan, or a concurrent start not yet recorded) | "a fuzd with no daemon.json is running at <socket>"; touches nothing (`cargo xtask install` prints this, then its own warning) | 1 |

**status** — exit 0 means the recorded daemon answers.

| Situation | Result | Exit |
| --- | --- | --- |
| running | "fuzd <version> (running, PID M, socket <socket>)"; a `--features sidecar` build with sidecars also lists them and the tool count (`-v` adds per-sidecar versions, dependencies, tools) | 0 |
| unresponsive | "not answering (pid M)", hint `fuzd stop --force`; keeps `daemon.json` | 1 |
| stopped, stale `daemon.json` (warn, clean), or a daemon with no `daemon.json` | "stopped" | 1 |

**Every command**

- A corrupt `daemon.json`, or one unreadable as this schema whose pid is gone or
  isn't fuzd: warn, delete it (regenerable), carry on as if absent.
- Bare `fuzd` beside a running daemon: "another fuzd is already running on
  <socket> (pid M)"; nothing unlinked or bound (exit 75).
- A command line that doesn't parse: argh's message on stderr (exit 2);
  `--help` / `help` prints usage on stdout (exit 0).
- A fuz home that can't be used as configured — an unusable `HOME` with
  `FUZ_HOME` unset, a relative `FUZ_HOME`, or a `FUZ_HOME` too long for the
  socket under it: the home's error and hint, nothing created (exit 2), from
  bare `fuzd` and every lifecycle command. A world-writable home is refused
  (exit 2) where `start` (and so `restart`) writes under it; the others leave
  it to that check.
- A `FUZ_HOME` too long for the socket under it — most often a home renamed
  while its daemon runs: `start`, `status`, `stop` (with or without
  `--force`), and `restart` exit 2 before reading anything else, and change
  nothing — no signal, no `daemon.json` cleanup, no "not running". When
  `daemon.json` records a pid, the hint names it as recorded (unverified: a
  daemon may still be running for this home) and says to reach the home
  through a shorter path, such as a symlink, to stop it. `logs` needs no
  socket, so it still reads the home's log.
- A daemon crash leaves a stale `daemon.json` the next command cleans. A
  manually deleted `daemon.json` orphans the daemon: `fuzd start` reports it
  running, `fuzd stop` can't reach it, and `~/.fuz/run/socket.lock` names its
  pid.

**Races**

- Two starts that both pass the health check both spawn; one child takes the
  lock, the other exits 75. The losing start ignores answers while the lock
  names another pid, waits for its child to exit, and reports "already running"
  (exit 0) without writing `daemon.json`. One window remains: if the winner
  hasn't bound by the time the loser's child exits, the loser reports "another
  fuzd is already running" (exit 1) though the winner comes up.
- Two stops both succeed. A second stop probing in the instant between the
  daemon closing its listener and releasing the lock finds it unresponsive
  (exit 1); run again, it reports "not running".

## Workloads

A workload lives while clients want it. A subscription takes a reference on a
workload that other clients may share; when
the last subscriber leaves, the workload idles for its grace period
(`OBSERVER_IDLE_GRACE`, `WATCHER_IDLE_GRACE` in `fuzd_server::workload`) so a
quick resubscribe reuses it, then stops. A shutdown stops every workload at
once. `fuz workload observe <domain>` prints one snapshot, or streams with
`--follow`.

## Status for scripts

There is no HTTP endpoint. `fuzd status` is the scripting surface (exit 0 = the
recorded daemon answers, 1 = stopped or not answering, 2 = a fuz home that
can't be used as configured — an error on stderr and nothing on stdout, under
`--json` too, so a broken home never reads as "stopped"). `--json` prints one
shape where `running` is the only key always present; the rest appear only on
the outcome that can speak to them, omitted rather than `null`:

- running, status RPC answered — `running`, `version`, `socket_path`, `pid`,
  `sidecars`, `tools`
- running, status RPC failed — `running`, `socket_path`, `pid`, `error`
- recorded but not answering — `running: false`, `socket_path`, `pid`,
  `reason: "not_answering"`
- not running — `running`, `reason: "stopped"`

Fields *inside* a `sidecars` entry are the exception: that type crosses the
postcard wire, which can't skip fields, so its empty optionals are `null`.

## Socket ownership

One daemon owns a socket path at a time. Before touching the path, the daemon
takes an exclusive `flock` on `<socket>.lock` (`~/.fuz/run/socket.lock` in
production), opened `0600`, and writes its pid into the body. Only then does it
unlink a leftover socket and bind. If another daemon holds the lock, it unlinks
and binds nothing, prints `error: another fuzd is already running on <socket>
(pid M)`, and exits 75 (`EX_TEMPFAIL`, fuz's code for a held lock); a fuz home
that can't be used as configured exits 2; every other startup failure exits
1. `fuzd start` reads 75 off its child and reports the
holder rather than an unexplained crash.

The CLI reads the body without locking — a probe `flock` could refuse a daemon
starting at that moment. The pid is written before binding and truncated on
release while the lock is still held, so anything that reached the socket reads
the owner's pid, and an empty body means released. `fuzd start` counts a health
answer as its child's only while the body names the child; `stop` / `restart`
count the old daemon gone once the body stops naming it or its pid is no longer
a live fuzd (a `SIGKILL` returns before the process is gone, and a killed
daemon leaves its pid in the body).

The kernel drops a `flock` with its holder, so a crash leaves nothing to
recover. The lock file is never removed: `flock` locks the inode, and unlinking
the path while another daemon is about to lock it would let two daemons hold
locks on different inodes.

## Graceful shutdown

Triggered by SIGINT, SIGTERM, or `DaemonShutdownRequest`.

1. Stop accepting connections; the draining flag flips.
2. Each connection's read loop stops at the shutdown signal. A
   `SIDECAR_CALL_RUN_REQUEST` dispatched after the draining flag flips (one
   queued behind the shutdown request) is answered
   `SidecarCallOutcome::Draining`.
3. Abort the accept loop, unlink the socket, and release the lock together. A
   restarting CLI spawns the next daemon as soon as the lock body stops naming
   this one, so a later unlink could delete the new daemon's socket — the lock
   covers ownership of the path, not the process lifetime.
4. Wait for connection tasks, up to `SHUTDOWN_TIMEOUT_SECS`: each finishes its
   current dispatch and flushes its writer, so the shutdown response reaches its
   client. A connection gets a flush budget (`SHUTDOWN_FLUSH_BUDGET`); one still
   busy after it (a client not reading its stream) is torn down with whatever it
   had queued, and one still open at the timeout is logged and abandoned.
   Workload collectors stop at once, ending their subscription streams.
5. Exit; the CLI, not the daemon, cleans up `daemon.json`. An observer sample
   already on the blocking pool is waited for, up to `RUNTIME_SHUTDOWN_TIMEOUT`
   (`fuzd`). A hung `systemctl` is killed by its own `SYSTEMCTL_SHOW_TIMEOUT`,
   so the wait never orphans one; what the bound cuts short is a sample that
   never returns, such as a `/proc` read stuck in the kernel.

## Known limitations

- **PID reuse under `--force`** — a window between each `/proc/<pid>/comm` check
  and the signal after it, so a SIGTERM (or, after the re-check, a SIGKILL)
  could reach a process that reused the pid. The check fails closed: a pid it
  can't confirm as `fuzd` (gone, unreadable, no `/proc`) is never signalled.
- **One daemon per user** — one `daemon.json`, one managed daemon.

Not doing: the daemon reading, writing, or watching `daemon.json`; orphan
scanning (it risks killing the wrong process).
