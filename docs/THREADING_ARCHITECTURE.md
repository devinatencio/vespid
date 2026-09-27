# Threading & Async Architecture

## Problem

Python 3.12 asyncio has a starvation bug: `call_soon_threadsafe` callbacks
are not reliably processed while the event loop is inside
`asyncio.wait(tasks, return_when=FIRST_COMPLETED)`.  This causes:

- `asyncio.to_thread()` completions to never resume the awaiting coroutine (the
  thread finishes, but the callback that wakes the coroutine is never called).
- `asyncio.run_coroutine_threadsafe()` to hang indefinitely — the scheduled
  coroutine never runs.
- Newly created `asyncio.create_task()` tasks to stay queued without execution.

On Python 3.13+ `loop.getaddrinfo()` is native async, which relieves the
most common executor contention, but `asyncio.to_thread` callbacks can still
be starved under load.

## Solution: dedicated threads + event loops

Each I/O-heavy subsystem runs in its own `threading.Thread` with a fresh
`asyncio.new_event_loop()`.  No subsystem contends with another for event
loop time, and `call_soon_threadsafe` works normally because each loop is
idle except for one coroutine.

## Thread layout

```
main process
│
├── [thread 1] main asyncio event loop
│   │  Lightweight, no long-running I/O.
│   │
│   ├── logproc.run()           — file tailing (inotify + asyncio)
│   ├── subs.run()              — feed syncs (sync httpx, inline)
│   ├── _nft_health_loop()      — sleeps 30s, yields
│   ├── _expiry_reap_loop()     — sleeps 60s, yields
│   ├── _gc_loop()              — sleeps 600s, yields
│   ├── _wait_stop()            — blocks on asyncio.Event
│   ├── _watch_for_credentials()— asyncio.Event waits
│   ├── _start_bus_when_ready() — asyncio.Event waits
│   └── _fleet_queue_drain_loop()— periodic retries
│
├── [thread 2] control socket server
│   │  ``vespid-ctl`` thread: blocking ``socket.accept()`` loop.
│   │  Each client handler spawns a handler thread.
│   │
│   └── [handler thread] _run_async(handler(request))
│       Creates a fresh ``asyncio.new_event_loop()``, runs the
│       handler coroutine, returns the result.  Zero dependency
│       on the main event loop.
│
├── [thread 3] fleet-subscriber
│   │  ``fleet-subscriber`` thread.
│   │
│   └── loop.run_until_complete(fleet_sub.run())
│       Dedicated event loop runs the subscriber coroutine.
│       Reconnection with exponential backoff works because
│       ``asyncio.sleep()`` processes normally.
│
├── [thread 4] config-subscriber
│   │  ``config-subscriber`` thread.
│   │
│   └── loop.run_until_complete(config_sub.run())
│       Same pattern as fleet subscriber.
│
├── [thread 5] rule-subscriber
│   │  ``rule-subscriber`` thread.
│   │
│   └── loop.run_until_complete(rule_sub.run())
│       Same pattern.  Polls ``/api/v1/rules/distribution``.
│
└── [thread 6] databus worker
    │  ``DataBus`` background thread.
    │
    ├── _heartbeat_loop()        — periodic heartbeats
    └── _worker_loop()           — event shipping
```

## HTTP client strategy

All HTTP is done with `httpx.Client` (sync), never `httpx.AsyncClient`:

| Caller | HTTP type | Pattern |
|--------|-----------|---------|
| Fleet initial sync | short GET | inline sync (blocks event loop ~0.1s) |
| Config check-in | short POST | inline sync |
| Rule poll | short GET | inline sync |
| Feed downloads | short GET | inline sync in main loop |
| Fleet SSE stream | long-lived stream | sync `Client.stream()` in a raw thread, polled via `threading.Event` + `asyncio.sleep()` |
| Config SSE stream | long-lived stream | same raw-thread + polling pattern |

`httpx.AsyncClient` is avoided because:
1. On Python 3.12, DNS resolution uses `loop.run_in_executor()`, consuming
   the default thread pool.
2. The `verify` and `timeout` parameters are silently ignored when a custom
   `transport` is passed to `AsyncClient`.
3. `AsyncClient.stream()` + `resp.aiter_lines()` can hang indefinitely in the
   main event loop when the thread pool is saturated.

## Control socket handlers

Handlers are async coroutines (they call `self.nft`, `self.subs`, etc. which
may do I/O).  The control socket thread creates a **fresh event loop** for
each command via `_run_async()`:

```python
def _run_async(coro, timeout=25.0):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(asyncio.wait_for(coro, timeout=timeout))
    finally:
        loop.close()
```

This guarantees the command runs regardless of the main event loop's state.

## Subscriber reconnection

Each subscriber's `run()` method has built-in reconnection with exponential
backoff:

```
initial: 5s → 10s → 20s → 40s → 80s → 160s → 300s (capped)
          ±20% jitter on each delay
```

The subscriber loop:

```
while not _stop.is_set():
    try:
        await _connect_and_consume()   # SSE stream (long-lived)
    except Exception:
        delay = _compute_backoff()
        await asyncio.sleep(delay)      # works in dedicated loop
        _backoff = min(_backoff * 2, _BACKOFF_MAX)
```

If the SSE connection drops, the `_run` thread sets a `threading.Event`, the
polling loop resumes, and the while loop triggers the next connection attempt
after the backoff delay.

## Key files

| File | Role |
|------|------|
| `vespid/daemon.py` | Main orchestrator; starts all threads and the main event loop |
| `vespid/control_socket.py` | Threaded socket server + `_run_async()` helper |
| `vespid/fleet_subscriber.py` | Fleet blocklist SSE subscriber |
| `vespid/config_subscriber.py` | Server-managed config SSE subscriber |
| `vespid/rule_subscriber.py` | Detection rule poller |
| `vespid/subscription_manager.py` | External feed downloader |
| `vespid/databus.py` | Thread-safe event telemetry bus |
| `vespid/http_client.py` | SSL context builder (`build_ssl_context`) |
| `vespid/auditd/parser.py` | Auditd log parser (runs in main loop) |
| `vespid/auditd/detector.py` | Host-based Sigma rule detection |

## Auditd integration

The auditd subsystem runs within the main asyncio event loop (thread 1).
It tails `/var/log/audit/audit.log` alongside other log files:

1. `AuditdParser` assembles multi-line auditd records (SYSCALL, EXECVE,
   PROCTITLE, CWD, PATH) into `HostEvent` objects
2. `HostDetector` matches events against 137 Sigma-derived rules
3. Matches are scored by `HostScorer` with exponential time decay
4. Events are published to the DataBus for shipping to the server

This does not require a separate thread because auditd event processing
is CPU-light and I/O patterns are identical to other log tailers.

## Performance considerations

| Component | Concurrency model | Bottleneck |
|-----------|-------------------|------------|
| Log tailing | asyncio (non-blocking inotify) | Disk I/O |
| Detection | In-process, O(1) amortized | CPU (regex matching) |
| nftables management | Subprocess calls | nft process startup |
| SSE subscribers | Dedicated threads | Network latency |
| DataBus shipping | Background thread | Server response time |
| Control socket | Thread per connection | Socket accept rate |

The agent typically uses < 50 MB RSS and < 5% CPU on a moderately
active server processing ~1000 log lines/second.
