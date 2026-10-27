# qumun - A Custom Linux Scheduler Framework using eBPF and Go

**qumun** is a scheduler development framework that empowers developers to build custom Linux schedulers using Golang and eBPF.

The name qumun comes from the Bunun language (an Indigenous people of Taiwan), where it means “heart.”
Just as the heart powers and sustains the body, a scheduler is the core heartbeat of the operating system — orchestrating tasks, balancing workloads, and keeping everything alive and running.

By choosing this name, we hope to highlight both the technical role of a scheduler and also share a piece of Taiwan’s Indigenous culture with the global open-source community.

## DEMO

![](./assets/demo.gif)

## Overview

![](./assets/design.png)

This scheduler is designed to prioritize interactive workloads over background CPU-intensive tasks. It's particularly suitable for:

- Low-latency interactive applications
- Gaming
- Video conferencing
- Live streaming

The scheduler consists of two main components:
1. A BPF component that implements low-level sched-ext functionalities
2. A user-space scheduler written in Go with scx_goland_core that implements the actual scheduling policy

## Key Features

- Virtual runtime (vruntime) based scheduling
- Latency-sensitive task prioritization
- Dynamic time slice adjustment
- CPU topology aware task placement
- Automatic idle CPU selection

## How It Works

The scheduling policy is based on virtual runtime:
- Each task receives a time slice of execution (slice_ns)
- The actual execution time is adjusted based on task's static priority (weight)
- Tasks are dispatched from lowest to highest vruntime
- Latency-sensitive tasks receive priority boost based on voluntary context switches

## Building

Prerequisites:
- Go 1.24+ (as required by `go.mod`)
- LLVM/Clang 17+
- libbpf
- Linux kernel 6.12+ with sched_ext support

## Usage

### Setting Up Dependencies

First, clone the required dependencies:

```bash
make dep
git submodule init
git submodule sync
git submodule update
cd scx
cargo build --release -p scx_rustland
```

This will clone libbpf and the custom libbpfgo fork needed for the project.

### Building the Scheduler

Build the scheduler with:

```bash
make build
```

This compiles the BPF program, builds libbpf, generates the skeleton, and builds the Go application.

### BPF Forward-Progress Regression Tests

```bash
python3 scripts/test_bpf_progress.py
```

These unprivileged tests compile the actual dispatch/running/stopping/tick callback
bodies with mocked kernel helpers using Clang. They check that pending work
with no eligible scheduler thread falls through to other dispatch queues,
successful scheduler dispatch retains priority and respects its batch limit,
and running/stopping counters exclude all scheduler-process threads in
user-space mode while still counting them in kernel mode. Scheduler threads
also refresh the user-space heartbeat timestamp on entering a CPU.
The per-task runtime watchdog excludes the same scheduler-process threads in
user-space mode, since their running callback does not set task start timestamps.
Kernel mode and ordinary tasks retain the existing watchdog behavior, including
the strict 500 ms threshold and the disabled-watchdog/missing-context cases.
These tests do not replace BPF verifier or live-kernel watchdog testing.

The opt-in loop-preemption experiment registers `usersched_loop_tid` through
`SetUserSchedLoopTid` after pinning the Go loop. Only wakeup enqueues for that TID
with pending work and no idle CPU may preempt its affinity-allowed assigned CPU,
at most once per millisecond using an atomic timestamp claim. A zero TID disables
the experiment. Tests cover gating, affinity, interval boundaries, and the
unchanged idle-CPU path.

Gthulhu enables `adaptive_wakeup` by default for its Go scheduling loop through
`EnableAdaptiveWakeup`, together with the configured minimum backend slice.
The low-level qumun setting remains opt-in for other consumers and kernel mode.
Go classifies each wakeup and returns the deadline, CPU, and preemption request;
BPF does not bypass Go for short bursts. When enabled, `goland_runnable` preserves
the previous full runnable burst before resetting the current accumulator.
`get_task_info` reports that saved burst through `exec_runtime` on wakeups, but
still reports current runtime on reenqueues. Low-level disabled reporting is unchanged.

For valid CPU dispatches, BPF consumes Go's `SCX_ENQ_PREEMPT` request without
passing it to the vtime DSQ, then kicks only a still-running ordinary task with a
later deadline. Scheduler-process tasks and missing task contexts remain
protected. Do not add a one-shot minimum-runtime rejection without a retry:
the removed 100 us gate caused eligible wakeups to wait until another scheduling
event. The callback harness covers sub-100 us preemption, rejection guards,
reference releases, flag-disabled dispatch flags, affinity fallback, and previous
full-burst reporting.

Adaptive mode consumes one queued record directly via `ring_buffer__consume_n`
on the pinned Go loop, without a C-to-Go callback or channel. The callback only
copies into C-owned memory, validates the 72-byte wire record, and never blocks.
Consumption errors propagate to the scheduling loop. `ReadyForDequeue` caches
one decoded record so repeated readiness checks cannot lose or reorder tasks.
Empty-pool waits and completed dispatch batches use Linux `sched_yield` outside
the fast bridge. The BPF dispatcher drains completed user decisions before
dispatching scheduler threads, and adaptive mode uses the configured minimum
slice for scheduler/fallback execution, matching rustland's separation of the
backend slice from its user-space deadline budget.

Privileged Go tests exercise actual kernel ring output, FIFO consumption,
readiness caching, empty/invalid rings, malformed records, and cancellation.
With BPF idle bypass disabled, repeated `adaptive_priority` measurements were
0.24, 0.22, and 0.21 on the development host; these are not portable guarantees.

### Low-Latency C Calls

#### Separating call overhead from scheduling latency

Build first, then run `make bench-select-cpu` on a BPF-capable host.
This compares `Program.Run()` and the direct bridge using the **same small
syscall BPF program**, reporting ns/op and allocations. It is not a Rust
comparison or a benchmark of production CPU-selection policy.

For production-path distributions, run:

```bash
sudo ./main -measure-latency
# Run a fixed workload, then stop with SIGINT to print "latency data" JSON.
```

Measurement is disabled by default. When enabled:

- `select_cpu` measures each Go `Sched.SelectCPU` call (including plugin
  overrides, preemption during the call, and errors), using Go monotonic time.
- `enqueue_to_dispatch_receive` uses BPF monotonic timestamps from just before
  queued-ring publication to processing the userspace dispatch record for an
  existing task. It includes ring transport, Go queue/policy/CPU selection,
  dispatch-ring residence, and kernel scheduling delays. It does **not** measure
  wakeup-to-running latency or guarantee the dispatch was accepted.
- Reports include count, 64 log2 buckets, and p50/p95/p99/max **bucket upper
  bounds** in nanoseconds. Bucket 0 is [0,1], bucket i is
  [2^i,2^(i+1)-1]. Empty summaries have count and bounds zero.

Per-task enqueue timestamps are consumed once; missing task contexts, tasks
that exit before dispatch, and kernel-only dispatches are excluded. Reenqueues
replace the timestamp, so duplicate/stale records cannot be individually
correlated without extending the wire protocol. Shutdown reports may omit
in-flight tasks; kernel buckets are a non-atomic snapshot.

Instrumentation adds two Go clock reads per selection, two BPF clock reads
per measured round trip, task-storage lookups, and one atomic histogram
increment. Compare distributions only with measurement enabled in both runs;
use instrumentation-disabled runs for final workload performance comparisons.
No ring record layouts or scheduling policies change.
Keep workload, debug logging, CPU affinity, and `GOMAXPROCS` consistent across
runs. Do not subtract the two p99 values: these are different sample populations,
not paired measurements. A short `select_cpu` distribution alongside a long
round-trip distribution points toward transport/queueing rather than just the
syscall wrapper; it does not by itself identify which queue is responsible.

The scheduling goroutine uses `runtime.LockOSThread` with a deferred
`UnlockOSThread`, so blocking and resuming cannot migrate it to another M.
This pins M, not P, and does not disable normal Go safe points or preemption.
Shutdown cancels and joins the loop before releasing its C ring buffer.

CPU selection, non-blocking dispatch, BSS counter updates, and scalar rodata access use
`internal/schedbridge.Call`.
It passes a C wrapper's function pointer directly to `runtime.asmcgocall`
(`//go:linkname`, `//go:noescape`), switching to the current M's g0 stack
without `runtime.cgocall`, `entersyscall`, or `exitsyscall`. These calls do not
release P or ask the runtime to create a replacement M. This does not prevent
other Go runtime activity from creating threads.

Wrapper function pointers are cached at package initialization. Each C wrapper
accepts one `void *` pointing to a matching Go argument/result struct;
compile-time checks enforce size, alignment, and every field offset. Arguments
stay on the stack, contain only scalar data or C-owned memory addresses, and
are never retained by C. CPU selection also keeps the program object alive
until the syscall returns.

`SelectCPU` runs the existing bounded `rs_select_cpu` program via one
`BPF_PROG_TEST_RUN` syscall, preserving negative CPU fallback and single-run
`EINTR` behavior. It uses the direct `schedbridge.Call` path, avoiding
`ebpf.Program.Run()` context serialization and Go allocations.
`DispatchTask` uses non-blocking
`user_ring_buffer__reserve`/`submit`, returns errors such as `ENOSPC` without
waiting, and preserves the 64-byte wire record. `NotifyComplete` and queue
decrements use the scalar C wrappers. Decrements retain the existing
conditional atomic subtraction, not a saturating compare-and-swap operation.

`GetNrQueued` and `GetNrScheduled` use `atomic.LoadUint64` on cached,
8-byte-aligned skeleton BSS addresses: there is no C call for either read.
`DrainQueuedTask` already consumes a Go channel non-blockingly; it needs no C
polling wrapper.

Only bounded, non-blocking, callback-free work belongs on the fast path. It
bypasses Cgo pointer checks, race instrumentation, and runtime Cgo bookkeeping.
Never use it for allocation, blocking syscalls, C-to-Go callbacks, or storing
Go pointers. `BlockTilReadyForDequeue` remains a Go channel wait in this
repository, which releases P normally. The producer's blocking libbpf ring
polling remains standard Cgo, as do initialization, BPF map updates, ring
allocation/free, and other potentially blocking calls. Normal Go safe points
between fast calls allow GC/STW progress; an unexpectedly blocking wrapper
passed to `Call` would delay STW while holding P.

`BPF_PROG_TYPE_SYSCALL` is kernel-marked sleepable. Even bounded BPF work does
not make the surrounding syscall non-blocking: kernel faults or reclaim can
delay it. Do not restrict the scheduler process to `GOMAXPROCS=1`: CPU
selection holds P, and other goroutines, including the ring-buffer producer,
need to make progress. Multiple Ps do not eliminate GC/STW delays if the
syscall blocks. Do not add unbounded work to this program. This is not a hard
real-time or absolute STW-latency guarantee. Plugin overrides of `SelectCPU`
retain their own execution behavior. Existing single-skeleton lifetime and
rodata-before-load requirements still apply.

For wrappers that may block, `schedbridge.CallSyscall` is an alternative
that calls `runtime.cgocall` with the same single-pointer ABI. It still uses
`asmcgocall` internally, but includes syscall, GC, signal, and Cgo bookkeeping
so the runtime can reclaim P. CPU selection does not currently use this
alternative; dispatch and counters also remain on the direct path.

The bridge relies on internal Go runtime APIs. Go 1.23+ requires
`-ldflags="-checklinkname=0"` to link it; `make build` includes this flag.
The supported scheduler targets are Linux amd64 and arm64; revalidate the ABI
and runtime behavior when upgrading Go.

Run the standalone tests and latency comparison (no BPF setup or root needed):

```bash
go test -ldflags="-checklinkname=0" ./internal/schedbridge
go test -ldflags="-checklinkname=0" ./internal/schedbridge \
  -run='^$' -bench=BenchmarkLoadUint64 -benchmem -count=5
# Or: make bench
```

The load benchmark compares the same scalar C load through standard Cgo and through
the single-pointer wrapper/`asmcgocall` path, including argument/result
marshalling; `GoAtomic` measures the counter-read path. Compare `ns/op` and
allocations on the deployment hardware; this measures call overhead, not
end-to-end scheduler latency.

`BenchmarkSyscall` compares a `getpid` syscall via generated Cgo and via
`CallSyscall`, both with runtime bookkeeping. The regression tests also block
in a C read with `GOMAXPROCS=1` and verify timer/GC progress and thread pinning.

With the build prerequisites installed, `make test-hotpath` builds the scheduler
and runs ABI, counter, dispatch/error, GC, and thread-pinning tests. Kernel-backed
tests for CPU selection and ring exhaustion skip when BPF permissions or kernel
support are unavailable; they do not attach the scheduler.

To compare CPU-selection call overhead on a BPF-capable host, use the same
`CGO_CFLAGS` and `CGO_LDFLAGS` as `make test-hotpath` and run:

```bash
go test -ldflags="-checklinkname=0" ./goland_core \
  -run='^$' -bench=BenchmarkSelectCPU -benchmem -count=5
```

This benchmark runs a small syscall BPF program through both `Program.Run`
and the direct `asmcgocall` bridge; it does not attach a scheduler or measure
production workload tail latency.

### Testing the Scheduler

To test the scheduler in a virtual environment using kernel v6.12.2:

```bash
make test
```

This uses `vng` (virtual kernel playground) to run the scheduler with the appropriate kernel version.

### Running in Production

To run the scheduler on your system:

```bash
sudo ./main
```

The scheduler will run until terminated with Ctrl+C (SIGINT) or SIGTERM.

### Debugging

If you need to inspect the BPF components, you can use:

```bash
sudo bpftool prog list            # List loaded BPF programs
sudo bpftool map list             # List BPF maps
sudo cat /sys/kernel/debug/tracing/trace_pipe # View BPF trace output
```

### Stress Testing by using `stress-ng`

```
stress-ng -c 20 --timeout 20s --metrics-brief
```

## License

This software is distributed under the terms of the Apache License 2.0.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.
