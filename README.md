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

### Low-Latency C Calls

The scheduling goroutine uses `runtime.LockOSThread` with a deferred
`UnlockOSThread`, so blocking and resuming cannot migrate it to another M.
This pins M, not P, and does not disable normal Go safe points or preemption.
Shutdown cancels and joins the loop before releasing its C ring buffer.

CPU selection, non-blocking dispatch, BSS counter updates, and scalar rodata
access use `internal/schedbridge`.
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
`EINTR` behavior. `DispatchTask` uses non-blocking
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
between fast calls allow GC/STW progress; an unexpectedly blocking C wrapper
or BPF program would delay STW while holding P.

`BPF_PROG_TYPE_SYSCALL` is kernel-marked sleepable. This optimization relies on
the current `rs_select_cpu` doing bounded work without sleeping helpers;
kernel faults or reclaim can still delay the syscall and STW. Do not add
sleeping helpers or unbounded work to this program. This is not a hard
real-time or absolute STW-latency guarantee. Plugin overrides of `SelectCPU`
retain their own execution behavior. Existing single-skeleton lifetime and
rodata-before-load requirements still apply.

`runtime.asmcgocall` is an unsupported Go runtime API. Go 1.23+ requires
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

The benchmark compares the same scalar C load through standard Cgo and through
the single-pointer wrapper/`asmcgocall` path, including argument/result
marshalling; `GoAtomic` measures the counter-read path. Compare `ns/op` and
allocations on the deployment hardware; this measures call overhead, not
end-to-end scheduler latency.

With the build prerequisites installed, `make test-hotpath` builds the scheduler
and runs ABI, counter, dispatch/error, GC, and thread-pinning tests. Kernel-backed
tests for CPU selection and ring exhaustion skip when BPF permissions or kernel
support are unavailable; they do not attach the scheduler.

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
