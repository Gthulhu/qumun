#!/usr/bin/env python3
"""Exercise production BPF callback bodies with deterministic kernel-helper mocks."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "ebpf" / "main.bpf.c"


def callback(source, name):
    start = source.index(f"void BPF_STRUCT_OPS({name},")
    end = source.index("\n}", start) + len("\n}")
    return source[start:end]


MOCKS = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef int32_t s32;
typedef uint32_t u32;
typedef uint64_t u64;
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define BPF_ANY 0
#define BPF_RB_NO_WAKEUP 0
#define dbg_msg(...) debug_log(__VA_ARGS__)
#define SHARED_DSQ 100
#define SCHED_DSQ 101
#define unlikely(condition) (condition)
#define SCX_KICK_PREEMPT 1
#define SCX_KICK_IDLE 2
#define SCX_ENQ_WAKEUP 4
#define SCX_ENQ_LAST 8
#define SCX_ENQ_PREEMPT 16
#define SCX_DSQ_LOCAL_ON 256
#define RL_CPU_ANY (1 << 20)
#define NSEC_PER_MSEC 1000000ULL
#define bpf_printk(...) debug_log(__VA_ARGS__)

struct task_struct {
    u32 pid, tgid;
    char comm[16];
    void *cpus_ptr;
    s32 cpu;
    bool running;
    u64 nr_cpus_allowed;
    struct { u64 slice, dsq_vtime, weight; } scx;
};
struct task_ctx {
    u64 start_ts, stop_ts, exec_runtime, awake_vtime, previous_burst_runtime;
    u64 last_woke_at, wakeup_freq, userspace_enqueued_at;
};
struct queued_task_ctx {
    s32 pid, cpu;
    u64 nr_cpus_allowed, flags, start_ts, stop_ts, exec_runtime, weight, vtime;
    s32 tgid;
};
struct dispatched_task_ctx {
    s32 pid, cpu;
    u64 flags, slice_ns, vtime;
};
static struct task_ctx context;
static bool kernel_mode, pending, queued;
static u64 nr_running, nr_scheduled, nr_queued, usersched_last_run_at;
static u64 default_slice = 20, vtime_now, now;
static int running_task, dispatched, handle_dispatched_task;
static int sched_available, sched_attempts, sched_moved;
static int drains, local_attempts, shared_attempts, cleared;
static bool local_available, shared_available;
static bool max_time_watchdog, missing_context;
static int kicks, context_lookups;
static const u32 usersched_pid = 42;
static u32 usersched_loop_tid;
static u64 usersched_last_preempt_at;
static int idle_cpu, idle_kicks, insert_flags;
static u64 insert_dsq;
static bool cpu_allowed;
static bool adaptive_wakeup, missing_running_pid, missing_running_task;
static struct task_struct current_task, dispatched_task;
static u32 mapped_pid;
static int releases, priority_tasks;
static u64 nr_user_dispatches, nr_bounce_dispatches, nr_cancel_dispatches;
static bool measure_latency;
static int dispatch_latency;
static u64 latency_buckets[64];

static void debug_log(const char *format, ...) {}
static bool time_before(u64 a, u64 b) { return (int64_t)(a - b) < 0; }
static bool is_usersched_task(struct task_struct *p)
{ return p->pid == usersched_pid; }
static bool is_belong_usersched_task(struct task_struct *p)
{ return p->tgid == usersched_pid; }
static int scx_bpf_task_cpu(const struct task_struct *p) { return p->cpu; }
static bool scx_bpf_task_running(const struct task_struct *p) { return p->running; }
static void *bpf_map_lookup_elem(void *map, const void *key)
{
    if (map == &dispatch_latency)
        return &latency_buckets[*(const u32 *)key];
    return map == &running_task && !missing_running_pid ? &mapped_pid : NULL;
}
static struct task_struct *bpf_task_from_pid(u32 pid)
{
    if (pid == current_task.pid)
        return missing_running_task ? NULL : &current_task;
    return pid == dispatched_task.pid ? &dispatched_task : NULL;
}
static void bpf_task_release(struct task_struct *p) { releases++; }
static void bpf_map_update_elem(void *map, void *key, void *value, int flags) {}
static u64 scx_bpf_now(void) { return now; }
static u64 bpf_ktime_get_ns(void) { return now; }
static u64 update_freq(u64 freq, u64 interval) { return freq; }
#define MIN(a, b) ((a) < (b) ? (a) : (b))
static int bpf_get_smp_processor_id(void) { return 0; }
static void scx_bpf_kick_cpu(int cpu, int flags)
{
    assert(cpu == 0);
    if (flags == SCX_KICK_PREEMPT) kicks++;
    else { assert(flags == SCX_KICK_IDLE); idle_kicks++; }
}
static int scx_bpf_pick_idle_cpu(void *mask, int flags) { return idle_cpu; }
static bool bpf_cpumask_test_cpu(int cpu, void *mask) { return cpu_allowed; }
static void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq, u64 slice, int flags)
{ insert_dsq = dsq; insert_flags = flags; }
static void scx_bpf_dsq_insert_vtime(struct task_struct *p, u64 dsq, u64 slice,
                                    u64 vtime, u64 flags)
{ insert_dsq = dsq; insert_flags = flags; p->scx.dsq_vtime = vtime; }
static void scx_bpf_dispatch_cancel(void) {}
static struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{ context_lookups++; return missing_context ? NULL : &context; }
static u64 scale_by_task_weight_inverse(struct task_struct *p, u64 slice)
{ return slice; }
static bool test_and_clear_usersched_needed(void)
{ cleared++; return true; }
static bool usersched_has_pending_tasks(void) { return pending; }
static u64 cpu_to_dsq(s32 cpu) { return cpu; }
static bool keep_running(struct task_struct *p, s32 cpu) { return queued; }
static bool is_queued(struct task_struct *p) { return queued; }
static u64 task_slice(struct task_struct *p, s32 cpu) { return default_slice; }
static int bpf_user_ringbuf_drain(void *ring, int cb, void *ctx, int flags)
{ drains++; return 0; }
static bool scx_bpf_dsq_move_to_local(u64 dsq, int flags)
{
    if (dsq == SCHED_DSQ) {
        assert(drains == 1);
        sched_attempts++;
        if (!sched_available)
            return false;
        sched_available--;
        sched_moved++;
        return true;
    }
    if (dsq == SHARED_DSQ) {
        shared_attempts++;
        return shared_available;
    }
    local_attempts++;
    return local_available;
}
"""

CASES = r"""
static void reset(void)
{
    kernel_mode = pending = queued = false;
    local_available = shared_available = false;
    sched_available = sched_attempts = sched_moved = 0;
    drains = local_attempts = shared_attempts = cleared = 0;
    nr_running = nr_queued = nr_scheduled = usersched_last_run_at = 0;
    now = 100;
    context = (struct task_ctx){0};
    measure_latency = false;
    for (int i = 0; i < 64; i++) latency_buckets[i] = 0;
    max_time_watchdog = true;
    missing_context = false;
    kicks = context_lookups = 0;
    usersched_loop_tid = usersched_last_preempt_at = 0;
    idle_cpu = -1;
    idle_kicks = insert_flags = 0;
    insert_dsq = 0;
    cpu_allowed = true;
    adaptive_wakeup = missing_running_pid = missing_running_task = false;
    current_task = (struct task_struct){
        .pid = 7, .tgid = 7, .running = true, .scx.dsq_vtime = 100,
    };
    dispatched_task = (struct task_struct){.pid = 8, .tgid = 8};
    mapped_pid = current_task.pid;
    releases = 0;
    adaptive_requests = adaptive_preempts = adaptive_no_running = 0;
    adaptive_not_earlier = adaptive_protected = 0;
    nr_user_dispatches = nr_bounce_dispatches = nr_cancel_dispatches = 0;
}

static void test_dispatch(void)
{
    reset();
    pending = true;
    goland_dispatch(0, NULL);
    assert(sched_attempts == 1 && sched_moved == 0);
    assert(drains == 1 && local_attempts == 1 && shared_attempts == 1);

    reset();
    pending = local_available = true;
    goland_dispatch(0, NULL);
    assert(drains == 1 && local_attempts == 1 && shared_attempts == 0);

    reset();
    pending = shared_available = true;
    goland_dispatch(0, NULL);
    assert(drains == 1 && local_attempts == 1 && shared_attempts == 1);

    for (int count = 1; count <= MAX_USERSCHED_DISPATCH + 1; count++) {
        reset();
        pending = true;
        sched_available = count;
        goland_dispatch(0, NULL);
        int expected = count < MAX_USERSCHED_DISPATCH ?
                       count : MAX_USERSCHED_DISPATCH;
        assert(sched_moved == expected);
        assert(sched_attempts <= MAX_USERSCHED_DISPATCH);
        assert(drains == 1 && local_attempts == 0 && shared_attempts == 0);
    }

    reset();
    goland_dispatch(0, NULL);
    assert(sched_attempts == 0 && drains == 1);
    assert(local_attempts == 1 && shared_attempts == 1);

    reset();
    kernel_mode = true;
    goland_dispatch(0, NULL);
    assert(sched_attempts == 0 && drains == 0);
    assert(local_attempts == 1 && shared_attempts == 1);

    reset();
    pending = queued = true;
    struct task_struct prev = {.pid = 9, .tgid = 9};
    goland_dispatch(0, &prev);
    assert(drains == 1 && prev.scx.slice == default_slice);
}

static void test_accounting(void)
{
    struct task_struct tasks[] = {
        {.pid = 42, .tgid = 42},
        {.pid = 43, .tgid = 42},
        {.pid = 44, .tgid = 44},
    };
    for (int mode = 0; mode <= 1; mode++) {
        for (int i = 0; i < 3; i++) {
            reset();
            kernel_mode = mode;
            bool excluded = !mode && i < 2;
            for (int iteration = 0; iteration < 100; iteration++) {
                now++;
                goland_running(&tasks[i]);
                assert(nr_running == (excluded ? 0 : 1));
                assert(usersched_last_run_at == (excluded ? now : 0));
                goland_stopping(&tasks[i], true);
                assert(nr_running == 0);
            }
            assert(cleared == (excluded ? 100 : 0));
        }
    }
}

static void test_tick(void)
{
    struct task_struct tasks[] = {
        {.pid = 42, .tgid = 42},
        {.pid = 43, .tgid = 42},
        {.pid = 44, .tgid = 44},
    };
    for (int mode = 0; mode <= 1; mode++) {
        for (int i = 0; i < 3; i++) {
            for (int enabled = 0; enabled <= 1; enabled++) {
                for (int missing = 0; missing <= 1; missing++) {
                    for (int stale = 0; stale <= 1; stale++) {
                        reset();
                        kernel_mode = mode;
                        max_time_watchdog = enabled;
                        missing_context = missing;
                        now = THRESHOLD + stale;
                        bool checked = enabled && (mode || i == 2);
                        goland_tick(&tasks[i]);
                        assert(context_lookups == (checked ? 1 : 0));
                        assert(kicks == (checked && !missing && stale ? 1 : 0));
                    }
                }
            }
        }
    }
}

static void test_loop_preempt(void)
{
    struct task_struct loop = {.pid = 43, .tgid = 42};
    for (int enabled = 0; enabled <= 1; enabled++) {
        for (int work = 0; work <= 1; work++) {
            for (int wake = 0; wake <= 1; wake++) {
                for (int correct_tid = 0; correct_tid <= 1; correct_tid++) {
                    for (int allowed = 0; allowed <= 1; allowed++) {
                        reset();
                        usersched_loop_tid = enabled ? (correct_tid ? 43 : 44) : 0;
                        pending = work;
                        cpu_allowed = allowed;
                        now = USERSCHED_PREEMPT_INTERVAL_NS;
                        enqueue_usersched_task(&loop, wake ? SCX_ENQ_WAKEUP : 0);
                        bool preempt = enabled && work && wake && correct_tid && allowed;
                        assert(kicks == (preempt ? 1 : 0));
                        assert(insert_dsq == (preempt ? SCX_DSQ_LOCAL_ON : SCHED_DSQ));
                        assert(insert_flags == (preempt ? SCX_ENQ_PREEMPT : SCX_ENQ_LAST));
                    }
                }
            }
        }
    }
    reset();
    usersched_loop_tid = 43;
    pending = true;
    now = USERSCHED_PREEMPT_INTERVAL_NS;
    enqueue_usersched_task(&loop, SCX_ENQ_WAKEUP);
    assert(kicks == 1);
    now += USERSCHED_PREEMPT_INTERVAL_NS - 1;
    enqueue_usersched_task(&loop, SCX_ENQ_WAKEUP);
    assert(kicks == 1 && insert_dsq == SCHED_DSQ);
    now++;
    enqueue_usersched_task(&loop, SCX_ENQ_WAKEUP);
    assert(kicks == 2);

    reset();
    usersched_loop_tid = 43;
    pending = true;
    idle_cpu = 0;
    now = USERSCHED_PREEMPT_INTERVAL_NS;
    enqueue_usersched_task(&loop, SCX_ENQ_WAKEUP);
    assert(kicks == 0 && idle_kicks == 1);
    assert(insert_dsq == SCX_DSQ_LOCAL_ON && insert_flags == SCX_ENQ_LAST);
    assert(usersched_last_preempt_at == 0);
}

static void test_adaptive_preempt(void)
{
    struct dispatched_task_ctx task = {.pid = 8, .cpu = 0, .vtime = 50};
    const u64 ages[] = {0, 1, 99999, 100000};
    for (unsigned i = 0; i < sizeof(ages) / sizeof(ages[0]); i++) {
        reset();
        now = 1000000;
        context.start_ts = now - ages[i];
        preempt_later_deadline(&task);
        assert(kicks == 1 && adaptive_preempts == 1 && releases == 1);
    }

    for (int rejection = 0; rejection < 9; rejection++) {
        reset();
        task.vtime = 50;
        switch (rejection) {
        case 0: current_task.running = false; break;
        case 1: current_task.cpu = 1; break;
        case 2: task.vtime = 100; break;
        case 3: task.vtime = 101; break;
        case 4: current_task.tgid = usersched_pid; break;
        case 5: missing_context = true; break;
        case 6: missing_running_pid = true; break;
        case 7: missing_running_task = true; break;
        case 8: mapped_pid = task.pid; break;
        }
        preempt_later_deadline(&task);
        assert(kicks == 0 && adaptive_preempts == 0);
        assert(releases == (rejection < 6 ? 1 : 0));
    }
}

static void test_adaptive_dispatch_flags(void)
{
    for (int enabled = 0; enabled <= 1; enabled++) {
        for (int target = 0; target < 3; target++) {
            reset();
            adaptive_wakeup = enabled;
            cpu_allowed = target != 2;
            struct dispatched_task_ctx task = {
                .pid = 8, .cpu = target == 1 ? RL_CPU_ANY : 0,
                .vtime = 50, .flags = SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT,
            };
            dispatch_task(&task);
            assert(insert_flags == (SCX_ENQ_WAKEUP |
                                    (enabled ? 0 : SCX_ENQ_PREEMPT)));
            assert(kicks == (enabled && target == 0 ? 1 : 0));
            assert(adaptive_requests == (enabled && target == 0 ? 1 : 0));
            assert(nr_bounce_dispatches == (target == 2 ? 1 : 0));
            assert(releases == (enabled && target == 0 ? 2 : 1));
        }
    }
}

static void test_previous_burst(void)
{
    for (int enabled = 0; enabled <= 1; enabled++) {
        reset();
        adaptive_wakeup = enabled;
        struct task_struct p = {.pid = 8, .tgid = 8, .scx.weight = 100};
        struct queued_task_ctx task;
        context.start_ts = 10;
        context.stop_ts = 20;
        context.exec_runtime = 10000000;
        context.previous_burst_runtime = 123;
        goland_runnable(&p, SCX_ENQ_WAKEUP);
        assert(context.exec_runtime == 0);
        assert(context.previous_burst_runtime == (enabled ? 10000000 : 123));
        get_task_info(&task, &p, 0, SCX_ENQ_WAKEUP);
        assert(task.exec_runtime == (enabled ? 10000000 : 0));
        assert(task.stop_ts - task.start_ts == 10);
        context.exec_runtime = 17;
        get_task_info(&task, &p, 0, 0);
        assert(task.exec_runtime == 17);
    }
}

static void test_latency(void)
{
    struct task_struct p = {.pid = 8, .tgid = 8};
    const u64 durations[] = {0, 1, 2, 3, 4, 7, 8, 1ULL << 63, UINT64_MAX - 1};
    const int buckets[] = {0, 0, 1, 1, 2, 2, 3, 63, 63};
    for (int i = 0; i < 9; i++) {
        reset();
        context.userspace_enqueued_at = 1;
        now = durations[i] + 1;
        record_dispatch_latency(&p);
        assert(context.userspace_enqueued_at == 1);
        assert(context_lookups == 0);
        measure_latency = true;
        record_dispatch_latency(&p);
        assert(latency_buckets[buckets[i]] == 1);
        assert(context.userspace_enqueued_at == 0);
        record_dispatch_latency(&p);
        assert(latency_buckets[buckets[i]] == 1);
    }
    reset();
    measure_latency = missing_context = true;
    record_dispatch_latency(&p);
    assert(latency_buckets[0] == 0);
}

int main(void)
{
    test_latency();
    test_dispatch();
    test_accounting();
    test_tick();
    test_loop_preempt();
    test_adaptive_preempt();
    test_adaptive_dispatch_flags();
    test_previous_burst();
    puts("dispatch progress, accounting, tick, loop/adaptive preemption, and burst reporting passed");
    return 0;
}
"""


class BPFProgressTest(unittest.TestCase):
    def test_queue_counter_precedes_publication(self):
        source = SOURCE.read_text()
        start = source.index("static void queue_task_to_userspace(")
        end = source.index("\n}", start)
        body = source[start:end]
        self.assertLess(
            body.index("__sync_fetch_and_add(&nr_queued, 1)"),
            body.index("bpf_ringbuf_submit(task, 0)"),
            "Consumers must see the queued count before the record is published",
        )

    def test_production_callbacks(self):
        source = SOURCE.read_text()
        defines = "\n".join(
            line for line in source.splitlines()
            if line.startswith(("#define MAX_USERSCHED_DISPATCH ", "#define THRESHOLD ",
                                "#define USERSCHED_PREEMPT_INTERVAL_NS ",
                                "#define MAX_WAKEUP_FREQ"))
        )
        callbacks = "\n".join(
            callback(source, name)
            for name in ("goland_dispatch", "goland_running", "goland_stopping",
                         "goland_tick", "goland_runnable")
        )
        helpers = []
        for signature in ("static void kick_task_cpu(", "u64 adaptive_requests,",
                          "static void record_dispatch_latency(",
                          "static void dispatch_task(",
                          "static void get_task_info("):
            start = source.index(signature)
            end = source.index("\n}", start) + len("\n}")
            helpers.append(source[start:end])
        callbacks = "\n".join(helpers) + "\n" + callbacks
        start = source.index("static void enqueue_usersched_task(")
        end = source.index("\n}", start) + len("\n}")
        callbacks = source[start:end] + "\n" + callbacks
        with tempfile.TemporaryDirectory(prefix="qumun-bpf-progress-") as directory:
            binary = Path(directory) / "test"
            subprocess.run(
                ["clang", "-std=gnu11", "-O2", "-Wall", "-Werror",
                 "-Wno-unused-function", "-x", "c", "-", "-o", str(binary)],
                input=MOCKS + "\n" + defines + "\n" + callbacks + CASES,
                text=True,
                check=True,
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
