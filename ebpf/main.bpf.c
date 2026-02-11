/* Copyright (c) Ian Chen <ychen.desl@gmail.com> */
/* The scx_goland is based on scx_rustland_core */
/* Copyright (c) Andrea Righi <andrea.righi@linux.dev> */
/*
 * scx_rustland_core: BPF backend for schedulers running in user-space.
 *
 * This BPF backend implements the low level sched-ext functionalities for a
 * user-space counterpart, that implements the actual scheduling policy.
 *
 * The BPF part collects total cputime and weight from the tasks that need to
 * run, then it sends all details to the user-space scheduler that decides the
 * best order of execution of the tasks (based on the collected metrics).
 *
 * The user-space scheduler then returns to the BPF component the list of tasks
 * to be dispatched in the proper order.
 *
 * Messages between the BPF component and the user-space scheduler are passed
 * using BPF_MAP_TYPE_RINGBUF / BPF_MAP_TYPE_USER_RINGBUF maps: @queued for
 * the messages sent by the BPF dispatcher to the user-space scheduler and
 * @dispatched for the messages sent by the user-space scheduler to the BPF
 * dispatcher.
 *
 * The BPF dispatcher is completely agnostic of the particular scheduling
 * policy implemented in user-space. For this reason developers that are
 * willing to use this scheduler to experiment scheduling policies should be
 * able to simply modify the Rust component, without having to deal with any
 * internal kernel / BPF details.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifdef LSP
#define __bpf__
#include "../../../../scheds/include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include <scx/percpu.bpf.h>
#include "intf.h"
#include <bpf/bpf_helpers.h>

/* Compatibility fallbacks for kernel flag macros that may not be defined
 * in older build environments or trimmed header sets used during BPF
 * compilation. Define them as 0 if missing so bitwise checks become no-op.
 */
#ifndef PF_KSWAPD
#define PF_KSWAPD 0
#endif
#ifndef PF_KCOMPACTD
#define PF_KCOMPACTD 0
#endif

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Introduce a custom DSQ shared across all the CPUs, where we can dispatch
 * tasks that will be executed on the first CPU available.
 *
 * Per-CPU DSQs are also provided, to allow the scheduler to run a task on a
 * specific CPU (see dsq_init()).
 */
#define SHARED_DSQ MAX_CPUS

/*
 * The user-space scheduler itself is dispatched using a separate DSQ, that
 * is consumed after all other DSQs.
 *
 * This ensures to work in bursts: tasks are queued, then the user-space
 * scheduler runs and dispatches them. Once all these tasks exhaust their
 * time slices, the scheduler is invoked again, repeating the cycle.
 */
#define SCHED_DSQ (MAX_CPUS + 1)

/*
 * Safety cap for dispatching usersched threads per invocation.
 */
#define MAX_USERSCHED_DISPATCH 64

/*
 * Scheduler attributes and statistics.
 */
const volatile u32 usersched_pid; /* User-space scheduler PID */
const volatile u32 khugepaged_pid; /* khugepaged PID */
u64 usersched_last_run_at; /* Timestamp of the last user-space scheduler execution */
static u64 nr_cpu_ids; /* Maximum possible CPU number */

/*
 * Number of tasks that are queued for scheduling.
 *
 * This number is incremented by the BPF component when a task is queued to the
 * user-space scheduler and it must be decremented by the user-space scheduler
 * when a task is consumed.
 */
volatile u64 nr_queued;

/*
 * Number of tasks that are waiting for scheduling.
 *
 * This number must be updated by the user-space scheduler to keep track if
 * there is still some scheduling work to do.
 */
volatile u64 nr_scheduled;

/*
 * Amount of currently running tasks.
 */
volatile u64 nr_running, nr_online_cpus;

/* Dispatch statistics */
volatile u64 nr_user_dispatches, nr_kernel_dispatches,
	     nr_cancel_dispatches, nr_bounce_dispatches;

/* Failure statistics */
volatile u64 nr_failed_dispatches, nr_sched_congested;

/* Report additional debugging information */
const volatile bool debug;

const volatile bool early_processing;

const volatile u64 default_slice = 20000000ULL; 

/* Rely on the in-kernel idle CPU selection policy */
const volatile bool builtin_idle;

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {						\
	if (debug)										\
		bpf_printk(_fmt, ##__VA_ARGS__);			\
} while(0)

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

const volatile bool kernel_mode = false;

/*
 * Maximum time slice lag for kernel mode.
 *
 * Increasing this value can help to increase the responsiveness of interactive
 * tasks at the cost of making regular and newly created tasks less responsive
 * (0 = disabled).
 */
const volatile u64 slice_lag = 40ULL * NSEC_PER_MSEC;

/*
 * Current global vruntime (used in kernel mode).
 */
static u64 vtime_now;

const volatile bool max_time_watchdog = true;

#define THRESHOLD 500000000  /* 500ms */

/*
 * Allocate/re-allocate a new cpumask.
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

/*
 * Maximum amount of tasks queued between kernel and user-space at a certain
 * time.
 *
 * The @queued and @dispatched lists are used in a producer/consumer fashion
 * between the BPF part and the user-space part.
 */
#define MAX_ENQUEUED_TASKS 4096

/*
 * Maximum amount of slots reserved to the tasks dispatched via shared queue.
 */
#define MAX_DISPATCH_SLOT (MAX_ENQUEUED_TASKS / 8)

/*
 * The map containing tasks that are queued to user space from the kernel.
 *
 * This map is drained by the user-space scheduler.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENQUEUED_TASKS *
				sizeof(struct queued_task_ctx));
} queued SEC(".maps");

/*
 * The user ring buffer containing pids that are dispatched from user space to
 * the kernel.
 *
 * Drained by the kernel in .dispatch().
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, MAX_ENQUEUED_TASKS *
				sizeof(struct dispatched_task_ctx));
} dispatched SEC(".maps");

/*
 * Map to track PIDs with vtime==0 (priority tasks).
 *
 * This hashmap stores PIDs as both key and value for tasks that have
 * vtime set to 0, indicating they are high priority tasks.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);    /* PID */
	__type(value, u64);   /* time slice */
	__uint(max_entries, MAX_ENQUEUED_TASKS);
} priority_tasks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, s32);    /* CPU */
	__type(value, u32);   /* PID */
	__uint(max_entries, MAX_CPUS);
} running_task SEC(".maps");

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *l3_cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return a CPU context.
 */
struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	/*
	 * Temporary cpumask for calculating scheduling domains.
	 */
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *l3_cpumask;

	/*
	 * Timestamp since last time the task ran on a CPU.
	 */
	u64 start_ts;

	/*
	 * Timestamp since last time the task released a CPU.
	 */
	u64 stop_ts;

	/*
	 * Execution time (in nanoseconds) since the last sleep event.
	 */
	u64 exec_runtime;

	/*
	 * Accumulated vruntime since last sleep (kernel mode).
	 */
	u64 awake_vtime;

	/*
	 * Timestamp of last wakeup (kernel mode).
	 */
	u64 last_woke_at;

	/*
	 * Wakeup frequency (kernel mode).
	 */
	u64 wakeup_freq;
};

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task or NULL if the context
 * doesn't exist.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor,
						(struct task_struct *)p, 0, 0);
	if (!tctx)
		dbg_msg("warning: failed to get task context for pid=%d (%s)",
			p->pid, p->comm);
	return tctx;
}

/*
 * Heartbeat timer used to periodically trigger the check to run the user-space
 * scheduler.
 *
 * Without this timer we may starve the scheduler if the system is completely
 * idle and hit the watchdog that would auto-kill this scheduler.
 */
struct usersched_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct usersched_timer);
} usersched_timer SEC(".maps");

/*
 * Time period of the scheduler heartbeat, used to periodically kick the
 * user-space scheduler and check if there is any pending activity.
 */
#define USERSCHED_TIMER_NS (NSEC_PER_SEC / 10)

/*
 * Return true if the target task @p is the user-space scheduler.
 */
static inline bool is_usersched_task(const struct task_struct *p)
{
	return p->pid == usersched_pid;
}

/*
 * Return true if the target task @p belongs to the user-space scheduler.
 */
static inline bool is_belong_usersched_task(const struct task_struct *p)
{
	return p->tgid == usersched_pid;
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

/*
 * Return true if the target task @p is a kworker thread.
 */
static inline bool is_kworker(const struct task_struct *p)
{
	return p->flags & PF_WQ_WORKER;
}

/*
 * Return true if the target task @p is kswapd.
 */
static inline bool is_kswapd(const struct task_struct *p)
{
        return p->flags & (PF_KSWAPD | PF_KCOMPACTD);
}

/*
 * Return true if the target task @p is khugepaged, false otherwise.
 */
static inline bool is_khugepaged(const struct task_struct *p)
{
	return khugepaged_pid && p->pid == khugepaged_pid;
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Flag used to wake-up the user-space scheduler.
 */
static volatile u32 usersched_needed;

/*
 * Set user-space scheduler wake-up flag (equivalent to an atomic release
 * operation).
 */
static void set_usersched_needed(void)
{
	__sync_fetch_and_or(&usersched_needed, 1);
}

/*
 * Check and clear user-space scheduler wake-up flag (equivalent to an atomic
 * acquire operation).
 */
static bool test_and_clear_usersched_needed(void)
{
	return __sync_fetch_and_and(&usersched_needed, 0) == 1;
}

/*
 * Return true if there's any pending activity to do for the scheduler, false
 * otherwise.
 *
 * NOTE: a task is sent to the user-space scheduler using the "queued"
 * ringbuffer, then the scheduler drains the queued tasks and adds them to
 * its internal data structures / state; at this point tasks become
 * "scheduled" and the user-space scheduler will take care of updating
 * nr_scheduled accordingly; lastly tasks will be dispatched and the
 * user-space scheduler will update nr_scheduled again.
 *
 * Checking nr_scheduled and the available data in the ringbuffer allows to
 * determine if there is still some pending work to do for the scheduler:
 * new tasks have been queued since last check, or there are still tasks
 * "queued" or "scheduled" since the previous user-space scheduler run.
 *
 * If there's no pending action, it is pointless to wake-up the scheduler
 * (even if a CPU becomes idle), because there is nothing to do.
 *
 * Also keep in mind that we don't need any protection here since this code
 * doesn't run concurrently with the user-space scheduler (that is single
 * threaded), therefore this check is also safe from a concurrency perspective.
 */
static bool usersched_has_pending_tasks(void)
{
	if (usersched_needed)
		return true;

	if (nr_queued || nr_scheduled)
		return true;

	return bpf_ringbuf_query(&queued, BPF_RB_AVAIL_DATA) > 0;
}

/*
 * Return the DSQ ID associated to a CPU, or SHARED_DSQ if the CPU is not
 * valid.
 */
static u64 cpu_to_dsq(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS) {
		scx_bpf_error("Invalid cpu: %d", cpu);
		return SHARED_DSQ;
	}
	return (u64)cpu;
}

/*
 * Helper function to update priority tasks map based on vtime.
 * If vtime == 0, add PID to map. If vtime != 0, remove PID from map.
 */
static void update_priority_task_map(u32 pid, u64 vtime, u64 slice)
{
	if (vtime == 0) {
		bpf_map_update_elem(&priority_tasks, &pid, &slice, BPF_ANY);
	} else {
		bpf_map_delete_elem(&priority_tasks, &pid);
	}
}

/*
 * Return true if @this_cpu and @that_cpu are in the same LLC, false
 * otherwise.
 */
static inline bool cpus_share_cache(s32 this_cpu, s32 that_cpu)
{
        if (this_cpu == that_cpu)
                return true;

	return cpu_llc_id(this_cpu) == cpu_llc_id(that_cpu);
}

/*
 * Return true if @this_cpu is faster than @that_cpu, false otherwise.
 */
static inline bool is_cpu_faster(s32 this_cpu, s32 that_cpu)
{
        if (this_cpu == that_cpu)
                return false;

	return cpu_priority(this_cpu) > cpu_priority(that_cpu);
}

/*
 * Return true if @cpu is a fully-idle SMT core, false otherwise.
 */
static inline bool is_smt_idle(s32 cpu)
{
	const struct cpumask *idle_smtmask;
        bool is_idle;

	if (!smt_enabled)
		return true;

	idle_smtmask = scx_bpf_get_idle_smtmask();
        is_idle = bpf_cpumask_test_cpu(cpu, idle_smtmask);
        scx_bpf_put_cpumask(idle_smtmask);

	return is_idle;
}

/*
 * Return true on a wake-up event, false otherwise.
 */
static inline bool is_wakeup(u64 wake_flags)
{
	return wake_flags & SCX_WAKE_TTWU;
}

/*
 * Find an idle CPU in the system for the task.
 *
 * NOTE: the idle CPU selection doesn't need to be formally perfect, it is
 * totally fine to accept racy conditions and potentially make mistakes, by
 * picking CPUs that are not idle or even offline, the logic has been designed
 * to handle these mistakes in favor of a more efficient response and a reduced
 * scheduling overhead.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	/*
	 * For tasks that can run only on a single CPU, we can simply verify if
	 * their only allowed CPU is still idle.
	 */
	if (p->nr_cpus_allowed == 1) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;

		return -EBUSY;
	}

	/*
	 * On wakeup if the waker's CPU is faster than the wakee's CPU, try
	 * to move the wakee closer to the waker.
	 *
	 * In presence of hybrid cores this helps to naturally migrate
	 * tasks over to the faster cores.
	 */
	if (is_wakeup(wake_flags) &&
	    is_cpu_faster(this_cpu, prev_cpu) && is_this_cpu_allowed) {
		/*
		 * If both the waker's CPU and the wakee's CPU are in the
		 * same LLC and the wakee's CPU is a fully idle SMT core,
		 * don't migrate.
		 */
		if (cpus_share_cache(this_cpu, prev_cpu) &&
		    is_smt_idle(prev_cpu) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;

		prev_cpu = this_cpu;
	}

	/*
	 * Fallback to the old API if the kernel doesn't support
	 * scx_bpf_select_cpu_and().
	 *
	 * This is required to support kernels <= 6.16.
	 */
	if (!bpf_ksym_exists(scx_bpf_select_cpu_and)) {
		bool is_idle = false;

		if (!wake_flags)
			return -EBUSY;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		return is_idle ? cpu : -EBUSY;
	}

	/*
	 * Pick any idle CPU usable by the task.
	 */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * Wake-up a target @cpu for the dispatched task @p. If @cpu can't be used
 * wakeup another valid CPU.
 */
static void kick_task_cpu(const struct task_struct *p, s32 cpu)
{
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		/*
		 * Kick the target CPU anyway, since it may be locked and
		 * needs to go back to idle to reset its state.
		 */
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

		/*
		 * Pick any other idle CPU that the task can use.
		 */
		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (cpu < 0)
			return;
	}
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

/*
 * Dispatch a task to a target per-CPU DSQ, waking up the corresponding CPU, if
 * needed.
 */
static void dispatch_task(const struct dispatched_task_ctx *task)
{
	struct task_struct *p;
	s32 prev_cpu;

	/* Ignore entry if the task doesn't exist anymore */
	p = bpf_task_from_pid(task->pid);
	if (!p)
		return;
	prev_cpu = scx_bpf_task_cpu(p);

	/*
	 * Dispatch task to the shared DSQ if the user-space scheduler
	 * didn't select any specific target CPU.
	 */
	if (task->cpu == RL_CPU_ANY) {
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ,
					 task->slice_ns, task->vtime, task->flags);
		kick_task_cpu(p, prev_cpu);

		goto out_release;
	}

	/*
	 * If the target CPU selected by the user-space scheduler is not
	 * valid, dispatch it to the SHARED_DSQ, independently on what the
	 * user-space scheduler has decided.
	 */
	if (!bpf_cpumask_test_cpu(task->cpu, p->cpus_ptr)) {
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ,
					 task->slice_ns, task->vtime, task->flags);
		__sync_fetch_and_add(&nr_bounce_dispatches, 1);
		kick_task_cpu(p, prev_cpu);

		goto out_release;
	}

	/*
	 * Dispatch a task to a target CPU selected by the user-space
	 * scheduler.
	 */
	if (task->vtime) {
		scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(task->cpu),
				task->slice_ns, task->vtime, task->flags);
		__sync_fetch_and_add(&nr_user_dispatches, 1);
	} else {
		s32 cur_pid;
		u64* elem;
		cur_pid = task->pid;
		elem = bpf_map_lookup_elem(&priority_tasks, &cur_pid);
		if (!elem){
			scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(task->cpu),
				task->slice_ns, task->vtime, task->flags);
			__sync_fetch_and_add(&nr_user_dispatches, 1);
		}
	}
	update_priority_task_map(task->pid, task->vtime, task->slice_ns);

	/*
	 * If the cpumask is not valid anymore, ignore the dispatch event.
	 *
	 * This can happen if the task has changed its affinity and the
	 * target CPU has become invalid. In this case cancelling the
	 * dispatch allows to prevent potential stalls in the scheduler,
	 * since the task will be re-enqueued by the core sched-ext code,
	 * potentially selecting a different CPU.
	 */
	if (!bpf_cpumask_test_cpu(task->cpu, p->cpus_ptr)) {
		scx_bpf_dispatch_cancel();
		__sync_fetch_and_add(&nr_cancel_dispatches, 1);

		goto out_release;
	}

	scx_bpf_kick_cpu(task->cpu, SCX_KICK_IDLE);

out_release:
	bpf_task_release(p);
}

/*
 * Return true if the waker commits to release the CPU after waking up @p,
 * false otherwise.
 */
static bool is_wake_sync(u64 wake_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();

	return (wake_flags & SCX_WAKE_SYNC) && !(current->flags & PF_EXITING);
}

/*
 * Return true it's safe to dispatch directly on @cpu, false otherwise.
 */
static bool can_direct_dispatch(s32 cpu)
{
	return !scx_bpf_dsq_nr_queued(SHARED_DSQ) &&
	       !scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu));
}

/*
 * Maximum rate of task wakeups/sec (tasks with a higher rate are capped to
 * this value).
 *
 * Note that the wakeup rate is evaluate over a period of 100ms, so this
 * number must be multiplied by 10 to determine the actual limit in
 * wakeups/sec.
 */
#define MAX_WAKEUP_FREQ		64ULL

/*
 * Maximum time a task can wait in the scheduler's queue before triggering
 * a stall (kernel mode).
 */
#define STARVATION_MS	5000ULL

/*
 * Exponential weighted moving average (EWMA).
 *
 * Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Update the average frequency of an event.
 *
 * The frequency is computed from the given interval since the last event
 * and combined with the previous frequency using an exponential weighted
 * moving average.
 */
static u64 update_freq(u64 freq, u64 interval)
{
	u64 new_freq;

	new_freq = (100 * NSEC_PER_MSEC) / interval;
	return calc_avg(freq, new_freq);
}

/*
 * Calculate and return the virtual deadline for the given task (kernel mode).
 *
 *  The deadline is defined as:
 *
 *    deadline = vruntime + awake_vtime
 *
 * Here, `vruntime` represents the task's total accumulated runtime,
 * inversely scaled by its weight, while `awake_vtime` accounts the runtime
 * accumulated since the last sleep event, also inversely scaled by the
 * task's weight.
 *
 * Fairness is driven by `vruntime`, while `awake_vtime` helps prioritize
 * tasks that sleep frequently and use the CPU in short bursts (resulting
 * in a small `awake_vtime` value), which are typically latency critical.
 */
static u64 task_deadline(struct task_struct *p, s32 cpu, struct task_ctx *tctx)
{
	/*
	 * Reference queue depth: how many tasks would take 1/10 the SLA to
	 * drain at average slice usage.
	 */
	const u64 STARVATION_THRESH = STARVATION_MS * NSEC_PER_MSEC / 10;
	const u64 q_thresh = MAX(STARVATION_THRESH / default_slice, 1);

	u64 nr_queue = scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu)) +
			scx_bpf_dsq_nr_queued(SHARED_DSQ);
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 awake_max = scale_by_task_weight_inverse(p, slice_lag);
	u64 vtime_min;

	/*
	 * Queue pressure factor = q_thresh / (q_thresh + nr_queued), applied to
	 * @lag_scale.
	 *
	 * Emergency clamp: if queued work (q * default_slice) already spans
	 * the starvation window, stop boosting vruntime credit.
	 */
	if (nr_queue * default_slice >= STARVATION_THRESH)
		lag_scale = 1;
	else
		lag_scale = MAX(lag_scale * q_thresh / (q_thresh + nr_queue), 1);

	/*
	 * Cap the partial accumulated vruntime since last sleep in
	 * function of @slice_lag and @lag_scale.
	 */
	vtime_min = vtime_now - scale_by_task_weight(p, slice_lag * lag_scale);
	if (time_before(p->scx.dsq_vtime, vtime_min))
		p->scx.dsq_vtime = vtime_min;

	/*
	 * Cap the partial accumulated vruntime since last sleep to
	 * @slice_lag.
	 */
	if (time_after(tctx->awake_vtime, awake_max))
		tctx->awake_vtime = awake_max;

	/*
	 * Evaluate task's deadline as the accumulated vruntime +
	 * accumulated vruntime since last sleep.
	 */
	return p->scx.dsq_vtime + tctx->awake_vtime;
}

/*
 * Return a time slice scaled by the task's weight (kernel mode).
 */
static u64 task_slice(const struct task_struct *p, s32 cpu)
{
	u64 nr_wait = scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu)) +
		      scx_bpf_dsq_nr_queued(SHARED_DSQ);

	/*
	 * Adjust time slice in function of the task's priority and the
	 * amount of tasks waiting to be dispatched.
	 */
	return scale_by_task_weight(p, default_slice) / MAX(nr_wait, 1);
}

/*
 * Return true if the task can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Dispatch a task in kernel mode to the appropriate DSQ.
 */
static void dispatch_task_kernel_mode(struct task_struct *p, s32 cpu, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx) {
		/*
		 * Fallback: dispatch with default values if no task context.
		 */
		scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(cpu),
					 default_slice, p->scx.dsq_vtime, enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}

	scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(cpu),
				 task_slice(p, cpu), task_deadline(p, cpu, tctx), enq_flags);
	__sync_fetch_and_add(&nr_kernel_dispatches, 1);
}

/*
 * Dispatch a task to SHARED_DSQ in kernel mode.
 */
static void dispatch_task_shared_kernel_mode(struct task_struct *p, s32 cpu, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx) {
		/*
		 * Fallback: dispatch with default values if no task context.
		 */
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ,
					 default_slice, p->scx.dsq_vtime, enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}

	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ,
				 task_slice(p, cpu), task_deadline(p, cpu, tctx), enq_flags);
	__sync_fetch_and_add(&nr_kernel_dispatches, 1);
}

s32 BPF_STRUCT_OPS(goland_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	/*
	 * Make sure @prev_cpu is usable, otherwise try to move close to
	 * the waker's CPU. If the waker's CPU is also not usable, then
	 * pick the first usable CPU.
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	/*
	 * Scheduler is dispatched directly in .dispatch() when needed, so
	 * we can skip it here. (Only in user-space mode)
	 */
	if (!kernel_mode && is_belong_usersched_task(p))
		return prev_cpu;

	/*
	 * If built-in idle CPU policy is not enabled and not in kernel mode,
	 * completely delegate the idle selection policy to user-space and
	 * keep re-using the same CPU here.
	 */
	if (!builtin_idle && !kernel_mode)
		return prev_cpu;

	/*
	 * Pick the idle CPU closest to @prev_cpu usable by the task.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
	if (cpu >= 0) {
		if (can_direct_dispatch(cpu)) {
			if (kernel_mode) {
				/*
				 * In kernel mode, use deadline-based dispatch.
				 */
				dispatch_task_kernel_mode(p, cpu, 0);
			} else {
				scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(cpu),
							 default_slice, p->scx.dsq_vtime, 0);
				__sync_fetch_and_add(&nr_kernel_dispatches, 1);
			}
		}
		return cpu;
	}

	/*
	 * If we couldn't find an idle CPU, in case of a sync wakeup
	 * prioritize the waker's CPU.
	 */
	return prev_cpu;
}

SEC("syscall")
int do_preempt(struct preempt_cpu_arg *input)
{	
	scx_bpf_kick_cpu(input->cpu_id, SCX_KICK_PREEMPT);
	return 0;
}

/*
 * Select and wake-up an idle CPU for a specific task from the user-space
 * scheduler.
 */
SEC("syscall")
int rs_select_cpu(struct task_cpu_arg *input)
{
	struct task_struct *p;
	int cpu = input->cpu;

	p = bpf_task_from_pid(input->pid);
	if (!p)
		return -EINVAL;

	/*
	 * If the target CPU is the current one, treat it as idle when no
	 * other tasks are queued.
	 *
	 * Since this function is invoked by the user-space scheduler,
	 * which will release the CPU shortly, there is no need to migrate
	 * the task elsewhere.
	 */
	if (cpu == bpf_get_smp_processor_id()) {
		u64 nr_tasks = nr_running + nr_queued + nr_scheduled + 1;

		if (nr_tasks < nr_online_cpus && !scx_bpf_dsq_nr_queued(cpu))
			goto out_release;
	}

	bpf_rcu_read_lock();
	/*
	 * Kernels that don't provide scx_bpf_select_cpu_and() only allow
	 * to use the built-in idle CPU selection policy only from
	 * ops.select_cpu() and opt.enqueue(), return any idle CPU usable
	 * by the task in this case.
	 */
	if (!bpf_ksym_exists(scx_bpf_select_cpu_and)) {
		if (!scx_bpf_test_and_clear_cpu_idle(cpu))
			cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	} else {
		/*
		 * Set SCX_WAKE_TTWU, pretending to be a wakeup, to prioritize
		 * faster CPU selection (we probably want to add an option to allow
		 * the user-space scheduler to use this logic or not).
		 */
		cpu = pick_idle_cpu(p, cpu, SCX_WAKE_TTWU);
	}
	bpf_rcu_read_unlock();

out_release:
	bpf_task_release(p);

	return cpu;
}

/*
 * Fill @task with all the information that need to be sent to the user-space
 * scheduler.
 */
static void get_task_info(struct queued_task_ctx *task,
			  const struct task_struct *p, s32 prev_cpu, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);

	task->pid = p->pid;
	task->cpu = prev_cpu;
	task->nr_cpus_allowed = p->nr_cpus_allowed;
	task->flags = enq_flags;
	task->start_ts = tctx ? tctx->start_ts : 0;
	task->stop_ts = tctx ? tctx->stop_ts : 0;
	task->exec_runtime = tctx ? tctx->exec_runtime : 0;
	task->weight = p->scx.weight;
	task->vtime = p->scx.dsq_vtime;
	task->tgid = p->tgid;
}

/*
 * User-space scheduler is congested: log that and increment congested counter.
 */
static void sched_congested(struct task_struct *p)
{
	dbg_msg("congested: pid=%d (%s)", p->pid, p->comm);
	__sync_fetch_and_add(&nr_sched_congested, 1);
}

/*
 * Return true if a task has been enqueued as a remote wakeup, false
 * otherwise.
 */
static bool is_queued_wakeup(const struct task_struct *p, u64 enq_flags)
{
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

/*
 * Queue a task to the user-space scheduler.
 */
static void queue_task_to_userspace(struct task_struct *p, s32 prev_cpu, u64 enq_flags)
{
	struct queued_task_ctx *task;

	/*
	 * Allocate a new entry in the ring buffer.
	 *
	 * If ring buffer is full, the user-space scheduler is congested,
	 * so dispatch the task directly using the shared DSQ (the task
	 * will be consumed by the first CPU available).
	 */
	task = bpf_ringbuf_reserve(&queued, sizeof(*task), 0);
	if (!task) {
		sched_congested(p);
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ,
					 SCX_SLICE_DFL, p->scx.dsq_vtime, enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}

	/*
	 * Collect task information and store them in the ring buffer that
	 * will be consumed by the user-space scheduler.
	 */
	dbg_msg("enqueue: pid=%d (%s)", p->pid, p->comm);
	get_task_info(task, p, prev_cpu, enq_flags);
	bpf_ringbuf_submit(task, 0);
	__sync_fetch_and_add(&nr_queued, 1);
}

/*
 * Enqueue a task in kernel mode.
 *
 * In kernel mode, all scheduling decisions are made in eBPF.
 * Tasks are dispatched directly to per-CPU DSQs or SHARED_DSQ
 * based on deadline-based scheduling similar to bpfland.
 */
static void enqueue_task_kernel_mode(struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;
	struct task_ctx *tctx;

	/*
	 * Always dispatch per-CPU kthreads directly on their target CPU.
	 *
	 * This allows to prioritize critical kernel threads that may
	 * potentially stall the entire system if they are blocked for too long
	 * (i.e., ksoftirqd/N, rcuop/N, etc.).
	 */
	if (is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu), enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}

	/*
	 * Prioritize kswapd and khugepaged to prevent memory pressure stalls.
	 */
	if (is_kswapd(p) || is_khugepaged(p)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu), enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}

	/*
	 * Handle priority tasks with custom dispatch logic (similar to user-space mode).
	 * Check if the task is in priority_tasks map and dispatch with preemption.
	 */
	u64 *prio_elem;
	u64 *running_prio_elem;
	u64 prio_slice;
	u32 pid = p->pid;
	s32 prio_cpu = -EBUSY;
	u64 prio_enq_flags = SCX_ENQ_PREEMPT;
	u32 *cur_pid_val;
	u32 cur_pid;

	prio_elem = bpf_map_lookup_elem(&priority_tasks, &pid);
	if (prio_elem) {
		prio_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (prio_cpu == -EBUSY) {
			prio_cpu = prev_cpu;
		}
		prio_slice = *prio_elem;
		if (prio_cpu >= 0) {
			cur_pid_val = bpf_map_lookup_elem(&running_task, &prio_cpu);
			if (cur_pid_val) {
				cur_pid = *cur_pid_val;
				running_prio_elem = bpf_map_lookup_elem(&priority_tasks, &cur_pid);
				/*
				 * If current running task is prioritized, do not preempt it (use SCX_ENQ_HEAD).
				 * Otherwise, keep the flag equals to SCX_ENQ_PREEMPT.
				 */
				if (running_prio_elem) {
					prio_enq_flags = SCX_ENQ_HEAD;
				}
			}
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prio_cpu,
				prio_slice, prio_enq_flags);
			__sync_fetch_and_add(&nr_kernel_dispatches, 1);
			scx_bpf_kick_cpu(prio_cpu, SCX_KICK_IDLE);
			return;
		}
	}

	/*
	 * If the task can only run on the current CPU, dispatch it to the
	 * corresponding per-CPU DSQ.
	 */
	if (is_pcpu_task(p)) {
		dispatch_task_kernel_mode(p, prev_cpu, enq_flags);
		return;
	}

	/*
	 * Attempt to dispatch directly to an idle CPU if ops.select_cpu() was
	 * skipped.
	 */
	if (!__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p)) {
		cpu = pick_idle_cpu(p, prev_cpu, 0);
		if (cpu >= 0) {
			dispatch_task_kernel_mode(p, cpu, enq_flags);
			if (prev_cpu != cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}

	/*
	 * Dispatch the task to the SHARED_DSQ using deadline-based scheduling.
	 */
	dispatch_task_shared_kernel_mode(p, prev_cpu, enq_flags);

	/*
	 * Kick the CPU to process the newly enqueued task.
	 */
	scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Task @p becomes ready to run. We can dispatch the task directly here if the
 * user-space scheduler is not required, or enqueue it to be processed by the
 * scheduler.
 */
void BPF_STRUCT_OPS(goland_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;
	bool is_wakeup = is_queued_wakeup(p, enq_flags);

	/*
	 * In kernel mode, dispatch all tasks in eBPF without user-space
	 * scheduler involvement.
	 */
	if (kernel_mode) {
		enqueue_task_kernel_mode(p, enq_flags);
		return;
	}

	/*
	 * ============================================================
	 * User-space mode: the following code is only executed when
	 * kernel_mode is false.
	 * ============================================================
	 */

	/*
	 * Insert the user-space scheduler to its dedicated DSQ, it will be
	 * consumed from ops.dispatch() only when there's any pending
	 * scheduling action to do.
	 */
	if (is_belong_usersched_task(p)) {
		if (usersched_has_pending_tasks()) {
			/*
			 * Try to find an idle CPU and dispatch directly to reduce latency.
			 * This avoids the overhead of going through SCHED_DSQ.
			 */
			cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
			if (cpu >= 0) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					default_slice, SCX_ENQ_LAST);
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
				return;
			}
		}
		scx_bpf_dsq_insert(p, SCHED_DSQ, default_slice, SCX_ENQ_LAST);
		return;
	}

	/*
	 * Always dispatch per-CPU kthreads directly on their target CPU.
	 *
	 * This allows to prioritize critical kernel threads that may
	 * potentially stall the entire system if they are blocked for too long
	 * (i.e., ksoftirqd/N, rcuop/N, etc.).
	 */
	if (is_kthread(p) && p->nr_cpus_allowed == 1 && early_processing) {
		cpu = scx_bpf_task_cpu(p);
		scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(cpu),
					 default_slice, p->scx.dsq_vtime, enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}
	if (is_kswapd(p) || is_khugepaged(p)) {
		cpu = scx_bpf_task_cpu(p);
		scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(cpu),
					 default_slice, p->scx.dsq_vtime, enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}

	/*
	 * Handle priority tasks with custom dispatch logic.
	 */
	u64* elem;
	u64 slice;
	u32 pid = p->pid;
	s32 prio_cpu = -EBUSY;
	u64 prio_enq_flags = SCX_ENQ_PREEMPT;
	u32* cur_pid_val;
	u32 cur_pid;

	elem = bpf_map_lookup_elem(&priority_tasks, &pid);
	if (elem) {
		prio_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (prio_cpu == -EBUSY) {
			prio_cpu = scx_bpf_task_cpu(p);
		}
		slice = *elem;
		if (prio_cpu >= 0) {
			cur_pid_val = bpf_map_lookup_elem(&running_task, &prio_cpu);
			if (cur_pid_val) {
				cur_pid = *cur_pid_val;
				elem = bpf_map_lookup_elem(&priority_tasks, &cur_pid);
				// If current running task is prioritized, do not preempt it (SCX_ENQ_HEAD).
				// Otherwise, keep the flag equals to SCX_ENQ_PREEMPT
				if (elem) {
					prio_enq_flags = SCX_ENQ_HEAD;
				}
			}
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prio_cpu,
				slice, prio_enq_flags);
			__sync_fetch_and_add(&nr_user_dispatches, 1);
			scx_bpf_kick_cpu(prio_cpu, SCX_KICK_IDLE);
			return;
		}
	}

	/*
	 * If @builtin_idle is enabled, give the task a chance to be
	 * directly dispatched only on a wakeup and only if
	 * ops.select_cpu() was skipped, otherwise the task is always
	 * queued to the user-space scheduler.
	 */
	if (!(builtin_idle && is_wakeup)) {
		queue_task_to_userspace(p, prev_cpu, enq_flags);
		goto out_kick;
	}

	/*
	 * Try to find an idle CPU in the system, if all CPUs are busy
	 * queue the task to the user-space scheduler.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, 0);
	if (cpu < 0) {
		queue_task_to_userspace(p, prev_cpu, enq_flags);
		goto out_kick;
	}

	/*
	 * Always force a CPU wakeup, so that the allocated CPU can be
	 * released and go back idle even if the task isn't directly
	 * dispatched.
	 */
	prev_cpu = cpu;
	is_wakeup = true;

	/*
	 * Perform direct dispatch only if the SHARED_DSQ is empty and
	 * the per-CPU DSQ is empty, otherwise we may risk to starve the
	 * tasks waiting in the queues.
	 */
	if (!scx_bpf_dsq_nr_queued(SHARED_DSQ) && !scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu))) {
		/*
		 * We can race with a dequeue here and the selected idle CPU
		 * might be not valid anymore, if the task affinity has changed.
		 *
		 * In this case just wakeup the picked CPU and ignore the enqueue,
		 * another enqueue event for the same task will be received later.
		 */
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			goto out_kick;

		/*
		 * Directly dispatch the task to selected idle CPU (queued wakeup).
		 */
		scx_bpf_dsq_insert_vtime(p, cpu_to_dsq(cpu),
					 SCX_SLICE_DFL, p->scx.dsq_vtime, enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		goto out_kick;
	}

	/*
	 * If we can't directly dispatch, queue the task to user-space.
	 */
	queue_task_to_userspace(p, prev_cpu, enq_flags);

out_kick:
	/*
	 * Wakeup the task's CPU if needed.
	 */
	if (is_wakeup)
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Handle a task dispatched from user-space, performing the actual low-level
 * BPF dispatch.
 */
static long handle_dispatched_task(struct bpf_dynptr *dynptr, void *context)
{
	const struct dispatched_task_ctx *task;

	task = bpf_dynptr_data(dynptr, 0, sizeof(*task));
	if (!task)
		return 0;

	dispatch_task(task);

	return !!scx_bpf_dispatch_nr_slots();
}

/*
 * Return true if the task can keep running on its current CPU from
 * ops.dispatch(), false if the task should migrate (kernel mode).
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	/* Do not keep running if the task doesn't need to run */
	if (!is_queued(p))
		return false;

	/*
	 * If the task can only run on this CPU, keep it running.
	 */
	if (is_pcpu_task(p))
		return true;

	return true;
}

/*
 * Dispatch tasks that are ready to run.
 *
 * This function is called when a CPU's local DSQ is empty and ready to accept
 * new dispatched tasks.
 *
 * We may dispatch tasks also on other CPUs from here, if the scheduler decided
 * so (usually if other CPUs are idle we may want to send more tasks to their
 * local DSQ to optimize the scheduling pipeline).
 */
void BPF_STRUCT_OPS(goland_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * In kernel mode, skip user-space scheduler related logic.
	 */
	if (kernel_mode) {
		/*
		 * Consume a task from the per-CPU DSQ.
		 */
		if (scx_bpf_dsq_move_to_local(cpu_to_dsq(cpu)))
			return;

		/*
		 * Consume a task from the shared DSQ.
		 */
		if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
			return;

		/*
		 * If the current task expired its time slice and no other task
		 * wants to run, simply replenish its time slice and let it run for
		 * another round on the same CPU.
		 */
		if (prev && keep_running(prev, cpu))
			prev->scx.slice = task_slice(prev, cpu);

		return;
	}

	/*
	 * ============================================================
	 * User-space mode: the following code is only executed when
	 * kernel_mode is false.
	 * ============================================================
	 */

	/*
	 * Dispatch the user-space scheduler if there's any pending action
	 * to do. Keep consuming from SCHED_DSQ until it's empty.
	 */
	if (usersched_has_pending_tasks()) {
		int consumed = 0;
		while (scx_bpf_dsq_move_to_local(SCHED_DSQ) && consumed++ < MAX_USERSCHED_DISPATCH)
			;
		return;
	}

	/*
	 * Consume all tasks from the @dispatched list and immediately
	 * dispatch them on the target CPU decided by the user-space
	 * scheduler.
	 */
	s32 ret = bpf_user_ringbuf_drain(&dispatched,
				handle_dispatched_task, NULL, BPF_RB_NO_WAKEUP);
	if (ret < 0)
		dbg_msg("User ringbuf drain error: %d", ret);

	/*
	 * Consume a task from the per-CPU DSQ.
	 */
	if (scx_bpf_dsq_move_to_local(cpu_to_dsq(cpu)))
		return;

	/*
	 * Consume a task from the shared DSQ.
	 */
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		return;

	/*
	 * If the current task expired its time slice and no other task
	 * wants to run, simply replenish its time slice and let it run for
	 * another round on the same CPU.
	 *
	 * In case of the user-space scheduler task, replenish its time
	 * slice only if there're still pending scheduling actions to do.
	 */
	if (prev && is_queued(prev) &&
	    (!is_belong_usersched_task(prev) || usersched_has_pending_tasks()))
		prev->scx.slice = default_slice;
}

void BPF_STRUCT_OPS(goland_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now = bpf_ktime_get_ns(), delta_t;

	if (!kernel_mode && is_belong_usersched_task(p))
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->exec_runtime = 0;

	/*
	 * In kernel mode, reset awake_vtime and update wakeup frequency.
	 */
	if (kernel_mode) {
		tctx->awake_vtime = 0;

		/*
		 * Update the task's wakeup frequency based on the time since the
		 * last wakeup, then cap the result to avoid large spikes.
		 */
		delta_t = now > tctx->last_woke_at ? now - tctx->last_woke_at : 1;
		tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
		tctx->wakeup_freq = MIN(tctx->wakeup_freq, MAX_WAKEUP_FREQ);
		tctx->last_woke_at = now;
	}
}

/*
 * Task @p starts on its selected CPU (update CPU ownership map).
 */
void BPF_STRUCT_OPS(goland_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;

	u32 pid = p->pid;
	bpf_map_update_elem(&running_task, &cpu, &pid, BPF_ANY);

	if (!kernel_mode && is_usersched_task(p)) {
		usersched_last_run_at = scx_bpf_now();
		return;
	}

	dbg_msg("start: pid=%d (%s) cpu=%ld", p->pid, p->comm, cpu);

	/*
	 * Mark the CPU as busy by setting the pid as owner (ignoring the
	 * user-space scheduler).
	 */
	__sync_fetch_and_add(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->start_ts = scx_bpf_now();

	/*
	 * In kernel mode, update global vtime_now.
	 */
	if (kernel_mode) {
		if (time_before(vtime_now, p->scx.dsq_vtime))
			vtime_now = p->scx.dsq_vtime;
	}
}

/*
 * Task @p stops running on its associated CPU (update CPU ownership map).
 */
void BPF_STRUCT_OPS(goland_stopping, struct task_struct *p, bool runnable)
{
	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	u64 slice, delta_vtime;

	if (!kernel_mode && is_belong_usersched_task(p)) {
		if (nr_scheduled + nr_queued == 0) {
			test_and_clear_usersched_needed();
		}
		return;
	}

	dbg_msg("stop: pid=%d (%s) cpu=%ld", p->pid, p->comm, cpu);

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->stop_ts = now;

	/*
	 * Update the partial execution time since last sleep.
	 */
	tctx->exec_runtime += now - tctx->start_ts;

	/*
	 * In kernel mode, update vruntime and awake_vtime.
	 */
	if (kernel_mode) {
		slice = now - tctx->start_ts;
		delta_vtime = scale_by_task_weight_inverse(p, slice);
		p->scx.dsq_vtime += delta_vtime;
		tctx->awake_vtime += delta_vtime;
	}
}

/*
 * A task joins the sched_ext scheduler.
 */
void BPF_STRUCT_OPS(goland_enable, struct task_struct *p)
{
	/*
	 * In kernel mode, initialize vruntime to the current global vruntime.
	 * In user-space mode, initialize to 0.
	 */
	if (kernel_mode)
		p->scx.dsq_vtime = vtime_now;
	else
		p->scx.dsq_vtime = 0;
	p->scx.slice = SCX_SLICE_DFL;
}

/*
 * A new task @p is being created.
 *
 * Allocate and initialize all the internal structures for the task (this
 * function is allowed to block, so it can be used to preallocate memory).
 */
s32 BPF_STRUCT_OPS(goland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	/*
	 * Create task's L2 cache cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l2_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	/*
	 * Create task's L3 cache cpumask.
	 */
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l3_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

/*
 * Heartbeat scheduler timer callback.
 *
 * If the system is completely idle the sched-ext watchdog may incorrectly
 * detect that as a stall and automatically disable the scheduler. So, use this
 * timer to periodically wake-up the scheduler and avoid long inactivity.
 *
 * This can also help to prevent real "stalling" conditions in the scheduler.
 */
static int usersched_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	struct task_struct *p;
	int err = 0;

	/*
	 * Trigger the user-space scheduler if it has been inactive for
	 * more than USERSCHED_TIMER_NS.
	 */
	if (time_delta(scx_bpf_now(), usersched_last_run_at) >= USERSCHED_TIMER_NS) {
		bpf_rcu_read_lock();
		p = bpf_task_from_pid(usersched_pid);
		if (p) {
			set_usersched_needed();
			scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_IDLE);
			bpf_task_release(p);
		}
		bpf_rcu_read_unlock();
	}

	/* Re-arm the timer */
	err = bpf_timer_start(timer, USERSCHED_TIMER_NS, 0);
	if (err)
		scx_bpf_error("Failed to arm stats timer");

	return 0;
}

/*
 * Initialize the heartbeat scheduler timer.
 */
static int usersched_timer_init(void)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	timer = bpf_map_lookup_elem(&usersched_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup scheduler timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &usersched_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, usersched_timer_fn);
	err = bpf_timer_start(timer, USERSCHED_TIMER_NS, 0);
	if (err)
		scx_bpf_error("Failed to arm scheduler timer");

	return err;
}

/*
 * Evaluate the amount of online CPUs.
 */
static s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask;
	int i, cpus = 0;

	online_cpumask = scx_bpf_get_online_cpumask();

	bpf_for(i, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(i, online_cpumask))
			continue;
		cpus++;
	}

	scx_bpf_put_cpumask(online_cpumask);

	return cpus;
}

/*
 * Create a DSQ for each CPU available in the system and a global shared DSQ.
 *
 * All the tasks processed by the user-space scheduler can be dispatched either
 * to a specific CPU/DSQ or to the first CPU available (SHARED_DSQ).
 *
 * Custom DSQs are then consumed from the .dispatch() callback, that will
 * transfer all the enqueued tasks to the consuming CPU's local DSQ.
 */
static int dsq_init(void)
{
	int err;
	s32 cpu;

	/* Initialize amount of online CPUs */
	nr_online_cpus = get_nr_online_cpus();

	/* Create per-CPU DSQs */
	bpf_for(cpu, 0, nr_cpu_ids) {
		err = scx_bpf_create_dsq(cpu_to_dsq(cpu), -1);
		if (err) {
			scx_bpf_error("failed to create pcpu DSQ %d: %d",
				      cpu, err);
			return err;
		}
	}

	/* Create the global shared DSQ */
	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}

	/* Create the scheduler's DSQ */
	err = scx_bpf_create_dsq(SCHED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create scheduler DSQ: %d", err);
		return err;
	}

	return 0;
}

static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int err = 0;

	/*
	 * Do nothing if the mask is already initialized.
	 */
	mask = *cpumask;
	if (mask)
		return 0;
	/*
	 * Create the CPU mask.
	 */
	err = calloc_cpumask(cpumask);
	if (!err)
		mask = *cpumask;
	if (!mask)
		err = -ENOMEM;

	return err;
}

SEC("syscall")
int enable_sibling_cpu(struct domain_arg *input)
{
	struct cpu_ctx *cctx;
	struct bpf_cpumask *mask, **pmask;
	int err = 0;

	cctx = try_lookup_cpu_ctx(input->cpu_id);
	if (!cctx)
		return -ENOENT;

	/* Make sure the target CPU mask is initialized */
	switch (input->lvl_id) {
	case 2:
		pmask = &cctx->l2_cpumask;
		break;
	case 3:
		pmask = &cctx->l3_cpumask;
		break;
	default:
		return -EINVAL;
	}
	err = init_cpumask(pmask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = *pmask;
	if (mask)
		bpf_cpumask_set_cpu(input->sibling_cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

/*
 * Initialize the scheduling class.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(goland_init)
{
	int err;

	/* Compile-time checks */
	BUILD_BUG_ON((MAX_CPUS % 2));

	/* Initialize maximum possible CPU number */
	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/* Initialize goland core */
	err = dsq_init();
	if (err)
		return err;

	/*
	 * In user-space mode, initialize the heartbeat timer to periodically
	 * wake up the user-space scheduler. In kernel mode, this is not needed.
	 */
	if (!kernel_mode) {
		err = usersched_timer_init();
		if (err)
			return err;
	}

	return 0;
}

/*
 * A task is being destroyed.
 *
 * Clean up the task from priority tasks map.
 */
void BPF_STRUCT_OPS(goland_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	/* Remove task from priority tasks map */
	update_priority_task_map(p->pid, 1, 0);
}

/*
 * Unregister the scheduling class.
 */
void BPF_STRUCT_OPS(goland_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * A CPU is about to change its idle state. If the CPU is going idle, ensure
 * that the user-space scheduler has a chance to run if there is any remaining
 * work to do.
 */
void BPF_STRUCT_OPS(goland_update_idle, s32 cpu, bool idle)
{
	/*
	 * In kernel mode, there's no user-space scheduler to notify.
	 */
	if (kernel_mode)
		return;

	/*
	 * Don't do anything if we exit from and idle state, a CPU owner will
	 * be assigned in .running().
	 */
	if (!idle)
		return;
	/*
	 * A CPU is now available, notify the user-space scheduler that tasks
	 * can be dispatched, if there is at least one task waiting to be
	 * scheduled, either queued (accounted in nr_queued) or scheduled
	 * (accounted in nr_scheduled).
	 *
	 * NOTE: nr_queued is incremented by the BPF component, more exactly in
	 * enqueue(), when a task is sent to the user-space scheduler, then
	 * the scheduler drains the queued tasks (updating nr_queued) and adds
	 * them to its internal data structures / state; at this point tasks
	 * become "scheduled" and the user-space scheduler will take care of
	 * updating nr_scheduled accordingly; lastly tasks will be dispatched
	 * and the user-space scheduler will update nr_scheduled again.
	 *
	 * Checking both counters allows to determine if there is still some
	 * pending work to do for the scheduler: new tasks have been queued
	 * since last check, or there are still tasks "queued" or "scheduled"
	 * since the previous user-space scheduler run. If the counters are
	 * both zero it is pointless to wake-up the scheduler (even if a CPU
	 * becomes idle), because there is nothing to do.
	 *
	 * Keep in mind that update_idle() doesn't run concurrently with the
	 * user-space scheduler (that is single-threaded): this function is
	 * naturally serialized with the user-space scheduler code, therefore
	 * this check here is also safe from a concurrency perspective.
	 */
	if (nr_queued || nr_scheduled) {
		/*
		 * Notify that user-space scheduler should run and kick this CPU
		 * to make it immediately ready to accept dispatched tasks.
		 */
		set_usersched_needed();
		scx_bpf_kick_cpu(cpu, 0);
	}
}

void BPF_STRUCT_OPS(goland_tick, struct task_struct *p)
{
	if (max_time_watchdog && (kernel_mode || !is_usersched_task(p))) {
		struct task_ctx *tctx = try_lookup_task_ctx(p);
		if (!tctx)
			return;
		u64 now = scx_bpf_now();
		u64 run_time = now - tctx->start_ts;
		if (unlikely(run_time > THRESHOLD)) {
			scx_bpf_kick_cpu(bpf_get_smp_processor_id(), SCX_KICK_PREEMPT);
			bpf_printk("pid: %d exceed the threshold", p->pid);
		}
	}
}
/*
 * Scheduling class declaration.
 */
SCX_OPS_DEFINE(goland,
	       .select_cpu		= (void *)goland_select_cpu,
	       .enqueue			= (void *)goland_enqueue,
	       .dispatch		= (void *)goland_dispatch,
		   .tick            = (void *)goland_tick,
		   .update_idle		= (void *)goland_update_idle,
	       .runnable		= (void *)goland_runnable,
	       .running			= (void *)goland_running,
	       .stopping		= (void *)goland_stopping,
	       .enable			= (void *)goland_enable,
	       .init_task		= (void *)goland_init_task,
	       .exit_task		= (void *)goland_exit_task,
	       .init			= (void *)goland_init,
	       .exit			= (void *)goland_exit,
	       .timeout_ms		= 5000,
	       .dispatch_max_batch	= MAX_DISPATCH_SLOT,
		   .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "goland");