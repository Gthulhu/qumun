// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

#ifndef WRAPPER_H__
#define WRAPPER_H__
typedef unsigned int __u32;

typedef __u32 u32;

typedef signed char __s8;

typedef unsigned char __u8;

typedef short unsigned int __u16;

typedef int __s32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __u16 u16;

typedef __s32 s32;

typedef __s64 s64;

typedef __u64 u64;

enum uei_sizes {
	UEI_REASON_LEN		= 128,
	UEI_MSG_LEN		= 1024,
	UEI_DUMP_DFL_LEN	= 32768,
};

struct user_exit_info {
	int		kind;
	s64		exit_code;
	char	reason[UEI_REASON_LEN];
	char	msg[UEI_MSG_LEN];
};
#include "main.skeleton.h"

void *open_skel();

u32 get_usersched_pid();

void set_usersched_pid(u32 id);

void set_kugepagepid(u32 id);

void set_debug(bool enabled);

void set_builtin_idle(bool enabled);

void enable_kernel_mode();

void set_early_processing(bool enabled);

void set_default_slice(u64 t);

u64 get_nr_scheduled();

u64 get_nr_queued();

void notify_complete(u64 nr_pending);

void sub_nr_queued();

void dec_nr_queued(u64 num);

void destroy_skel(void *);

int update_priority_task(u32 pid, u64 slice);

int remove_priority_task(u32 pid);

void set_scx_enums(
	u64 SCX_OPS_NAME_LEN,
	u64 SCX_SLICE_DFL,
	u64 SCX_SLICE_INF,
	u64 SCX_RQ_ONLINE,
	u64 SCX_RQ_CAN_STOP_TICK,
	u64 SCX_RQ_BAL_PENDING,
	u64 SCX_RQ_BAL_KEEP,
	u64 SCX_RQ_BYPASSING,
	u64 SCX_RQ_CLK_VALID,
	u64 SCX_RQ_IN_WAKEUP,
	u64 SCX_RQ_IN_BALANCE,
	u64 SCX_DSQ_FLAG_BUILTIN,
	u64 SCX_DSQ_FLAG_LOCAL_ON,
	u64 SCX_DSQ_INVALID,
	u64 SCX_DSQ_GLOBAL,
	u64 SCX_DSQ_LOCAL,
	u64 SCX_DSQ_LOCAL_ON,
	u64 SCX_DSQ_LOCAL_CPU_MASK,
	u64 SCX_TASK_QUEUED,
	u64 SCX_TASK_RESET_RUNNABLE_AT,
	u64 SCX_TASK_DEQD_FOR_SLEEP,
	u64 SCX_TASK_STATE_SHIFT,
	u64 SCX_TASK_STATE_BITS,
	u64 SCX_TASK_STATE_MASK,
	u64 SCX_TASK_CURSOR,
	u64 SCX_TASK_NONE,
	u64 SCX_TASK_INIT,
	u64 SCX_TASK_READY,
	u64 SCX_TASK_ENABLED,
	u64 SCX_TASK_NR_STATES,
	u64 SCX_TASK_DSQ_ON_PRIQ,
	u64 SCX_KICK_IDLE,
	u64 SCX_KICK_PREEMPT,
	u64 SCX_KICK_WAIT,
	u64 SCX_ENQ_WAKEUP,
	u64 SCX_ENQ_HEAD,
	u64 SCX_ENQ_PREEMPT,
	u64 SCX_ENQ_REENQ,
	u64 SCX_ENQ_LAST,
	u64 SCX_ENQ_CLEAR_OPSS,
	u64 SCX_ENQ_DSQ_PRIQ
);

#endif