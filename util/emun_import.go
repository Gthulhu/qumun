// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package util

/*
#include "wrapper.h"
*/
import "C"
import (
	"fmt"
)

func defaultScxEnums() *ScxEnums {
	return &ScxEnums{
		SCX_OPS_NAME_LEN:           128,
		SCX_SLICE_DFL:              20000000,
		SCX_SLICE_INF:              18446744073709551615,
		SCX_RQ_ONLINE:              1,
		SCX_RQ_CAN_STOP_TICK:       2,
		SCX_RQ_BAL_PENDING:         4,
		SCX_RQ_BAL_KEEP:            8,
		SCX_RQ_BYPASSING:           16,
		SCX_RQ_CLK_VALID:           32,
		SCX_RQ_IN_WAKEUP:           65536,
		SCX_RQ_IN_BALANCE:          131072,
		SCX_DSQ_FLAG_BUILTIN:       9223372036854775808,
		SCX_DSQ_FLAG_LOCAL_ON:      4611686018427387904,
		SCX_DSQ_INVALID:            9223372036854775808,
		SCX_DSQ_GLOBAL:             9223372036854775809,
		SCX_DSQ_LOCAL:              9223372036854775810,
		SCX_DSQ_LOCAL_ON:           13835058055282163712,
		SCX_DSQ_LOCAL_CPU_MASK:     4294967295,
		SCX_TASK_QUEUED:            1,
		SCX_TASK_RESET_RUNNABLE_AT: 4,
		SCX_TASK_DEQD_FOR_SLEEP:    8,
		SCX_TASK_STATE_SHIFT:       8,
		SCX_TASK_STATE_BITS:        2,
		SCX_TASK_STATE_MASK:        768,
		SCX_TASK_CURSOR:            18446744071562067968, // -2147483648 as uint64
		SCX_TASK_NONE:              0,
		SCX_TASK_INIT:              1,
		SCX_TASK_READY:             2,
		SCX_TASK_ENABLED:           3,
		SCX_TASK_NR_STATES:         4,
		SCX_TASK_DSQ_ON_PRIQ:       1,
		SCX_KICK_IDLE:              1,
		SCX_KICK_PREEMPT:           2,
		SCX_KICK_WAIT:              4,
		SCX_ENQ_WAKEUP:             1,
		SCX_ENQ_HEAD:               16,
		SCX_ENQ_PREEMPT:            4294967296,
		SCX_ENQ_REENQ:              1099511627776,
		SCX_ENQ_LAST:               2199023255552,
		SCX_ENQ_CLEAR_OPSS:         72057594037927936,
		SCX_ENQ_DSQ_PRIQ:           144115188075855872,
	}
}

func ImportScxEnums() error {
	e, err := GetScxEnums()
	if err != nil {
		e = defaultScxEnums()
	}
	if e == nil {
		return fmt.Errorf("ScxEnums instance is nil")
	}
	C.set_scx_enums(
		(C.u64)(e.SCX_OPS_NAME_LEN),
		(C.u64)(e.SCX_SLICE_DFL),
		(C.u64)(e.SCX_SLICE_INF),
		(C.u64)(e.SCX_RQ_ONLINE),
		(C.u64)(e.SCX_RQ_CAN_STOP_TICK),
		(C.u64)(e.SCX_RQ_BAL_PENDING),
		(C.u64)(e.SCX_RQ_BAL_KEEP),
		(C.u64)(e.SCX_RQ_BYPASSING),
		(C.u64)(e.SCX_RQ_CLK_VALID),
		(C.u64)(e.SCX_RQ_IN_WAKEUP),
		(C.u64)(e.SCX_RQ_IN_BALANCE),
		(C.u64)(e.SCX_DSQ_FLAG_BUILTIN),
		(C.u64)(e.SCX_DSQ_FLAG_LOCAL_ON),
		(C.u64)(e.SCX_DSQ_INVALID),
		(C.u64)(e.SCX_DSQ_GLOBAL),
		(C.u64)(e.SCX_DSQ_LOCAL),
		(C.u64)(e.SCX_DSQ_LOCAL_ON),
		(C.u64)(e.SCX_DSQ_LOCAL_CPU_MASK),
		(C.u64)(e.SCX_TASK_QUEUED),
		(C.u64)(e.SCX_TASK_RESET_RUNNABLE_AT),
		(C.u64)(e.SCX_TASK_DEQD_FOR_SLEEP),
		(C.u64)(e.SCX_TASK_STATE_SHIFT),
		(C.u64)(e.SCX_TASK_STATE_BITS),
		(C.u64)(e.SCX_TASK_STATE_MASK),
		(C.u64)(e.SCX_TASK_CURSOR),
		(C.u64)(e.SCX_TASK_NONE),
		(C.u64)(e.SCX_TASK_INIT),
		(C.u64)(e.SCX_TASK_READY),
		(C.u64)(e.SCX_TASK_ENABLED),
		(C.u64)(e.SCX_TASK_NR_STATES),
		(C.u64)(e.SCX_TASK_DSQ_ON_PRIQ),
		(C.u64)(e.SCX_KICK_IDLE),
		(C.u64)(e.SCX_KICK_PREEMPT),
		(C.u64)(e.SCX_KICK_WAIT),
		(C.u64)(e.SCX_ENQ_WAKEUP),
		(C.u64)(e.SCX_ENQ_HEAD),
		(C.u64)(e.SCX_ENQ_PREEMPT),
		(C.u64)(e.SCX_ENQ_REENQ),
		(C.u64)(e.SCX_ENQ_LAST),
		(C.u64)(e.SCX_ENQ_CLEAR_OPSS),
		(C.u64)(e.SCX_ENQ_DSQ_PRIQ),
	)
	return nil
}
