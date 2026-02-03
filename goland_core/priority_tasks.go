// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package core

/*
#include "wrapper.h"
*/
import "C"

import (
	"fmt"
)

// Priority level constants
const (
	// PrioHighMin is the minimum (highest) priority for preemptive tasks
	PrioHighMin = 0
	// PrioHighMax is the maximum priority for preemptive tasks (0-9 can preempt)
	PrioHighMax = 9
	// PrioMedMin is the minimum priority for vtime-reduced tasks
	PrioMedMin = 10
	// PrioMedMax is the maximum priority for vtime-reduced tasks
	PrioMedMax = 20
)

// UpdatePriorityTask adds or updates a task in the priority_tasks BPF map.
// When a task is in this map, it will be prioritized during scheduling.
// This function uses the default highest priority (0).
// pid: the process ID of the task
// slice: the time slice to assign to this priority task (in nanoseconds)
func (s *Sched) UpdatePriorityTask(pid uint32, slice uint64) error {
	ret := C.update_priority_task(C.u32(pid), C.u64(slice))
	if ret != 0 {
		return fmt.Errorf("failed to update priority task: pid=%d, ret=%d", pid, ret)
	}
	return nil
}

// UpdatePriorityTaskWithPrio adds or updates a task in the priority_tasks BPF map
// with a specific priority level.
//
// Priority levels:
//   - 0-9:   High priority - can preempt tasks with lower priority (higher number)
//   - 10-20: Medium priority - gets vtime reduction but no preemption.
//     Priority 10 gets 50% vtime reduction, priority 20 gets 5% reduction.
//
// pid: the process ID of the task
// slice: the time slice to assign to this priority task (in nanoseconds)
// prio: priority level (0-20), where lower is higher priority
func (s *Sched) UpdatePriorityTaskWithPrio(pid uint32, slice uint64, prio uint32) error {
	if prio > PrioMedMax {
		return fmt.Errorf("invalid priority level: %d (must be 0-%d)", prio, PrioMedMax)
	}
	ret := C.update_priority_task_with_prio(C.u32(pid), C.u64(slice), C.u32(prio))
	if ret != 0 {
		return fmt.Errorf("failed to update priority task with prio: pid=%d, prio=%d, ret=%d", pid, prio, ret)
	}
	return nil
}

// RemovePriorityTask removes a task from the priority_tasks BPF map.
// After removal, the task will no longer be treated as a priority task.
// pid: the process ID of the task to remove
func (s *Sched) RemovePriorityTask(pid uint32) error {
	ret := C.remove_priority_task(C.u32(pid))
	if ret != 0 {
		return fmt.Errorf("failed to remove priority task: pid=%d, ret=%d", pid, ret)
	}
	return nil
}
