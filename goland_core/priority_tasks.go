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

// UpdatePriorityTask adds or updates a task in the priority_tasks BPF map.
// When a task is in this map, it will be prioritized during scheduling.
// pid: the process ID of the task
// slice: the time slice to assign to this priority task (in nanoseconds)
func (s *Sched) UpdatePriorityTask(pid uint32, slice uint64) error {
	ret := C.update_priority_task(C.u32(pid), C.u64(slice))
	if ret != 0 {
		return fmt.Errorf("failed to update priority task: pid=%d, ret=%d", pid, ret)
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
