// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/Gthulhu/plugin/models"
	"golang.org/x/sys/unix"
)

func (s *Sched) BlockTilReadyForDequeue(ctx context.Context) {
	if s.directQueue {
		if ctx.Err() == nil && !s.queuedReady && s.queuedErr == nil {
			s.queuedErr = s.YieldScheduler()
		}
		return
	}
	for {
		select {
		case t, ok := <-s.queue:
			if !ok {
				runtime.Gosched()
				continue
			}
			s.queue <- t
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *Sched) QueuedError() error { return s.queuedErr }

func (s *Sched) YieldScheduler() error {
	_, _, errno := unix.Syscall(unix.SYS_SCHED_YIELD, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("yield scheduler thread: %w", errno)
	}
	return nil
}

func (s *Sched) ReadyForDequeue() bool {
	if s.directQueue {
		if !s.queuedReady {
			s.dequeueDirect(&s.queuedNext)
			s.queuedReady = s.queuedNext.Pid != -1
		}
		return s.queuedReady
	}
	select {
	case t, ok := <-s.queue:
		if !ok {
			return false
		}
		s.queue <- t
		return true
	default:
		return false
	}
}

func (s *Sched) DequeueTask(task *models.QueuedTask) {
	if s.directQueue {
		if s.queuedReady {
			*task = s.queuedNext
			s.queuedReady = false
		} else {
			s.dequeueDirect(task)
		}
		return
	}
	select {
	case t := <-s.queue:
		err := fastDecode(t, task)
		if err != nil {
			task.Pid = -1
			return
		}
		return
	default:
		task.Pid = -1
		return
	}
}

// Task queued for dispatching to the BPF component (see bpf_intf::dispatched_task_ctx).
type DispatchedTask struct {
	Pid        int32  // pid that uniquely identifies a task
	Cpu        int32  // target CPU selected by the scheduler
	Flags      uint64 // special dispatch flags
	SliceNs    uint64 // time slice assigned to the task (0 = default)
	Vtime      uint64 // task deadline / vruntime
	CpuMaskCnt uint64 // cpumask generation counter (private)
}

// NewDispatchedTask creates a DispatchedTask from a QueuedTask.
func NewDispatchedTask(task *models.QueuedTask) *DispatchedTask {
	return &DispatchedTask{
		Pid:     task.Pid,
		Cpu:     task.Cpu,
		Flags:   task.Flags,
		SliceNs: 0, // use default time slice
		Vtime:   0,
	}
}

func (s *Sched) DispatchTask(t *DispatchedTask) error {
	return s.dispatchTask(t)
}

func fastDecode(data []byte, task *models.QueuedTask) error {
	if len(data) < int(unsafe.Sizeof(models.QueuedTask{})) {
		return fmt.Errorf("data length is less than QueuedTask size")
	}
	task.Pid = int32(binary.LittleEndian.Uint32(data[0:4]))
	task.Cpu = int32(binary.LittleEndian.Uint32(data[4:8]))
	task.NrCpusAllowed = binary.LittleEndian.Uint64(data[8:16])
	task.Flags = binary.LittleEndian.Uint64(data[16:24])
	task.StartTs = binary.LittleEndian.Uint64(data[24:32])
	task.StopTs = binary.LittleEndian.Uint64(data[32:40])
	task.SumExecRuntime = binary.LittleEndian.Uint64(data[40:48])
	task.Weight = binary.LittleEndian.Uint64(data[48:56])
	task.Vtime = binary.LittleEndian.Uint64(data[56:64])
	task.Tgid = int32(binary.LittleEndian.Uint32(data[64:68]))

	return nil
}

func encodeDispatch(data []byte, t *DispatchedTask) {
	binary.LittleEndian.PutUint32(data[0:4], uint32(t.Pid))
	binary.LittleEndian.PutUint32(data[4:8], uint32(t.Cpu))
	binary.LittleEndian.PutUint64(data[8:16], t.Flags)
	binary.LittleEndian.PutUint64(data[16:24], t.SliceNs)
	binary.LittleEndian.PutUint64(data[24:32], t.Vtime)
	binary.LittleEndian.PutUint64(data[32:40], t.CpuMaskCnt)

}

func IsSMTActive() (bool, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/smt/active")
	if err != nil {
		return false, err
	}

	contents := strings.TrimSpace(string(data))
	smtActive, err := strconv.Atoi(contents)
	if err != nil {
		return false, err
	}

	return smtActive == 1, nil
}
