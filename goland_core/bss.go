// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"unsafe"

	"github.com/Gthulhu/qumun/internal/schedbridge"
	bpf "github.com/aquasecurity/libbpfgo"
)

/*
#include "wrapper.h"
*/
import "C"

type BssData struct {
	Nr_running            uint64 `json:"nr_running"`            // Number of tasks currently running in the userspace scheduler
	Nr_queued             uint64 `json:"nr_queued"`             // Number of tasks queued in the userspace scheduler
	Nr_scheduled          uint64 `json:"nr_scheduled"`          // Number of tasks scheduled by the userspace scheduler
	Nr_online_cpus        uint64 `json:"nr_online_cpus"`        // Number of online CPUs in the system
	Usersched_last_run_at uint64 `json:"usersched_last_run_at"` // The PID of the userspace scheduler
	Nr_user_dispatches    uint64 `json:"nr_user_dispatches"`    // Number of user-space dispatches
	Nr_kernel_dispatches  uint64 `json:"nr_kernel_dispatches"`  // Number of kernel-space dispatches
	Nr_cancel_dispatches  uint64 `json:"nr_cancel_dispatches"`  // Number of cancelled dispatches
	Nr_bounce_dispatches  uint64 `json:"nr_bounce_dispatches"`  // Number of bounce dispatches
	Nr_failed_dispatches  uint64 `json:"nr_failed_dispatches"`  // Number of failed dispatches
	Nr_sched_congested    uint64 `json:"nr_sched_congested"`    // Number of times the scheduler was congested
}

func (data BssData) String() string {
	return fmt.Sprintf("Usersched_last_run_at: %v, Nr_queued: %v ", data.Usersched_last_run_at, data.Nr_queued) +
		fmt.Sprintf("Nr_scheduled: %v, Nr_running: %v ", data.Nr_scheduled, data.Nr_running) +
		fmt.Sprintf("Nr_online_cpus: %v, Nr_user_dispatches: %v ", data.Nr_online_cpus, data.Nr_user_dispatches) +
		fmt.Sprintf("Nr_kernel_dispatches: %v, Nr_cancel_dispatches: %v ", data.Nr_kernel_dispatches, data.Nr_cancel_dispatches) +
		fmt.Sprintf("Nr_bounce_dispatches: %v, Nr_failed_dispatches: %v", data.Nr_bounce_dispatches, data.Nr_failed_dispatches) +
		fmt.Sprintf("Nr_sched_congested: %v", data.Nr_sched_congested)
}

func LoadSkel() unsafe.Pointer {
	obj := C.open_skel()
	initCounterPointers()
	return obj
}

var nrQueued, nrScheduled *uint64

// SetUserSchedLoopTid enables experimental wakeup preemption for the pinned loop.
// Call after locking the scheduling goroutine to its OS thread.
func (s *Sched) SetUserSchedLoopTid(tid uint32) {
	schedbridge.StoreUint32(unsafe.Pointer(&C.global_obj.bss.usersched_loop_tid), tid)
}

func initCounterPointers() {
	nrQueued = (*uint64)(unsafe.Pointer(&C.global_obj.bss.nr_queued))
	nrScheduled = (*uint64)(unsafe.Pointer(&C.global_obj.bss.nr_scheduled))
}

func GetUserSchedPid() int {
	return int(schedbridge.LoadUint32(unsafe.Pointer(&C.global_obj.rodata.usersched_pid)))
}

func (s *Sched) GetNrQueued() uint64 {
	return atomic.LoadUint64(nrQueued)
}

func (s *Sched) GetNrScheduled() uint64 {
	return atomic.LoadUint64(nrScheduled)
}

func NotifyComplete(nr_pending uint64) error {
	schedbridge.StoreUint64(unsafe.Pointer(nrScheduled), nr_pending)
	return nil
}

func (s *Sched) SubNrQueued() error {
	schedbridge.SubUint64(unsafe.Pointer(nrQueued), 1)
	return nil
}

func (s *Sched) DecNrQueued(num uint64) error {
	schedbridge.SubUint64(unsafe.Pointer(nrQueued), num)
	return nil
}

type BssMap struct {
	*bpf.BPFMap
}

func (s *Sched) GetBssData() (BssData, error) {
	if s.bss == nil {
		return BssData{}, fmt.Errorf("BssMap is nil")
	}
	i := 0
	b, err := s.bss.BPFMap.GetValue(unsafe.Pointer(&i))
	if err != nil {
		return BssData{}, err
	}
	var bss BssData
	buff := bytes.NewBuffer(b)
	err = binary.Read(buff, binary.LittleEndian, &bss)
	if err != nil {
		return BssData{}, err
	}
	return bss, nil
}
