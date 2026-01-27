// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

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
	return C.open_skel()
}

func GetUserSchedPid() int {
	return int(C.get_usersched_pid())
}

func GetNrQueued() uint64 {
	return uint64(C.get_nr_queued())
}
func GetNrScheduled() uint64 {
	return uint64(C.get_nr_scheduled())
}

func NotifyComplete(nr_pending uint64) error {
	C.notify_complete(C.u64(nr_pending))
	return nil
}

func (s *Sched) SubNrQueued() error {
	C.sub_nr_queued()
	return nil
}

func (s *Sched) DecNrQueued(num uint64) error {
	C.dec_nr_queued(C.u64(num))
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
