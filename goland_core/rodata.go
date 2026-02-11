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
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type RodataMap struct {
	*bpf.BPFMap
}

type Rodata struct {
	DefaultSlice           uint64   `json:"default_slice"`
	SmtEnabled             bool     `json:"smt_enabled"`
	Debug                  bool     `json:"debug"`
	Pad0                   [54]byte `json:"-"` // __pad0[54]
	SCXOpsNameLen          uint64   `json:"scx_ops_name_len"`
	SCXSliceDfl            uint64   `json:"scx_slice_dfl"`
	SCXSliceInf            uint64   `json:"scx_slice_inf"`
	SCXRqOnline            uint64   `json:"scx_rq_online"`
	SCXRqCanStopTick       uint64   `json:"scx_rq_can_stop_tick"`
	SCXRqBalPending        uint64   `json:"scx_rq_bal_pending"`
	SCXRqBalKeep           uint64   `json:"scx_rq_bal_keep"`
	SCXRqBypassing         uint64   `json:"scx_rq_bypassing"`
	SCXRqClkValid          uint64   `json:"scx_rq_clk_valid"`
	SCXRqInWakeup          uint64   `json:"scx_rq_in_wakeup"`
	SCXRqInBalance         uint64   `json:"scx_rq_in_balance"`
	SCXDsqFlagBuiltin      uint64   `json:"scx_dsq_flag_builtin"`
	SCXDsqFlagLocalOn      uint64   `json:"scx_dsq_flag_local_on"`
	SCXDsqInvalid          uint64   `json:"scx_dsq_invalid"`
	SCXDsqGlobal           uint64   `json:"scx_dsq_global"`
	SCXDsqLocal            uint64   `json:"scx_dsq_local"`
	SCXDsqLocalOn          uint64   `json:"scx_dsq_local_on"`
	SCXDsqLocalCpuMask     uint64   `json:"scx_dsq_local_cpu_mask"`
	SCXTaskQueued          uint64   `json:"scx_task_queued"`
	SCXTaskResetRunnableAt uint64   `json:"scx_task_reset_runnable_at"`
	SCXTaskDeqdForSleep    uint64   `json:"scx_task_deqd_for_sleep"`
	SCXTaskStateShift      uint64   `json:"scx_task_state_shift"`
	SCXTaskStateBits       uint64   `json:"scx_task_state_bits"`
	SCXTaskStateMask       uint64   `json:"scx_task_state_mask"`
	SCXTaskCursor          uint64   `json:"scx_task_cursor"`
	SCXTaskNone            uint64   `json:"scx_task_none"`
	SCXTaskInit            uint64   `json:"scx_task_init"`
	SCXTaskReady           uint64   `json:"scx_task_ready"`
	SCXTaskEnabled         uint64   `json:"scx_task_enabled"`
	SCXTaskNrStates        uint64   `json:"scx_task_nr_states"`
	SCXTaskDsqOnPriq       uint64   `json:"scx_task_dsq_on_priq"`
	SCXKickIdle            uint64   `json:"scx_kick_idle"`
	SCXKickPreempt         uint64   `json:"scx_kick_preempt"`
	SCXKickWait            uint64   `json:"scx_kick_wait"`
	SCXEnqWakeup           uint64   `json:"scx_enq_wakeup"`
	SCXEnqHead             uint64   `json:"scx_enq_head"`
	SCXEnqPreempt          uint64   `json:"scx_enq_preempt"`
	SCXEnqReenq            uint64   `json:"scx_enq_reenq"`
	SCXEnqLast             uint64   `json:"scx_enq_last"`
	SCXEnqClearOpss        uint64   `json:"scx_enq_clear_opss"`
	SCXEnqDsqPriq          uint64   `json:"scx_enq_dsq_priq"`
	UeiDumpLen             uint32   `json:"uei_dump_len"`
	UserschedPid           uint32   `json:"usersched_pid"`
	KhugepagePid           uint32   `json:"khugepage_pid"`
	SwitchPartial          bool     `json:"switch_partial"`
	EarlyProcessing        bool     `json:"early_processing"`
	BuiltinIdle            bool     `json:"builtin_idle"`
}

func (s *Sched) GetRoData() (Rodata, error) {
	if s.rodata == nil {
		return Rodata{}, fmt.Errorf("BssMap is nil")
	}
	i := 0
	b, err := s.rodata.BPFMap.GetValue(unsafe.Pointer(&i))
	if err != nil {
		return Rodata{}, err
	}
	var ro Rodata
	buff := bytes.NewBuffer(b)
	err = binary.Read(buff, binary.LittleEndian, &ro)
	if err != nil {
		return Rodata{}, err
	}
	return ro, nil
}

func (s *Sched) AssignUserSchedPid(pid int) error {
	C.set_kugepagepid(C.u32(KhugepagePid()))
	C.set_usersched_pid(C.u32(pid))
	return nil
}

func (s *Sched) SetDebug(enabled bool) {
	C.set_debug(C.bool(enabled))
}

func (s *Sched) SetBuiltinIdle(enabled bool) {
	C.set_builtin_idle(C.bool(enabled))
}

func (s *Sched) EnableKernelMode() {
	C.enable_kernel_mode()
}

func (s *Sched) DisableMaxTimeWatchdog() {
	C.disable_max_time_watchdog()
}

func (s *Sched) SetEarlyProcessing(enabled bool) {
	C.set_early_processing(C.bool(enabled))
}

func (s *Sched) SetDefaultSlice(t uint64) {
	C.set_default_slice(C.u64(t))
}

// KhugepagePid finds and returns the PID of the khugepaged process
func KhugepagePid() uint32 {
	procDir := "/proc"

	// Read all entries in /proc
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		// Skip non-directories and non-numeric directories
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		// Check if directory name is numeric (PID)
		if _, err := strconv.Atoi(pidStr); err != nil {
			continue
		}

		// Read the comm file to get process name
		commPath := filepath.Join(procDir, pidStr, "comm")
		commData, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		comm := strings.TrimSpace(string(commData))
		if comm != "khugepaged" {
			continue
		}

		// Check if exe symlink exists (should not exist for kernel threads like khugepaged)
		exePath := filepath.Join(procDir, pidStr, "exe")
		if _, err := os.Readlink(exePath); err == nil {
			// exe symlink exists, this is not a kernel thread
			continue
		}

		// Convert PID string to uint32
		if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			return uint32(pid)
		}
	}

	return 0
}
