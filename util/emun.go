// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package util

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// ScxEnums mirrors the Rust Enums struct, holding values read from BTF enums
// in vmlinux. Missing symbols are left as zero.
type ScxEnums struct {
	SCX_OPS_NAME_LEN           uint64
	SCX_SLICE_DFL              uint64
	SCX_SLICE_INF              uint64
	SCX_RQ_ONLINE              uint64
	SCX_RQ_CAN_STOP_TICK       uint64
	SCX_RQ_BAL_PENDING         uint64
	SCX_RQ_BAL_KEEP            uint64
	SCX_RQ_BYPASSING           uint64
	SCX_RQ_CLK_VALID           uint64
	SCX_RQ_IN_WAKEUP           uint64
	SCX_RQ_IN_BALANCE          uint64
	SCX_DSQ_FLAG_BUILTIN       uint64
	SCX_DSQ_FLAG_LOCAL_ON      uint64
	SCX_DSQ_INVALID            uint64
	SCX_DSQ_GLOBAL             uint64
	SCX_DSQ_LOCAL              uint64
	SCX_DSQ_LOCAL_ON           uint64
	SCX_DSQ_LOCAL_CPU_MASK     uint64
	SCX_TASK_QUEUED            uint64
	SCX_TASK_RESET_RUNNABLE_AT uint64
	SCX_TASK_DEQD_FOR_SLEEP    uint64
	SCX_TASK_STATE_SHIFT       uint64
	SCX_TASK_STATE_BITS        uint64
	SCX_TASK_STATE_MASK        uint64
	SCX_TASK_CURSOR            uint64
	SCX_TASK_NONE              uint64
	SCX_TASK_INIT              uint64
	SCX_TASK_READY             uint64
	SCX_TASK_ENABLED           uint64
	SCX_TASK_NR_STATES         uint64
	SCX_TASK_DSQ_ON_PRIQ       uint64
	SCX_KICK_IDLE              uint64
	SCX_KICK_PREEMPT           uint64
	SCX_KICK_WAIT              uint64
	SCX_ENQ_WAKEUP             uint64
	SCX_ENQ_HEAD               uint64
	SCX_ENQ_PREEMPT            uint64
	SCX_ENQ_REENQ              uint64
	SCX_ENQ_LAST               uint64
	SCX_ENQ_CLEAR_OPSS         uint64
	SCX_ENQ_DSQ_PRIQ           uint64
}

var (
	loadOnce  sync.Once
	enumsInst *ScxEnums
	loadErr   error
)

// VmlinuxBTFPathEnv allows overriding the BTF vmlinux path.
const VmlinuxBTFPathEnv = "QUMUN_VMLINUX_BTF"

// Default vmlinux BTF path.
const defaultVmlinuxBTF = "/sys/kernel/btf/vmlinux"

// GetScxEnums returns the loaded enumeration values, performing a lazy load on first call.
func GetScxEnums() (*ScxEnums, error) {
	loadOnce.Do(func() {
		enumsInst, loadErr = loadFromBTF()
	})
	return enumsInst, loadErr
}

// loadFromBTF performs the actual parsing of BTF enums from vmlinux.
func loadFromBTF() (*ScxEnums, error) {
	path := os.Getenv(VmlinuxBTFPathEnv)
	if path == "" {
		path = defaultVmlinuxBTF
	}
	spec, err := btf.LoadSpec(path)
	if err != nil {
		return nil, fmt.Errorf("load BTF spec from %s: %w", path, err)
	}

	enumCache := map[string]*btf.Enum{}
	// Build a lookup map for required enum type names.
	needed := map[string]struct{}{
		"scx_public_consts": {},
		"scx_rq_flags":      {},
		"scx_dsq_id_flags":  {},
		"scx_ent_flags":     {},
		"scx_task_state":    {},
		"scx_ent_dsq_flags": {},
		"scx_kick_flags":    {},
		"scx_enq_flags":     {},
	}

	for t, err := range spec.All() {
		if err != nil {
			return nil, fmt.Errorf("iterate BTF types: %w", err)
		}
		if e, ok := t.(*btf.Enum); ok {
			if _, wanted := needed[e.Name]; wanted {
				enumCache[e.Name] = e
			}
		}
	}
	if len(enumCache) == 0 {
		return nil, errors.New("no required SCX enum types found in BTF")
	}

	read := func(enumType, name string) uint64 {
		e := enumCache[enumType]
		if e == nil {
			return 0
		}
		for _, v := range e.Values {
			if v.Name == name {
				return uint64(v.Value)
			}
		}
		return 0
	}

	scx := &ScxEnums{
		SCX_OPS_NAME_LEN:           read("scx_public_consts", "SCX_OPS_NAME_LEN"),
		SCX_SLICE_DFL:              read("scx_public_consts", "SCX_SLICE_DFL"),
		SCX_SLICE_INF:              read("scx_public_consts", "SCX_SLICE_INF"),
		SCX_RQ_ONLINE:              read("scx_rq_flags", "SCX_RQ_ONLINE"),
		SCX_RQ_CAN_STOP_TICK:       read("scx_rq_flags", "SCX_RQ_CAN_STOP_TICK"),
		SCX_RQ_BAL_PENDING:         read("scx_rq_flags", "SCX_RQ_BAL_PENDING"),
		SCX_RQ_BAL_KEEP:            read("scx_rq_flags", "SCX_RQ_BAL_KEEP"),
		SCX_RQ_BYPASSING:           read("scx_rq_flags", "SCX_RQ_BYPASSING"),
		SCX_RQ_CLK_VALID:           read("scx_rq_flags", "SCX_RQ_CLK_VALID"),
		SCX_RQ_IN_WAKEUP:           read("scx_rq_flags", "SCX_RQ_IN_WAKEUP"),
		SCX_RQ_IN_BALANCE:          read("scx_rq_flags", "SCX_RQ_IN_BALANCE"),
		SCX_DSQ_FLAG_BUILTIN:       read("scx_dsq_id_flags", "SCX_DSQ_FLAG_BUILTIN"),
		SCX_DSQ_FLAG_LOCAL_ON:      read("scx_dsq_id_flags", "SCX_DSQ_FLAG_LOCAL_ON"),
		SCX_DSQ_INVALID:            read("scx_dsq_id_flags", "SCX_DSQ_INVALID"),
		SCX_DSQ_GLOBAL:             read("scx_dsq_id_flags", "SCX_DSQ_GLOBAL"),
		SCX_DSQ_LOCAL:              read("scx_dsq_id_flags", "SCX_DSQ_LOCAL"),
		SCX_DSQ_LOCAL_ON:           read("scx_dsq_id_flags", "SCX_DSQ_LOCAL_ON"),
		SCX_DSQ_LOCAL_CPU_MASK:     read("scx_dsq_id_flags", "SCX_DSQ_LOCAL_CPU_MASK"),
		SCX_TASK_QUEUED:            read("scx_ent_flags", "SCX_TASK_QUEUED"),
		SCX_TASK_RESET_RUNNABLE_AT: read("scx_ent_flags", "SCX_TASK_RESET_RUNNABLE_AT"),
		SCX_TASK_DEQD_FOR_SLEEP:    read("scx_ent_flags", "SCX_TASK_DEQD_FOR_SLEEP"),
		SCX_TASK_STATE_SHIFT:       read("scx_ent_flags", "SCX_TASK_STATE_SHIFT"),
		SCX_TASK_STATE_BITS:        read("scx_ent_flags", "SCX_TASK_STATE_BITS"),
		SCX_TASK_STATE_MASK:        read("scx_ent_flags", "SCX_TASK_STATE_MASK"),
		SCX_TASK_CURSOR:            read("scx_ent_flags", "SCX_TASK_CURSOR"),
		SCX_TASK_NONE:              read("scx_task_state", "SCX_TASK_NONE"),
		SCX_TASK_INIT:              read("scx_task_state", "SCX_TASK_INIT"),
		SCX_TASK_READY:             read("scx_task_state", "SCX_TASK_READY"),
		SCX_TASK_ENABLED:           read("scx_task_state", "SCX_TASK_ENABLED"),
		SCX_TASK_NR_STATES:         read("scx_task_state", "SCX_TASK_NR_STATES"),
		SCX_TASK_DSQ_ON_PRIQ:       read("scx_ent_dsq_flags", "SCX_TASK_DSQ_ON_PRIQ"),
		SCX_KICK_IDLE:              read("scx_kick_flags", "SCX_KICK_IDLE"),
		SCX_KICK_PREEMPT:           read("scx_kick_flags", "SCX_KICK_PREEMPT"),
		SCX_KICK_WAIT:              read("scx_kick_flags", "SCX_KICK_WAIT"),
		SCX_ENQ_WAKEUP:             read("scx_enq_flags", "SCX_ENQ_WAKEUP"),
		SCX_ENQ_HEAD:               read("scx_enq_flags", "SCX_ENQ_HEAD"),
		SCX_ENQ_PREEMPT:            read("scx_enq_flags", "SCX_ENQ_PREEMPT"),
		SCX_ENQ_REENQ:              read("scx_enq_flags", "SCX_ENQ_REENQ"),
		SCX_ENQ_LAST:               read("scx_enq_flags", "SCX_ENQ_LAST"),
		SCX_ENQ_CLEAR_OPSS:         read("scx_enq_flags", "SCX_ENQ_CLEAR_OPSS"),
		SCX_ENQ_DSQ_PRIQ:           read("scx_enq_flags", "SCX_ENQ_DSQ_PRIQ"),
	}

	return scx, nil
}
