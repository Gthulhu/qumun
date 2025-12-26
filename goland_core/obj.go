// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package core

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"github.com/Gthulhu/plugin/models"
	"github.com/Gthulhu/plugin/plugin"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	RL_CPU_ANY = 1 << 20
)

type Sched struct {
	mod          *bpf.Module
	plugin       plugin.CustomScheduler
	bss          *BssMap
	uei          *UeiMap
	rodata       *RodataMap
	structOps    *bpf.BPFMap
	urb          *bpf.UserRingBuffer
	queue        chan []byte // The map containing tasks that are queued to user space from the kernel.
	dispatch     chan []byte
	preemptCpu   *ebpf.Program
	siblingCpu   *ebpf.Program
	selectCpuPrg *ebpf.Program // Cilium eBPF program for syscall-based invocation
}

func init() {
	unix.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
}

func LoadSched(objPath string) *Sched {
	obj := LoadSkel()
	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath:     "",
		KernelLogLevel: 0,
	})
	if err != nil {
		panic(err)
	}
	if err := bpfModule.BPFReplaceExistedObject(obj); err != nil {
		panic(err)
	}

	s := &Sched{
		mod: bpfModule,
	}

	return s
}

func (s *Sched) SetPlugin(p plugin.CustomScheduler) {
	s.plugin = p
}

func (s *Sched) Start() {
	var err error
	bpfModule := s.mod
	bpfModule.BPFLoadObject()
	iters := bpfModule.Iterator()
	for {
		prog := iters.NextProgram()
		if prog == nil {
			break
		}
		if prog.Name() == "kprobe_handle_mm_fault" {
			log.Println("attach kprobe_handle_mm_fault")
			_, err := prog.AttachGeneric()
			if err != nil {
				log.Panicf("attach kprobe_handle_mm_fault failed: %v", err)
			}
			continue
		}
		if prog.Name() == "kretprobe_handle_mm_fault" {
			log.Println("attach kretprobe_handle_mm_fault")
			_, err := prog.AttachGeneric()
			if err != nil {
				log.Panicf("attach kretprobe_handle_mm_fault failed: %v", err)
			}
			continue
		}
	}
	iters = bpfModule.Iterator()
	for {
		m := iters.NextMap()
		if m == nil {
			break
		}
		fmt.Printf("map: %s, type: %s, fd: %d\n", m.Name(), m.Type().String(), m.FileDescriptor())
		if m.Name() == "main_bpf.bss" {
			s.bss = &BssMap{m}
		} else if m.Name() == "main_bpf.data" {
			s.uei = &UeiMap{m}
		} else if m.Name() == "main_bpf.rodata" {
			s.rodata = &RodataMap{m}
		} else if m.Name() == "queued" {
			s.queue = make(chan []byte, 128)
			rb, err := s.mod.InitRingBuf("queued", s.queue)
			if err != nil {
				panic(err)
			}
			rb.Poll(10)
		} else if m.Name() == "dispatched" {
			s.dispatch = make(chan []byte, 128)
			s.urb, err = s.mod.InitUserRingBuf("dispatched", s.dispatch)
			if err != nil {
				panic(err)
			}
			// s.urb.Start()
		}
		if m.Type().String() == "BPF_MAP_TYPE_STRUCT_OPS" {
			s.structOps = m
		}
	}

	iters = bpfModule.Iterator()
	for {
		prog := iters.NextProgram()
		if prog == nil {
			break
		}

		if prog.Name() == "rs_select_cpu" {
			if ciliumProg, err := ebpf.NewProgramFromFD(prog.FileDescriptor()); err == nil {
				s.selectCpuPrg = ciliumProg
			}
		}

		if prog.Name() == "enable_sibling_cpu" {
			if ciliumProg, err := ebpf.NewProgramFromFD(prog.FileDescriptor()); err == nil {
				s.siblingCpu = ciliumProg
			}
		}

		if prog.Name() == "do_preempt" {
			if ciliumProg, err := ebpf.NewProgramFromFD(prog.FileDescriptor()); err == nil {
				s.preemptCpu = ciliumProg
			}
		}
	}
}

type task_cpu_arg struct {
	pid   int32
	cpu   int32
	flags uint64
}

var selectFailed error = fmt.Errorf("prog (selectCpu) not found")

func (s *Sched) DefaultSelectCPU(t *models.QueuedTask) (error, int32) {
	return s.selectCPU(t)
}

func (s *Sched) selectCPU(t *models.QueuedTask) (error, int32) {
	if s.selectCpuPrg == nil {
		return selectFailed, 0
	}

	arg := task_cpu_arg{
		pid:   t.Pid,
		cpu:   t.Cpu,
		flags: t.Flags,
	}

	data := (*[16]byte)(unsafe.Pointer(&arg))[:]

	ret, err := s.selectCpuPrg.Run(&ebpf.RunOptions{
		Context: data[:],
	})
	if err != nil {
		return err, 0
	}

	retVal := int32(ret)
	if ret > 2147483647 {
		return nil, RL_CPU_ANY
	}
	return nil, retVal
}

type preempt_arg struct {
	cpuId int32
}

type domain_arg struct {
	lvlId        int32
	cpuId        int32
	siblingCpuId int32
}

func (s *Sched) PreemptCpu(cpuId int32) error {
	if s.preemptCpu == nil {
		return fmt.Errorf("prog (preemptCpu) not found")
	}

	arg := preempt_arg{
		cpuId: cpuId,
	}
	data := (*[4]byte)(unsafe.Pointer(&arg))[:]

	ret, err := s.preemptCpu.Run(&ebpf.RunOptions{
		Context: data[:],
	})
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("retVal: %v", ret)
	}
	return nil
}

func (s *Sched) EnableSiblingCpu(lvlId, cpuId, siblingCpuId int32) error {
	if s.siblingCpu == nil {
		return fmt.Errorf("prog (siblingCpu) not found")
	}

	arg := domain_arg{
		lvlId:        lvlId,
		cpuId:        cpuId,
		siblingCpuId: siblingCpuId,
	}
	data := (*[12]byte)(unsafe.Pointer(&arg))[:]

	ret, err := s.siblingCpu.Run(&ebpf.RunOptions{
		Context: data[:],
	})
	if err != nil {
		return err
	}
	if ret != 0 {
		return fmt.Errorf("retVal: %v", ret)
	}
	return nil
}

func (s *Sched) Attach() error {
	_, err := s.structOps.AttachStructOps()
	return err
}

func (s *Sched) Close() {
	if s.selectCpuPrg != nil {
		s.selectCpuPrg.Close()
	}
	if s.siblingCpu != nil {
		s.siblingCpu.Close()
	}
	if s.preemptCpu != nil {
		s.preemptCpu.Close()
	}
	s.urb.Close()
	s.mod.Close()
}
