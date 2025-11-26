package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"

	"github.com/Gthulhu/plugin/models"
	"github.com/Gthulhu/plugin/plugin"
	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

const (
	RL_CPU_ANY = 1 << 20
)

type Sched struct {
	mod        *bpf.Module
	plugin     plugin.CustomScheduler
	bss        *BssMap
	uei        *UeiMap
	rodata     *RodataMap
	structOps  *bpf.BPFMap
	queue      chan []byte // The map containing tasks that are queued to user space from the kernel.
	dispatch   chan []byte
	selectCpu  *bpf.BPFProg
	preemptCpu *bpf.BPFProg
	siblingCpu *bpf.BPFProg
	urb        *bpf.UserRingBuffer
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
			s.queue = make(chan []byte, 4096)
			rb, err := s.mod.InitRingBuf("queued", s.queue)
			if err != nil {
				panic(err)
			}
			rb.Poll(10)
		} else if m.Name() == "dispatched" {
			s.dispatch = make(chan []byte, 4096)
			s.urb, err = s.mod.InitUserRingBuf("dispatched", s.dispatch)
			if err != nil {
				panic(err)
			}
			s.urb.Start()
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
			s.selectCpu = prog
		}

		if prog.Name() == "enable_sibling_cpu" {
			s.siblingCpu = prog
		}

		if prog.Name() == "do_preempt" {
			s.preemptCpu = prog
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
	if s.selectCpu != nil {
		arg := &task_cpu_arg{
			pid:   t.Pid,
			cpu:   t.Cpu,
			flags: t.Flags,
		}
		var data bytes.Buffer
		binary.Write(&data, binary.LittleEndian, arg)
		opt := bpf.RunOpts{
			CtxIn:     data.Bytes(),
			CtxSizeIn: uint32(data.Len()),
		}
		err := s.selectCpu.Run(&opt)
		if err != nil {
			return err, 0
		}
		if opt.RetVal > 2147483647 {
			return nil, RL_CPU_ANY
		}
		return nil, int32(opt.RetVal)
	}
	return selectFailed, 0
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
	if s.preemptCpu != nil {
		arg := &preempt_arg{
			cpuId: cpuId,
		}
		var data bytes.Buffer
		binary.Write(&data, binary.LittleEndian, arg)
		opt := bpf.RunOpts{
			CtxIn:     data.Bytes(),
			CtxSizeIn: uint32(data.Len()),
		}
		err := s.preemptCpu.Run(&opt)
		if err != nil {
			return err
		}
		if opt.RetVal != 0 {
			return fmt.Errorf("retVal: %v", opt.RetVal)
		}
		return nil
	}
	return fmt.Errorf("prog (selectCpu) not found")
}

func (s *Sched) EnableSiblingCpu(lvlId, cpuId, siblingCpuId int32) error {
	if s.siblingCpu != nil {
		arg := &domain_arg{
			lvlId:        lvlId,
			cpuId:        cpuId,
			siblingCpuId: siblingCpuId,
		}
		var data bytes.Buffer
		binary.Write(&data, binary.LittleEndian, arg)
		opt := bpf.RunOpts{
			CtxIn:     data.Bytes(),
			CtxSizeIn: uint32(data.Len()),
		}
		err := s.siblingCpu.Run(&opt)
		if err != nil {
			return err
		}
		if opt.RetVal != 0 {
			return fmt.Errorf("retVal: %v", opt.RetVal)
		}
		return nil
	}
	return fmt.Errorf("prog (siblingCpu) not found")
}

func (s *Sched) Attach() error {
	_, err := s.structOps.AttachStructOps()
	return err
}

func (s *Sched) Close() {
	s.urb.Close()
	s.mod.Close()
}
