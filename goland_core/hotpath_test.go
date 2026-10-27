// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"syscall"
	"testing"
	"unsafe"

	"github.com/Gthulhu/plugin/models"
	"github.com/Gthulhu/qumun/internal/schedbridge"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func TestSharedCounters(t *testing.T) {
	oldQueued, oldScheduled := nrQueued, nrScheduled
	t.Cleanup(func() { nrQueued, nrScheduled = oldQueued, oldScheduled })
	queued, scheduled := uint64(1<<32+9), uint64(1<<32+3)
	nrQueued, nrScheduled = &queued, &scheduled
	s := &Sched{}
	if got := s.GetNrQueued(); got != queued {
		t.Fatalf("queued: got %d, want %d", got, queued)
	}
	if got := s.GetNrScheduled(); got != scheduled {
		t.Fatalf("scheduled: got %d, want %d", got, scheduled)
	}
	if err := NotifyComplete(123); err != nil || scheduled != 123 {
		t.Fatalf("notify: scheduled=%d, error=%v", scheduled, err)
	}
	if err := s.SubNrQueued(); err != nil || queued != 1<<32+8 {
		t.Fatalf("subtract one: queued=%d, error=%v", queued, err)
	}
	if err := s.DecNrQueued(1<<32 + 8); err != nil || queued != 0 {
		t.Fatalf("drain: queued=%d, error=%v", queued, err)
	}
	if err := s.SubNrQueued(); err != nil || queued != 0 {
		t.Fatalf("empty queue: queued=%d, error=%v", queued, err)
	}
}

func TestDispatchEncoding(t *testing.T) {
	task := &DispatchedTask{
		Pid: -123, Cpu: RL_CPU_ANY, Flags: 1<<63 + 1,
		SliceNs: 123456, Vtime: 1<<63 + 7, CpuMaskCnt: 987,
	}
	var args dispatchArgs
	encodeDispatch(args.data[:], task)
	var got DispatchedTask
	if err := binary.Read(bytes.NewReader(args.data[:]), binary.LittleEndian, &got); err != nil {
		t.Fatal(err)
	}
	if got != *task {
		t.Fatalf("wire record: got %+v, want %+v", got, *task)
	}
	if !bytes.Equal(args.data[40:], make([]byte, 24)) {
		t.Fatal("reserved dispatch bytes must be zero")
	}
}

func TestDispatchUninitialized(t *testing.T) {
	s := &Sched{}
	if err := s.DispatchTask(&DispatchedTask{}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("got %v, want EINVAL", err)
	}
}

func TestSelectCPUUninitialized(t *testing.T) {
	s := &Sched{}
	if err, _ := s.SelectCPU(&models.QueuedTask{}); !errors.Is(err, selectFailed) {
		t.Fatalf("got %v, want missing-program error", err)
	}
}

func TestSelectCPUInvalidFD(t *testing.T) {
	args := selectArgs{fd: -1}
	schedbridge.Call(selectCPUFn, unsafe.Pointer(&args))
	if args.err >= 0 {
		t.Fatalf("invalid FD did not return a negative errno: %d", args.err)
	}
}

func TestSelectCPUProgram(t *testing.T) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Syscall, License: "GPL", Flags: unix.BPF_F_SLEEPABLE,
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R0, asm.R1, 4, asm.Word),
			asm.Return(),
		},
	})
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
			errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("BPF syscall programs unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer prog.Close()
	s := &Sched{selectCpuPrg: prog}
	for _, cpu := range []int32{7, -22} {
		var context [16]byte
		binary.LittleEndian.PutUint32(context[0:4], 123)
		binary.LittleEndian.PutUint32(context[4:8], uint32(cpu))
		binary.LittleEndian.PutUint64(context[8:16], 1<<63)
		reference, err := prog.Run(&ebpf.RunOptions{Context: context[:]})
		if err != nil {
			t.Fatalf("standard program run: %v", err)
		}
		err, got := s.SelectCPU(&models.QueuedTask{Pid: 123, Cpu: cpu, Flags: 1 << 63})
		if err != nil {
			t.Fatal(err)
		}
		want := int32(reference)
		if reference > 2147483647 {
			want = RL_CPU_ANY
		}
		if got != want {
			t.Fatalf("CPU %d: got %d, want %d", cpu, got, want)
		}
	}
	task := models.QueuedTask{Pid: 123, Cpu: 7}
	if got := testing.AllocsPerRun(100, func() {
		if err, cpu := s.SelectCPU(&task); err != nil || cpu != 7 {
			panic("invalid CPU selection")
		}
	}); got != 0 {
		t.Fatalf("got %g Go allocations per CPU selection, want 0", got)
	}
}

func TestDispatchRingFull(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.UserRingbuf, MaxEntries: uint32(syscall.Getpagesize()),
	})
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
			errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("BPF user ring buffer unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer m.Close()
	ring, err := openDispatchRing(m.FD())
	if err != nil {
		t.Fatal(err)
	}
	defer closeDispatchRing(ring)
	s := &Sched{dispatchRing: ring}
	task := DispatchedTask{Pid: 123}
	if got := testing.AllocsPerRun(10, func() {
		if err := s.DispatchTask(&task); err != nil {
			panic(err)
		}
	}); got != 0 {
		t.Fatalf("got %g Go allocations per dispatch, want 0", got)
	}
	submitted := 0
	for i := 0; i < syscall.Getpagesize(); i++ {
		err := s.DispatchTask(&DispatchedTask{Pid: int32(i + 1)})
		if errors.Is(err, syscall.ENOSPC) {
			if submitted == 0 {
				t.Fatal("ring was full before any submissions")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		submitted++
	}
	t.Fatal("dispatch did not report a full ring")
}
