// SPDX-License-Identifier: Apache-2.0

package core

/*
#include "hotpath.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/Gthulhu/plugin/models"
	"github.com/Gthulhu/qumun/internal/schedbridge"
	"github.com/cilium/ebpf"
)

var (
	selectCPUFn    = unsafe.Pointer(C.c_select_cpu_wrapper)
	dispatchTaskFn = unsafe.Pointer(C.c_dispatch_task_wrapper)
	dequeueTaskFn  = unsafe.Pointer(C.c_dequeue_task_wrapper)
)

type dequeueArgs struct {
	queue    unsafe.Pointer
	result   int32
	reserved int32
	data     [72]byte
}

var (
	_ [unsafe.Sizeof(dequeueArgs{}) - C.sizeof_struct_qumun_dequeue_args]byte
	_ [C.sizeof_struct_qumun_dequeue_args - unsafe.Sizeof(dequeueArgs{})]byte
	_ [unsafe.Alignof(dequeueArgs{}) - C.QUMUN_DEQUEUE_ALIGN]byte
	_ [C.QUMUN_DEQUEUE_ALIGN - unsafe.Alignof(dequeueArgs{})]byte
	_ [unsafe.Offsetof(dequeueArgs{}.queue) - C.QUMUN_DEQUEUE_QUEUE]byte
	_ [C.QUMUN_DEQUEUE_QUEUE - unsafe.Offsetof(dequeueArgs{}.queue)]byte
	_ [unsafe.Offsetof(dequeueArgs{}.result) - C.QUMUN_DEQUEUE_RESULT]byte
	_ [C.QUMUN_DEQUEUE_RESULT - unsafe.Offsetof(dequeueArgs{}.result)]byte
	_ [unsafe.Offsetof(dequeueArgs{}.data) - C.QUMUN_DEQUEUE_DATA]byte
	_ [C.QUMUN_DEQUEUE_DATA - unsafe.Offsetof(dequeueArgs{}.data)]byte
	_ [unsafe.Sizeof(models.QueuedTask{}) - 72]byte
	_ [72 - unsafe.Sizeof(models.QueuedTask{})]byte
)

func openQueuedRing(fd int) (unsafe.Pointer, error) {
	var code C.int
	queue := C.qumun_queue_open(C.int(fd), &code)
	if queue == nil {
		return nil, fmt.Errorf("initialize queued ring: %w", syscall.Errno(-code))
	}
	return unsafe.Pointer(queue), nil
}

func closeQueuedRing(queue unsafe.Pointer) {
	C.qumun_queue_close((*C.struct_qumun_queue)(queue))
}

func (s *Sched) dequeueDirect(task *models.QueuedTask) {
	task.Pid = -1
	if s.queuedErr != nil {
		return
	}
	args := dequeueArgs{queue: s.queuedRing}
	schedbridge.Call(dequeueTaskFn, unsafe.Pointer(&args))
	runtime.KeepAlive(s)
	if args.result < 0 {
		s.queuedErr = fmt.Errorf("consume queued ring: %w", syscall.Errno(-args.result))
	} else if args.result == 1 {
		s.queuedErr = fastDecode(args.data[:], task)
	} else if args.result != 0 {
		s.queuedErr = fmt.Errorf("consume queued ring: unexpected record count %d", args.result)
	}
}

type cpuContext struct {
	pid   int32
	cpu   int32
	flags uint64
}

type selectArgs struct {
	fd       int32
	err      int32
	retval   uint32
	reserved uint32
	context  cpuContext
}

type dispatchArgs struct {
	ring     unsafe.Pointer
	err      int32
	reserved uint32
	data     [64]byte
}

// Both directions reject size, alignment, and field-offset mismatches.
var (
	_ [unsafe.Sizeof(cpuContext{}) - C.sizeof_struct_qumun_cpu_context]byte
	_ [C.sizeof_struct_qumun_cpu_context - unsafe.Sizeof(cpuContext{})]byte
	_ [unsafe.Alignof(cpuContext{}) - C.QUMUN_CONTEXT_ALIGN]byte
	_ [C.QUMUN_CONTEXT_ALIGN - unsafe.Alignof(cpuContext{})]byte
	_ [unsafe.Offsetof(cpuContext{}.pid) - C.QUMUN_CONTEXT_PID]byte
	_ [C.QUMUN_CONTEXT_PID - unsafe.Offsetof(cpuContext{}.pid)]byte
	_ [unsafe.Offsetof(cpuContext{}.cpu) - C.QUMUN_CONTEXT_CPU]byte
	_ [C.QUMUN_CONTEXT_CPU - unsafe.Offsetof(cpuContext{}.cpu)]byte
	_ [unsafe.Offsetof(cpuContext{}.flags) - C.QUMUN_CONTEXT_FLAGS]byte
	_ [C.QUMUN_CONTEXT_FLAGS - unsafe.Offsetof(cpuContext{}.flags)]byte
	_ [unsafe.Sizeof(selectArgs{}) - C.sizeof_struct_qumun_select_args]byte
	_ [C.sizeof_struct_qumun_select_args - unsafe.Sizeof(selectArgs{})]byte
	_ [unsafe.Alignof(selectArgs{}) - C.QUMUN_SELECT_ALIGN]byte
	_ [C.QUMUN_SELECT_ALIGN - unsafe.Alignof(selectArgs{})]byte
	_ [unsafe.Offsetof(selectArgs{}.fd) - C.QUMUN_SELECT_FD]byte
	_ [C.QUMUN_SELECT_FD - unsafe.Offsetof(selectArgs{}.fd)]byte
	_ [unsafe.Offsetof(selectArgs{}.err) - C.QUMUN_SELECT_ERROR]byte
	_ [C.QUMUN_SELECT_ERROR - unsafe.Offsetof(selectArgs{}.err)]byte
	_ [unsafe.Offsetof(selectArgs{}.retval) - C.QUMUN_SELECT_RETVAL]byte
	_ [C.QUMUN_SELECT_RETVAL - unsafe.Offsetof(selectArgs{}.retval)]byte
	_ [unsafe.Offsetof(selectArgs{}.reserved) - C.QUMUN_SELECT_RESERVED]byte
	_ [C.QUMUN_SELECT_RESERVED - unsafe.Offsetof(selectArgs{}.reserved)]byte
	_ [unsafe.Offsetof(selectArgs{}.context) - C.QUMUN_SELECT_CONTEXT]byte
	_ [C.QUMUN_SELECT_CONTEXT - unsafe.Offsetof(selectArgs{}.context)]byte
	_ [unsafe.Sizeof(dispatchArgs{}) - C.sizeof_struct_qumun_dispatch_args]byte
	_ [C.sizeof_struct_qumun_dispatch_args - unsafe.Sizeof(dispatchArgs{})]byte
	_ [unsafe.Alignof(dispatchArgs{}) - C.QUMUN_DISPATCH_ALIGN]byte
	_ [C.QUMUN_DISPATCH_ALIGN - unsafe.Alignof(dispatchArgs{})]byte
	_ [unsafe.Offsetof(dispatchArgs{}.ring) - C.QUMUN_DISPATCH_RING]byte
	_ [C.QUMUN_DISPATCH_RING - unsafe.Offsetof(dispatchArgs{}.ring)]byte
	_ [unsafe.Offsetof(dispatchArgs{}.err) - C.QUMUN_DISPATCH_ERROR]byte
	_ [C.QUMUN_DISPATCH_ERROR - unsafe.Offsetof(dispatchArgs{}.err)]byte
	_ [unsafe.Offsetof(dispatchArgs{}.reserved) - C.QUMUN_DISPATCH_RESERVED]byte
	_ [C.QUMUN_DISPATCH_RESERVED - unsafe.Offsetof(dispatchArgs{}.reserved)]byte
	_ [unsafe.Offsetof(dispatchArgs{}.data) - C.QUMUN_DISPATCH_DATA]byte
	_ [C.QUMUN_DISPATCH_DATA - unsafe.Offsetof(dispatchArgs{}.data)]byte
)

func runSelectCPU(prog *ebpf.Program, task *models.QueuedTask) (error, int32) {
	args := selectArgs{
		fd: int32(prog.FD()),
		context: cpuContext{
			pid: task.Pid, cpu: task.Cpu, flags: task.Flags,
		},
	}
	schedbridge.Call(selectCPUFn, unsafe.Pointer(&args))
	runtime.KeepAlive(prog)
	if args.err != 0 {
		return fmt.Errorf("select CPU: %w", syscall.Errno(-args.err)), 0
	}
	if args.retval > 2147483647 {
		return nil, RL_CPU_ANY
	}
	return nil, int32(args.retval)
}

func openDispatchRing(fd int) (unsafe.Pointer, error) {
	var code C.int
	ring := C.qumun_dispatch_open(C.int(fd), &code)
	if ring == nil {
		return nil, fmt.Errorf("initialize dispatch ring: %w", syscall.Errno(-code))
	}
	return unsafe.Pointer(ring), nil
}

func closeDispatchRing(ring unsafe.Pointer) {
	C.qumun_dispatch_close((*C.struct_user_ring_buffer)(ring))
}

func (s *Sched) dispatchTask(task *DispatchedTask) error {
	args := dispatchArgs{ring: s.dispatchRing}
	encodeDispatch(args.data[:], task)
	schedbridge.Call(dispatchTaskFn, unsafe.Pointer(&args))
	runtime.KeepAlive(s)
	if args.err != 0 {
		return fmt.Errorf("user_ring_buffer reserve/submit failed: %w", syscall.Errno(-args.err))
	}
	return nil
}
