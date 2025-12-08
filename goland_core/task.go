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
)

func (s *Sched) BlockTilReadyForDequeue(ctx context.Context) {
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

func (s *Sched) ReadyForDequeue() bool {
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

// func (s *Sched) DispatchTask(t *DispatchedTask) error {
// 	if err := s.urb.Error(); err != nil {
// 		return err
// 	}
// 	s.dispatch <- fastEncode(t)
// 	return nil
// }

func (s *Sched) DispatchTask(t *DispatchedTask) error {
	return s.urb.Submit(fastEncode(t))
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

func fastEncode(t *DispatchedTask) []byte {
	data := make([]byte, 8*8) // 64 bytes

	binary.LittleEndian.PutUint32(data[0:4], uint32(t.Pid))
	binary.LittleEndian.PutUint32(data[4:8], uint32(t.Cpu))
	binary.LittleEndian.PutUint64(data[8:16], t.Flags)
	binary.LittleEndian.PutUint64(data[16:24], t.SliceNs)
	binary.LittleEndian.PutUint64(data[24:32], t.Vtime)
	binary.LittleEndian.PutUint64(data[32:40], t.CpuMaskCnt)

	return data
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
