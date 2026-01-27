// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Gthulhu/plugin/models"
	core "github.com/Gthulhu/qumun/goland_core"
	"github.com/Gthulhu/qumun/util"
)

const (
	MAX_LATENCY_WEIGHT = 1000
	SLICE_NS_DEFAULT   = 5000 * 1000 // 5ms
	SLICE_NS_MIN       = 500 * 1000
	SCX_ENQ_WAKEUP     = 1
	NSEC_PER_SEC       = 1000000000 // 1 second in nanoseconds
	PF_WQ_WORKER       = 0x00000020
)

const taskPoolSize = 4096

var taskPool = make([]Task, taskPoolSize)
var taskPoolCount = 0
var taskPoolHead, taskPoolTail int

func DrainQueuedTask(s *core.Sched) uint64 {
	var count uint64
	for (taskPoolTail+1)%taskPoolSize != taskPoolHead {
		var newQueuedTask models.QueuedTask
		s.DequeueTask(&newQueuedTask)
		if newQueuedTask.Pid == -1 || count == core.GetNrQueued() {
			s.DecNrQueued(count)
			return count
		}
		deadline := updatedEnqueueTask(s, &newQueuedTask)
		t := Task{
			QueuedTask: &newQueuedTask,
			Deadline:   deadline,
		}
		InsertTaskToPool(t)
		count++
	}
	return 0
}

var timeout = uint64(3 * NSEC_PER_SEC)

func updatedEnqueueTask(s *core.Sched, t *models.QueuedTask) uint64 {
	if minVruntime < t.Vtime {
		minVruntime = t.Vtime
	}
	minVruntimeLocal := saturating_sub(minVruntime, SLICE_NS_DEFAULT)
	if t.Vtime == 0 {
		t.Vtime = minVruntimeLocal + (SLICE_NS_DEFAULT * 100 / t.Weight)
	} else if t.Vtime < minVruntimeLocal {
		t.Vtime = minVruntimeLocal
	}
	t.Vtime += (t.StopTs - t.StartTs) * t.Weight / 100

	return t.Vtime + min(t.SumExecRuntime, SLICE_NS_DEFAULT*100)
}

func GetTaskFromPool() *models.QueuedTask {
	if taskPoolHead == taskPoolTail {
		return nil
	}
	t := &taskPool[taskPoolHead]
	taskPoolHead = (taskPoolHead + 1) % taskPoolSize
	taskPoolCount--
	return t.QueuedTask
}

var minVruntime uint64 = 0 // global vruntime

func now() uint64 {
	return uint64(time.Now().UnixNano())
}

func calcAvg(oldVal uint64, newVal uint64) uint64 {
	return (oldVal - (oldVal >> 2)) + (newVal >> 2)
}

func saturating_sub(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return 0
}

type Task struct {
	*models.QueuedTask
	Deadline  uint64
	Timestamp uint64
}

func LessQueuedTask(
	a, b *Task,
) bool {
	if a.Deadline != b.Deadline {
		return a.Deadline < b.Deadline
	}
	if a.Timestamp != b.Timestamp {
		return a.Timestamp < b.Timestamp
	}
	return a.Pid < b.Pid
}

func InsertTaskToPool(
	newTask Task,
) bool {
	if taskPoolCount >= taskPoolSize-1 {
		return false
	}
	insertIdx := taskPoolTail
	for i := 0; i < taskPoolCount; i++ {
		idx := (taskPoolHead + i) % taskPoolSize
		if LessQueuedTask(
			&newTask,
			&taskPool[idx],
		) {
			insertIdx = idx
			break
		}
	}

	cur := taskPoolTail
	for cur != insertIdx {
		next := (cur - 1 + taskPoolSize) % taskPoolSize
		taskPool[cur] = taskPool[next]
		cur = next
	}
	taskPool[insertIdx] = newTask
	taskPoolTail = (taskPoolTail + 1) % taskPoolSize
	taskPoolCount++
	return true
}

func main() {
	bpfModule := core.LoadSched("main.bpf.o")
	defer bpfModule.Close()
	pid := os.Getpid()
	err := bpfModule.AssignUserSchedPid(pid)
	if err != nil {
		log.Printf("AssignUserSchedPid failed: %v", err)
	}

	err = util.ImportScxEnums()
	if err != nil {
		log.Panicf("ImportScxEnums failed: %v", err)
	}

	bpfModule.SetDebug(true)
	bpfModule.SetBuiltinIdle(true)
	bpfModule.Start()

	err = util.InitCacheDomains(bpfModule)
	if err != nil {
		log.Panicf("InitCacheDomains failed: %v", err)
	}

	if err := bpfModule.Attach(); err != nil {
		log.Panicf("bpfModule attach failed: %v", err)
	}

	log.Printf("UserSched's Pid: %v", core.GetUserSchedPid())
	log.Printf("scheduler started")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	cont := true
	timer := time.NewTicker(1 * time.Second)
	notifyCount := 0

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		var t *models.QueuedTask
		var task *core.DispatchedTask
		var err error
		var cpu int32

		for true {
			select {
			case <-ctx.Done():
				return
			default:
			}
			t = GetTaskFromPool()
			if t == nil {
				bpfModule.BlockTilReadyForDequeue(ctx)
				DrainQueuedTask(bpfModule)
			} else if t.Pid != -1 {
				task = core.NewDispatchedTask(t)
				err, cpu = bpfModule.SelectCPU(t)
				if err != nil {
					log.Printf("SelectCPU failed: %v", err)
					return
				}

				// Evaluate used task time slice.
				nrWaiting := core.GetNrQueued() + core.GetNrScheduled() + 1
				task.Vtime = t.Vtime
				task.SliceNs = max(SLICE_NS_DEFAULT/nrWaiting, SLICE_NS_MIN)
				task.Cpu = cpu

				err = bpfModule.DispatchTask(task)
				if err != nil {
					log.Printf("DispatchTask failed: %v", err)
					return
				}

				err = core.NotifyComplete(uint64(taskPoolCount))
				if err != nil {
					log.Printf("NotifyComplete failed: %v", err)
					return
				}
			}
		}
	}()

	for cont {
		select {
		case <-signalChan:
			log.Println("receive os signal")
			cancel()
			cont = false
		case <-timer.C:
			notifyCount++
			if notifyCount%10 == 0 {
				bss, err := bpfModule.GetBssData()
				if err != nil {
					log.Println("GetBssData failed", "error", err)
				} else {
					b, err := json.Marshal(bss)
					if err != nil {
						log.Println("json.Marshal failed", "error", err)
					} else {
						log.Println("bss data", "data", string(b))
					}
				}
			}
			if bpfModule.Stopped() {
				log.Println("bpfModule stopped")
				uei, err := bpfModule.GetUeiData()
				if err == nil {
					log.Println("uei", "kind", uei.Kind, "exitCode", uei.ExitCode, "reason", uei.GetReason(), "message", uei.GetMessage())
				} else {
					log.Println("GetUeiData failed", "error", err)
				}
				cont = false
			}
		}
	}
	timer.Stop()
	log.Println("scheduler exit")
}
