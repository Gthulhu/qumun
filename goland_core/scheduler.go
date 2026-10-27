// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0
// Author: Ian Chen <ychen.desl@gmail.com>

package core

import (
	"time"

	"github.com/Gthulhu/plugin/models"
)

func (s *Sched) DrainQueuedTask() uint64 {
	if s.plugin != nil {
		return uint64(s.plugin.DrainQueuedTask(s))
	}
	return 0
}

func (s *Sched) SelectQueuedTask() *models.QueuedTask {
	if s.plugin != nil {
		return s.plugin.SelectQueuedTask(s)
	}
	return nil
}

func (s *Sched) SelectCPU(t *models.QueuedTask) (error, int32) {
	if s.selectLatency != nil {
		start := time.Now()
		defer func() { s.selectLatency.observe(uint64(time.Since(start))) }()
	}
	if s.plugin != nil {
		return s.plugin.SelectCPU(s, t)
	}
	return s.selectCPU(t)
}

func (s *Sched) DetermineTimeSlice(t *models.QueuedTask) uint64 {
	if s.plugin != nil {
		return s.plugin.DetermineTimeSlice(s, t)
	}
	return 0
}

func (s *Sched) GetPoolCount() uint64 {
	if s.plugin != nil {
		return s.plugin.GetPoolCount()
	}
	return 0
}
