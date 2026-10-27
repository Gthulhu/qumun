// SPDX-License-Identifier: Apache-2.0

package core

import (
	"math"
	"testing"

	"github.com/Gthulhu/plugin/models"
)

func TestLatencyHistogram(t *testing.T) {
	var h latencyHistogram
	if got := h.summary(); got != (LatencySummary{}) {
		t.Fatalf("empty summary: %+v", got)
	}
	for _, ns := range []uint64{0, 1, 2, 3, 4, 7, 8, math.MaxUint64} {
		h.observe(ns)
	}
	if h[0] != 2 || h[1] != 2 || h[2] != 2 || h[3] != 1 || h[63] != 1 {
		t.Fatalf("incorrect bucket boundaries: %v", h)
	}
	s := h.summary()
	if s.Count != 8 || s.P50UpperNS != 3 || s.P95UpperNS != math.MaxUint64 ||
		s.P99UpperNS != math.MaxUint64 || s.MaxUpperNS != math.MaxUint64 {
		t.Fatalf("incorrect summary: %+v", s)
	}
	h = latencyHistogram{0: 50, 1: 45, 2: 4, 3: 1}
	s = h.summary()
	if s.P50UpperNS != 1 || s.P95UpperNS != 3 || s.P99UpperNS != 7 || s.MaxUpperNS != 15 {
		t.Fatalf("incorrect percentile ranks: %+v", s)
	}
	h = latencyHistogram{1: math.MaxUint64}
	if s = h.summary(); s.P99UpperNS != 3 || s.Count != math.MaxUint64 {
		t.Fatalf("large sample count overflowed: %+v", s)
	}
	if got := testing.AllocsPerRun(100, func() { h.observe(123) }); got != 0 {
		t.Fatalf("histogram allocated: %g allocations", got)
	}
}

func TestLatencyMeasurementOptIn(t *testing.T) {
	s := &Sched{}
	if _, err := s.GetLatencyReport(); err == nil {
		t.Fatal("disabled measurement must report an error")
	}
	if err, _ := s.SelectCPU(&models.QueuedTask{}); err != selectFailed {
		t.Fatalf("disabled SelectCPU changed: %v", err)
	}
	if s.selectLatency != nil {
		t.Fatal("disabled measurement allocated a histogram")
	}
	s.selectLatency = &latencyHistogram{}
	if err, _ := s.SelectCPU(&models.QueuedTask{}); err != selectFailed {
		t.Fatalf("enabled SelectCPU changed: %v", err)
	}
	if got := s.selectLatency.summary().Count; got != 1 {
		t.Fatalf("SelectCPU samples: got %d, want 1", got)
	}
}
