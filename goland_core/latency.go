// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"unsafe"
)

type latencyHistogram [64]uint64

func (h *latencyHistogram) observe(ns uint64) {
	bucket := bits.Len64(ns) - 1
	if bucket < 0 {
		bucket = 0
	}
	h[bucket]++
}

// LatencySummary reports inclusive log2 bucket upper bounds, not exact
// percentiles. All durations are nanoseconds.
type LatencySummary struct {
	Count      uint64     `json:"count"`
	P50UpperNS uint64     `json:"p50_upper_ns"`
	P95UpperNS uint64     `json:"p95_upper_ns"`
	P99UpperNS uint64     `json:"p99_upper_ns"`
	MaxUpperNS uint64     `json:"max_upper_ns"`
	Buckets    [64]uint64 `json:"buckets"`
}

func (h latencyHistogram) summary() LatencySummary {
	s := LatencySummary{Buckets: h}
	for _, count := range h {
		s.Count += count
	}
	if s.Count == 0 {
		return s
	}
	upper := func(percent uint64) uint64 {
		// ceil(count * percent / 100), without overflowing the product.
		target := s.Count/100*percent + (s.Count%100*percent+99)/100
		var count uint64
		for i, n := range h {
			count += n
			if count >= target {
				if i == 63 {
					return math.MaxUint64
				}
				return uint64(1)<<(i+1) - 1
			}
		}
		return 0
	}
	s.P50UpperNS, s.P95UpperNS = upper(50), upper(95)
	s.P99UpperNS, s.MaxUpperNS = upper(99), upper(100)
	return s
}

type LatencyReport struct {
	SelectCPU                LatencySummary `json:"select_cpu"`
	EnqueueToDispatchReceive LatencySummary `json:"enqueue_to_dispatch_receive"`
}

// GetLatencyReport requires a stopped scheduling loop. Kernel buckets are
// read individually and are only a snapshot if dispatches are still in flight.
func (s *Sched) GetLatencyReport() (LatencyReport, error) {
	if s.selectLatency == nil {
		return LatencyReport{}, fmt.Errorf("latency measurements are not enabled")
	}
	m, err := s.mod.GetMap("dispatch_latency")
	if err != nil {
		return LatencyReport{}, fmt.Errorf("get dispatch latency map: %w", err)
	}
	var h latencyHistogram
	for i := uint32(0); i < uint32(len(h)); i++ {
		value, err := m.GetValue(unsafe.Pointer(&i))
		if err != nil {
			return LatencyReport{}, fmt.Errorf("read dispatch latency bucket %d: %w", i, err)
		}
		if len(value) != 8 {
			return LatencyReport{}, fmt.Errorf("dispatch latency bucket %d: got %d bytes, want 8", i, len(value))
		}
		h[i] = binary.LittleEndian.Uint64(value)
	}
	return LatencyReport{
		SelectCPU:                s.selectLatency.summary(),
		EnqueueToDispatchReceive: h.summary(),
	}, nil
}
