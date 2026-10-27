// SPDX-License-Identifier: Apache-2.0

package schedbridge

import (
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"
)

func TestMemoryOperations(t *testing.T) {
	var wide uint64
	for _, value := range []uint64{0, 1, 1<<32 + 7, 1<<64 - 1} {
		StoreUint64(unsafe.Pointer(&wide), value)
		if got := LoadUint64(unsafe.Pointer(&wide)); got != value || wide != value {
			t.Fatalf("uint64: got %#x, memory %#x, want %#x", got, wide, value)
		}
		if got := cgoLoadUint64(unsafe.Pointer(&wide)); got != value {
			t.Fatalf("Cgo load: got %#x, want %#x", got, value)
		}
	}

	var narrow uint32
	for _, value := range []uint32{0, 1, 1<<32 - 1} {
		StoreUint32(unsafe.Pointer(&narrow), value)
		if got := LoadUint32(unsafe.Pointer(&narrow)); got != value || narrow != value {
			t.Fatalf("uint32: got %#x, memory %#x, want %#x", got, narrow, value)
		}
	}

	// Guard adjacent bytes against an oversized C boolean store.
	flags := [3]byte{0xa5, 0, 0x5a}
	for _, value := range []bool{true, false} {
		StoreBool(unsafe.Pointer(&flags[1]), value)
		want := byte(0)
		if value {
			want = 1
		}
		if flags != [3]byte{0xa5, want, 0x5a} {
			t.Fatalf("bool store corrupted flags: %x", flags)
		}
	}
}

func TestSubUint64(t *testing.T) {
	for _, tc := range []struct {
		current, amount, want uint64
	}{
		{0, 1, 0},
		{5, 0, 5},
		{5, 1, 4},
		{5, 5, 0},
		{5, 6, 5},
		{1<<64 - 1, 1<<32 + 1, 1<<64 - 1 - (1<<32 + 1)},
	} {
		value := tc.current
		SubUint64(unsafe.Pointer(&value), tc.amount)
		if value != tc.want {
			t.Fatalf("%d - %d: got %d, want %d", tc.current, tc.amount, value, tc.want)
		}
	}
}

func TestConcurrentCalls(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var value uint64
			for j := uint64(0); j < 1000; j++ {
				StoreUint64(unsafe.Pointer(&value), j)
				if got := LoadUint64(unsafe.Pointer(&value)); got != j {
					t.Errorf("got %d, want %d", got, j)
					return
				}
				if j%100 == 0 {
					runtime.GC()
				}
			}
		}()
	}
	wg.Wait()
}

func TestLoadAllocations(t *testing.T) {
	var value uint64 = 42
	if got := testing.AllocsPerRun(1000, func() {
		if LoadUint64(unsafe.Pointer(&value)) != 42 {
			panic("invalid result")
		}
	}); got != 0 {
		t.Fatalf("got %g allocations per direct load, want 0", got)
	}
}

func TestDirectCallsBypassCgo(t *testing.T) {
	var value uint64
	before := runtime.NumCgoCall()
	StoreUint64(unsafe.Pointer(&value), 42)
	if got := LoadUint64(unsafe.Pointer(&value)); got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
	if after := runtime.NumCgoCall(); after != before {
		t.Fatalf("direct calls entered Cgo: before=%d, after=%d", before, after)
	}
	if cgoLoadUint64(unsafe.Pointer(&value)) != 42 {
		t.Fatal("invalid standard Cgo result")
	}
	if after := runtime.NumCgoCall(); after != before+1 {
		t.Fatalf("standard Cgo call not counted: before=%d, after=%d", before, after)
	}
}

func TestPinnedThreadAcrossWaitAndGC(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)

	waiting := make(chan struct{})
	resume := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid := syscall.Gettid()
		var value uint64
		for i := 0; i < 1000; i++ {
			StoreUint64(unsafe.Pointer(&value), uint64(i))
			if got := LoadUint64(unsafe.Pointer(&value)); got != uint64(i) {
				t.Errorf("before wait: got %d, want %d", got, i)
			}
		}
		close(waiting)
		<-resume
		if got := syscall.Gettid(); got != tid {
			t.Errorf("thread changed after wait: got %d, want %d", got, tid)
		}
		if got := LoadUint64(unsafe.Pointer(&value)); got != 999 {
			t.Errorf("after GC: got %d, want 999", got)
		}
	}()
	<-waiting
	runtime.GC()
	close(resume)
	<-done
}

var benchmarkResult uint64

func BenchmarkLoadUint64(b *testing.B) {
	b.Run("Cgo", func(b *testing.B) {
		var value uint64 = 42
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchmarkResult = cgoLoadUint64(unsafe.Pointer(&value))
		}
	})
	b.Run("Asmcgocall", func(b *testing.B) {
		var value uint64 = 42
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchmarkResult = LoadUint64(unsafe.Pointer(&value))
		}
	})
	b.Run("GoAtomic", func(b *testing.B) {
		var value uint64 = 42
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchmarkResult = atomic.LoadUint64(&value)
		}
	})
}
