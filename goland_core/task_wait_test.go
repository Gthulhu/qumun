package core

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestBlockTilReadyForDequeueRequeueBlocksWithWaitingProducer(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)

	s := &Sched{queue: make(chan []byte, 128)}
	for i := 0; i < cap(s.queue); i++ {
		s.queue <- []byte{1}
	}

	producerStarted, producerDone := make(chan struct{}), make(chan struct{})
	go func() {
		close(producerStarted)
		s.queue <- []byte{2}
		close(producerDone)
	}()
	<-producerStarted
	// The full buffer forces this producer to wait before the consumer starts.
	runtime.Gosched()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.BlockTilReadyForDequeue(ctx)
		close(done)
	}()
	select {
	case <-producerDone:
	case <-time.After(time.Second):
		t.Fatal("producer did not fill the freed channel slot")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("expected current implementation to block requeueing into the full channel")
	case <-time.After(20 * time.Millisecond):
	}
	// Release the blocked send so the reproduction leaves no stuck goroutine.
	<-s.queue
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumer did not resume after freeing a channel slot")
	}
}

func TestDirectWaitCancellation(t *testing.T) {
	s := &Sched{directQueue: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.BlockTilReadyForDequeue(ctx)
	if s.QueuedError() != nil {
		t.Fatal(s.QueuedError())
	}
}
