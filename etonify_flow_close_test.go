package tun

import (
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type etonifyClosePort struct {
	access           sync.Mutex
	paths            map[Return]bool
	attachCount      atomic.Int32
	detachCount      atomic.Int32
	entered, release chan struct{}
	onDetach         func()
}

func (*etonifyClosePort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("192.0.2.1"), netip.Addr{}
}
func (*etonifyClosePort) PortMTU() uint32             { return 1500 }
func (*etonifyClosePort) WritePackets([][]byte) error { return nil }
func (p *etonifyClosePort) AttachReturn(path Return) error {
	if p.attachCount.Add(1) == 1 && p.entered != nil {
		close(p.entered)
		<-p.release
	}
	p.access.Lock()
	if p.paths == nil {
		p.paths = make(map[Return]bool)
	}
	p.paths[path] = true
	p.access.Unlock()
	return nil
}
func (p *etonifyClosePort) DetachReturn(path Return) error {
	count := p.detachCount.Add(1)
	p.access.Lock()
	delete(p.paths, path)
	p.access.Unlock()
	if count == 1 && p.onDetach != nil {
		p.onDetach()
	}
	return nil
}
func (p *etonifyClosePort) pathCount() int {
	p.access.Lock()
	defer p.access.Unlock()
	return len(p.paths)
}
func etonifyCloseDispatcher(t *testing.T) *ForwardDispatcher {
	t.Helper()
	d := NewForwardDispatcher(nil, nil, logger.NOP(), UDPNatOptions{}, 0)
	t.Cleanup(d.Close)
	return d
}

func TestEtonifyDispatcherDoubleCloseSharedNAT(t *testing.T) {
	p := &etonifyClosePort{}
	first, second := etonifyCloseDispatcher(t), etonifyCloseDispatcher(t)
	shared := first.natFor(p)
	if second.natFor(p) != shared {
		t.Fatal("initial allocator not shared")
	}
	first.Close()
	first.Close()
	if p.detachCount.Load() != 1 {
		t.Fatalf("detach calls=%d, want1", p.detachCount.Load())
	}
	third := etonifyCloseDispatcher(t)
	if third.natFor(p) != shared {
		t.Fatal("double Close removed another owner's NAT")
	}
}

func TestEtonifyDispatcherConcurrentClose(t *testing.T) {
	p := &etonifyClosePort{}
	first, second := etonifyCloseDispatcher(t), etonifyCloseDispatcher(t)
	shared := first.natFor(p)
	second.natFor(p)
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() { defer workers.Done(); first.Close() }()
	}
	workers.Wait()
	if p.detachCount.Load() != 1 || p.pathCount() != 1 {
		t.Fatalf("teardown duplicated: detach=%d paths=%d", p.detachCount.Load(), p.pathCount())
	}
	third := etonifyCloseDispatcher(t)
	if third.natFor(p) != shared {
		t.Fatal("concurrent Close lost shared ownership")
	}
}

func TestEtonifyDispatcherCloseDuringAttachReturn(t *testing.T) {
	p := &etonifyClosePort{entered: make(chan struct{}), release: make(chan struct{})}
	d := etonifyCloseDispatcher(t)
	attached := make(chan struct{})
	go func() { defer close(attached); d.natFor(p) }()
	select {
	case <-p.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("AttachReturn not entered")
	}
	closed := make(chan struct{})
	go func() { defer close(closed); d.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	for !d.closed.Load() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if !d.closed.Load() {
		close(p.release)
		t.Fatal("Close did not acquire shutdown")
	}
	close(p.release)
	for _, done := range []chan struct{}{attached, closed} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("registration/shutdown deadlocked")
		}
	}
	if p.pathCount() != 0 || p.detachCount.Load() != 1 {
		t.Fatal("return path survived Close")
	}
	before := p.attachCount.Load()
	if d.natFor(p) != nil {
		t.Fatal("closed dispatcher published a NAT")
	}
	if p.attachCount.Load() != before {
		t.Fatal("closed dispatcher attached another path")
	}
}

func TestEtonifyDispatcherCloseReentrantDetach(t *testing.T) {
	p := &etonifyClosePort{}
	d := etonifyCloseDispatcher(t)
	d.natFor(p)
	p.onDetach = d.Close
	d.Close()
	if p.detachCount.Load() != 1 {
		t.Fatalf("reentrant Close detached %d times", p.detachCount.Load())
	}
}
