package tun

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

type etonifyNATPort struct {
	etonifyClosePort
	mu       sync.Mutex
	held     map[natSelectorKey]bool
	releases int
	count    uint16
}

func (p *etonifyNATPort) PortSelectorRanges(uint8) []SelectorRange {
	return []SelectorRange{{Start: 50000, Count: p.count}}
}
func (*etonifyNATPort) ExpandSelectorRanges(uint8) bool { return false }
func (p *etonifyNATPort) ReserveSelector(protocol uint8, address netip.AddrPort) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := natSelectorKey{protocol: protocol, portAddress: address.Addr(), selector: address.Port()}
	if p.held == nil {
		p.held = make(map[natSelectorKey]bool)
	}
	if p.held[key] {
		return false
	}
	p.held[key] = true
	return true
}
func (p *etonifyNATPort) ReleaseSelector(protocol uint8, address netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := natSelectorKey{protocol: protocol, portAddress: address.Addr(), selector: address.Port()}
	if !p.held[key] {
		panic("duplicate selector release")
	}
	delete(p.held, key)
	p.releases++
}

func etonifyNATFlow(t *testing.T, n *portNAT, d *ForwardDispatcher, protocol uint8, client, server netip.AddrPort) *forwardFlow {
	t.Helper()
	address, _ := n.port.PortAddresses()
	reservation, ok := n.reserve(d, protocol, address, client, server)
	if !ok {
		t.Fatal("reserve failed")
	}
	flow := &forwardFlow{nat: n, protocol: protocol}
	n.publish(flow, reservation)
	return flow
}

func TestEtonifyNATRetiredSelectorNotReused(t *testing.T) {
	p := &etonifyNATPort{count: 2}
	d := NewForwardDispatcher(nil, nil, logger.NOP(), UDPNatOptions{}, 0)
	n := d.natFor(p)
	client := netip.MustParseAddrPort("10.0.0.2:50000")
	server := netip.MustParseAddrPort("198.51.100.1:443")
	flow := etonifyNATFlow(t, n, d, 17, client, server)
	n.release(flow)
	other := etonifyNATFlow(t, n, d, 17, netip.MustParseAddrPort("10.0.0.3:50000"), server)
	if flow.selectorKey == other.selectorKey {
		t.Fatal("retired UDP selector immediately reused")
	}
	n.release(other)
	d.Close()
}

func TestEtonifyNATLastClosePreservesLogicalQuarantine(t *testing.T) {
	p := &etonifyNATPort{count: 1}
	d := NewForwardDispatcher(nil, nil, logger.NOP(), UDPNatOptions{}, 0)
	n := d.natFor(p)
	flow := etonifyNATFlow(t, n, d, 17, netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("198.51.100.1:443"))
	n.release(flow)
	d.Close()
	if len(p.held) != 0 || p.releases != 1 {
		t.Fatal("last close did not free physical reservation once")
	}
	next := NewForwardDispatcher(nil, nil, logger.NOP(), UDPNatOptions{}, 0)
	defer next.Close()
	n2 := next.natFor(p)
	if n2 != n {
		t.Fatal("last close discarded logical quarantine")
	}
	address, _ := p.PortAddresses()
	if _, ok := n2.reserve(next, 17, address, netip.MustParseAddrPort("10.0.0.3:50000"), netip.MustParseAddrPort("198.51.100.2:443")); ok {
		t.Fatal("retired port accepted old selector")
	}
}

func etonifyNATFlowAt(t *testing.T, n *portNAT, d *ForwardDispatcher, protocol uint8, client, server netip.AddrPort, now int64) *forwardFlow {
	t.Helper()
	address, _ := n.port.PortAddresses()
	if client.Addr().Is6() {
		address = netip.MustParseAddr("2001:db8::1")
	}
	r, ok := n.reserveAt(d, protocol, address, client, server, now)
	if !ok {
		t.Fatal("reserveAt failed")
	}
	f := &forwardFlow{nat: n, protocol: protocol}
	n.publish(f, r)
	return f
}

func TestEtonifyNATQuarantineBoundaryAndSharedMapping(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		p := &etonifyNATPort{count: 2}
		d := etonifyCloseDispatcher(t)
		n := d.natFor(p)
		client := netip.MustParseAddrPort("10.0.0.2:50000")
		a := netip.MustParseAddrPort("198.51.100.1:443")
		b := netip.MustParseAddrPort("198.51.100.2:443")
		if ipv6 {
			client = netip.MustParseAddrPort("[fd00::2]:50000")
			a = netip.MustParseAddrPort("[2001:db8::2]:443")
			b = netip.MustParseAddrPort("[2001:db8::3]:443")
		}
		f1 := etonifyNATFlowAt(t, n, d, 17, client, a, 0)
		f2 := etonifyNATFlowAt(t, n, d, 17, client, b, 0)
		if f1.selectorKey != f2.selectorKey {
			t.Fatal("mapping no longer shared")
		}
		n.releaseAt(f1, 0)
		if n.selectorQuarantined(f1.selectorKey, 0) {
			t.Fatal("live mapping quarantined")
		}
		n.releaseAt(f2, 0)
		if !n.selectorQuarantined(f1.selectorKey, int64(udpSelectorQuarantine)-1) {
			t.Fatal("quarantine ended early")
		}
		other := netip.AddrPortFrom(client.Addr(), 50001)
		f3 := etonifyNATFlowAt(t, n, d, 17, other, a, int64(udpSelectorQuarantine)-1)
		if f3.selectorKey == f1.selectorKey {
			t.Fatal("selector reused before deadline")
		}
		if _, ok := n.reserveAt(d, 17, f1.selectorKey.portAddress, client, a, int64(udpSelectorQuarantine)-1); ok {
			t.Fatal("exhaustion did not refuse")
		}
		f4 := etonifyNATFlowAt(t, n, d, 17, client, a, int64(udpSelectorQuarantine))
		if f4.selectorKey != f1.selectorKey {
			t.Fatal("expired selector not reusable")
		}
		if p.releases != 1 {
			t.Fatal("expiry callback count")
		}
		n.releaseAt(f3, 0)
		n.releaseAt(f4, 0)
		n.sweepQuarantine(int64(udpSelectorQuarantine))
		n.sweepQuarantine(int64(udpSelectorQuarantine))
		if len(n.selectors) != 0 || len(n.mappings) != 0 || len(p.held) != 0 || p.releases != 3 {
			t.Fatal("quarantine retained state or repeated callback")
		}
	}
}

func TestEtonifyNATTCPAndICMPReleaseImmediately(t *testing.T) {
	for _, protocol := range []uint8{6, 1, 58} {
		p := &etonifyNATPort{count: 1}
		d := etonifyCloseDispatcher(t)
		n := d.natFor(p)
		f := etonifyNATFlowAt(t, n, d, protocol, netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("198.51.100.1:443"), 0)
		n.releaseAt(f, 0)
		if len(n.selectors) != 0 || len(p.held) != 0 || p.releases != 1 {
			t.Fatal("non-UDP reservation retained")
		}
	}
}

func TestEtonifyNATRetirementGenerationAndCleanup(t *testing.T) {
	p := &etonifyNATPort{count: 1}
	d := etonifyCloseDispatcher(t)
	n := d.natFor(p)
	f := etonifyNATFlowAt(t, n, d, 17, netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("198.51.100.1:443"), natNow())
	n.release(f)
	d.Close()
	portNATAccess.Lock()
	generation := n.generation
	portNATAccess.Unlock()
	next := etonifyCloseDispatcher(t)
	if next.natFor(p) != n {
		t.Fatal("idle allocator not reused")
	}
	cleanupRetiredPortNAT(n, generation, natNow()+int64(udpSelectorQuarantine))
	portNATAccess.Lock()
	same := portNATs[p] == n
	portNATAccess.Unlock()
	if !same {
		t.Fatal("stale timer evicted live owner")
	}
	next.Close()
	portNATAccess.Lock()
	generation = n.generation
	portNATAccess.Unlock()
	cleanupRetiredPortNAT(n, generation, natNow()+int64(udpSelectorQuarantine))
	portNATAccess.Lock()
	retained := portNATs[p] != nil
	timer := n.idleTimer
	portNATAccess.Unlock()
	if retained || timer != nil || p.releases != 1 {
		t.Fatal("idle cleanup leaked or double released")
	}
}

func TestEtonifyNATConcurrentAllocatorsAndClose(t *testing.T) {
	p := &etonifyNATPort{count: 64}
	d := etonifyCloseDispatcher(t)
	n := d.natFor(p)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, ok := n.reserveAt(d, 17, netip.MustParseAddr("192.0.2.1"), netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), uint16(50000+i)), netip.MustParseAddrPort("198.51.100.1:443"), 0)
			if !ok {
				t.Error("concurrent allocation refused")
				return
			}
			f := &forwardFlow{nat: n, protocol: 17}
			n.publish(f, r)
			n.releaseAt(f, 0)
		}(i)
	}
	wg.Wait()
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); d.Close() }()
	}
	wg.Wait()
	if len(p.held) != 0 || p.releases != 32 {
		t.Fatal("concurrent teardown lost ownership")
	}
	portNATAccess.Lock()
	gen := n.generation
	portNATAccess.Unlock()
	cleanupRetiredPortNAT(n, gen, natNow()+int64(udpSelectorQuarantine))
}

func TestEtonifyNATRegistryBackpressure(t *testing.T) {
	// Isolate this registry-only pressure experiment. No test is parallel; timers
	// retain their original identity and cannot erase entries in this fixture.
	portNATAccess.Lock()
	saved := portNATs
	portNATs = make(map[Port]*portNAT)
	portNATAccess.Unlock()
	defer func() {
		portNATAccess.Lock()
		for _, n := range portNATs {
			if n.idleTimer != nil {
				n.idleTimer.Stop()
			}
		}
		portNATs = saved
		portNATAccess.Unlock()
	}()
	var first *portNAT
	for i := 0; i < retiredPortNATCapacity; i++ {
		p := &etonifyNATPort{count: 1}
		n := acquirePortNAT(p)
		if n == nil {
			t.Fatalf("early registry refusal %d", i)
		}
		if i == 0 {
			first = n
		}
		d := NewForwardDispatcher(nil, nil, logger.NOP(), UDPNatOptions{}, 0)
		f := etonifyNATFlowAt(t, n, d, 17, netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("198.51.100.1:443"), natNow())
		n.release(f)
		releasePortNAT(n)
	}
	if n := acquirePortNAT(&etonifyNATPort{count: 1}); n != nil {
		t.Fatal("unexpired protection evicted to admit a new port")
	}
	d := etonifyCloseDispatcher(t)
	if d.natFor(&etonifyNATPort{count: 1}) != nil {
		t.Fatal("natFor did not control capacity refusal")
	}
	portNATAccess.Lock()
	gen := first.generation
	portNATAccess.Unlock()
	cleanupRetiredPortNAT(first, gen, natNow()+int64(udpSelectorQuarantine))
	n := acquirePortNAT(&etonifyNATPort{count: 1})
	if n == nil {
		t.Fatal("expired capacity not reusable")
	}
	releasePortNAT(n)
	portNATAccess.Lock()
	size := len(portNATs)
	portNATAccess.Unlock()
	if size != retiredPortNATCapacity-1 {
		t.Fatal("registry bound or immediate empty removal")
	}
}

func TestEtonifyNATCloseOverlapsStaleTimer(t *testing.T) {
	p := &etonifyNATPort{count: 1}
	d := etonifyCloseDispatcher(t)
	n := d.natFor(p)
	f := etonifyNATFlowAt(t, n, d, 17, netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("198.51.100.1:443"), natNow())
	n.release(f)
	d.Close()
	portNATAccess.Lock()
	generation := n.generation
	portNATAccess.Unlock()
	next := etonifyCloseDispatcher(t)
	if next.natFor(p) != n {
		t.Fatal("idle reacquisition")
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); next.Close() }()
		go func() { defer wg.Done(); cleanupRetiredPortNAT(n, generation, natNow()+int64(udpSelectorQuarantine)) }()
	}
	wg.Wait()
	portNATAccess.Lock()
	retained := portNATs[p] == n
	generation = n.generation
	portNATAccess.Unlock()
	if !retained || p.releases != 1 {
		t.Fatal("stale cleanup crossed lifecycle generation")
	}
	cleanupRetiredPortNAT(n, generation, natNow()+int64(udpSelectorQuarantine))
}

func BenchmarkEtonifyNATShortRangeExhaustion(b *testing.B) {
	p := &etonifyNATPort{count: 1}
	n := acquirePortNAT(p)
	defer releasePortNAT(n)
	d := NewForwardDispatcher(nil, nil, logger.NOP(), UDPNatOptions{}, 0)
	a, _ := p.PortAddresses()
	c := netip.MustParseAddrPort("10.0.0.2:50000")
	s := netip.MustParseAddrPort("198.51.100.1:443")
	r, ok := n.reserveAt(d, 17, a, c, s, 0)
	if !ok {
		b.Fatal("initial reservation")
	}
	f := &forwardFlow{nat: n, protocol: 17}
	n.publish(f, r)
	n.releaseAt(f, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := n.reserveAt(d, 17, a, c, s, 1); ok {
			b.Fatal("unsafe reuse")
		}
	}
	b.StopTimer()
	n.sweepQuarantine(int64(udpSelectorQuarantine))
}

func BenchmarkEtonifyNATQuarantineSweep(b *testing.B) {
	p := &etonifyNATPort{count: 2}
	n := acquirePortNAT(p)
	defer releasePortNAT(n)
	d := NewForwardDispatcher(nil, nil, logger.NOP(), UDPNatOptions{}, 0)
	address, _ := p.PortAddresses()
	client := netip.MustParseAddrPort("10.0.0.2:50000")
	server := netip.MustParseAddrPort("198.51.100.1:443")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now := int64(i) * int64(udpSelectorQuarantine)
		r, ok := n.reserveAt(d, 17, address, client, server, now)
		if !ok {
			b.Fatal("allocation refused after expiry")
		}
		f := &forwardFlow{nat: n, protocol: 17}
		n.publish(f, r)
		n.releaseAt(f, now)
	}
	b.StopTimer()
	n.sweepQuarantine(int64(b.N) * int64(udpSelectorQuarantine))
}
