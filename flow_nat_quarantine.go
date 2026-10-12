package tun

import (
	"net/netip"
	"time"
)

const (
	udpSelectorQuarantine  = 4 * time.Minute
	retiredPortNATCapacity = 1024
)

var natEpoch = time.Now()

func natNow() int64 { return int64(time.Since(natEpoch)) }

// Caller owns n.access. Never invoked with the shared registry locked when a
// physical reservation is held: Port callbacks can be external code.
func (n *portNAT) expireSelectorLocked(key natSelectorKey, entry *natSelector) {
	delete(n.selectors, key)
	if entry.held {
		entry.held = false
		if reserver, ok := portCapability[PortWithSelectorReservation](n.port); ok {
			reserver.ReleaseSelector(key.protocol, netip.AddrPortFrom(key.portAddress, key.selector))
		}
	}
}

func (n *portNAT) sweepQuarantine(now int64) {
	n.access.Lock()
	defer n.access.Unlock()
	for key, entry := range n.selectors {
		if entry.references == 0 && entry.deadline <= now {
			n.expireSelectorLocked(key, entry)
		}
	}
}

func (n *portNAT) selectorQuarantined(key natSelectorKey, now int64) bool {
	n.access.RLock()
	defer n.access.RUnlock()
	entry := n.selectors[key]
	return entry != nil && entry.references == 0 && entry.deadline > now
}

// Registry -> allocator -> shard is the lock order. Retired allocators have
// already released every physical reservation, so expiry has no Port callback.
func pruneRetiredPortNATsLocked(now int64) {
	for port, n := range portNATs {
		if n.references != 0 {
			continue
		}
		n.access.Lock()
		for key, entry := range n.selectors {
			if entry.references == 0 && entry.deadline <= now {
				delete(n.selectors, key)
			}
		}
		if len(n.selectors) == 0 {
			if n.idleTimer != nil {
				n.idleTimer.Stop()
				n.idleTimer = nil
			}
			n.generation++
			delete(portNATs, port)
		}
		n.access.Unlock()
	}
}

func cleanupRetiredPortNAT(n *portNAT, generation uint64, now int64) {
	portNATAccess.Lock()
	defer portNATAccess.Unlock()
	if portNATs[n.port] != n || n.references != 0 || n.generation != generation {
		return
	}
	n.access.Lock()
	defer n.access.Unlock()
	for key, entry := range n.selectors {
		if entry.references == 0 && entry.deadline <= now {
			delete(n.selectors, key)
		}
	}
	if len(n.selectors) == 0 {
		if n.idleTimer != nil {
			n.idleTimer.Stop()
		}
		delete(portNATs, n.port)
		n.idleTimer = nil
		return
	}
	var deadline int64
	for _, entry := range n.selectors {
		deadline = max(deadline, entry.deadline)
	}
	n.idleTimer = time.AfterFunc(time.Duration(max(deadline-natNow(), 1)), func() { cleanupRetiredPortNAT(n, generation, natNow()) })
}
