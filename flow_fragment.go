package tun

import (
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

const (
	fragmentTimeout       = 30 * time.Second
	fragmentSweepInterval = time.Second
	fragmentTableCapacity = 4096
)

type fragmentKey struct {
	source      netip.Addr
	destination netip.Addr
	protocol    uint8
	id          uint32
}

type fragmentEntry struct {
	flow     *forwardFlow
	rule     *rewriteRule
	deadline int64
	coverage fragmentCoverage
	maxEnd   int
	total    int
}

type fragmentTable struct {
	access    sync.Mutex
	entries   map[fragmentKey]*fragmentEntry
	lastSweep int64
}

func (t *fragmentTable) insert(key fragmentKey, flow *forwardFlow, rule *rewriteRule, received int, now int64) {
	if !validFragmentRange(0, received, true) {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	if entry := t.entries[key]; entry != nil {
		if entry.deadline > now && entry.flow == flow {
			return // Duplicate first fragment must not erase coverage or extend TTL.
		}
		delete(t.entries, key)
	}
	if len(t.entries) >= fragmentTableCapacity {
		if now-t.lastSweep < int64(fragmentSweepInterval) {
			return
		}
		t.lastSweep = now
		for existingKey, entry := range t.entries {
			if entry.deadline <= now {
				delete(t.entries, existingKey)
			}
		}
		if len(t.entries) >= fragmentTableCapacity {
			return
		}
	}
	entry := &fragmentEntry{flow: flow, rule: rule, deadline: now + int64(fragmentTimeout), maxEnd: received, total: -1}
	entry.coverage.add(0, received, true)
	t.entries[key] = entry
}

func (t *fragmentTable) remove(key fragmentKey) {
	t.access.Lock()
	delete(t.entries, key)
	t.access.Unlock()
}

func (t *fragmentTable) lookup(key fragmentKey, info fragmentInfo, now int64) *fragmentEntry {
	if !validFragmentRange(info.offset, len(info.payload), info.more) {
		return nil
	}
	t.access.Lock()
	defer t.access.Unlock()
	entry := t.entries[key]
	if entry == nil {
		return nil
	}
	if entry.deadline <= now {
		delete(t.entries, key)
		return nil
	}
	end := info.offset + len(info.payload)
	if !info.more {
		if entry.total == -2 || (entry.total >= 0 && entry.total != end) || entry.maxEnd > end {
			entry.total = -2 // Conflicting final lengths poison completion until expiry.
			return nil
		}
		entry.total = end
	}
	if entry.total >= 0 && end > entry.total {
		entry.total = -2
		return nil
	}
	entry.maxEnd = max(entry.maxEnd, end)
	entry.coverage.add(info.offset, len(info.payload), info.more)
	if entry.coverage.complete(entry.total) {
		delete(t.entries, key)
	}
	return entry
}

type fragmentInfo struct {
	protocol uint8
	id       uint32
	offset   int
	more     bool
	payload  []byte
}

func parseFragment(parsed *forwardPacket) (fragmentInfo, bool) {
	if parsed.ipVersion == 4 {
		ipHdr := header.IPv4(parsed.network)
		return fragmentInfo{
			protocol: parsed.protocol,
			id:       uint32(ipHdr.ID()),
			offset:   int(ipHdr.FragmentOffset()),
			more:     ipHdr.More(),
			payload:  ipHdr.Payload(),
		}, true
	}
	fragmentHeader := header.IPv6Fragment(header.IPv6(parsed.network).Payload())
	if !fragmentHeader.IsValid() {
		return fragmentInfo{}, false
	}
	return fragmentInfo{
		protocol: fragmentHeader.NextHeader(),
		id:       fragmentHeader.ID(),
		offset:   int(fragmentHeader.FragmentOffset()) * 8,
		more:     fragmentHeader.More(),
		payload:  fragmentHeader.Payload(),
	}, true
}

func (r *portReturn) classifyFragment(parsed *forwardPacket, size int, now int64) (returnDecision, ForwardWriteback) {
	info, ok := parseFragment(parsed)
	if !ok || !validFragmentRange(info.offset, len(info.payload), info.more) {
		return returnPass, nil
	}
	key := fragmentKey{
		source:      parsed.source.Addr(),
		destination: parsed.destination.Addr(),
		protocol:    info.protocol,
		id:          info.id,
	}
	if info.offset == 0 {
		parsed.protocol = info.protocol
		parsed.parseTransport(info.payload)
		var (
			flow *forwardFlow
			rule *rewriteRule
		)
		if parsed.hasFlow {
			flow, rule = r.matchReverse(parsed)
		}
		if flow == nil {
			r.fragments.remove(key)
			return returnPass, nil
		}
		if info.more {
			r.fragments.insert(key, flow, rule, len(info.payload), now)
		}
		if flow.closed.Load() {
			return returnDrop, nil
		}
		if flow.tracker != nil {
			flow.tracker.CountReverse(size)
		}
		flow.observeReverse(parsed, now)
		applyRewrite(parsed, rule)
		return returnWrite, flow.owner.writeback
	}
	entry := r.fragments.lookup(key, info, now)
	if entry == nil {
		return returnPass, nil
	}
	if entry.flow.closed.Load() {
		return returnDrop, nil
	}
	if entry.flow.tracker != nil {
		entry.flow.tracker.CountReverse(size)
	}
	entry.flow.lastReverse.Store(now)
	applyRewriteAddresses(parsed, entry.rule)
	return returnWrite, entry.flow.owner.writeback
}
