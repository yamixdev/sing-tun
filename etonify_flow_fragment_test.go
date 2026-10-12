package tun

import (
	"net/netip"
	"testing"
	"time"
)

func etonifyFragmentTable() (fragmentTable, fragmentKey, *forwardFlow) {
	return fragmentTable{entries: make(map[fragmentKey]*fragmentEntry)}, fragmentKey{source: netip.MustParseAddr("192.0.2.1"), protocol: 17}, &forwardFlow{}
}

func TestEtonifyFragmentDuplicateAndOverlap(t *testing.T) {
	for _, offsets := range [][]int{{16, 16, 48, 32}, {32, 16, 16, 48}, {16, 24, 48, 32}} {
		table, key, flow := etonifyFragmentTable()
		table.insert(key, flow, &rewriteRule{}, 16, 0)
		for _, offset := range offsets {
			if table.lookup(key, fragmentInfo{offset: offset, more: offset != 48, payload: make([]byte, 16)}, 1) == nil {
				t.Fatalf("offset %d lost association; order %v", offset, offsets)
			}
		}
		if len(table.entries) != 0 {
			t.Fatal("complete coverage retained")
		}
	}
}

func TestEtonifyFragmentDuplicateFirstKeepsCoverageAndExpiry(t *testing.T) {
	table, key, flow := etonifyFragmentTable()
	rule := &rewriteRule{}
	table.insert(key, flow, rule, 16, 0)
	table.lookup(key, fragmentInfo{offset: 16, more: true, payload: make([]byte, 16)}, 1)
	table.insert(key, flow, rule, 16, int64(20*time.Second))
	entry := table.lookup(key, fragmentInfo{offset: 32, payload: make([]byte, 16)}, int64(21*time.Second))
	if entry == nil || len(table.entries) != 0 {
		t.Fatal("duplicate first erased previous coverage")
	}
	table.insert(key, flow, rule, 16, 0)
	table.insert(key, flow, rule, 16, int64(20*time.Second))
	if table.lookup(key, fragmentInfo{offset: 16, payload: make([]byte, 16)}, int64(fragmentTimeout)+1) != nil {
		t.Fatal("duplicate first extended fixed expiry")
	}
}

func TestEtonifyFragmentInvalidAndConflictingFinal(t *testing.T) {
	for _, size := range []int{-1, 0, 9, 65536} {
		table, key, flow := etonifyFragmentTable()
		table.insert(key, flow, &rewriteRule{}, size, 0)
		if len(table.entries) != 0 {
			t.Fatalf("invalid first size %d allocated", size)
		}
	}
	for _, info := range []fragmentInfo{
		{offset: -8, payload: make([]byte, 8)}, {offset: 1, payload: make([]byte, 8)},
		{offset: 16, more: true, payload: make([]byte, 9)}, {offset: 65528, payload: make([]byte, 8)},
	} {
		table, key, flow := etonifyFragmentTable()
		table.insert(key, flow, &rewriteRule{}, 16, 0)
		if table.lookup(key, info, 1) != nil {
			t.Fatal("invalid range accepted")
		}
		if table.lookup(key, fragmentInfo{offset: 16, payload: make([]byte, 16)}, 2) == nil {
			t.Fatal("invalid range changed association")
		}
	}
	table, key, flow := etonifyFragmentTable()
	table.insert(key, flow, &rewriteRule{}, 16, 0)
	table.lookup(key, fragmentInfo{offset: 48, payload: make([]byte, 16)}, 1)
	table.lookup(key, fragmentInfo{offset: 32, payload: make([]byte, 16)}, 2)
	table.lookup(key, fragmentInfo{offset: 16, more: true, payload: make([]byte, 16)}, 3)
	if len(table.entries) != 1 {
		t.Fatal("conflicting final lengths declared completion")
	}
}

func TestEtonifyFragmentCapacityAndDifferentFlow(t *testing.T) {
	table, key, flow := etonifyFragmentTable()
	for i := 0; i < fragmentTableCapacity+1; i++ {
		key.id = uint32(i)
		table.insert(key, flow, nil, 16, 0)
	}
	if len(table.entries) != fragmentTableCapacity {
		t.Fatal("capacity not bounded")
	}
	key.id = 0
	newFlow := &forwardFlow{}
	table.insert(key, newFlow, nil, 16, 1)
	if table.entries[key].flow != newFlow {
		t.Fatal("replacement blocked by full cache")
	}
	key.id = 9000
	table.insert(key, flow, nil, 16, int64(fragmentTimeout)+1)
	if len(table.entries) != 1 {
		t.Fatal("expired full cache did not sweep")
	}
}

func BenchmarkEtonifyFragmentDuplicates(b *testing.B) {
	table, key, flow := etonifyFragmentTable()
	table.insert(key, flow, nil, 16, 0)
	info := fragmentInfo{offset: 16, more: true, payload: make([]byte, 16)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table.lookup(key, info, 1)
	}
}

func TestEtonifyFragmentCoverageBounds(t *testing.T) {
	var coverage fragmentCoverage
	if !coverage.add(0, 65528, true) || coverage.complete(65535) || !coverage.add(65528, 7, false) || !coverage.complete(65535) {
		t.Fatal("maximum payload coverage")
	}
	before := coverage
	for _, r := range [][3]int{{-8, 8, 0}, {1, 8, 0}, {0, 9, 1}, {65528, 8, 0}, {int(^uint(0)>>1) - 7, 16, 0}} {
		if coverage.add(r[0], r[1], r[2] != 0) || coverage != before {
			t.Fatal("invalid range mutated bitmap")
		}
	}
	for _, total := range []int{-1, 0, 65536} {
		if coverage.complete(total) {
			t.Fatal("invalid total complete")
		}
	}
}

func BenchmarkEtonifyFragmentFullCache(b *testing.B) {
	table, key, flow := etonifyFragmentTable()
	for i := 0; i < fragmentTableCapacity; i++ {
		key.id = uint32(i)
		table.insert(key, flow, nil, 16, 0)
	}
	key.id = 9000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table.insert(key, flow, nil, 16, 0)
	}
	if len(table.entries) != fragmentTableCapacity {
		b.Fatal("cache grew")
	}
}
