package tun

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type etonifyJudgeHandler struct {
	Handler
	entered chan struct{}
	release chan struct{}
}

func (h *etonifyJudgeHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	close(h.entered)
	<-h.release
	return FlowVerdict{Action: ActionAccept}
}

func TestEtonifyJudgeDoesNotBlockDispatch(t *testing.T) {
	h := &etonifyJudgeHandler{entered: make(chan struct{}), release: make(chan struct{})}
	d := NewForwardDispatcher(h, nil, logger.NOP(), UDPNatOptions{}, 0)
	defer d.Close()
	released := false
	defer func() {
		if !released {
			close(h.release)
		}
	}()
	ready := make(chan struct{}, 1)
	s := d.NewStage(nil, func() { ready <- struct{}{} })
	done := make(chan bool, 1)
	packet := goHairpinTestPacket(t, false)
	go func() { done <- s.Dispatch(packet) }()
	<-h.entered
	select {
	case handled := <-done:
		if !handled {
			t.Fatal("pending flow not held")
		}
	case <-time.After(time.Second):
		t.Fatal("JudgeFlow blocked packet dispatch")
	}
	want := bytes.Clone(packet)
	for range 20 {
		s.Dispatch(packet)
	}
	clear(packet)
	close(h.release)
	released = true
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("judgement did not resume")
	}
	count := 0
	s.ResumeJudged(func(packet []byte, _ ForwardFrameMeta) {
		count++
		if !bytes.Equal(packet, want) {
			t.Fatal("held packet aliases reused input")
		}
	})
	if count != 16 {
		t.Fatalf("resumed packets=%d, want bounded batch of 16", count)
	}
	if s.held != 0 || len(s.judging) != 0 {
		t.Fatal("resumed queue retained packets")
	}
}

func TestEtonifyExplicitFlowCloseExpiresImmediately(t *testing.T) {
	f := &forwardFlow{}
	entry := &flowEntry{action: ActionFlow, flow: f, deadline: int64(time.Hour)}
	f.CloseFlow()
	if !entryExpired(entry, 0) {
		t.Fatal("explicitly closed flow remains cached and drops new packets")
	}
}

func TestEtonifyJudgedQueueDiscardedOnResetOrClose(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "reset", true: "close"}[shutdown], func(t *testing.T) {
			h := &etonifyJudgeHandler{entered: make(chan struct{}), release: make(chan struct{})}
			d := NewForwardDispatcher(h, nil, logger.NOP(), UDPNatOptions{}, 0)
			defer d.Close()
			ready := make(chan struct{}, 1)
			s := d.NewStage(nil, func() { ready <- struct{}{} })
			s.Dispatch(goHairpinTestPacket(t, false))
			<-h.entered
			close(h.release)
			select {
			case <-ready:
			case <-time.After(time.Second):
				t.Fatal("judgement did not resume")
			}
			if shutdown {
				d.Close()
			} else {
				d.ResetNetwork()
			}
			s.ResumeJudged(func([]byte, ForwardFrameMeta) { t.Fatal("stale judgement replayed") })
			if s.held != 0 || len(s.judging) != 0 || len(s.judged) != 0 {
				t.Fatal("cancelled queue retained packets")
			}
		})
	}
}
