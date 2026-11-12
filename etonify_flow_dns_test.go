package tun

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type etonifyBlockingDNSHandler struct {
	Handler
	entered  chan struct{}
	release  chan struct{}
	finished chan etonifyDNSResult
}

type etonifyDNSPacketHandler struct {
	Handler
	handle func(N.PacketWriter)
}

func (h etonifyDNSPacketHandler) NewDNSPacket(_ []byte, _, _ M.Socksaddr, writer N.PacketWriter) {
	h.handle(writer)
}

type etonifyDNSWriteback struct {
	writes int
}

func (*etonifyDNSWriteback) ReturnHeadroom() int { return 0 }

func (w *etonifyDNSWriteback) WriteReturnPackets(packets [][]byte) error {
	w.writes += len(packets)
	return nil
}

func TestEtonifyDNSHijackBoundsBlockedHandlers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{}, flowDNSConcurrency+1)
		release := make(chan struct{})
		defer close(release)
		handler := etonifyDNSPacketHandler{handle: func(N.PacketWriter) {
			started <- struct{}{}
			<-release
		}}
		dispatcher := NewForwardDispatcher(handler, nil, logger.NOP(), 0, UDPNatOptions{}, 0)
		defer dispatcher.Close()
		packet := forwardPacket{transport: make([]byte, header.UDPMinimumSize)}
		for range flowDNSConcurrency + 1 {
			dispatcher.hijackDNSPacket(&packet, 0)
		}
		synctest.Wait()
		if got := len(started); got != flowDNSConcurrency {
			t.Fatalf("started %d blocked handlers, want %d", got, flowDNSConcurrency)
		}
	})
}

func TestEtonifyDNSHijackDiscardsPreResetReplies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		writers := make(chan N.PacketWriter, 1)
		handler := etonifyDNSPacketHandler{handle: func(writer N.PacketWriter) { writers <- writer }}
		writeback := new(etonifyDNSWriteback)
		dispatcher := NewForwardDispatcher(handler, writeback, logger.NOP(), 0, UDPNatOptions{}, 0)
		defer dispatcher.Close()
		packet := forwardPacket{
			transport:   make([]byte, header.UDPMinimumSize),
			source:      netip.MustParseAddrPort("198.18.0.2:12345"),
			destination: netip.MustParseAddrPort("198.18.0.1:53"),
		}
		dispatcher.hijackDNSPacket(&packet, 0)
		oldWriter := <-writers
		dispatcher.ResetNetwork()
		destination := M.SocksaddrFromNetIP(packet.destination)
		if err := oldWriter.WritePacket(buf.As([]byte("old")), destination); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("pre-reset reply returned %v, want os.ErrClosed", err)
		}
		dispatcher.hijackDNSPacket(&packet, dispatcher.resetGeneration.Load())
		newWriter := <-writers
		if err := newWriter.WritePacket(buf.As([]byte("new")), destination); err != nil {
			t.Fatal(err)
		}
		if got := writeback.writes; got != 1 {
			t.Fatalf("wrote %d replies, want only the post-reset reply", got)
		}
	})
}

type etonifyDNSResult struct {
	payload []byte
	err     error
}

func (h *etonifyBlockingDNSHandler) JudgeFlow(_ uint8, _, destination netip.AddrPort, _ []byte) FlowVerdict {
	if destination.Port() == 53 {
		return FlowVerdict{Action: ActionHijackDNS}
	}
	return FlowVerdict{Action: ActionAccept}
}

func (h *etonifyBlockingDNSHandler) NewDNSPacket(payload []byte, _, destination M.Socksaddr, writer N.PacketWriter) {
	close(h.entered)
	<-h.release
	err := writer.WritePacket(buf.As([]byte("reply")), destination)
	h.finished <- etonifyDNSResult{bytes.Clone(payload), err}
}

func TestEtonifyBlockedDNSDoesNotStopGoStack(t *testing.T) {
	handler := &etonifyBlockingDNSHandler{
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		finished: make(chan etonifyDNSResult, 1),
	}
	device := NewMemoryTun(MemoryTunOptions{MTU: 1500})
	t.Cleanup(func() { device.Close() })
	stack, err := NewGo(StackOptions{
		Context: context.Background(), Tun: device, TunOptions: Options{MTU: 1500},
		Handler: handler, Logger: logger.NOP(), UDPTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stack.Close() })
	local := netip.MustParseAddrPort("198.18.0.2:12345")
	remote := netip.MustParseAddrPort("198.18.0.1:54321")
	socket, err := stack.ListenUDP(local)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			close(handler.release)
		}
	})
	writePacket := func(source, destination netip.AddrPort, payload []byte) {
		t.Helper()
		packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
		goEncodeUDPPacket(packet, 4, source, destination, payload, 1)
		if _, writeErr := device.Write(packet); writeErr != nil {
			t.Fatal(writeErr)
		}
		clear(packet)
	}
	query := []byte("query")
	writePacket(local, netip.AddrPortFrom(remote.Addr(), 53), query)
	select {
	case <-handler.entered:
	case <-time.After(time.Second):
		t.Fatal("DNS request did not reach the handler")
	}
	udp := []byte("other traffic")
	writePacket(remote, local, udp)
	socket.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [32]byte
	n, _, err := socket.ReadFrom(buffer[:])
	if err != nil {
		t.Fatalf("unrelated UDP packet stalled while DNS was blocked: %v", err)
	}
	if !bytes.Equal(buffer[:n], udp) {
		t.Fatalf("received %q, want %q", buffer[:n], udp)
	}
	closed := make(chan error, 1)
	go func() { closed <- stack.Close() }()
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Go stack close stalled while DNS was blocked")
	}
	close(handler.release)
	released = true
	select {
	case result := <-handler.finished:
		if !bytes.Equal(result.payload, query) {
			t.Fatalf("DNS payload changed to %q, want %q", result.payload, query)
		}
		if !errors.Is(result.err, os.ErrClosed) {
			t.Fatalf("late DNS reply returned %v, want os.ErrClosed", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS request did not finish")
	}
}
