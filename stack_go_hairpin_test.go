package tun

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type goHairpinTestIO struct {
	goPlatformIO
	pending   [][]byte
	delivered [][]byte
	blocked   bool
}

func (o *goHairpinTestIO) writeFrame([][]byte, ForwardFrameMeta) error {
	return errGoTransmitBlocked
}

func (o *goHairpinTestIO) writeData(frame [][]byte, _ ForwardFrameMeta, _ *GoConn, _ uint64) error {
	if o.blocked {
		return errGoTransmitBlocked
	}
	o.pending = append(o.pending, frame...)
	return nil
}

func (o *goHairpinTestIO) flush() {
	for _, packet := range o.pending {
		o.delivered = append(o.delivered, bytes.Clone(packet))
	}
	o.pending = nil
}

func goHairpinTestPacket(t *testing.T, ipv6 bool) []byte {
	t.Helper()
	encoded := "4500002c123400004006dc70c6120002c6120001303901bb10203040000000005002100003c50000deadbeef"
	if ipv6 {
		encoded = "6000000000180640fd000000000000000000000000000002fd000000000000000000000000000001303901bb10203040000000005002100095e80000deadbeef"
	}
	packet, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func goHairpinTestEngine() (*goEngine, *goHairpinTestIO) {
	platformIO := &goHairpinTestIO{}
	engine := &goEngine{
		stack: &Go{
			logger:               logger.NOP(),
			validateChecksum:     true,
			inet4LoopbackAddress: []netip.Addr{netip.MustParseAddr("198.18.0.1")},
			inet6LoopbackAddress: []netip.Addr{netip.MustParseAddr("fd00::1")},
		},
		platformIO:        platformIO,
		reassemblyEntries: make([]goReassemblyEntry, 1),
	}
	engine.packetReadOptions.Store(new(N.ReadWaitOptions))
	return engine, platformIO
}

func goHairpinTestDelivered(t *testing.T, platformIO *goHairpinTestIO, original []byte) {
	t.Helper()
	if len(platformIO.pending) != 0 || len(platformIO.delivered) != 1 {
		t.Fatalf("hairpin delivery: pending=%d delivered=%d, want 0/1", len(platformIO.pending), len(platformIO.delivered))
	}
	want := bytes.Clone(original)
	if header.IPVersion(original) == 4 {
		copy(want[12:16], original[16:20])
		copy(want[16:20], original[12:16])
	} else {
		copy(want[8:24], original[24:40])
		copy(want[24:40], original[8:24])
	}
	if !bytes.Equal(platformIO.delivered[0], want) {
		t.Fatalf("hairpin changed fields other than IP addresses:\n got %x\nwant %x", platformIO.delivered[0], want)
	}
}

func TestGoHairpinQueuedWrite(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(t *testing.T) {
			engine, platformIO := goHairpinTestEngine()
			original := goHairpinTestPacket(t, ipv6)
			packet := bytes.Clone(original)
			parsed, ok := parseForwardPacket(packet)
			if !ok || !goValidateTransportChecksum(&parsed) {
				t.Fatal("invalid TCP fixture")
			}
			if !engine.handleLoopbackHairpin(packet, ForwardFrameMeta{}, &parsed) {
				t.Fatal("loopback TCP packet not handled")
			}
			platformIO.flush()
			goHairpinTestDelivered(t, platformIO, original)
		})
	}
}

func TestGoHairpinInjectedFlush(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(t *testing.T) {
			engine, platformIO := goHairpinTestEngine()
			original := goHairpinTestPacket(t, ipv6)
			engine.injectStack.push(&goInjectedFrame{buffer: buf.As(bytes.Clone(original))})
			engine.injectCount.Add(1)
			engine.processInjected()
			goHairpinTestDelivered(t, platformIO, original)
			if engine.injectCount.Load() != 0 {
				t.Fatal("injected frame retained")
			}
		})
	}
}

func TestGoHairpinReassemblyFlush(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(t *testing.T) {
			engine, platformIO := goHairpinTestEngine()
			original := goHairpinTestPacket(t, ipv6)
			headerLength := header.IPv4MinimumSize
			if ipv6 {
				headerLength = header.IPv6MinimumSize
			}
			for _, offset := range []int{16, 0} {
				payload := original[headerLength+offset:]
				if offset == 0 {
					payload = payload[:16]
				}
				fragment := bytes.Clone(original[:headerLength])
				if ipv6 {
					fragment[6] = header.IPv6FragmentHeader
					binary.BigEndian.PutUint16(fragment[4:6], uint16(8+len(payload)))
					fragmentHeader := []byte{6, 0, 0, 0, 0, 0, 0x12, 0x34}
					binary.BigEndian.PutUint16(fragmentHeader[2:4], uint16(offset))
					if offset == 0 {
						fragmentHeader[3] |= 1
					}
					fragment = append(fragment, fragmentHeader...)
				} else {
					ipHdr := header.IPv4(fragment)
					flags := uint8(0)
					if offset == 0 {
						flags = header.IPv4FlagMoreFragments
					}
					ipHdr.SetFlagsFragmentOffset(flags, uint16(offset))
					ipHdr.SetTotalLength(uint16(headerLength + len(payload)))
					ipHdr.SetChecksum(0)
					ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
				}
				fragment = append(fragment, payload...)
				buffer := buf.As(fragment)
				engine.processFrame(&goFrame{buffer: buffer})
				buffer.Release()
			}
			goHairpinTestDelivered(t, platformIO, original)
			if engine.reassemblyEntries[0].active || engine.reassemblyEntries[0].buffer != nil {
				t.Fatal("completed fragment buffer retained")
			}
		})
	}
}

type goHairpinTestLogger struct {
	logger.Logger
	warnings []string
}

func (l *goHairpinTestLogger) Warn(args ...any) {
	l.warnings = append(l.warnings, fmt.Sprint(args...))
}

func TestGoHairpinBlockedWriteReportsDrop(t *testing.T) {
	engine, platformIO := goHairpinTestEngine()
	platformIO.blocked = true
	log := &goHairpinTestLogger{Logger: logger.NOP()}
	engine.stack.logger = log
	for range 2 {
		packet := goHairpinTestPacket(t, false)
		parsed, _ := parseForwardPacket(packet)
		if !engine.handleLoopbackHairpin(packet, ForwardFrameMeta{}, &parsed) {
			t.Fatal("blocked hairpin packet not consumed")
		}
	}
	if len(log.warnings) != 1 || !strings.Contains(log.warnings[0], "loopback frames") {
		t.Fatalf("expected rate-limited hairpin drop warning, got %v", log.warnings)
	}
	if len(platformIO.pending) != 0 || len(platformIO.delivered) != 0 {
		t.Fatal("blocked packet queued for delivery")
	}
}
