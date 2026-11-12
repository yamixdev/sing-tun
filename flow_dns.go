package tun

import (
	"bytes"
	"math"
	"net/netip"
	"os"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const flowDNSConcurrency = 64

func (d *ForwardDispatcher) hijackDNSPacket(packet *forwardPacket, generation uint32) {
	if !d.dnsPacketCurrent(generation) {
		return
	}
	// The handler can wait for an upstream dial. Drop DNS datagrams under
	// load instead of waiting on the packet engine or holding the stage lock.
	select {
	case d.dnsInFlight <- struct{}{}:
	default:
		return
	}
	payload := bytes.Clone(header.UDP(packet.transport).Payload())
	source, destination := packet.source, packet.destination
	go func() {
		defer func() { <-d.dnsInFlight }()
		if d.dnsPacketCurrent(generation) {
			writer := &dnsResponseWriter{dispatcher: d, generation: generation, source: source}
			d.handler.NewDNSPacket(payload, M.SocksaddrFromNetIP(source), M.SocksaddrFromNetIP(destination), writer)
		}
	}()
}

func (d *ForwardDispatcher) dnsPacketCurrent(generation uint32) bool {
	return !d.closed.Load() && d.resetGeneration.Load() == generation
}

type dnsResponseWriter struct {
	dispatcher *ForwardDispatcher
	generation uint32
	source     netip.AddrPort
}

func (w *dnsResponseWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if !destination.IsIP() {
		return E.New("invalid destination: ", destination)
	}
	sourceAddr := w.source.Addr().Unmap()
	destinationAddr := destination.Addr.Unmap()
	headroom := w.dispatcher.writeback.ReturnHeadroom()
	udpLen := header.UDPMinimumSize + buffer.Len()
	var (
		packet []byte
		udpHdr header.UDP
		ipHdr  header.Network
	)
	if sourceAddr.Is4() {
		if !destinationAddr.Is4() {
			return E.New("send IPv6 packet to IPv4 connection")
		}
		size := header.IPv4MinimumSize + udpLen
		if size > math.MaxUint16 {
			return E.New("DNS response too large: ", buffer.Len())
		}
		packet = make([]byte, headroom+size)
		inet4Hdr := header.IPv4(packet[headroom:])
		inet4Hdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(size),
			TTL:         synthesizedTTL,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     destinationAddr,
			DstAddr:     sourceAddr,
		})
		udpHdr = header.UDP(inet4Hdr.Payload())
		ipHdr = inet4Hdr
	} else {
		if destinationAddr.Is4() {
			destinationAddr = netip.AddrFrom16(destinationAddr.As16())
		}
		if udpLen > math.MaxUint16 {
			return E.New("DNS response too large: ", buffer.Len())
		}
		size := header.IPv6MinimumSize + udpLen
		packet = make([]byte, headroom+size)
		inet6Hdr := header.IPv6(packet[headroom:])
		inet6Hdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(udpLen),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          synthesizedTTL,
			SrcAddr:           destinationAddr,
			DstAddr:           sourceAddr,
		})
		udpHdr = header.UDP(inet6Hdr.Payload())
		ipHdr = inet6Hdr
	}
	udpHdr.Encode(&header.UDPFields{
		SrcPort: destination.Port,
		DstPort: w.source.Port(),
		Length:  uint16(udpLen),
	})
	copy(udpHdr.Payload(), buffer.Bytes())
	udpChecksum := ^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), uint16(udpLen)),
	))
	if udpChecksum == 0 {
		udpChecksum = 0xffff
	}
	udpHdr.SetChecksum(udpChecksum)
	if inet4Hdr, isInet4 := ipHdr.(header.IPv4); isInet4 {
		inet4Hdr.SetChecksum(^inet4Hdr.CalculateChecksum())
	}
	if !w.dispatcher.dnsPacketCurrent(w.generation) {
		return os.ErrClosed
	}
	return w.dispatcher.writeback.WriteReturnPackets([][]byte{packet})
}
