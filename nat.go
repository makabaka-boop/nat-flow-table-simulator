// Package natsim is an in-process simulation of endpoint-dependent UDP NAT for a
// test network with one public IPv4 address. It translates packet descriptions
// rather than sending or receiving real network packets.
package natsim

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MinPublicPort is the first public UDP port that NAT may allocate.
	MinPublicPort uint16 = 40000
	// MaxPublicPort is the last public UDP port that NAT may allocate.
	MaxPublicPort uint16 = 40127
	// mappingTTL is the idle lifetime of a NAT mapping.
	mappingTTL = 30 * time.Second
)

// Protocol identifies a simulated network protocol.
type Protocol uint8

const (
	UDP Protocol = 1
)

func (p Protocol) String() string {
	switch p {
	case UDP:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

// Direction is the direction in which a simulated packet traverses NAT.
type Direction uint8

const (
	Outbound Direction = 1
	Inbound  Direction = 2
)

// Reason describes why NAT refused to translate a packet.
type Reason string

const (
	// ReasonNone means the packet was accepted.
	ReasonNone Reason = ""
	// ReasonNotUDP means the packet did not use UDP.
	ReasonNotUDP Reason = "protocol is not UDP"
	// ReasonInvalidDirection means the caller supplied an unknown direction.
	ReasonInvalidDirection Reason = "invalid packet direction"
	// ReasonInvalidSource means the source endpoint is not a usable IPv4 endpoint.
	ReasonInvalidSource Reason = "invalid source IPv4 endpoint"
	// ReasonInvalidDestination means the destination endpoint is not a usable IPv4 endpoint.
	ReasonInvalidDestination Reason = "invalid destination IPv4 endpoint"
	// ReasonHairpinNotSupported means an internal host sent a packet to the NAT's own public endpoint.
	ReasonHairpinNotSupported Reason = "hairpin to NAT public endpoint is not supported"
	// ReasonWrongDestination means an inbound packet did not arrive at the NAT public address.
	ReasonWrongDestination Reason = "inbound destination is not the NAT public address"
	// ReasonNoMapping means no active mapping uses the packet's public destination port.
	ReasonNoMapping Reason = "no active mapping for public destination port"
	// ReasonRemoteMismatch means the inbound remote endpoint does not match the mapping.
	ReasonRemoteMismatch Reason = "inbound remote tuple does not match mapping"
	// ReasonPortsExhausted means every public port in the configured range is active.
	ReasonPortsExhausted Reason = "all public UDP ports are in use"
)

// Clock allows tests to control expiry without waiting in real time.
type Clock interface {
	Now() time.Time
}

// SystemClock reads the operating system clock.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

// ControlledClock is a goroutine-safe manually advanced clock for tests.
type ControlledClock struct {
	now atomic.Int64
}

// NewControlledClock creates a clock at t.
func NewControlledClock(t time.Time) *ControlledClock {
	c := &ControlledClock{}
	c.now.Store(t.UnixNano())
	return c
}

// Now returns the controlled time.
func (c *ControlledClock) Now() time.Time {
	return time.Unix(0, c.now.Load()).UTC()
}

// Advance moves the controlled clock forward.
func (c *ControlledClock) Advance(d time.Duration) {
	c.now.Add(d.Nanoseconds())
}

// Packet is a simulated UDP/IP packet's addressing information.
type Packet struct {
	Protocol    Protocol
	Source      netip.AddrPort
	Destination netip.AddrPort
}

func (p Packet) String() string {
	return fmt.Sprintf("%s %s -> %s", p.Protocol, p.Source, p.Destination)
}

// IsValid reports whether both packet endpoints are usable address-port pairs.
func (p Packet) IsValid() bool {
	return p.Source.IsValid() && p.Destination.IsValid()
}

// MappingKey is the full four-tuple which owns an endpoint-dependent mapping.
type MappingKey struct {
	InternalAddr [4]byte
	InternalPort uint16
	RemoteAddr   [4]byte
	RemotePort   uint16
}

// Result is NAT's single decision for one packet.
type Result struct {
	Direction Direction
	// Original is the packet as presented to Translate.
	Original Packet
	// Translated is the packet after NAT. It is invalid when Allowed is false.
	Translated Packet
	// Key is the mapping owner. It is the zero value when no mapping is used.
	Key MappingKey
	// PublicPort is the external port assigned to the mapping.
	PublicPort uint16
	// Created is true when this packet allocated a new mapping.
	Created bool
	// ExpiresAt is the new idle deadline after this legal use.
	ExpiresAt time.Time
	Allowed   bool
	Reason    Reason
}

func (r Result) String() string {
	if !r.Allowed {
		return fmt.Sprintf("REJECT %s %s: %s", r.Direction, r.Original, r.Reason)
	}
	if r.Direction == Outbound {
		return fmt.Sprintf("ACCEPT outbound %s => %s; mapping public port %d expires at %s",
			r.Original, r.Translated, r.PublicPort, r.ExpiresAt.Format(time.RFC3339Nano))
	}
	return fmt.Sprintf("ACCEPT inbound %s => %s; mapping public port %d expires at %s",
		r.Original, r.Translated, r.PublicPort, r.ExpiresAt.Format(time.RFC3339Nano))
}

func (d Direction) String() string {
	switch d {
	case Outbound:
		return "outbound"
	case Inbound:
		return "inbound"
	default:
		return "invalid"
	}
}

type mapping struct {
	key       MappingKey
	public    netip.AddrPort
	expiresAt time.Time
}

func (m *mapping) touch(now time.Time) {
	m.expiresAt = now.Add(mappingTTL)
}

// Service is the simulated NAT. All decisions are made while holding one mutex,
// so mapping creation, expiry recycling, port allocation and inbound admission
// observe one consistent state.
type Service struct {
	publicIP netip.Addr
	clock    Clock

	mu       sync.Mutex
	mappings map[MappingKey]*mapping
	byPort   map[uint16]*mapping
}

// New creates a NAT service for publicIP. A mapped IPv6 representation of an
// IPv4 address is accepted and canonicalized.
func New(publicIP netip.Addr, clock Clock) (*Service, error) {
	ip, ok := canonicalIPv4(publicIP)
	if !ok {
		return nil, fmt.Errorf("public address must be IPv4: %v", publicIP)
	}
	if clock == nil {
		clock = SystemClock{}
	}
	return &Service{
		publicIP: ip,
		clock:    clock,
		mappings: make(map[MappingKey]*mapping),
		byPort:   make(map[uint16]*mapping),
	}, nil
}

// PublicIP returns the NAT service's single public IPv4 address.
func (s *Service) PublicIP() netip.Addr {
	return s.publicIP
}

// ActiveMappings removes expired entries and returns the number of live mappings.
func (s *Service) ActiveMappings() int {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepExpiredLocked(now)
	return len(s.mappings)
}

// Translate makes one NAT decision. Outbound UDP packets create or refresh a
// mapping. Inbound UDP packets are forwarded only when source, source port,
// destination port and destination address exactly identify a live mapping.
func (s *Service) Translate(direction Direction, pkt Packet) Result {
	if direction != Outbound && direction != Inbound {
		return reject(direction, pkt, ReasonInvalidDirection)
	}
	if pkt.Protocol != UDP {
		return reject(direction, pkt, ReasonNotUDP)
	}

	src, srcOK := validUDPAddrPort(pkt.Source)
	if !srcOK {
		return reject(direction, pkt, ReasonInvalidSource)
	}
	dst, dstOK := validUDPAddrPort(pkt.Destination)
	if !dstOK {
		return reject(direction, pkt, ReasonInvalidDestination)
	}
	canonical := Packet{Protocol: UDP, Source: src, Destination: dst}

	switch direction {
	case Outbound:
		return s.outbound(pkt, canonical)
	case Inbound:
		return s.inbound(pkt, canonical)
	default:
		return reject(direction, pkt, ReasonInvalidDirection)
	}
}

func (s *Service) outbound(original, pkt Packet) Result {
	// Internal hosts cannot use the NAT address as a destination in this model.
	if pkt.Destination.Addr() == s.publicIP {
		return reject(Outbound, original, ReasonHairpinNotSupported)
	}
	// A packet apparently sourced by NAT's own public address is not internal.
	if pkt.Source.Addr() == s.publicIP {
		return reject(Outbound, original, ReasonInvalidSource)
	}

	key := MappingKey{
		InternalAddr: pkt.Source.Addr().As4(),
		InternalPort: pkt.Source.Port(),
		RemoteAddr:   pkt.Destination.Addr().As4(),
		RemotePort:   pkt.Destination.Port(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	created := false
	now := s.clock.Now()
	s.sweepExpiredLocked(now)

	m, ok := s.mappings[key]
	if !ok {
		// The single NAT lock serializes map creation and smallest-port choice.
		port, found := s.smallestFreePortLocked()
		if !found {
			return reject(Outbound, original, ReasonPortsExhausted)
		}
		m = &mapping{
			key:    key,
			public: netip.AddrPortFrom(s.publicIP, port),
		}
		s.mappings[key] = m
		s.byPort[port] = m
		created = true
	}

	m.touch(now)
	return Result{
		Direction:  Outbound,
		Original:   original,
		Translated: Packet{Protocol: UDP, Source: m.public, Destination: pkt.Destination},
		Key:        key,
		PublicPort: m.public.Port(),
		Created:    created,
		ExpiresAt:  m.expiresAt,
		Allowed:    true,
		Reason:     ReasonNone,
	}
}

func (s *Service) inbound(original, pkt Packet) Result {
	if pkt.Destination.Addr() != s.publicIP {
		return reject(Inbound, original, ReasonWrongDestination)
	}
	// Public clients are not behind the NAT.
	if pkt.Source.Addr() == s.publicIP {
		return reject(Inbound, original, ReasonInvalidSource)
	}

	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepExpiredLocked(now)
	m, ok := s.byPort[pkt.Destination.Port()]
	if !ok {
		return reject(Inbound, original, ReasonNoMapping)
	}

	if pkt.Source.Addr().As4() != m.key.RemoteAddr || pkt.Source.Port() != m.key.RemotePort {
		return reject(Inbound, original, ReasonRemoteMismatch)
	}

	internal := netip.AddrPortFrom(netip.AddrFrom4(m.key.InternalAddr), m.key.InternalPort)
	m.touch(now)
	return Result{
		Direction: Inbound,
		Original:  original,
		Translated: Packet{
			Protocol:    UDP,
			Source:      pkt.Source,
			Destination: internal,
		},
		Key:        m.key,
		PublicPort: m.public.Port(),
		Created:    false,
		ExpiresAt:  m.expiresAt,
		Allowed:    true,
		Reason:     ReasonNone,
	}
}

func (m *mapping) aliveAt(now time.Time) bool {
	return now.Before(m.expiresAt)
}

// sweepExpiredLocked deletes every mapping whose deadline has arrived. A call at
// exactly expiresAt deletes the mapping, so its port is immediately reusable.
func (s *Service) sweepExpiredLocked(now time.Time) {
	for _, m := range s.byPort {
		if !m.aliveAt(now) {
			s.deleteMappingLocked(m)
		}
	}
}

func (s *Service) deleteMappingLocked(m *mapping) {
	delete(s.mappings, m.key)
	if current := s.byPort[m.public.Port()]; current == m {
		delete(s.byPort, m.public.Port())
	}
}

func (s *Service) smallestFreePortLocked() (uint16, bool) {
	for port := MinPublicPort; port <= MaxPublicPort; port++ {
		if _, occupied := s.byPort[port]; !occupied {
			return port, true
		}
	}
	return 0, false
}

func reject(direction Direction, pkt Packet, reason Reason) Result {
	return Result{
		Direction: direction,
		Original:  pkt,
		Allowed:   false,
		Reason:    reason,
	}
}

func validUDPAddrPort(v netip.AddrPort) (netip.AddrPort, bool) {
	if !v.IsValid() || v.Port() == 0 {
		return netip.AddrPort{}, false
	}
	ip, ok := canonicalIPv4(v.Addr())
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, v.Port()), true
}

func canonicalIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.IsValid() {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}
