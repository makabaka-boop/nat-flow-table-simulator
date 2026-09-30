// Package natsim simulates a NAT gateway that owns a single public IPv4
// address and a small UDP port pool. It never sends or receives real
// network packets: callers hand it abstract packets (endpoint tuples) and
// receive translation verdicts.
//
// Behaviour modelled:
//   - Outbound UDP creates a mapping keyed by the full 4-tuple
//     (internal IP:port, remote IP:port) — endpoint-dependent mapping.
//   - The public port is the smallest free port in the configured pool.
//   - Inbound packets are forwarded only when the remote endpoint and the
//     destination public port exactly match a live mapping —
//     endpoint-dependent filtering.
//   - A mapping expires a fixed idle timeout after its last legitimate use;
//     a port whose mapping has just expired may be handed out again.
//   - Mapping creation, port exhaustion, expiry reclamation and inbound
//     arrival are all serialised through one mutex, so two live mappings
//     can never hold the same public port.
package natsim

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Default policy values of the simulated gateway.
const (
	DefaultPortMin     = 40000
	DefaultPortMax     = 40127
	DefaultIdleTimeout = 30 * time.Second
)

// Endpoint is one side of a UDP conversation.
type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

// String renders the endpoint as "ip:port".
func (e Endpoint) String() string {
	if !e.IP.IsValid() {
		return "<invalid>"
	}
	return netip.AddrPortFrom(e.IP, e.Port).String()
}

func (e Endpoint) valid() bool {
	return e.IP.IsValid() && e.Port != 0
}

// RejectReason explains why a packet was not translated. Empty means the
// packet was accepted.
type RejectReason string

// Rejection reasons reported in translation results.
const (
	RejectNone            RejectReason = ""
	RejectInvalidEndpoint RejectReason = "invalid endpoint"
	RejectPortExhausted   RejectReason = "public port pool exhausted"
	RejectNoMapping       RejectReason = "no mapping for destination public port"
	RejectMappingExpired  RejectReason = "mapping expired"
	RejectRemoteMismatch  RejectReason = "remote endpoint does not match mapping"
)

// OutboundResult is the verdict for an internal -> remote packet.
type OutboundResult struct {
	OK        bool         // packet was translated and "sent"
	Reused    bool         // an existing mapping was reused instead of created
	Internal  Endpoint     // pre-translation source
	Public    Endpoint     // post-translation source (public IP + pooled port)
	Remote    Endpoint     // untouched destination
	Reject    RejectReason // why the packet was dropped, if !OK
	ExpiresAt time.Time    // idle-expiry deadline of the mapping, if OK
}

func (r OutboundResult) String() string {
	if !r.OK {
		return fmt.Sprintf("OUT %s -> %s: REJECTED (%s)", r.Internal, r.Remote, r.Reject)
	}
	op := "MAP"
	if r.Reused {
		op = "REUSE"
	}
	return fmt.Sprintf("OUT %s -> %s: %s as %s (expires %s)",
		r.Internal, r.Remote, op, r.Public, r.ExpiresAt.Format("15:04:05.000000"))
}

// InboundResult is the verdict for a remote -> public-port packet.
type InboundResult struct {
	OK        bool         // packet was translated and "forwarded"
	Remote    Endpoint     // pre-translation source
	Public    Endpoint     // pre-translation destination (public IP + pooled port)
	Internal  Endpoint     // post-translation destination, if OK
	Reject    RejectReason // why the packet was dropped, if !OK
	ExpiresAt time.Time    // idle-expiry deadline of the mapping, if OK
}

func (r InboundResult) String() string {
	if !r.OK {
		return fmt.Sprintf("IN  %s -> %s: REJECTED (%s)", r.Remote, r.Public, r.Reject)
	}
	return fmt.Sprintf("IN  %s -> %s: FORWARD to %s (expires %s)",
		r.Remote, r.Public, r.Internal, r.ExpiresAt.Format("15:04:05.000000"))
}

// MappingInfo is a read-only snapshot of one live mapping.
type MappingInfo struct {
	Internal  Endpoint
	Remote    Endpoint
	Public    Endpoint
	LastUsed  time.Time
	ExpiresAt time.Time
}

// mappingKey identifies a mapping: the full 4-tuple of the flow.
type mappingKey struct {
	internal Endpoint
	remote   Endpoint
}

// mapping is the state kept per live translation.
type mapping struct {
	key        mappingKey
	publicPort uint16
	lastUsed   time.Time
	expiresAt  time.Time
}

// expired reports whether the mapping is unusable at now. A mapping whose
// idle timeout has exactly elapsed counts as expired, so its public port is
// immediately reclaimable.
func (m *mapping) expired(now time.Time) bool {
	return !now.Before(m.expiresAt)
}

// NAT is the simulated gateway. The zero value is not usable; construct one
// with New or Default. All methods are safe for concurrent use: every
// decision is made while holding the single internal mutex, so concurrent
// mapping creation, port exhaustion, expiry reclamation and inbound arrival
// are arbitrated by one consistent state.
type NAT struct {
	mu          sync.Mutex
	clock       Clock
	publicIP    netip.Addr
	portMin     uint16
	portMax     uint16
	idleTimeout time.Duration

	byKey  map[mappingKey]*mapping
	byPort map[uint16]*mapping // invariant: a live public port has exactly one mapping
}

// New builds a gateway with a single public IPv4 address, an inclusive
// public UDP port pool [portMin, portMax] and an idle timeout applied after
// the last legitimate use of each mapping. A nil clock uses RealClock.
func New(publicIP netip.Addr, portMin, portMax uint16, idleTimeout time.Duration, clock Clock) *NAT {
	if !publicIP.IsValid() || !publicIP.Is4() {
		panic("natsim: publicIP must be a valid IPv4 address")
	}
	if portMin == 0 || portMax < portMin {
		panic("natsim: invalid public port range")
	}
	if idleTimeout <= 0 {
		panic("natsim: idle timeout must be positive")
	}
	if clock == nil {
		clock = RealClock{}
	}
	return &NAT{
		clock:       clock,
		publicIP:    publicIP,
		portMin:     portMin,
		portMax:     portMax,
		idleTimeout: idleTimeout,
		byKey:       make(map[mappingKey]*mapping),
		byPort:      make(map[uint16]*mapping),
	}
}

// Default builds a gateway with the default pool (40000-40127) and the
// default 30s idle timeout.
func Default(publicIP netip.Addr, clock Clock) *NAT {
	return New(publicIP, DefaultPortMin, DefaultPortMax, DefaultIdleTimeout, clock)
}

// TranslateOutbound handles a UDP packet from an internal device to a remote
// endpoint. The first packet of a 4-tuple allocates the smallest free public
// port; later packets of the same 4-tuple reuse the mapping. Every accepted
// packet resets the mapping's idle timer.
func (n *NAT) TranslateOutbound(internal, remote Endpoint) OutboundResult {
	n.mu.Lock()
	defer n.mu.Unlock()

	res := OutboundResult{Internal: internal, Remote: remote}
	if !internal.valid() || !remote.valid() {
		res.Reject = RejectInvalidEndpoint
		return res
	}

	now := n.clock.Now()
	// Reclaim before allocating: ports whose mappings have (just) expired
	// are free again and keep "smallest free port" deterministic.
	n.evictExpiredLocked(now)

	key := mappingKey{internal: internal, remote: remote}
	if m, ok := n.byKey[key]; ok {
		n.touchLocked(m, now)
		res.OK = true
		res.Reused = true
		res.Public = Endpoint{IP: n.publicIP, Port: m.publicPort}
		res.ExpiresAt = m.expiresAt
		return res
	}

	port, ok := n.allocPortLocked()
	if !ok {
		res.Reject = RejectPortExhausted
		return res
	}
	m := &mapping{key: key, publicPort: port}
	n.touchLocked(m, now)
	n.byKey[key] = m
	n.byPort[port] = m

	res.OK = true
	res.Public = Endpoint{IP: n.publicIP, Port: port}
	res.ExpiresAt = m.expiresAt
	return res
}

// TranslateInbound handles a UDP packet arriving from a remote endpoint at
// one of the gateway's public ports. It is forwarded only if the remote
// endpoint and the public port match a live mapping. A forwarded packet
// resets the mapping's idle timer; a rejected one does not.
func (n *NAT) TranslateInbound(remote Endpoint, publicPort uint16) InboundResult {
	n.mu.Lock()
	defer n.mu.Unlock()

	res := InboundResult{Remote: remote, Public: Endpoint{IP: n.publicIP, Port: publicPort}}
	if !remote.valid() {
		res.Reject = RejectInvalidEndpoint
		return res
	}

	now := n.clock.Now()
	m, ok := n.byPort[publicPort]
	if !ok {
		res.Reject = RejectNoMapping
		return res
	}
	if m.expired(now) {
		n.removeLocked(m)
		res.Reject = RejectMappingExpired
		return res
	}
	if m.key.remote != remote {
		// Endpoint-dependent filtering: only the mapped remote may talk to
		// this port, and a rejected probe is not a legitimate use.
		res.Reject = RejectRemoteMismatch
		return res
	}

	n.touchLocked(m, now)
	res.OK = true
	res.Internal = m.key.internal
	res.ExpiresAt = m.expiresAt
	return res
}

// Snapshot returns the live mappings, ordered by public port. Expired
// mappings are reclaimed as a side effect, so the result only ever contains
// usable mappings.
func (n *NAT) Snapshot() []MappingInfo {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.evictExpiredLocked(n.clock.Now())
	out := make([]MappingInfo, 0, len(n.byPort))
	for _, m := range n.byPort {
		out = append(out, MappingInfo{
			Internal:  m.key.internal,
			Remote:    m.key.remote,
			Public:    Endpoint{IP: n.publicIP, Port: m.publicPort},
			LastUsed:  m.lastUsed,
			ExpiresAt: m.expiresAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Public.Port < out[j].Public.Port })
	return out
}

// allocPortLocked returns the smallest public port not held by a live
// mapping. Callers must have evicted expired mappings first.
func (n *NAT) allocPortLocked() (uint16, bool) {
	for p := n.portMin; ; p++ {
		if _, used := n.byPort[p]; !used {
			return p, true
		}
		if p == n.portMax {
			return 0, false
		}
	}
}

// evictExpiredLocked removes every mapping whose idle timeout has elapsed.
func (n *NAT) evictExpiredLocked(now time.Time) {
	for _, m := range n.byPort {
		if m.expired(now) {
			n.removeLocked(m)
		}
	}
}

// removeLocked deletes a mapping from both indexes.
func (n *NAT) removeLocked(m *mapping) {
	delete(n.byKey, m.key)
	delete(n.byPort, m.publicPort)
}

// touchLocked records a legitimate use and pushes out the expiry deadline.
func (n *NAT) touchLocked(m *mapping, now time.Time) {
	m.lastUsed = now
	m.expiresAt = now.Add(n.idleTimeout)
}
