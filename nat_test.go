package natsim

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	publicAddr = netip.MustParseAddr("192.0.2.1")
	internalIP = netip.MustParseAddr("10.0.0.10")
	remoteIP   = netip.MustParseAddr("203.0.113.5")
	testEpoch  = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
)

func ap(addr string, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(addr), port)
}

func udp(src, dst netip.AddrPort) Packet {
	return Packet{Protocol: UDP, Source: src, Destination: dst}
}

func newTestNAT(t *testing.T) (*Service, *ControlledClock) {
	t.Helper()
	clock := NewControlledClock(testEpoch)
	svc, err := New(publicAddr, clock)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return svc, clock
}

func assertReject(t *testing.T, r Result, want Reason) {
	t.Helper()
	if r.Allowed {
		t.Fatalf("expected rejection %q, got accepted result: %s", want, r)
	}
	if r.Reason != want {
		t.Fatalf("reject reason = %q, want %q; result: %s", r.Reason, want, r)
	}
	if r.Translated.IsValid() {
		t.Fatalf("rejected packet must not have a translation: %#v", r.Translated)
	}
}

func assertAccepted(t *testing.T, r Result) {
	t.Helper()
	if !r.Allowed {
		t.Fatalf("expected accepted packet, got reason %q: %s", r.Reason, r)
	}
	if r.ExpiresAt.IsZero() || r.PublicPort == 0 {
		t.Fatalf("accepted result must identify mapping and deadline: %#v", r)
	}
}

func TestOutboundAllocatesSmallestPortsAndReusesExactTuple(t *testing.T) {
	svc, clock := newTestNAT(t)

	first := svc.Translate(Outbound, udp(ap("10.0.0.10", 5000), ap("203.0.113.5", 53)))
	assertAccepted(t, first)
	if !first.Created || first.PublicPort != 40000 {
		t.Fatalf("first mapping = created %v port %d, want new port 40000", first.Created, first.PublicPort)
	}
	wantSrc := netip.AddrPortFrom(publicAddr, 40000)
	if first.Translated.Source != wantSrc || first.Translated.Destination != ap("203.0.113.5", 53) {
		t.Fatalf("outbound translation = %s, want %s => %s", first.Translated, wantSrc, ap("203.0.113.5", 53))
	}
	if first.ExpiresAt != testEpoch.Add(30*time.Second) {
		t.Fatalf("expiry = %v, want %v", first.ExpiresAt, testEpoch.Add(30*time.Second))
	}

	second := svc.Translate(Outbound, udp(ap("10.0.0.11", 6000), ap("203.0.113.5", 443)))
	assertAccepted(t, second)
	if !second.Created || second.PublicPort != 40001 {
		t.Fatalf("second mapping = created %v port %d, want new port 40001", second.Created, second.PublicPort)
	}

	clock.Advance(10 * time.Second)
	again := svc.Translate(Outbound, udp(ap("10.0.0.10", 5000), ap("203.0.113.5", 53)))
	assertAccepted(t, again)
	if again.Created || again.PublicPort != 40000 {
		t.Fatalf("same tuple reused mapping = created %v port %d, want existing port 40000", again.Created, again.PublicPort)
	}
	if again.ExpiresAt != testEpoch.Add(40*time.Second) {
		t.Fatalf("legal outbound use expiry = %v, want %v", again.ExpiresAt, testEpoch.Add(40*time.Second))
	}
	if svc.ActiveMappings() != 2 {
		t.Fatalf("active mappings = %d, want 2", svc.ActiveMappings())
	}
}

func TestInboundRequiresRemoteFourTupleAndForwardsInternally(t *testing.T) {
	svc, clock := newTestNAT(t)
	out := svc.Translate(Outbound, udp(ap("10.0.0.10", 5000), ap("203.0.113.5", 53)))
	assertAccepted(t, out)

	validIn := udp(ap("203.0.113.5", 53), ap("192.0.2.1", 40000))
	in := svc.Translate(Inbound, validIn)
	assertAccepted(t, in)
	if in.Translated != udp(ap("203.0.113.5", 53), ap("10.0.0.10", 5000)) {
		t.Fatalf("inbound translation = %s, want %s", in.Translated, udp(ap("203.0.113.5", 53), ap("10.0.0.10", 5000)))
	}
	if in.ExpiresAt != testEpoch.Add(30*time.Second) {
		t.Fatalf("legal inbound use expiry = %v, want %v", in.ExpiresAt, testEpoch.Add(30*time.Second))
	}

	clock.Advance(time.Second)

	wrongRemoteIP := svc.Translate(Inbound, udp(ap("203.0.113.6", 53), ap("192.0.2.1", 40000)))
	assertReject(t, wrongRemoteIP, ReasonRemoteMismatch)

	wrongRemotePort := svc.Translate(Inbound, udp(ap("203.0.113.5", 54), ap("192.0.2.1", 40000)))
	assertReject(t, wrongRemotePort, ReasonRemoteMismatch)

	wrongPublicPort := svc.Translate(Inbound, udp(ap("203.0.113.5", 53), ap("192.0.2.1", 40001)))
	assertReject(t, wrongPublicPort, ReasonNoMapping)

	wrongPublicIP := svc.Translate(Inbound, udp(ap("203.0.113.5", 53), ap("198.51.100.1", 40000)))
	assertReject(t, wrongPublicIP, ReasonWrongDestination)

	// Rejected inbound packets do not refresh the mapping.
	clock.Advance(29 * time.Second)
	stale := svc.Translate(Inbound, validIn)
	assertReject(t, stale, ReasonNoMapping)
}

func TestDistinctRemoteTupleReceivesDistinctMapping(t *testing.T) {
	svc, _ := newTestNAT(t)
	toA := svc.Translate(Outbound, udp(ap("10.0.0.10", 5000), ap("203.0.113.5", 53)))
	toB := svc.Translate(Outbound, udp(ap("10.0.0.10", 5000), ap("203.0.113.6", 53)))
	assertAccepted(t, toA)
	assertAccepted(t, toB)
	if toA.PublicPort == toB.PublicPort {
		t.Fatalf("remote-dependent mappings shared public port %d", toA.PublicPort)
	}

	fromA := svc.Translate(Inbound, udp(ap("203.0.113.5", 53), ap("192.0.2.1", toA.PublicPort)))
	fromB := svc.Translate(Inbound, udp(ap("203.0.113.6", 53), ap("192.0.2.1", toB.PublicPort)))
	assertAccepted(t, fromA)
	assertAccepted(t, fromB)

	cross1 := svc.Translate(Inbound, udp(ap("203.0.113.6", 53), ap("192.0.2.1", toA.PublicPort)))
	cross2 := svc.Translate(Inbound, udp(ap("203.0.113.5", 53), ap("192.0.2.1", toB.PublicPort)))
	assertReject(t, cross1, ReasonRemoteMismatch)
	assertReject(t, cross2, ReasonRemoteMismatch)
}

func TestExpiryBoundaryAndPortRecycling(t *testing.T) {
	svc, clock := newTestNAT(t)
	out := svc.Translate(Outbound, udp(ap("10.0.0.10", 5000), ap("203.0.113.5", 53)))
	assertAccepted(t, out)

	clock.Advance(29 * time.Second)
	stillAlive := svc.Translate(Inbound, udp(ap("203.0.113.5", 53), ap("192.0.2.1", 40000)))
	assertAccepted(t, stillAlive)
	if stillAlive.ExpiresAt != testEpoch.Add(59*time.Second) {
		t.Fatalf("legal inbound use did not refresh: %v", stillAlive.ExpiresAt)
	}

	// One nanosecond short of the deadline is still live.
	clock.Advance(30*time.Second - time.Nanosecond)
	if svc.ActiveMappings() != 1 {
		t.Fatalf("mapping expired before TTL; active=%d", svc.ActiveMappings())
	}

	// Exactly at the deadline, the mapping is gone and port 40000 can be reused.
	clock.Advance(time.Nanosecond)
	expired := svc.Translate(Inbound, udp(ap("203.0.113.5", 53), ap("192.0.2.1", 40000)))
	assertReject(t, expired, ReasonNoMapping)

	reused := svc.Translate(Outbound, udp(ap("10.0.0.11", 6000), ap("203.0.113.7", 8000)))
	assertAccepted(t, reused)
	if !reused.Created || reused.PublicPort != 40000 {
		t.Fatalf("expired port allocation = created %v port %d, want 40000", reused.Created, reused.PublicPort)
	}
	if svc.ActiveMappings() != 1 {
		t.Fatalf("active mappings after recycle = %d, want 1", svc.ActiveMappings())
	}
}

func TestPortExhaustionReportsReason(t *testing.T) {
	svc, _ := newTestNAT(t)
	const count = int(MaxPublicPort-MinPublicPort) + 1

	for i := 0; i < count; i++ {
		pkt := udp(
			ap("10.0.0."+strconv.Itoa(1+i/100), uint16(1000+i%100)),
			ap("198.51.100."+strconv.Itoa(i/254), uint16(1025+i)),
		)
		// Ensure simple test endpoints above are unique and valid.
		if got := svc.Translate(Outbound, pkt); !got.Allowed {
			t.Fatalf("mapping %d unexpectedly rejected: %s", i, got)
		} else if want := MinPublicPort + uint16(i); got.PublicPort != want {
			t.Fatalf("mapping %d port = %d, want %d", i, got.PublicPort, want)
		}
	}

	extra := svc.Translate(Outbound, udp(ap("10.0.0.200", 9999), ap("198.51.100.250", 9999)))
	assertReject(t, extra, ReasonPortsExhausted)
}

func TestConcurrentDistinctMappingsAllocateUniquePorts(t *testing.T) {
	svc, _ := newTestNAT(t)
	const n = int(MaxPublicPort-MinPublicPort) + 1

	type indexedResult struct {
		index  int
		result Result
	}
	start := make(chan struct{})
	results := make(chan indexedResult, n)
	var arrived, workers sync.WaitGroup
	arrived.Add(n)
	workers.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer workers.Done()
			src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i & 255)}), uint16(1024+i))
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i & 255)}), uint16(1024+i))
			pkt := udp(src, dst)
			arrived.Done()
			<-start
			results <- indexedResult{i, svc.Translate(Outbound, pkt)}
		}(i)
	}

	arrived.Wait()
	close(start)
	go func() {
		workers.Wait()
		close(results)
	}()

	seen := make(map[uint16]int, n)
	for rr := range results {
		if !rr.result.Allowed {
			t.Fatalf("goroutine %d rejected: %s", rr.index, rr.result)
		}
		if other, exists := seen[rr.result.PublicPort]; exists {
			t.Fatalf("port %d assigned to goroutines %d and %d", rr.result.PublicPort, other, rr.index)
		}
		seen[rr.result.PublicPort] = rr.index
	}
	if len(seen) != n || svc.ActiveMappings() != n {
		t.Fatalf("unique ports=%d active=%d, want %d/%d", len(seen), svc.ActiveMappings(), n, n)
	}
	for port := MinPublicPort; port <= MaxPublicPort; port++ {
		if _, ok := seen[port]; !ok {
			t.Fatalf("port %d was not allocated", port)
		}
	}
}

func TestConcurrentSameTupleCreatesOneMapping(t *testing.T) {
	svc, _ := newTestNAT(t)
	const n = 64
	pkt := udp(ap("10.0.0.10", 5000), ap("203.0.113.5", 53))
	var wg sync.WaitGroup
	results := make(chan Result, n)
	barrier := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier
			results <- svc.Translate(Outbound, pkt)
		}()
	}
	close(barrier)
	wg.Wait()
	close(results)

	created := 0
	for r := range results {
		assertAccepted(t, r)
		if r.PublicPort != 40000 {
			t.Fatalf("same tuple got port %d, want 40000", r.PublicPort)
		}
		if r.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("same tuple created %d mappings, want 1", created)
	}
	if svc.ActiveMappings() != 1 {
		t.Fatalf("active mappings = %d, want 1", svc.ActiveMappings())
	}
}

func TestConcurrentInboundExpiryAndAllocationUseSameArbitration(t *testing.T) {
	svc, clock := newTestNAT(t)

	// Create the mapping that will expire first, then fill every other port.
	first := svc.Translate(Outbound, udp(ap("10.0.0.10", 5000), ap("203.0.113.5", 53)))
	assertAccepted(t, first)
	clock.Advance(29 * time.Second)
	for port := MinPublicPort + 1; port <= MaxPublicPort; port++ {
		offset := int(port - MinPublicPort)
		pkt := udp(
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 1, byte(offset >> 8), byte(offset & 255)}), uint16(2000+offset)),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(offset >> 8), byte(offset & 255)}), uint16(3000+offset)),
		)
		if r := svc.Translate(Outbound, pkt); !r.Allowed || r.PublicPort != port {
			t.Fatalf("setup port %d got %#v", port, r)
		}
	}
	if got := svc.ActiveMappings(); got != 128 {
		t.Fatalf("setup active mappings = %d, want 128", got)
	}
	clock.Advance(time.Second)
	if got := svc.ActiveMappings(); got != 127 {
		t.Fatalf("after exact first deadline active mappings = %d, want 127", got)
	}

	// 128 inbound attempts race with one outbound recycle. Half target the old
	// remote tuple and half the new owner's tuple; every result is deterministic.
	const inboundWorkers = 128
	const workers = inboundWorkers + 1
	var arrived, done sync.WaitGroup
	arrived.Add(workers)
	done.Add(workers)
	start := make(chan struct{})
	type rejection struct {
		reason   Reason
		newOwner bool
	}
	allocated := make(chan uint16, 1)
	allowed := make(chan uint16, inboundWorkers)
	rejected := make(chan rejection, inboundWorkers)
	outboundErrs := make(chan Reason, 1)
	validIn := udp(ap("203.0.113.5", 53), ap("192.0.2.1", 40000))
	newOut := udp(ap("10.0.0.200", 9000), ap("203.0.113.99", 9000))
	recycledIn := udp(ap("203.0.113.99", 9000), ap("192.0.2.1", 40000))

	for i := 0; i < inboundWorkers; i++ {
		pkt := validIn
		if i%2 == 0 {
			pkt = recycledIn
		}
		go func(pkt Packet) {
			defer done.Done()
			arrived.Done()
			<-start
			r := svc.Translate(Inbound, pkt)
			if r.Allowed {
				allowed <- r.PublicPort
			} else {
				rejected <- rejection{reason: r.Reason, newOwner: pkt == recycledIn}
			}
		}(pkt)
	}
	go func() {
		defer done.Done()
		arrived.Done()
		<-start
		r := svc.Translate(Outbound, newOut)
		if r.Allowed {
			allocated <- r.PublicPort
		} else {
			outboundErrs <- r.Reason
		}
	}()
	arrived.Wait()
	close(start)
	done.Wait()
	close(allocated)
	close(allowed)
	close(rejected)
	close(outboundErrs)

	gotPort, ok := <-allocated
	if !ok || gotPort != 40000 {
		t.Fatalf("exactly one allocation on port 40000 expected, got port %d ok=%v", gotPort, ok)
	}
	acceptedForNewOwner := 0
	for port := range allowed {
		if port != 40000 {
			t.Fatalf("unexpected accepted port %d", port)
		}
		acceptedForNewOwner++
	}
	for reason := range outboundErrs {
		t.Fatalf("recycling outbound rejected: %s", reason)
	}
	oldOwners := 0
	newOwnersRejected := 0
	for rejection := range rejected {
		switch rejection.reason {
		case ReasonNoMapping:
			if rejection.newOwner {
				newOwnersRejected++
			} else {
				oldOwners++
			}
		case ReasonRemoteMismatch:
			if rejection.newOwner {
				newOwnersRejected++
			} else {
				oldOwners++
			}
		default:
			t.Fatalf("concurrent rejected reason = %q", rejection.reason)
		}
	}
	if acceptedForNewOwner+newOwnersRejected != inboundWorkers/2 {
		t.Fatalf("new-owner accepted=%d rejected=%d, total want %d", acceptedForNewOwner, newOwnersRejected, inboundWorkers/2)
	}
	if oldOwners != inboundWorkers/2 {
		t.Fatalf("old-owner rejected count=%d, want %d", oldOwners, inboundWorkers/2)
	}
	if got := svc.ActiveMappings(); got != 128 {
		t.Fatalf("active mappings after expiry race = %d, want 128", got)
	}
	if svc.Translate(Outbound, udp(ap("10.0.0.201", 9001), ap("203.0.113.100", 9001))).Allowed {
		t.Fatal("expected exhausted NAT after recycling its final port")
	}
}

func TestInvalidPacketsAndReasons(t *testing.T) {
	svc, _ := newTestNAT(t)

	tests := []struct {
		name      string
		direction Direction
		pkt       Packet
		reason    Reason
	}{
		{"not udp outbound", Outbound, Packet{Protocol: Protocol(99), Source: ap("10.0.0.1", 1), Destination: ap("203.0.113.1", 2)}, ReasonNotUDP},
		{"not udp inbound", Inbound, Packet{Protocol: Protocol(99), Source: ap("203.0.113.1", 2), Destination: ap("192.0.2.1", 40000)}, ReasonNotUDP},
		{"invalid direction", Direction(0), udp(ap("10.0.0.1", 1), ap("203.0.113.1", 2)), ReasonInvalidDirection},
		{"zero source port", Outbound, udp(netip.AddrPortFrom(internalIP, 0), ap("203.0.113.1", 2)), ReasonInvalidSource},
		{"zero destination port", Outbound, udp(ap("10.0.0.1", 1), netip.AddrPortFrom(remoteIP, 0)), ReasonInvalidDestination},
		{"ipv6 source", Outbound, udp(ap("2001:db8::1", 1), ap("203.0.113.1", 2)), ReasonInvalidSource},
		{"hairpin", Outbound, udp(ap("10.0.0.1", 1), ap("192.0.2.1", 40000)), ReasonHairpinNotSupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertReject(t, svc.Translate(tt.direction, tt.pkt), tt.reason)
		})
	}
}

func TestNewValidatesPublicIPv4(t *testing.T) {
	if _, err := New(netip.Addr{}, nil); err == nil {
		t.Fatal("New(zero address) unexpectedly succeeded")
	}
	if _, err := New(netip.MustParseAddr("2001:db8::1"), nil); err == nil {
		t.Fatal("New(IPv6) unexpectedly succeeded")
	}

	// An IPv4-mapped IPv6 address is accepted as IPv4.
	svc, err := New(netip.MustParseAddr("::ffff:192.0.2.1"), SystemClock{})
	if err != nil {
		t.Fatalf("New(mapped IPv4) error = %v", err)
	}
	if !svc.PublicIP().Is4() || svc.PublicIP() != publicAddr {
		t.Fatalf("canonical public IP = %v, want %v", svc.PublicIP(), publicAddr)
	}
}

func TestResultStringMentionsTranslationOrReason(t *testing.T) {
	svc, _ := newTestNAT(t)
	accepted := svc.Translate(Outbound, udp(ap("10.0.0.10", 5000), ap("203.0.113.5", 53)))
	if s := accepted.String(); s == "" ||
		!containsAll(s, "10.0.0.10:5000", "203.0.113.5:53", "192.0.2.1:40000") {
		t.Fatalf("accepted string did not list before/after endpoints: %s", s)
	}

	rejected := svc.Translate(Inbound, udp(ap("203.0.113.6", 53), ap("192.0.2.1", 40000)))
	if s := rejected.String(); s == "" ||
		!containsAll(s, "203.0.113.6:53", "192.0.2.1:40000", string(ReasonRemoteMismatch)) {
		t.Fatalf("rejected string did not list endpoints and reason: %s", s)
	}
}

func containsAll(s string, wants ...string) bool {
	for _, want := range wants {
		if !strings.Contains(s, want) {
			return false
		}
	}
	return true
}
