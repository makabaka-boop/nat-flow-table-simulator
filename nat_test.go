package natsim

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

var (
	testPublicIP = netip.MustParseAddr("203.0.113.1")
	t0           = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
)

func ep(ip string, port uint16) Endpoint {
	return Endpoint{IP: netip.MustParseAddr(ip), Port: port}
}

func newTestNAT(clk Clock) *NAT {
	return Default(testPublicIP, clk)
}

func requireOutboundOK(t *testing.T, r OutboundResult) {
	t.Helper()
	if !r.OK {
		t.Fatalf("outbound %s -> %s rejected: %s", r.Internal, r.Remote, r.Reject)
	}
}

func requireInboundOK(t *testing.T, r InboundResult) {
	t.Helper()
	if !r.OK {
		t.Fatalf("inbound %s -> %s rejected: %s", r.Remote, r.Public, r.Reject)
	}
}

// runConcurrently starts n goroutines that all block on a barrier and are
// released at (approximately) the same instant, maximising contention on
// the NAT state.
func runConcurrently(n int, fn func(i int)) {
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(n)
	done.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start // barrier: wait until every goroutine has arrived
			fn(i)
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()
}

func TestOutboundAllocatesSmallestFreePort(t *testing.T) {
	clk := NewFakeClock(t0)
	nat := newTestNAT(clk)

	r1 := nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 53))
	requireOutboundOK(t, r1)
	if got := r1.Public.Port; got != 40000 {
		t.Fatalf("first mapping got port %d, want 40000", got)
	}
	if r1.Reused {
		t.Error("first mapping must not be flagged as reused")
	}
	if r1.Public.IP != testPublicIP {
		t.Errorf("translated source IP = %s, want %s", r1.Public.IP, testPublicIP)
	}

	r2 := nat.TranslateOutbound(ep("10.0.0.3", 5000), ep("8.8.8.8", 53))
	requireOutboundOK(t, r2)
	if got := r2.Public.Port; got != 40001 {
		t.Fatalf("second mapping got port %d, want 40001", got)
	}

	// Same 4-tuple reuses the existing mapping and its port.
	r3 := nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 53))
	requireOutboundOK(t, r3)
	if !r3.Reused || r3.Public.Port != 40000 {
		t.Errorf("same 4-tuple: reused=%v port=%d, want reused port 40000", r3.Reused, r3.Public.Port)
	}

	// Same internal endpoint but a different remote is a different mapping
	// (endpoint-dependent mapping).
	r4 := nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("1.1.1.1", 53))
	requireOutboundOK(t, r4)
	if r4.Reused || r4.Public.Port != 40002 {
		t.Errorf("new remote: reused=%v port=%d, want new mapping on 40002", r4.Reused, r4.Public.Port)
	}
}

func TestConcurrentMappingCreationPortUniqueness(t *testing.T) {
	clk := NewFakeClock(t0)
	nat := newTestNAT(clk)

	const workers = DefaultPortMax - DefaultPortMin + 1 // exactly fills the pool
	results := make([]OutboundResult, workers)
	runConcurrently(workers, func(i int) {
		results[i] = nat.TranslateOutbound(ep("10.0.0.2", uint16(10000+i)), ep("8.8.8.8", 53))
	})

	seen := make(map[uint16]int, workers)
	for i, r := range results {
		if !r.OK {
			t.Fatalf("goroutine %d rejected: %s", i, r.Reject)
		}
		p := r.Public.Port
		if p < DefaultPortMin || p > DefaultPortMax {
			t.Fatalf("goroutine %d got out-of-pool port %d", i, p)
		}
		if j, dup := seen[p]; dup {
			t.Fatalf("public port %d assigned to both goroutine %d and %d", p, j, i)
		}
		seen[p] = i
	}
	// 128 distinct successful mappings must cover the whole pool exactly.
	for p := uint16(DefaultPortMin); p <= DefaultPortMax; p++ {
		if _, ok := seen[p]; !ok {
			t.Fatalf("pool port %d was never allocated", p)
		}
	}

	// The pool is now exhausted: one more distinct 4-tuple must be rejected.
	r := nat.TranslateOutbound(ep("10.0.0.2", 30000), ep("8.8.8.8", 53))
	if r.OK || r.Reject != RejectPortExhausted {
		t.Fatalf("129th mapping: OK=%v reject=%q, want %q", r.OK, r.Reject, RejectPortExhausted)
	}
}

func TestConcurrentSameTupleGetsOneMapping(t *testing.T) {
	clk := NewFakeClock(t0)
	nat := newTestNAT(clk)

	const workers = 64
	results := make([]OutboundResult, workers)
	runConcurrently(workers, func(i int) {
		results[i] = nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 53))
	})

	for i, r := range results {
		if !r.OK {
			t.Fatalf("goroutine %d rejected: %s", i, r.Reject)
		}
		if r.Public.Port != 40000 {
			t.Fatalf("goroutine %d got port %d, want the single shared port 40000", i, r.Public.Port)
		}
	}
	if got := len(nat.Snapshot()); got != 1 {
		t.Fatalf("snapshot has %d mappings, want exactly 1", got)
	}
}

func TestPortExhaustionAndReclaim(t *testing.T) {
	clk := NewFakeClock(t0)
	nat := newTestNAT(clk)

	// Fill the whole pool with distinct 4-tuples.
	for i := 0; i < DefaultPortMax-DefaultPortMin+1; i++ {
		r := nat.TranslateOutbound(ep("10.0.0.2", uint16(10000+i)), ep("8.8.8.8", 53))
		requireOutboundOK(t, r)
		if want := uint16(DefaultPortMin + i); r.Public.Port != want {
			t.Fatalf("mapping %d got port %d, want %d", i, r.Public.Port, want)
		}
	}

	// Pool exhausted.
	r := nat.TranslateOutbound(ep("10.0.0.2", 20000), ep("8.8.8.8", 53))
	if r.OK || r.Reject != RejectPortExhausted {
		t.Fatalf("full pool: OK=%v reject=%q, want %q", r.OK, r.Reject, RejectPortExhausted)
	}

	// At t0+15s, refresh only the mapping on port 40000; it now expires at
	// t0+45s while all the others still expire at t0+30s.
	clk.Advance(15 * time.Second)
	keep := nat.TranslateOutbound(ep("10.0.0.2", 10000), ep("8.8.8.8", 53))
	requireOutboundOK(t, keep)
	if keep.Public.Port != 40000 || !keep.Reused {
		t.Fatalf("refresh: reused=%v port=%d, want reuse of 40000", keep.Reused, keep.Public.Port)
	}

	// At t0+30s the 127 unrefreshed mappings expire. Reclamation must skip
	// the still-live port 40000 and hand out 40001.
	clk.Advance(15 * time.Second)
	r2 := nat.TranslateOutbound(ep("10.0.0.9", 5000), ep("8.8.8.8", 53))
	requireOutboundOK(t, r2)
	if r2.Public.Port != 40001 {
		t.Fatalf("reclaim got port %d, want 40001 (40000 still live)", r2.Public.Port)
	}

	// At t0+45s the refreshed mapping expires too, and 40000 — now the
	// smallest free port — is reclaimed.
	clk.Advance(15 * time.Second)
	r3 := nat.TranslateOutbound(ep("10.0.0.10", 5000), ep("8.8.8.8", 53))
	requireOutboundOK(t, r3)
	if r3.Public.Port != 40000 {
		t.Fatalf("after refreshed mapping expired, got port %d, want reclaimed 40000", r3.Public.Port)
	}
}

func TestInboundRemoteIsolation(t *testing.T) {
	clk := NewFakeClock(t0)
	nat := newTestNAT(clk)

	a := nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 53))
	requireOutboundOK(t, a)
	b := nat.TranslateOutbound(ep("10.0.0.3", 6000), ep("1.1.1.1", 443))
	requireOutboundOK(t, b)

	// A public port with no mapping at all.
	r := nat.TranslateInbound(ep("8.8.8.8", 53), 40005)
	if r.OK || r.Reject != RejectNoMapping {
		t.Errorf("unmapped port: OK=%v reject=%q, want %q", r.OK, r.Reject, RejectNoMapping)
	}

	// Right public port, wrong remote IP.
	r = nat.TranslateInbound(ep("9.9.9.9", 53), a.Public.Port)
	if r.OK || r.Reject != RejectRemoteMismatch {
		t.Errorf("wrong remote IP: OK=%v reject=%q, want %q", r.OK, r.Reject, RejectRemoteMismatch)
	}

	// Right remote IP, wrong remote port: the 4-tuple must match exactly.
	r = nat.TranslateInbound(ep("8.8.8.8", 54), a.Public.Port)
	if r.OK || r.Reject != RejectRemoteMismatch {
		t.Errorf("wrong remote port: OK=%v reject=%q, want %q", r.OK, r.Reject, RejectRemoteMismatch)
	}

	// The remote of mapping A cannot reach mapping B's port either.
	r = nat.TranslateInbound(ep("8.8.8.8", 53), b.Public.Port)
	if r.OK || r.Reject != RejectRemoteMismatch {
		t.Errorf("cross-mapping probe: OK=%v reject=%q, want %q", r.OK, r.Reject, RejectRemoteMismatch)
	}

	// Exact 4-tuple match is forwarded to the mapped internal endpoint.
	r = nat.TranslateInbound(ep("8.8.8.8", 53), a.Public.Port)
	requireInboundOK(t, r)
	if r.Internal != ep("10.0.0.2", 5000) {
		t.Errorf("forwarded to %s, want 10.0.0.2:5000", r.Internal)
	}
	if r.Public != (Endpoint{IP: testPublicIP, Port: a.Public.Port}) {
		t.Errorf("pre-translation destination = %s, want %s:%d", r.Public, testPublicIP, a.Public.Port)
	}

	r = nat.TranslateInbound(ep("1.1.1.1", 443), b.Public.Port)
	requireInboundOK(t, r)
	if r.Internal != ep("10.0.0.3", 6000) {
		t.Errorf("forwarded to %s, want 10.0.0.3:6000", r.Internal)
	}
}

func TestExpiryBoundary(t *testing.T) {
	clk := NewFakeClock(t0)
	nat := newTestNAT(clk)

	out := nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 53))
	requireOutboundOK(t, out)
	port := out.Public.Port
	if want := t0.Add(DefaultIdleTimeout); !out.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", out.ExpiresAt, want)
	}

	// One nanosecond before the deadline the mapping is still alive.
	clk.Advance(DefaultIdleTimeout - time.Nanosecond)
	if got := len(nat.Snapshot()); got != 1 {
		t.Fatalf("1ns before expiry: %d live mappings, want 1", got)
	}

	// Exactly at the deadline the mapping is expired: inbound is rejected
	// and the port becomes reclaimable.
	clk.Advance(time.Nanosecond)
	r := nat.TranslateInbound(ep("8.8.8.8", 53), port)
	if r.OK || r.Reject != RejectMappingExpired {
		t.Fatalf("inbound at exact expiry: OK=%v reject=%q, want %q", r.OK, r.Reject, RejectMappingExpired)
	}
	if got := len(nat.Snapshot()); got != 0 {
		t.Fatalf("at exact expiry: %d live mappings, want 0", got)
	}

	// The just-expired port is the smallest free port and is reused.
	r2 := nat.TranslateOutbound(ep("10.0.0.7", 7777), ep("1.1.1.1", 443))
	requireOutboundOK(t, r2)
	if r2.Public.Port != port {
		t.Fatalf("just-expired port %d not reallocated, got %d", port, r2.Public.Port)
	}
}

func TestLegitimateUseRefreshesExpiry(t *testing.T) {
	clk := NewFakeClock(t0)
	nat := newTestNAT(clk)

	out := nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 53)) // expires t0+30s
	requireOutboundOK(t, out)
	port := out.Public.Port

	// A rejected probe (wrong remote) at t0+20s must NOT extend the lifetime.
	clk.Advance(20 * time.Second)
	bad := nat.TranslateInbound(ep("9.9.9.9", 53), port)
	if bad.OK || bad.Reject != RejectRemoteMismatch {
		t.Fatalf("probe: OK=%v reject=%q, want %q", bad.OK, bad.Reject, RejectRemoteMismatch)
	}
	clk.Advance(10 * time.Second) // t0+30s: original deadline reached
	r := nat.TranslateInbound(ep("8.8.8.8", 53), port)
	if r.OK || r.Reject != RejectMappingExpired {
		t.Fatalf("rejected probe refreshed the mapping: OK=%v reject=%q, want %q", r.OK, r.Reject, RejectMappingExpired)
	}

	// A legitimate inbound packet DOES push the deadline out.
	out = nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 53)) // t0+30s, expires t0+60s
	requireOutboundOK(t, out)
	clk.Advance(25 * time.Second)                                      // t0+55s
	requireInboundOK(t, nat.TranslateInbound(ep("8.8.8.8", 53), port)) // expires t0+85s
	clk.Advance(25 * time.Second)                                      // t0+80s
	if got := len(nat.Snapshot()); got != 1 {
		t.Fatalf("t0+80s: %d live mappings, want 1 (refreshed at t0+55s)", got)
	}
	clk.Advance(5 * time.Second) // t0+85s: refreshed deadline reached exactly
	r = nat.TranslateInbound(ep("8.8.8.8", 53), port)
	if r.OK || r.Reject != RejectMappingExpired {
		t.Fatalf("at refreshed deadline: OK=%v reject=%q, want %q", r.OK, r.Reject, RejectMappingExpired)
	}
}

// TestConcurrentMixedOperationsConsistentState hammers the gateway with
// concurrent mapping creation, reuse, legitimate inbound traffic and hostile
// probes, then verifies the core invariant: no two live mappings ever share
// a public port, and every live port belongs to the pool.
func TestConcurrentMixedOperationsConsistentState(t *testing.T) {
	clk := NewFakeClock(t0)
	nat := newTestNAT(clk)

	pre := nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 53))
	requireOutboundOK(t, pre)

	const workers = 200
	runConcurrently(workers, func(i int) {
		switch i % 4 {
		case 0: // new distinct 4-tuples
			r := nat.TranslateOutbound(ep("10.0.0.3", uint16(20000+i)), ep("1.1.1.1", 443))
			if !r.OK {
				t.Errorf("goroutine %d: new mapping rejected: %s", i, r.Reject)
			}
		case 1: // reuse of the existing mapping
			r := nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 53))
			if !r.OK || r.Public.Port != pre.Public.Port {
				t.Errorf("goroutine %d: reuse got OK=%v port=%d, want port %d",
					i, r.OK, r.Public.Port, pre.Public.Port)
			}
		case 2: // legitimate inbound
			r := nat.TranslateInbound(ep("8.8.8.8", 53), pre.Public.Port)
			if !r.OK {
				t.Errorf("goroutine %d: legitimate inbound rejected: %s", i, r.Reject)
			}
		case 3: // hostile inbound
			r := nat.TranslateInbound(ep("6.6.6.6", 666), pre.Public.Port)
			if r.OK || r.Reject != RejectRemoteMismatch {
				t.Errorf("goroutine %d: hostile probe OK=%v reject=%q, want %q",
					i, r.OK, r.Reject, RejectRemoteMismatch)
			}
		}
	})

	seen := make(map[uint16]bool)
	for _, m := range nat.Snapshot() {
		if seen[m.Public.Port] {
			t.Fatalf("two live mappings share public port %d", m.Public.Port)
		}
		seen[m.Public.Port] = true
		if m.Public.Port < DefaultPortMin || m.Public.Port > DefaultPortMax {
			t.Fatalf("live mapping holds out-of-pool port %d", m.Public.Port)
		}
	}
	// 1 pre-created + 50 distinct case-0 mappings must all be live.
	if got := len(seen); got != 51 {
		t.Fatalf("%d live mappings, want 51", got)
	}
}

func TestInvalidEndpointsRejected(t *testing.T) {
	nat := newTestNAT(NewFakeClock(t0))

	cases := []OutboundResult{
		nat.TranslateOutbound(Endpoint{}, ep("8.8.8.8", 53)),          // no internal IP
		nat.TranslateOutbound(ep("10.0.0.2", 0), ep("8.8.8.8", 53)),   // zero internal port
		nat.TranslateOutbound(ep("10.0.0.2", 5000), Endpoint{}),       // no remote IP
		nat.TranslateOutbound(ep("10.0.0.2", 5000), ep("8.8.8.8", 0)), // zero remote port
	}
	for i, r := range cases {
		if r.OK || r.Reject != RejectInvalidEndpoint {
			t.Errorf("case %d: OK=%v reject=%q, want %q", i, r.OK, r.Reject, RejectInvalidEndpoint)
		}
	}

	in := nat.TranslateInbound(Endpoint{}, 40000)
	if in.OK || in.Reject != RejectInvalidEndpoint {
		t.Errorf("inbound: OK=%v reject=%q, want %q", in.OK, in.Reject, RejectInvalidEndpoint)
	}

	if got := len(nat.Snapshot()); got != 0 {
		t.Errorf("rejected packets created %d mappings, want 0", got)
	}
}

func TestRealClock(t *testing.T) {
	before := time.Now()
	now := RealClock{}.Now()
	after := time.Now()
	if now.Before(before) || now.After(after) {
		t.Fatalf("RealClock.Now() = %v, want within [%v, %v]", now, before, after)
	}
}
