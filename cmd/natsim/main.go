// Command natsim runs a scripted, deterministic demonstration of the NAT
// simulator: outbound mapping, endpoint-dependent inbound filtering, idle
// expiry, port reclamation and pool exhaustion. No real packets are sent.
package main

import (
	"fmt"
	"net/netip"
	"time"

	"natsim"
)

func ep(ip string, port uint16) natsim.Endpoint {
	return natsim.Endpoint{IP: netip.MustParseAddr(ip), Port: port}
}

func step(format string, args ...any) {
	fmt.Printf("\n=== "+format+" ===\n", args...)
}

func main() {
	clock := natsim.NewFakeClock(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	nat := natsim.Default(netip.MustParseAddr("203.0.113.1"), clock)
	fmt.Printf("public IP 203.0.113.1, UDP port pool 40000-40127, idle timeout 30s\n")

	step("outbound: LAN hosts open mappings (smallest free public port wins)")
	fmt.Println(nat.TranslateOutbound(ep("10.0.0.2", 50000), ep("8.8.8.8", 53)))
	fmt.Println(nat.TranslateOutbound(ep("10.0.0.3", 50000), ep("1.1.1.1", 443)))
	fmt.Println(nat.TranslateOutbound(ep("10.0.0.2", 50000), ep("8.8.8.8", 53))) // same 4-tuple: reuse

	step("inbound: endpoint-dependent filtering")
	fmt.Println(nat.TranslateInbound(ep("9.9.9.9", 53), 40000)) // stranger: rejected
	fmt.Println(nat.TranslateInbound(ep("8.8.8.8", 54), 40000)) // right IP, wrong port: rejected
	fmt.Println(nat.TranslateInbound(ep("8.8.8.8", 53), 40002)) // unmapped port: rejected
	fmt.Println(nat.TranslateInbound(ep("8.8.8.8", 53), 40000)) // exact 4-tuple: forwarded

	step("clock +31s: idle mappings expire, ports become reclaimable")
	clock.Advance(31 * time.Second)
	fmt.Println(nat.TranslateInbound(ep("8.8.8.8", 53), 40000))                  // expired: rejected
	fmt.Println(nat.TranslateOutbound(ep("10.0.0.9", 12345), ep("8.8.4.4", 53))) // reclaims 40000

	step("fill the remaining 127 pool ports, then exhaust the pool")
	for i := 0; i < 127; i++ {
		r := nat.TranslateOutbound(ep("10.0.0.10", uint16(30000+i)), ep("8.8.8.8", 53))
		if !r.OK {
			fmt.Println("unexpected rejection:", r)
			return
		}
	}
	fmt.Println("active mappings:", len(nat.Snapshot()))
	fmt.Println(nat.TranslateOutbound(ep("10.0.0.11", 53), ep("8.8.8.8", 53))) // pool exhausted

	step("final mapping table")
	for _, m := range nat.Snapshot() {
		fmt.Printf("  %s -> %s  via  %s  (last used %s, expires %s)\n",
			m.Internal, m.Remote, m.Public,
			m.LastUsed.Format("15:04:05"), m.ExpiresAt.Format("15:04:05"))
	}
}
