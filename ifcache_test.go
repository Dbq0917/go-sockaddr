// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sockaddr

import (
	"net"
	"testing"
)

// fakeHost is a simulated host whose interfaces and addresses can change
// over time, used to exercise InterfaceCache invalidation.
type fakeHost struct {
	interfaces  []net.Interface
	addrs       map[int][]string
	defaultName string
	scans       int
}

func newFakeHost() *fakeHost {
	up := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	return &fakeHost{
		interfaces: []net.Interface{
			{Name: "lo", Index: 4, Flags: net.FlagUp | net.FlagLoopback},
			{Name: "docker0", Index: 8, Flags: up},
			{Name: "eth0", Index: 1, Flags: up},
			{Name: "eth1", Index: 2, Flags: up},
			{Name: "dummy0", Index: 9, Flags: net.FlagMulticast},
		},
		addrs: map[int][]string{
			4: {"127.0.0.1/8"},
			8: {"172.17.0.1/16"},
			1: {"10.0.0.10/24"},
			2: {"10.1.0.10/24"},
			9: {"10.9.9.9/24"},
		},
		defaultName: "eth1",
	}
}

func (h *fakeHost) enum() (IfAddrs, error) {
	h.scans++
	out := make(IfAddrs, 0)
	for _, intf := range h.interfaces {
		for _, cidr := range h.addrs[intf.Index] {
			out = append(out, IfAddr{Interface: intf, SockAddr: MustIPv4Addr(cidr)})
		}
	}
	return out, nil
}

func (h *fakeHost) live() ([]net.Interface, error) { return h.interfaces, nil }

func (h *fakeHost) defaultIf() (string, error) { return h.defaultName, nil }

func (h *fakeHost) hasAddr(index int, want string) (bool, error) {
	for _, cidr := range h.addrs[index] {
		if cidr == want {
			return true, nil
		}
	}
	return false, nil
}

func (h *fakeHost) setDown(name string) {
	for i := range h.interfaces {
		if h.interfaces[i].Name == name {
			h.interfaces[i].Flags = net.FlagMulticast
		}
	}
}

func (h *fakeHost) cache() *InterfaceCache {
	return NewInterfaceCacheForTesting(h.enum, h.live, h.hasAddr, h.defaultIf)
}

func ifAddrStrings(ifAddrs IfAddrs) []string {
	out := make([]string, 0, len(ifAddrs))
	for _, ifAddr := range ifAddrs {
		out = append(out, ifAddr.Name+"="+IfAddrAttr(ifAddr, "address"))
	}
	return out
}

// TestInterfaceCacheRanking checks filtering and ranking: loopback and down
// interfaces are excluded, the default-route interface wins, and virtual
// interfaces (docker0) are deprioritized last.
func TestInterfaceCacheRanking(t *testing.T) {
	host := newFakeHost()
	usable, err := host.cache().GetUsableInterfaces()
	if err != nil {
		t.Fatalf("GetUsableInterfaces: %v", err)
	}

	if len(usable) != 3 {
		t.Fatalf("expected 3 usable addresses, got %v", ifAddrStrings(usable))
	}
	if usable[0].Name != "eth1" {
		t.Fatalf("expected default-route interface eth1 first, got %q", usable[0].Name)
	}
	if usable[len(usable)-1].Name != "docker0" {
		t.Fatalf("expected docker0 deprioritized last, got %q", usable[len(usable)-1].Name)
	}
	for _, ifAddr := range usable {
		if ifAddr.Name == "lo" || ifAddr.Name == "dummy0" {
			t.Fatalf("loopback or down interface must be filtered out: %q", ifAddr.Name)
		}
	}
}

// TestInterfaceCacheNoRescanWhenStable ensures repeated selections on an
// unchanged host do not pay for a full enumeration.
func TestInterfaceCacheNoRescanWhenStable(t *testing.T) {
	host := newFakeHost()
	cache := host.cache()

	if _, err := cache.GetAllInterfaces(); err != nil {
		t.Fatalf("GetAllInterfaces: %v", err)
	}
	scans := host.scans
	for i := 0; i < 5; i++ {
		if _, err := cache.GetAllInterfaces(); err != nil {
			t.Fatalf("GetAllInterfaces: %v", err)
		}
		if _, err := cache.GetUsableInterfaces(); err != nil {
			t.Fatalf("GetUsableInterfaces: %v", err)
		}
	}
	if host.scans != scans {
		t.Fatalf("cache rescanned on every call: scans before=%d after=%d", scans, host.scans)
	}
}

// TestInterfaceCacheAddressAppearsAfterStart simulates a service that starts
// before DHCP hands out a lease: the first selection comes up empty, the
// address arrives later, and every subsequent selection must immediately
// return the new address.
func TestInterfaceCacheAddressAppearsAfterStart(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	host := &fakeHost{
		interfaces: []net.Interface{
			{Name: "lo", Index: 4, Flags: net.FlagUp | net.FlagLoopback},
			{Name: "eth0", Index: 1, Flags: up},
		},
		addrs: map[int][]string{
			4: {"127.0.0.1/8"},
		},
		defaultName: "eth0",
	}
	cache := host.cache()

	// Service starts before DHCP: nothing usable to bind to.
	usable, err := cache.GetUsableInterfaces()
	if err != nil {
		t.Fatalf("GetUsableInterfaces: %v", err)
	}
	if len(usable) != 0 {
		t.Fatalf("expected empty selection before DHCP, got %v", ifAddrStrings(usable))
	}

	// DHCP hands out a lease.
	host.addrs[1] = []string{"10.0.0.10/24"}

	// The next five selections must all observe the new address immediately.
	for i := 0; i < 5; i++ {
		usable, err = cache.GetUsableInterfaces()
		if err != nil {
			t.Fatalf("selection %d: %v", i, err)
		}
		if len(usable) != 1 || IfAddrAttr(usable[0], "address") != "10.0.0.10" {
			t.Fatalf("selection %d: expected 10.0.0.10, got %v", i, ifAddrStrings(usable))
		}
	}

	// Once the selection is positive the cache must serve it without
	// re-enumerating every time.
	scans := host.scans
	if _, err := cache.GetUsableInterfaces(); err != nil {
		t.Fatalf("GetUsableInterfaces: %v", err)
	}
	if host.scans != scans {
		t.Fatalf("positive selection was not cached: scans before=%d after=%d", scans, host.scans)
	}
}

// TestInterfaceCacheAddressRemoved ensures a withdrawn address disappears
// from the very next selection.
func TestInterfaceCacheAddressRemoved(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	host := &fakeHost{
		interfaces: []net.Interface{
			{Name: "lo", Index: 4, Flags: net.FlagUp | net.FlagLoopback},
			{Name: "eth0", Index: 1, Flags: up},
		},
		addrs: map[int][]string{
			4: {"127.0.0.1/8"},
			1: {"10.0.0.10/24"},
		},
		defaultName: "eth0",
	}
	cache := host.cache()

	usable, err := cache.GetUsableInterfaces()
	if err != nil {
		t.Fatalf("GetUsableInterfaces: %v", err)
	}
	if len(usable) != 1 {
		t.Fatalf("expected 1 usable address, got %v", ifAddrStrings(usable))
	}

	// The lease is revoked.
	delete(host.addrs, 1)

	usable, err = cache.GetUsableInterfaces()
	if err != nil {
		t.Fatalf("GetUsableInterfaces: %v", err)
	}
	if len(usable) != 0 {
		t.Fatalf("expected empty selection after address removal, got %v", ifAddrStrings(usable))
	}
}

// TestInterfaceCacheFailoverOnLinkDown ensures an interface going down is
// detected by the cheap fingerprint check and the selection fails over.
func TestInterfaceCacheFailoverOnLinkDown(t *testing.T) {
	host := newFakeHost()
	cache := host.cache()

	usable, err := cache.GetUsableInterfaces()
	if err != nil {
		t.Fatalf("GetUsableInterfaces: %v", err)
	}
	if usable[0].Name != "eth1" {
		t.Fatalf("expected eth1 first, got %q", usable[0].Name)
	}

	host.setDown("eth1")

	usable, err = cache.GetUsableInterfaces()
	if err != nil {
		t.Fatalf("GetUsableInterfaces: %v", err)
	}
	if usable[0].Name != "eth0" {
		t.Fatalf("expected failover to eth0, got %q", usable[0].Name)
	}
	for _, ifAddr := range usable {
		if ifAddr.Name == "eth1" {
			t.Fatalf("down interface eth1 still selected: %v", ifAddrStrings(usable))
		}
	}
}

// TestInterfaceCacheInvalidate ensures explicit invalidation forces a
// re-enumeration on the next read.
func TestInterfaceCacheInvalidate(t *testing.T) {
	host := newFakeHost()
	cache := host.cache()

	if _, err := cache.GetUsableInterfaces(); err != nil {
		t.Fatalf("GetUsableInterfaces: %v", err)
	}
	scans := host.scans

	host.defaultName = "eth0"
	cache.Invalidate()

	usable, err := cache.GetUsableInterfaces()
	if err != nil {
		t.Fatalf("GetUsableInterfaces: %v", err)
	}
	if host.scans == scans {
		t.Fatal("Invalidate did not force a re-enumeration")
	}
	if usable[0].Name != "eth0" {
		t.Fatalf("expected eth0 first after default route change, got %q", usable[0].Name)
	}
}

// TestGetUsableIPRealHost is a smoke test against the real host: when the
// host has a private address on its default interface, GetUsableIP must
// agree with GetPrivateIP.
func TestGetUsableIPRealHost(t *testing.T) {
	InvalidateInterfaceCache()

	usable, err := GetUsableIP()
	if err != nil {
		t.Fatalf("GetUsableIP: %v", err)
	}
	private, err := GetPrivateIP()
	if err != nil {
		t.Fatalf("GetPrivateIP: %v", err)
	}
	if private == "" {
		t.Skip("host has no private address on a default route")
	}
	if usable != private {
		t.Fatalf("GetUsableIP=%q disagrees with GetPrivateIP=%q", usable, private)
	}
}
