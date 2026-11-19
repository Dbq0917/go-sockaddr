// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sockaddr

import (
	"net"
	"testing"
)

// multiHomedIfAddrs simulates a multi-homed host (or container) where the
// loopback interface is enumerated first and carries both a loopback
// address and a non-loopback alias, one interface is up with a routable
// address, and one interface has gone down.
func multiHomedIfAddrs(defaultIfName string) IfAddrs {
	return IfAddrs{
		IfAddr{
			Interface: net.Interface{Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
			SockAddr:  MustIPv4Addr("127.0.0.1/8"),
		},
		IfAddr{
			Interface: net.Interface{Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
			SockAddr:  MustIPv4Addr("10.255.255.254/32"),
		},
		IfAddr{
			Interface: net.Interface{Name: "nic1", Flags: net.FlagUp | net.FlagBroadcast},
			SockAddr:  MustIPv4Addr("192.168.1.10/24"),
		},
		IfAddr{
			Interface: net.Interface{Name: defaultIfName, Flags: net.FlagUp | net.FlagBroadcast},
			SockAddr:  MustIPv4Addr("172.16.0.10/24"),
		},
		IfAddr{
			Interface: net.Interface{Name: "nic2", Flags: net.FlagBroadcast},
			SockAddr:  MustIPv4Addr("10.1.0.10/24"),
		},
	}
}

func defaultTestInterfaceName(t *testing.T) string {
	t.Helper()
	ri, err := NewRouteInfo()
	if err != nil {
		t.Skipf("unable to get route info: %v", err)
	}
	name, err := ri.GetDefaultInterfaceName()
	if err != nil || name == "" {
		t.Skipf("no default route on this host: %v", err)
	}
	return name
}

func ifAddrStrings(ifAddrs IfAddrs) []string {
	out := make([]string, 0, len(ifAddrs))
	for _, ifAddr := range ifAddrs {
		out = append(out, ifAddr.Name+"="+ifAddr.SockAddr.String())
	}
	return out
}

func TestFilterUsableIfAddrsExcludesLoopbackAndDown(t *testing.T) {
	defaultIfName := defaultTestInterfaceName(t)
	in := multiHomedIfAddrs(defaultIfName)

	filtered, err := filterUsableIfAddrs(in, false, false)
	if err != nil {
		t.Fatalf("filter failed: %v", err)
	}

	for _, ifAddr := range filtered {
		if ifAddr.Flags&net.FlagLoopback != 0 {
			t.Fatalf("loopback interface not excluded: %v", ifAddrStrings(filtered))
		}
		if ip := ToIPAddr(ifAddr.SockAddr); ip != nil && (*ip).NetIP().IsLoopback() {
			t.Fatalf("loopback address not excluded: %v", ifAddrStrings(filtered))
		}
		if ifAddr.Flags&net.FlagUp == 0 {
			t.Fatalf("address from a down interface not excluded: %v", ifAddrStrings(filtered))
		}
	}

	if len(filtered) != 2 {
		t.Fatalf("expected 2 usable addresses, got %v", ifAddrStrings(filtered))
	}

	// The address on the interface with the default route must sort first.
	if filtered[0].Name != defaultIfName {
		t.Fatalf("expected default route interface %q first, got %v", defaultIfName, ifAddrStrings(filtered))
	}
}

func TestFilterUsableIfAddrsAllowLoopback(t *testing.T) {
	defaultIfName := defaultTestInterfaceName(t)
	in := multiHomedIfAddrs(defaultIfName)

	filtered, err := filterUsableIfAddrs(in, false, true)
	if err != nil {
		t.Fatalf("filter failed: %v", err)
	}

	var haveLoopback bool
	for _, ifAddr := range filtered {
		if ip := ToIPAddr(ifAddr.SockAddr); ip != nil && (*ip).NetIP().IsLoopback() {
			haveLoopback = true
		}
		if ifAddr.Flags&net.FlagUp == 0 {
			t.Fatalf("address from a down interface not excluded: %v", ifAddrStrings(filtered))
		}
	}
	if !haveLoopback {
		t.Fatalf("expected loopback candidates with allowLoopback: %v", ifAddrStrings(filtered))
	}

	// Even when allowed, loopback candidates sort after usable addresses.
	if filtered[0].Name != defaultIfName {
		t.Fatalf("expected default route interface %q first, got %v", defaultIfName, ifAddrStrings(filtered))
	}
}
