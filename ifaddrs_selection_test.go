// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sockaddr

import (
	"errors"
	"net"
	"testing"
)

func useInterfaceTestHooks(t *testing.T, enumerator func() (IfAddrs, error), defaultIfName func() (string, error)) {
	t.Helper()

	originalEnumerator := enumerateInterfaces
	originalDefaultIfName := defaultIfNameFunc

	enumerateInterfaces = enumerator
	defaultIfNameFunc = defaultIfName
	InvalidateInterfaceCache()

	t.Cleanup(func() {
		enumerateInterfaces = originalEnumerator
		defaultIfNameFunc = originalDefaultIfName
		InvalidateInterfaceCache()
	})
}

func testIfAddr(name string, flags net.Flags, address string) IfAddr {
	return IfAddr{
		Interface: net.Interface{
			Name:  name,
			Flags: flags,
		},
		SockAddr: MustIPv4Addr(address),
	}
}

func TestGetAllInterfacesCachesSnapshot(t *testing.T) {
	calls := 0
	useInterfaceTestHooks(t, func() (IfAddrs, error) {
		calls++
		return IfAddrs{testIfAddr("cache0", net.FlagUp, "192.168.1.10/24")}, nil
	}, func() (string, error) {
		return "cache0", nil
	})

	first, err := GetAllInterfaces()
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	first[0].Name = "mutated"

	second, err := GetAllInterfaces()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected one enumeration, got %d", calls)
	}
	if second[0].Name != "cache0" {
		t.Fatalf("cache was mutated through returned snapshot: %q", second[0].Name)
	}

	InvalidateInterfaceCache()
	if _, err := GetAllInterfaces(); err != nil {
		t.Fatalf("call after invalidation failed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected enumeration after invalidation, got %d calls", calls)
	}
}

func TestGetPrivateIPUsesDefaultRouteAndSkipsUnusableInterfaces(t *testing.T) {
	useInterfaceTestHooks(t, func() (IfAddrs, error) {
		return IfAddrs{
			testIfAddr("lo", net.FlagUp|net.FlagLoopback, "10.255.255.254/32"),
			testIfAddr("docker0", net.FlagUp, "172.17.0.1/16"),
			testIfAddr("eth0", net.FlagUp, "192.168.1.5/24"),
			testIfAddr("eth1", 0, "192.168.2.5/24"),
		}, nil
	}, func() (string, error) {
		return "eth0", nil
	})

	ip, err := GetPrivateIP()
	if err != nil {
		t.Fatalf("GetPrivateIP failed: %v", err)
	}
	if ip != "192.168.1.5" {
		t.Fatalf("expected default interface address, got %q", ip)
	}

	privateIfs, err := GetPrivateInterfaces()
	if err != nil {
		t.Fatalf("GetPrivateInterfaces failed: %v", err)
	}
	for _, ifAddr := range privateIfs {
		if ifAddr.Name == "lo" || ifAddr.Name == "eth1" {
			t.Fatalf("selected unusable interface %q", ifAddr.Name)
		}
	}
}

func TestGetPrivateIPDoesNotFallBackWithoutDefaultRoute(t *testing.T) {
	useInterfaceTestHooks(t, func() (IfAddrs, error) {
		return IfAddrs{
			testIfAddr("docker0", net.FlagUp, "172.17.0.1/16"),
		}, nil
	}, func() (string, error) {
		return "", errors.New("no default interface found")
	})

	ip, err := GetPrivateIP()
	if err == nil {
		t.Fatal("expected an error when the default route cannot be determined")
	}
	if ip != "" {
		t.Fatalf("must not fall back to a non-default interface, got %q", ip)
	}
}

func TestGetPrivateIPRefreshesStaleCachedAddress(t *testing.T) {
	calls := 0
	useInterfaceTestHooks(t, func() (IfAddrs, error) {
		calls++
		address := "192.168.1.5/24"
		if calls > 1 {
			address = "192.168.1.6/24"
		}
		return IfAddrs{
			testIfAddr("eth0", net.FlagUp, address),
		}, nil
	}, func() (string, error) {
		return "eth0", nil
	})

	first, err := GetPrivateIP()
	if err != nil {
		t.Fatalf("first GetPrivateIP failed: %v", err)
	}
	if first != "192.168.1.5" {
		t.Fatalf("unexpected first address %q", first)
	}

	second, err := GetPrivateIP()
	if err != nil {
		t.Fatalf("second GetPrivateIP failed: %v", err)
	}
	if second != "192.168.1.6" {
		t.Fatalf("expected refreshed address, got %q", second)
	}
	if calls != 2 {
		t.Fatalf("expected stale cache to be refreshed, got %d enumerations", calls)
	}
}

func TestIfByFlagRequiresEverySelector(t *testing.T) {
	ifAddrs := IfAddrs{
		testIfAddr("up-forwardable", net.FlagUp, "8.8.8.8"),
		testIfAddr("down-forwardable", 0, "8.8.8.9"),
		testIfAddr("loopback", net.FlagUp|net.FlagLoopback, "127.0.0.1"),
	}

	matched, _, err := IfByFlag("up|forwardable", ifAddrs)
	if err != nil {
		t.Fatalf("IfByFlag failed: %v", err)
	}
	if len(matched) != 1 || matched[0].Name != "up-forwardable" {
		t.Fatalf("expected only the up and forwardable interface, got %#v", matched)
	}

	matched, _, err = IfByFlag("up|loopback", ifAddrs)
	if err != nil {
		t.Fatalf("IfByFlag failed: %v", err)
	}
	if len(matched) != 1 || matched[0].Name != "loopback" {
		t.Fatalf("expected only the loopback interface, got %#v", matched)
	}
}
