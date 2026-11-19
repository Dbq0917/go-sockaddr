// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sockaddr

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// InterfaceEnumFunc enumerates every address on every interface of the host.
// This is the expensive operation an InterfaceCache exists to avoid.
type InterfaceEnumFunc func() (IfAddrs, error)

// InterfaceLiveFunc returns the link-layer view of the host's interfaces
// (names, indexes, flags) without enumerating any addresses.  It is cheap
// enough to be called on every cached read.
type InterfaceLiveFunc func() ([]net.Interface, error)

// InterfaceHasAddrFunc reports whether the interface with the given index
// currently owns the CIDR address want (e.g. "10.0.0.10/24").
type InterfaceHasAddrFunc func(index int, want string) (bool, error)

// DefaultInterfaceFunc returns the name of the interface that holds the
// default route, or an error if there is none.
type DefaultInterfaceFunc func() (string, error)

// InterfaceCache caches the host's interface addresses so that repeated
// selections do not each pay for a full enumeration of every interface.
//
// The cache is self-validating: every read first performs cheap checks (a
// link-layer fingerprint of the interface list plus a targeted ownership
// check for each cached address) and only falls back to a full enumeration
// when something actually changed.  An address that is added or removed
// after the cache was populated is therefore reflected by the very next
// selection, while a steady-state host never triggers a rescan.
//
// A selection that came up empty is never trusted: there is no cheap way to
// prove that an interface still has no address, so the next selection
// re-enumerates.  This is what allows a process that started before DHCP
// handed out a lease to observe the address as soon as it arrives instead of
// serving the stale empty result until restart.
type InterfaceCache struct {
	enum      InterfaceEnumFunc
	live      InterfaceLiveFunc
	hasAddr   InterfaceHasAddrFunc
	defaultIf DefaultInterfaceFunc

	mu             sync.Mutex
	valid          bool
	all            IfAddrs
	fingerprint    string
	defaultName    string
	usableWasEmpty bool
}

// NewInterfaceCache returns an InterfaceCache backed by the real host.
func NewInterfaceCache() *InterfaceCache {
	return &InterfaceCache{
		enum:      enumInterfaces,
		live:      net.Interfaces,
		hasAddr:   hostHasAddr,
		defaultIf: defaultInterfaceName,
	}
}

// NewInterfaceCacheForTesting returns an InterfaceCache backed by the
// supplied host functions.  It exists so tests (and out-of-tree harnesses)
// can simulate hosts whose addresses change over time.
func NewInterfaceCacheForTesting(enum InterfaceEnumFunc, live InterfaceLiveFunc, hasAddr InterfaceHasAddrFunc, defaultIf DefaultInterfaceFunc) *InterfaceCache {
	return &InterfaceCache{
		enum:      enum,
		live:      live,
		hasAddr:   hasAddr,
		defaultIf: defaultIf,
	}
}

// defaultInterfaceCache backs the package-level Get* helpers.
var defaultInterfaceCache = NewInterfaceCache()

// InvalidateInterfaceCache drops the package-level interface cache.  The next
// call to any of the package-level Get* helpers re-enumerates the host.  It
// is safe to call at any time and is intended for callers that learn about
// address changes out of band (e.g. their own netlink subscription).
func InvalidateInterfaceCache() {
	defaultInterfaceCache.Invalidate()
}

// GetUsableInterfaces returns the addresses a service should consider binding
// to, ranked by usefulness: the interface holding the default route first,
// then ordinary interfaces, with virtual/bridge interfaces (docker0 and
// friends) deprioritized last.  Loopback interfaces, interfaces that are
// down, and non-forwardable addresses (link-local and friends) are excluded.
//
// The result is derived from the cached interface list; see InterfaceCache
// for when a fresh enumeration happens.
func GetUsableInterfaces() (IfAddrs, error) {
	return defaultInterfaceCache.GetUsableInterfaces()
}

// GetUsableIP returns a string with a single IP address a service should
// bind to: the first address of GetUsableInterfaces.  If the system can't
// determine its IP address, an empty string will be returned instead.
func GetUsableIP() (string, error) {
	usable, err := GetUsableInterfaces()
	if err != nil {
		return "", err
	}
	if len(usable) == 0 {
		return "", nil
	}

	ip := ToIPAddr(usable[0].SockAddr)
	if ip == nil {
		return "", nil
	}
	return (*ip).NetIP().String(), nil
}

// Invalidate drops the cached enumeration.  The next read re-enumerates the
// host.
func (c *InterfaceCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.valid = false
	c.usableWasEmpty = false
	c.all = nil
	c.fingerprint = ""
	c.defaultName = ""
}

// GetAllInterfaces returns the cached list of all interface addresses,
// re-enumerating the host only when the cheap validation detects a change.
func (c *InterfaceCache) GetAllInterfaces() (IfAddrs, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureLocked(false); err != nil {
		return nil, err
	}
	return c.all, nil
}

// GetUsableInterfaces returns the ranked list of usable addresses; see the
// package-level GetUsableInterfaces for the ranking rules.
func (c *InterfaceCache) GetUsableInterfaces() (IfAddrs, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// A previous empty selection cannot be re-validated cheaply (an address
	// may have been added to an interface that had none), so force a
	// re-enumeration.  This is the case that matters for a service that
	// started before DHCP handed out a lease.
	if err := c.ensureLocked(c.usableWasEmpty); err != nil {
		return nil, err
	}

	usable := selectUsableIfAddrs(c.all, c.defaultName)
	c.usableWasEmpty = len(usable) == 0
	return usable, nil
}

// ensureLocked makes sure the cache is populated, re-enumerating when forced
// or when the cheap validation detects a change.
func (c *InterfaceCache) ensureLocked(force bool) error {
	if c.valid && !force && len(c.all) > 0 && c.validateLocked() {
		return nil
	}
	return c.refreshLocked()
}

// validateLocked performs the cheap change checks: the link-layer fingerprint
// of the interface list must be unchanged and every cached address must still
// be owned by its interface.  No full enumeration is performed.
func (c *InterfaceCache) validateLocked() bool {
	ifaces, err := c.live()
	if err != nil {
		return false
	}
	if fingerprintInterfaces(ifaces) != c.fingerprint {
		return false
	}
	for _, ifAddr := range c.all {
		ok, err := c.hasAddr(ifAddr.Index, ifAddrCIDR(ifAddr))
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// refreshLocked performs a full enumeration and snapshots the data the cheap
// validation is based on.
func (c *InterfaceCache) refreshLocked() error {
	all, err := c.enum()
	if err != nil {
		c.valid = false
		return err
	}
	ifaces, err := c.live()
	if err != nil {
		c.valid = false
		return err
	}

	// A missing default route is not fatal; it only affects ranking.
	defaultName, err := c.defaultIf()
	if err != nil {
		defaultName = ""
	}

	c.all = all
	c.fingerprint = fingerprintInterfaces(ifaces)
	c.defaultName = defaultName
	c.valid = true
	return nil
}

// fingerprintInterfaces builds a cheap link-layer fingerprint of the
// interface list.  Interfaces appearing or disappearing, and flag changes
// such as an interface going up or down, change the fingerprint.
func fingerprintInterfaces(ifaces []net.Interface) string {
	sorted := make([]net.Interface, len(ifaces))
	copy(sorted, ifaces)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Index < sorted[j].Index })

	var b strings.Builder
	for _, iface := range sorted {
		fmt.Fprintf(&b, "%d:%s:%s;", iface.Index, iface.Name, iface.Flags.String())
	}
	return b.String()
}

// ifAddrCIDR returns the CIDR form ("10.0.0.10/24") of an IfAddr, matching
// the string form produced by net.Interface.Addrs.
func ifAddrCIDR(ifAddr IfAddr) string {
	ip := ToIPAddr(ifAddr.SockAddr)
	if ip == nil {
		return ifAddr.SockAddr.String()
	}
	return fmt.Sprintf("%s/%d", (*ip).NetIP().String(), (*ip).Maskbits())
}

// hostHasAddr implements InterfaceHasAddrFunc against the real host.
func hostHasAddr(index int, want string) (bool, error) {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return false, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if addr.String() == want {
			return true, nil
		}
	}
	return false, nil
}

// defaultInterfaceName implements DefaultInterfaceFunc against the real host.
func defaultInterfaceName() (string, error) {
	ri, err := NewRouteInfo()
	if err != nil {
		return "", err
	}
	return ri.GetDefaultInterfaceName()
}

// virtualIfNamePrefixes are name prefixes of virtual/bridge interfaces that
// are deprioritized when selecting a usable address.
var virtualIfNamePrefixes = []string{
	"docker", "veth", "br-", "virbr", "vboxnet", "vmnet",
	"cni", "flannel", "lxc", "tun", "tap",
}

func isVirtualIfName(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range virtualIfNamePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// selectUsableIfAddrs filters all down to the addresses a service should
// consider binding to and ranks them: default route first, virtual/bridge
// interfaces last.
func selectUsableIfAddrs(all IfAddrs, defaultName string) IfAddrs {
	usable := make(IfAddrs, 0, len(all))
	for _, ifAddr := range all {
		if ifAddr.Flags&net.FlagUp == 0 || ifAddr.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ToIPAddr(ifAddr.SockAddr) == nil {
			continue
		}
		if IsRFC(ForwardingBlacklist, ifAddr.SockAddr) {
			continue
		}
		usable = append(usable, ifAddr)
	}

	sort.SliceStable(usable, func(i, j int) bool {
		return lessUsableIfAddr(usable[i], usable[j], defaultName)
	})
	return usable
}

func lessUsableIfAddr(p, q IfAddr, defaultName string) bool {
	pDefault := defaultName != "" && p.Name == defaultName
	qDefault := defaultName != "" && q.Name == defaultName
	if pDefault != qDefault {
		return pDefault
	}

	pVirtual := isVirtualIfName(p.Name)
	qVirtual := isVirtualIfName(q.Name)
	if pVirtual != qVirtual {
		return !pVirtual
	}

	if c := AscIfType(&p, &q); c != sortDeferDecision {
		return c == sortReceiverBeforeArg
	}
	if c := AscIfNetworkSize(&p, &q); c != sortDeferDecision {
		return c == sortReceiverBeforeArg
	}
	if p.Name != q.Name {
		return p.Name < q.Name
	}
	return AscIfAddress(&p, &q) == sortReceiverBeforeArg
}
