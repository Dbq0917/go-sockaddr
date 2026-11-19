// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sockaddr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// Regexp used to enforce the sign being a required part of the grammar for
	// some values.
	signRE       *regexp.Regexp = regexp.MustCompile(`^[\s]*[+-]`)
	whitespaceRE *regexp.Regexp = regexp.MustCompile(`[\s]+`)
	// These regular expressions enable the deprecated parseDefaultIfNameWindows
	// and should be removed when those functions are.
	ifNameRE *regexp.Regexp = regexp.MustCompile(`^(?:Ethernet|Wireless LAN) adapter ([^:]+):`)
	ipAddrRE *regexp.Regexp = regexp.MustCompile(`^   IPv[46] Address\. \. \. \. \. \. \. \. \. \. \. : ([^\s]+)`)

	interfaceCacheMu      sync.Mutex
	interfaceCache        IfAddrs
	interfaceCacheExpires time.Time
	interfaceCacheValid   bool

	// enumerateInterfaces is replaceable so cache behavior can be tested
	// without depending on the host's current network configuration.
	enumerateInterfaces = getAllInterfaces

	// defaultIfNameFunc is replaceable so address-selection behavior can be
	// tested without depending on the host's current route table.
	defaultIfNameFunc = getDefaultIfNameFromRoute
)

const interfaceCacheTTL = 5 * time.Second

// IfAddrs is a slice of IfAddr
type IfAddrs []IfAddr

func (ifs IfAddrs) Len() int { return len(ifs) }

// CmpIfFunc is the function signature that must be met to be used in the
// OrderedIfAddrBy multiIfAddrSorter
type CmpIfAddrFunc func(p1, p2 *IfAddr) int

// multiIfAddrSorter implements the Sort interface, sorting the IfAddrs within.
type multiIfAddrSorter struct {
	ifAddrs IfAddrs
	cmp     []CmpIfAddrFunc
}

// Sort sorts the argument slice according to the Cmp functions passed to
// OrderedIfAddrBy.
func (ms *multiIfAddrSorter) Sort(ifAddrs IfAddrs) {
	ms.ifAddrs = ifAddrs
	sort.Sort(ms)
}

// OrderedIfAddrBy sorts SockAddr by the list of sort function pointers.
func OrderedIfAddrBy(cmpFuncs ...CmpIfAddrFunc) *multiIfAddrSorter {
	return &multiIfAddrSorter{
		cmp: cmpFuncs,
	}
}

// Len is part of sort.Interface.
func (ms *multiIfAddrSorter) Len() int {
	return len(ms.ifAddrs)
}

// Less is part of sort.Interface. It is implemented by looping along the Cmp()
// functions until it finds a comparison that is either less than or greater
// than.  A return value of 0 defers sorting to the next function in the
// multisorter (which means the results of sorting may leave the resutls in a
// non-deterministic order).
func (ms *multiIfAddrSorter) Less(i, j int) bool {
	p, q := &ms.ifAddrs[i], &ms.ifAddrs[j]
	// Try all but the last comparison.
	var k int
	for k = 0; k < len(ms.cmp)-1; k++ {
		cmp := ms.cmp[k]
		x := cmp(p, q)
		switch x {
		case -1:
			// p < q, so we have a decision.
			return true
		case 1:
			// p > q, so we have a decision.
			return false
		}
		// p == q; try the next comparison.
	}
	// All comparisons to here said "equal", so just return whatever the
	// final comparison reports.
	switch ms.cmp[k](p, q) {
	case -1:
		return true
	case 1:
		return false
	default:
		// Still a tie! Now what?
		return false
	}
}

// Swap is part of sort.Interface.
func (ms *multiIfAddrSorter) Swap(i, j int) {
	ms.ifAddrs[i], ms.ifAddrs[j] = ms.ifAddrs[j], ms.ifAddrs[i]
}

// AscIfAddress is a sorting function to sort IfAddrs by their respective
// address type.  Non-equal types are deferred in the sort.
func AscIfAddress(p1Ptr, p2Ptr *IfAddr) int {
	return AscAddress(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// AscIfDefault is a sorting function to sort IfAddrs by whether or not they
// have a default route or not.  Non-equal types are deferred in the sort.
//
// FIXME: This is a particularly expensive sorting operation because of the
// non-memoized calls to NewRouteInfo().  In an ideal world the routeInfo data
// once at the start of the sort and pass it along as a context or by wrapping
// the IfAddr type with this information (this would also solve the inability to
// return errors and the possibility of failing silently).  Fortunately,
// N*log(N) where N = 3 is only ~6.2 invocations.  Not ideal, but not worth
// optimizing today.  The common case is this gets called once or twice.
// Patches welcome.
func AscIfDefault(p1Ptr, p2Ptr *IfAddr) int {
	ri, err := NewRouteInfo()
	if err != nil {
		return sortDeferDecision
	}

	defaultIfName, err := ri.GetDefaultInterfaceName()
	if err != nil {
		return sortDeferDecision
	}

	return ascIfDefault(defaultIfName)(p1Ptr, p2Ptr)
}

func ascIfDefault(defaultIfName string) CmpIfAddrFunc {
	return func(p1Ptr, p2Ptr *IfAddr) int {
		switch {
		case p1Ptr.Name == defaultIfName && p2Ptr.Name == defaultIfName:
			return sortDeferDecision
		case p1Ptr.Name == defaultIfName:
			return sortReceiverBeforeArg
		case p2Ptr.Name == defaultIfName:
			return sortArgBeforeReceiver
		default:
			return sortDeferDecision
		}
	}
}

func defaultInterfaceName() string {
	defaultIfName, err := defaultIfNameFunc()
	if err != nil {
		return ""
	}

	return defaultIfName
}

func getDefaultIfNameFromRoute() (string, error) {
	ri, err := NewRouteInfo()
	if err != nil {
		return "", err
	}

	return ri.GetDefaultInterfaceName()
}

// AscIfName is a sorting function to sort IfAddrs by their interface names.
func AscIfName(p1Ptr, p2Ptr *IfAddr) int {
	return strings.Compare(p1Ptr.Name, p2Ptr.Name)
}

// AscIfNetworkSize is a sorting function to sort IfAddrs by their respective
// network mask size.
func AscIfNetworkSize(p1Ptr, p2Ptr *IfAddr) int {
	return AscNetworkSize(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// AscIfPort is a sorting function to sort IfAddrs by their respective
// port type.  Non-equal types are deferred in the sort.
func AscIfPort(p1Ptr, p2Ptr *IfAddr) int {
	return AscPort(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// AscIfPrivate is a sorting function to sort IfAddrs by "private" values before
// "public" values.  Both IPv4 and IPv6 are compared against RFC6890 (RFC6890
// includes, and is not limited to, RFC1918 and RFC6598 for IPv4, and IPv6
// includes RFC4193).
func AscIfPrivate(p1Ptr, p2Ptr *IfAddr) int {
	return AscPrivate(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// AscIfType is a sorting function to sort IfAddrs by their respective address
// type.  Non-equal types are deferred in the sort.
func AscIfType(p1Ptr, p2Ptr *IfAddr) int {
	return AscType(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// DescIfAddress is identical to AscIfAddress but reverse ordered.
func DescIfAddress(p1Ptr, p2Ptr *IfAddr) int {
	return -1 * AscAddress(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// DescIfDefault is identical to AscIfDefault but reverse ordered.
func DescIfDefault(p1Ptr, p2Ptr *IfAddr) int {
	return -1 * AscIfDefault(p1Ptr, p2Ptr)
}

// DescIfName is identical to AscIfName but reverse ordered.
func DescIfName(p1Ptr, p2Ptr *IfAddr) int {
	return -1 * strings.Compare(p1Ptr.Name, p2Ptr.Name)
}

// DescIfNetworkSize is identical to AscIfNetworkSize but reverse ordered.
func DescIfNetworkSize(p1Ptr, p2Ptr *IfAddr) int {
	return -1 * AscNetworkSize(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// DescIfPort is identical to AscIfPort but reverse ordered.
func DescIfPort(p1Ptr, p2Ptr *IfAddr) int {
	return -1 * AscPort(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// DescIfPrivate is identical to AscIfPrivate but reverse ordered.
func DescIfPrivate(p1Ptr, p2Ptr *IfAddr) int {
	return -1 * AscPrivate(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// DescIfType is identical to AscIfType but reverse ordered.
func DescIfType(p1Ptr, p2Ptr *IfAddr) int {
	return -1 * AscType(&p1Ptr.SockAddr, &p2Ptr.SockAddr)
}

// FilterIfByType filters IfAddrs and returns a list of the matching type
func FilterIfByType(ifAddrs IfAddrs, type_ SockAddrType) (matchedIfs, excludedIfs IfAddrs) {
	excludedIfs = make(IfAddrs, 0, len(ifAddrs))
	matchedIfs = make(IfAddrs, 0, len(ifAddrs))

	for _, ifAddr := range ifAddrs {
		if ifAddr.Type()&type_ != 0 {
			matchedIfs = append(matchedIfs, ifAddr)
		} else {
			excludedIfs = append(excludedIfs, ifAddr)
		}
	}
	return matchedIfs, excludedIfs
}

// IfAttr forwards the selector to IfAttr.Attr() for resolution.  If there is
// more than one IfAddr, only the first IfAddr is used.
func IfAttr(selectorName string, ifAddr IfAddr) (string, error) {
	attrName := AttrName(strings.ToLower(selectorName))
	attrVal, err := ifAddr.Attr(attrName)
	return attrVal, err
}

// IfAttrs forwards the selector to IfAttrs.Attr() for resolution.  If there is
// more than one IfAddr, only the first IfAddr is used.
func IfAttrs(selectorName string, ifAddrs IfAddrs) (string, error) {
	if len(ifAddrs) == 0 {
		return "", nil
	}

	attrName := AttrName(strings.ToLower(selectorName))
	attrVal, err := ifAddrs[0].Attr(attrName)
	return attrVal, err
}

// GetAllInterfaces returns all available network interfaces and their IP
// addresses.  Results are cached briefly because collecting interface
// addresses requires a full enumeration and can be expensive on hosts with
// many interfaces.  Use InvalidateInterfaceCache to force the next call to
// refresh the cache.
func GetAllInterfaces() (IfAddrs, error) {
	ifAddrs, _, err := getAllInterfacesCached()
	return ifAddrs, err
}

// InvalidateInterfaceCache discards the cached interface snapshot.  The next
// call to GetAllInterfaces will enumerate the interfaces again.
func InvalidateInterfaceCache() {
	interfaceCacheMu.Lock()
	defer interfaceCacheMu.Unlock()

	interfaceCache = nil
	interfaceCacheExpires = time.Time{}
	interfaceCacheValid = false
}

// getAllInterfacesCached returns a snapshot and whether it came from the
// cache.  Callers that select addresses must validate cached candidates
// before returning them because the host's network configuration may have
// changed since the snapshot was taken.
func getAllInterfacesCached() (IfAddrs, bool, error) {
	now := time.Now()

	interfaceCacheMu.Lock()
	defer interfaceCacheMu.Unlock()

	if interfaceCacheValid && now.Before(interfaceCacheExpires) {
		return cloneIfAddrs(interfaceCache), true, nil
	}

	ifAddrs, err := enumerateInterfaces()
	if err != nil {
		return nil, false, err
	}

	interfaceCache = cloneIfAddrs(ifAddrs)
	interfaceCacheExpires = now.Add(interfaceCacheTTL)
	interfaceCacheValid = true

	return cloneIfAddrs(ifAddrs), false, nil
}

func cloneIfAddrs(ifAddrs IfAddrs) IfAddrs {
	cloned := make(IfAddrs, len(ifAddrs))
	for i, ifAddr := range ifAddrs {
		cloned[i] = ifAddr
		if len(ifAddr.HardwareAddr) > 0 {
			cloned[i].HardwareAddr = append(net.HardwareAddr(nil), ifAddr.HardwareAddr...)
		}
	}
	return cloned
}

func getAllInterfaces() (IfAddrs, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	ifAddrs := make(IfAddrs, 0, len(ifs))
	for _, intf := range ifs {
		addrs, err := intf.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			var ipAddr IPAddr
			ipAddr, err = NewIPAddr(addr.String())
			if err != nil {
				return IfAddrs{}, fmt.Errorf("unable to create an IP address from %q", addr.String())
			}

			ifAddr := IfAddr{
				SockAddr:  ipAddr,
				Interface: intf,
			}
			ifAddrs = append(ifAddrs, ifAddr)
		}
	}

	return ifAddrs, nil
}

// GetDefaultInterfaces returns IfAddrs of the addresses attached to the default
// route.
func GetDefaultInterfaces() (IfAddrs, error) {
	for attempt := 0; attempt < 2; attempt++ {
		defaultIfs, cached, err := getDefaultInterfacesCached()
		if err != nil {
			return IfAddrs{}, err
		}

		if !cached {
			return defaultIfs, nil
		}
		if len(defaultIfs) > 0 && cachedIfAddrsStillUsable(defaultIfs) {
			return defaultIfs, nil
		}

		InvalidateInterfaceCache()
	}

	return IfAddrs{}, nil
}

func getDefaultInterfacesCached() (IfAddrs, bool, error) {
	defaultIfName, err := defaultIfNameFunc()
	if err != nil {
		return nil, false, err
	}

	var defaultIfs IfAddrs
	ifAddrs, cached, err := getAllInterfacesCached()
	if err != nil {
		return nil, false, err
	}

	for _, ifAddr := range ifAddrs {
		if ifAddr.Name == defaultIfName {
			defaultIfs = append(defaultIfs, ifAddr)
		}
	}

	return defaultIfs, cached, nil
}

// GetPrivateInterfaces returns an IfAddrs that are part of RFC 6890 and have a
// default route.  If the system can't determine its IP address or find an RFC
// 6890 IP address, an empty IfAddrs will be returned instead.  This function is
// the `eval` equivalent of:
//
// ```
// $ sockaddr eval -r '{{GetAllInterfaces | include "type" "ip" | include "flags" "forwardable" | include "flags" "up" | sort "default,type,size" | include "RFC" "6890" }}'
// ```
func GetPrivateInterfaces() (IfAddrs, error) {
	privateIfs, _, err := getPrivateInterfacesCached()
	return privateIfs, err
}

// GetPublicInterfaces returns an IfAddrs that are NOT part of RFC 6890 and has a
// default route.  If the system can't determine its IP address or find a non
// RFC 6890 IP address, an empty IfAddrs will be returned instead.  This
// function is the `eval` equivalent of:
//
// ```
// $ sockaddr eval -r '{{GetAllInterfaces | include "type" "ip" | include "flags" "forwardable" | include "flags" "up" | sort "default,type,size" | exclude "RFC" "6890" }}'
// ```
func GetPublicInterfaces() (IfAddrs, error) {
	publicIfs, _, err := getPublicInterfacesCached()
	return publicIfs, err
}

func getPrivateInterfacesCached() (IfAddrs, bool, error) {
	ifAddrs, cached, err := getInterfacesCached(func(all IfAddrs) (IfAddrs, error) {
		return privateInterfacesFrom(all, defaultInterfaceName())
	})
	return ifAddrs, cached, err
}

func getPublicInterfacesCached() (IfAddrs, bool, error) {
	ifAddrs, cached, err := getInterfacesCached(func(all IfAddrs) (IfAddrs, error) {
		return publicInterfacesFrom(all, defaultInterfaceName())
	})
	return ifAddrs, cached, err
}

func getInterfacesCached(filter func(IfAddrs) (IfAddrs, error)) (IfAddrs, bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		allIfAddrs, cached, err := getAllInterfacesCached()
		if err != nil {
			return IfAddrs{}, false, err
		}

		filtered, err := filter(allIfAddrs)
		if err != nil {
			return IfAddrs{}, false, err
		}

		if !cached {
			return filtered, false, nil
		}

		if len(filtered) > 0 && cachedIfAddrsStillUsable(filtered) {
			return filtered, true, nil
		}

		// The cached snapshot no longer reflects the host.  Refresh it and
		// make one more attempt using the fresh data.
		InvalidateInterfaceCache()
	}

	return IfAddrs{}, false, nil
}

func privateInterfacesFrom(ifAddrs IfAddrs, defaultIfName string) (IfAddrs, error) {
	privateIfs, err := selectableInterfaces(ifAddrs)
	if err != nil || len(privateIfs) == 0 {
		return IfAddrs{}, err
	}

	sortIfAddrsByDefault(privateIfs, defaultIfName)

	privateIfs, _, err = IfByRFC("6890", privateIfs)
	if err != nil {
		return IfAddrs{}, err
	}

	return privateIfs, nil
}

func publicInterfacesFrom(ifAddrs IfAddrs, defaultIfName string) (IfAddrs, error) {
	publicIfs, err := selectableInterfaces(ifAddrs)
	if err != nil || len(publicIfs) == 0 {
		return IfAddrs{}, err
	}

	sortIfAddrsByDefault(publicIfs, defaultIfName)

	_, publicIfs, err = IfByRFC("6890", publicIfs)
	if err != nil {
		return IfAddrs{}, err
	}

	return publicIfs, nil
}

func selectableInterfaces(ifAddrs IfAddrs) (IfAddrs, error) {
	ifAddrs, _ = FilterIfByType(ifAddrs, TypeIP)
	if len(ifAddrs) == 0 {
		return IfAddrs{}, nil
	}

	ifAddrs, _, err := IfByFlag("up|forwardable", ifAddrs)
	if err != nil || len(ifAddrs) == 0 {
		return IfAddrs{}, err
	}

	_, ifAddrs, err = IfByFlag("loopback", ifAddrs)
	if err != nil {
		return IfAddrs{}, err
	}

	return ifAddrs, nil
}

func sortIfAddrsByDefault(ifAddrs IfAddrs, defaultIfName string) {
	comparators := []CmpIfAddrFunc{AscIfType, AscIfNetworkSize}
	if defaultIfName != "" {
		comparators = append([]CmpIfAddrFunc{ascIfDefault(defaultIfName)}, comparators...)
	}
	OrderedIfAddrBy(comparators...).Sort(ifAddrs)
}

func cachedIfAddrsStillUsable(ifAddrs IfAddrs) bool {
	if len(ifAddrs) == 0 {
		return false
	}

	for _, ifAddr := range ifAddrs {
		if !ifAddrIsCurrentlyUsable(ifAddr) {
			return false
		}
	}

	return true
}

func ifAddrIsCurrentlyUsable(ifAddr IfAddr) bool {
	if ifAddr.Name == "" || !interfaceIsUsable(ifAddr.Name) {
		return false
	}

	ipAddr := ToIPAddr(ifAddr.SockAddr)
	if ipAddr == nil {
		return false
	}

	netIP := *(*ipAddr).NetIP()
	if netIP == nil || netIP.IsUnspecified() || netIP.IsMulticast() || netIP.IsLoopback() {
		return false
	}

	network := "udp4"
	udpAddr := &net.UDPAddr{IP: netIP}
	if netIP.To4() == nil {
		network = "udp6"
		if netIP.IsLinkLocalUnicast() {
			udpAddr.Zone = ifAddr.Name
		}
	}

	conn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return false
	}
	_ = conn.Close()

	return true
}

// IfByAddress returns a list of matched and non-matched IfAddrs, or an error if
// the regexp fails to compile.
func IfByAddress(inputRe string, ifAddrs IfAddrs) (matched, remainder IfAddrs, err error) {
	re, err := regexp.Compile(inputRe)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compile address regexp %+q: %v", inputRe, err)
	}

	matchedAddrs := make(IfAddrs, 0, len(ifAddrs))
	excludedAddrs := make(IfAddrs, 0, len(ifAddrs))
	for _, addr := range ifAddrs {
		if re.MatchString(addr.SockAddr.String()) {
			matchedAddrs = append(matchedAddrs, addr)
		} else {
			excludedAddrs = append(excludedAddrs, addr)
		}
	}

	return matchedAddrs, excludedAddrs, nil
}

// IfByName returns a list of matched and non-matched IfAddrs, or an error if
// the regexp fails to compile.
func IfByName(inputRe string, ifAddrs IfAddrs) (matched, remainder IfAddrs, err error) {
	re, err := regexp.Compile(inputRe)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compile name regexp %+q: %v", inputRe, err)
	}

	matchedAddrs := make(IfAddrs, 0, len(ifAddrs))
	excludedAddrs := make(IfAddrs, 0, len(ifAddrs))
	for _, addr := range ifAddrs {
		if re.MatchString(addr.Name) {
			matchedAddrs = append(matchedAddrs, addr)
		} else {
			excludedAddrs = append(excludedAddrs, addr)
		}
	}

	return matchedAddrs, excludedAddrs, nil
}

// IfByPort returns a list of matched and non-matched IfAddrs, or an error if
// the regexp fails to compile.
func IfByPort(inputRe string, ifAddrs IfAddrs) (matchedIfs, excludedIfs IfAddrs, err error) {
	re, err := regexp.Compile(inputRe)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compile port regexp %+q: %v", inputRe, err)
	}

	ipIfs, nonIfs := FilterIfByType(ifAddrs, TypeIP)
	matchedIfs = make(IfAddrs, 0, len(ipIfs))
	excludedIfs = append(IfAddrs(nil), nonIfs...)
	for _, addr := range ipIfs {
		ipAddr := ToIPAddr(addr.SockAddr)
		if ipAddr == nil {
			continue
		}

		port := strconv.FormatInt(int64((*ipAddr).IPPort()), 10)
		if re.MatchString(port) {
			matchedIfs = append(matchedIfs, addr)
		} else {
			excludedIfs = append(excludedIfs, addr)
		}
	}

	return matchedIfs, excludedIfs, nil
}

// IfByRFC returns a list of matched and non-matched IfAddrs that contain the
// relevant RFC-specified traits.
func IfByRFC(selectorParam string, ifAddrs IfAddrs) (matched, remainder IfAddrs, err error) {
	inputRFC, err := strconv.ParseUint(selectorParam, 10, 64)
	if err != nil {
		return IfAddrs{}, IfAddrs{}, fmt.Errorf("unable to parse RFC number %q: %v", selectorParam, err)
	}

	matchedIfAddrs := make(IfAddrs, 0, len(ifAddrs))
	remainingIfAddrs := make(IfAddrs, 0, len(ifAddrs))

	rfcNetMap := KnownRFCs()
	rfcNets, ok := rfcNetMap[uint(inputRFC)]
	if !ok {
		return nil, nil, fmt.Errorf("unsupported RFC %d", inputRFC)
	}

	for _, ifAddr := range ifAddrs {
		var contained bool
		for _, rfcNet := range rfcNets {
			if rfcNet.Contains(ifAddr.SockAddr) {
				matchedIfAddrs = append(matchedIfAddrs, ifAddr)
				contained = true
				break
			}
		}
		if !contained {
			remainingIfAddrs = append(remainingIfAddrs, ifAddr)
		}
	}

	return matchedIfAddrs, remainingIfAddrs, nil
}

// IfByRFCs returns a list of matched and non-matched IfAddrs that contain the
// relevant RFC-specified traits.  Multiple RFCs can be specified and separated
// by the `|` symbol.  No protection is taken to ensure an IfAddr does not end
// up in both the included and excluded list.
func IfByRFCs(selectorParam string, ifAddrs IfAddrs) (matched, remainder IfAddrs, err error) {
	var includedIfs, excludedIfs IfAddrs
	for rfcStr := range strings.SplitSeq(selectorParam, "|") {
		includedRFCIfs, excludedRFCIfs, err := IfByRFC(rfcStr, ifAddrs)
		if err != nil {
			return IfAddrs{}, IfAddrs{}, fmt.Errorf("unable to lookup RFC number %q: %v", rfcStr, err)
		}
		includedIfs = append(includedIfs, includedRFCIfs...)
		excludedIfs = append(excludedIfs, excludedRFCIfs...)
	}

	return includedIfs, excludedIfs, nil
}

// IfByMaskSize returns a list of matched and non-matched IfAddrs that have the
// matching mask size.
func IfByMaskSize(selectorParam string, ifAddrs IfAddrs) (matchedIfs, excludedIfs IfAddrs, err error) {
	maskSize, err := strconv.ParseUint(selectorParam, 10, 64)
	if err != nil {
		return IfAddrs{}, IfAddrs{}, fmt.Errorf("invalid exclude size argument (%q): %v", selectorParam, err)
	}

	ipIfs, nonIfs := FilterIfByType(ifAddrs, TypeIP)
	matchedIfs = make(IfAddrs, 0, len(ipIfs))
	excludedIfs = append(IfAddrs(nil), nonIfs...)
	for _, addr := range ipIfs {
		ipAddr := ToIPAddr(addr.SockAddr)
		if ipAddr == nil {
			return IfAddrs{}, IfAddrs{}, fmt.Errorf("unable to filter mask sizes on non-IP type %s: %v", addr.SockAddr.Type().String(), addr.SockAddr.String())
		}

		switch {
		case (*ipAddr).Type()&TypeIPv4 != 0 && maskSize > 32:
			return IfAddrs{}, IfAddrs{}, fmt.Errorf("mask size out of bounds for IPv4 address: %d", maskSize)
		case (*ipAddr).Type()&TypeIPv6 != 0 && maskSize > 128:
			return IfAddrs{}, IfAddrs{}, fmt.Errorf("mask size out of bounds for IPv6 address: %d", maskSize)
		}

		if (*ipAddr).Maskbits() == int(maskSize) {
			matchedIfs = append(matchedIfs, addr)
		} else {
			excludedIfs = append(excludedIfs, addr)
		}
	}

	return matchedIfs, excludedIfs, nil
}

// IfByType returns a list of matching and non-matching IfAddr that match the
// specified type.  For instance:
//
// include "type" "IPv4,IPv6"
//
// will include any IfAddrs that is either an IPv4 or IPv6 address.  Any
// addresses on those interfaces that don't match will be included in the
// remainder results.
func IfByType(inputTypes string, ifAddrs IfAddrs) (matched, remainder IfAddrs, err error) {
	matchingIfAddrs := make(IfAddrs, 0, len(ifAddrs))
	remainingIfAddrs := make(IfAddrs, 0, len(ifAddrs))

	ifTypes := strings.Split(strings.ToLower(inputTypes), "|")
	for _, ifType := range ifTypes {
		switch ifType {
		case "ip", "ipv4", "ipv6", "unix":
			// Valid types
		default:
			return nil, nil, fmt.Errorf("unsupported type %q %q", ifType, inputTypes)
		}
	}

	for _, ifAddr := range ifAddrs {
		for _, ifType := range ifTypes {
			var matched bool
			switch {
			case ifType == "ip" && ifAddr.Type()&TypeIP != 0:
				matched = true
			case ifType == "ipv4" && ifAddr.Type()&TypeIPv4 != 0:
				matched = true
			case ifType == "ipv6" && ifAddr.Type()&TypeIPv6 != 0:
				matched = true
			case ifType == "unix" && ifAddr.Type()&TypeUnix != 0:
				matched = true
			}

			if matched {
				matchingIfAddrs = append(matchingIfAddrs, ifAddr)
			} else {
				remainingIfAddrs = append(remainingIfAddrs, ifAddr)
			}
		}
	}

	return matchingIfAddrs, remainingIfAddrs, nil
}

// IfByFlag returns a list of matching and non-matching IfAddrs that match the
// specified type.  For instance:
//
// include "flag" "up,broadcast"
//
// will include any IfAddrs that have both the "up" and "broadcast" flags set.
// Any addresses on those interfaces that don't match will be omitted from the
// results.
func IfByFlag(inputFlags string, ifAddrs IfAddrs) (matched, remainder IfAddrs, err error) {
	matchedAddrs := make(IfAddrs, 0, len(ifAddrs))
	excludedAddrs := make(IfAddrs, 0, len(ifAddrs))

	var (
		requireFlags net.Flags
		wantDown     bool

		wantForwardable,
		wantGlobalUnicast,
		wantInterfaceLocalMulticast,
		wantLinkLocalMulticast,
		wantLinkLocalUnicast,
		wantLoopback,
		wantMulticast,
		wantUnspecified bool
	)
	for flagName := range strings.SplitSeq(strings.ToLower(inputFlags), "|") {
		switch flagName {
		case "broadcast":
			requireFlags |= net.FlagBroadcast
		case "down":
			wantDown = true
		case "forwardable":
			wantForwardable = true
		case "global unicast":
			wantGlobalUnicast = true
		case "interface-local multicast":
			wantInterfaceLocalMulticast = true
		case "link-local multicast":
			wantLinkLocalMulticast = true
		case "link-local unicast":
			wantLinkLocalUnicast = true
		case "loopback":
			wantLoopback = true
		case "multicast":
			wantMulticast = true
		case "point-to-point":
			requireFlags |= net.FlagPointToPoint
		case "unspecified":
			wantUnspecified = true
		case "up":
			requireFlags |= net.FlagUp
		default:
			return nil, nil, fmt.Errorf("unknown interface flag: %+q", flagName)
		}
	}

	for _, ifAddr := range ifAddrs {
		matched := ifAddr.Flags&requireFlags == requireFlags
		if wantDown {
			matched = matched && ifAddr.Flags&net.FlagUp == 0
		}

		var netIP net.IP
		if ip := ToIPAddr(ifAddr.SockAddr); ip != nil {
			netIP = *(*ip).NetIP()
		}

		if wantGlobalUnicast {
			matched = matched && netIP != nil && netIP.IsGlobalUnicast()
		}
		if wantInterfaceLocalMulticast {
			matched = matched && netIP != nil && netIP.IsInterfaceLocalMulticast()
		}
		if wantLinkLocalMulticast {
			matched = matched && netIP != nil && netIP.IsLinkLocalMulticast()
		}
		if wantLinkLocalUnicast {
			matched = matched && netIP != nil && netIP.IsLinkLocalUnicast()
		}
		if wantUnspecified {
			matched = matched && netIP != nil && netIP.IsUnspecified()
		}
		if wantForwardable {
			matched = matched && !IsRFC(ForwardingBlacklist, ifAddr.SockAddr)
		}
		if wantLoopback {
			matched = matched &&
				(ifAddr.Flags&net.FlagLoopback != 0 || (netIP != nil && netIP.IsLoopback()))
		}
		if wantMulticast {
			matched = matched &&
				(ifAddr.Flags&net.FlagMulticast != 0 || (netIP != nil && netIP.IsMulticast()))
		}

		if matched {
			matchedAddrs = append(matchedAddrs, ifAddr)
		} else {
			excludedAddrs = append(excludedAddrs, ifAddr)
		}
	}
	return matchedAddrs, excludedAddrs, nil
}

// IfByNetwork returns an IfAddrs that are equal to or included within the
// network passed in by selector.
func IfByNetwork(selectorParam string, inputIfAddrs IfAddrs) (IfAddrs, IfAddrs, error) {
	var includedIfs, excludedIfs IfAddrs
	for netStr := range strings.SplitSeq(selectorParam, "|") {
		netAddr, err := NewIPAddr(netStr)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to create an IP address from %+q: %v", netStr, err)
		}

		for _, ifAddr := range inputIfAddrs {
			if netAddr.Contains(ifAddr.SockAddr) {
				includedIfs = append(includedIfs, ifAddr)
			} else {
				excludedIfs = append(excludedIfs, ifAddr)
			}
		}
	}

	return includedIfs, excludedIfs, nil
}

// IfAddrMath will return a new IfAddr struct with a mutated value.
func IfAddrMath(operation, value string, inputIfAddr IfAddr) (IfAddr, error) {

	switch strings.ToLower(operation) {
	case "address":
		// "address" operates on the IP address and is allowed to overflow or
		// underflow networks, however it will wrap along the underlying address's
		// underlying type.

		if !signRE.MatchString(value) {
			return IfAddr{}, fmt.Errorf("sign (+/-) is required for operation %q", operation)
		}

		switch sockType := inputIfAddr.Type(); sockType {
		case TypeIPv4:
			// 33 == Accept any uint32 value
			// TODO(seanc@): Add the ability to parse hex
			i, err := strconv.ParseInt(value, 10, 33)
			if err != nil {
				return IfAddr{}, fmt.Errorf("unable to convert %q to int for operation %q: %v", value, operation, err)
			}

			ipv4 := *ToIPv4Addr(inputIfAddr.SockAddr)
			ipv4Uint32 := uint32(ipv4.Address)
			ipv4Uint32 += uint32(i)
			return IfAddr{
				SockAddr: IPv4Addr{
					Address: IPv4Address(ipv4Uint32),
					Mask:    ipv4.Mask,
				},
				Interface: inputIfAddr.Interface,
			}, nil
		case TypeIPv6:
			// 64 == Accept any int32 value
			// TODO(seanc@): Add the ability to parse hex.  Also parse a bignum int.
			i, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return IfAddr{}, fmt.Errorf("unable to convert %q to int for operation %q: %v", value, operation, err)
			}

			ipv6 := *ToIPv6Addr(inputIfAddr.SockAddr)
			ipv6BigIntA := new(big.Int)
			ipv6BigIntA.Set(ipv6.Address)
			ipv6BigIntB := big.NewInt(i)

			ipv6Addr := ipv6BigIntA.Add(ipv6BigIntA, ipv6BigIntB)
			ipv6Addr.And(ipv6Addr, ipv6HostMask)

			return IfAddr{
				SockAddr: IPv6Addr{
					Address: IPv6Address(ipv6Addr),
					Mask:    ipv6.Mask,
				},
				Interface: inputIfAddr.Interface,
			}, nil
		default:
			return IfAddr{}, fmt.Errorf("unsupported type for operation %q: %T", operation, sockType)
		}
	case "network":
		// "network" operates on the network address.  Positive values start at the
		// network address and negative values wrap at the network address, which
		// means a "-1" value on a network will be the broadcast address after
		// wrapping is applied.

		if !signRE.MatchString(value) {
			return IfAddr{}, fmt.Errorf("sign (+/-) is required for operation %q", operation)
		}

		switch sockType := inputIfAddr.Type(); sockType {
		case TypeIPv4:
			// 33 == Accept any uint32 value
			// TODO(seanc@): Add the ability to parse hex
			i, err := strconv.ParseInt(value, 10, 33)
			if err != nil {
				return IfAddr{}, fmt.Errorf("unable to convert %q to int for operation %q: %v", value, operation, err)
			}

			ipv4 := *ToIPv4Addr(inputIfAddr.SockAddr)
			ipv4Uint32 := uint32(ipv4.NetworkAddress())

			// Wrap along network mask boundaries.  EZ-mode wrapping made possible by
			// use of int64 vs a uint.
			var wrappedMask int64
			if i >= 0 {
				wrappedMask = i
			} else {
				wrappedMask = 1 + i + int64(^uint32(ipv4.Mask))
			}

			ipv4Uint32 = ipv4Uint32 + (uint32(wrappedMask) &^ uint32(ipv4.Mask))

			return IfAddr{
				SockAddr: IPv4Addr{
					Address: IPv4Address(ipv4Uint32),
					Mask:    ipv4.Mask,
				},
				Interface: inputIfAddr.Interface,
			}, nil
		case TypeIPv6:
			// 64 == Accept any int32 value
			// TODO(seanc@): Add the ability to parse hex.  Also parse a bignum int.
			i, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return IfAddr{}, fmt.Errorf("unable to convert %q to int for operation %q: %v", value, operation, err)
			}

			ipv6 := *ToIPv6Addr(inputIfAddr.SockAddr)
			ipv6BigInt := new(big.Int)
			ipv6BigInt.Set(ipv6.NetworkAddress())

			mask := new(big.Int)
			mask.Set(ipv6.Mask)
			if i > 0 {
				wrappedMask := new(big.Int)
				wrappedMask.SetInt64(i)

				wrappedMask.AndNot(wrappedMask, mask)
				ipv6BigInt.Add(ipv6BigInt, wrappedMask)
			} else {
				// Mask off any bits that exceed the network size.  Subtract the
				// wrappedMask from the last usable - 1
				wrappedMask := new(big.Int)
				wrappedMask.SetInt64(-1 * i)
				wrappedMask.Sub(wrappedMask, big.NewInt(1))

				wrappedMask.AndNot(wrappedMask, mask)

				lastUsable := new(big.Int)
				lastUsable.Set(ipv6.LastUsable().(IPv6Addr).Address)

				ipv6BigInt = lastUsable.Sub(lastUsable, wrappedMask)
			}

			return IfAddr{
				SockAddr: IPv6Addr{
					Address: IPv6Address(ipv6BigInt),
					Mask:    ipv6.Mask,
				},
				Interface: inputIfAddr.Interface,
			}, nil
		default:
			return IfAddr{}, fmt.Errorf("unsupported type for operation %q: %T", operation, sockType)
		}
	case "mask":
		// "mask" operates on the IP address and returns the IP address on
		// which the given integer mask has been applied. If the applied mask
		// corresponds to a larger network than the mask of the IP address,
		// the latter will be replaced by the former.
		switch sockType := inputIfAddr.Type(); sockType {
		case TypeIPv4:
			i, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return IfAddr{}, fmt.Errorf("unable to convert %q to int for operation %q: %v", value, operation, err)
			}

			if i > 32 {
				return IfAddr{}, fmt.Errorf("parameter for operation %q on ipv4 addresses must be between 0 and 32", operation)
			}

			ipv4 := *ToIPv4Addr(inputIfAddr.SockAddr)

			ipv4Mask := net.CIDRMask(int(i), 32)
			ipv4MaskUint32 := binary.BigEndian.Uint32(ipv4Mask)

			maskedIpv4 := ipv4.NetIP().Mask(ipv4Mask)
			maskedIpv4Uint32 := binary.BigEndian.Uint32(maskedIpv4)

			maskedIpv4MaskUint32 := min(ipv4MaskUint32, uint32(ipv4.Mask))

			return IfAddr{
				SockAddr: IPv4Addr{
					Address: IPv4Address(maskedIpv4Uint32),
					Mask:    IPv4Mask(maskedIpv4MaskUint32),
				},
				Interface: inputIfAddr.Interface,
			}, nil
		case TypeIPv6:
			i, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return IfAddr{}, fmt.Errorf("unable to convert %q to int for operation %q: %v", value, operation, err)
			}

			if i > 128 {
				return IfAddr{}, fmt.Errorf("parameter for operation %q on ipv6 addresses must be between 0 and 64", operation)
			}

			ipv6 := *ToIPv6Addr(inputIfAddr.SockAddr)

			ipv6Mask := net.CIDRMask(int(i), 128)
			ipv6MaskBigInt := new(big.Int)
			ipv6MaskBigInt.SetBytes(ipv6Mask)

			maskedIpv6 := ipv6.NetIP().Mask(ipv6Mask)
			maskedIpv6BigInt := new(big.Int)
			maskedIpv6BigInt.SetBytes(maskedIpv6)

			maskedIpv6MaskBigInt := new(big.Int)
			maskedIpv6MaskBigInt.Set(ipv6.Mask)

			if ipv6MaskBigInt.Cmp(maskedIpv6MaskBigInt) == -1 {
				maskedIpv6MaskBigInt = ipv6MaskBigInt
			}

			return IfAddr{
				SockAddr: IPv6Addr{
					Address: IPv6Address(maskedIpv6BigInt),
					Mask:    IPv6Mask(maskedIpv6MaskBigInt),
				},
				Interface: inputIfAddr.Interface,
			}, nil
		default:
			return IfAddr{}, fmt.Errorf("unsupported type for operation %q: %T", operation, sockType)
		}
	default:
		return IfAddr{}, fmt.Errorf("unsupported math operation: %q", operation)
	}
}

// IfAddrsMath will apply an IfAddrMath operation each IfAddr struct.  Any
// failure will result in zero results.
func IfAddrsMath(operation, value string, inputIfAddrs IfAddrs) (IfAddrs, error) {
	outputAddrs := make(IfAddrs, 0, len(inputIfAddrs))
	for _, ifAddr := range inputIfAddrs {
		result, err := IfAddrMath(operation, value, ifAddr)
		if err != nil {
			return IfAddrs{}, fmt.Errorf("unable to perform an IPMath operation on %s: %v", ifAddr, err)
		}
		outputAddrs = append(outputAddrs, result)
	}
	return outputAddrs, nil
}

// IncludeIfs returns an IfAddrs based on the passed in selector.
func IncludeIfs(selectorName, selectorParam string, inputIfAddrs IfAddrs) (IfAddrs, error) {
	var includedIfs IfAddrs
	var err error

	switch strings.ToLower(selectorName) {
	case "address":
		includedIfs, _, err = IfByAddress(selectorParam, inputIfAddrs)
	case "flag", "flags":
		includedIfs, _, err = IfByFlag(selectorParam, inputIfAddrs)
	case "name":
		includedIfs, _, err = IfByName(selectorParam, inputIfAddrs)
	case "network":
		includedIfs, _, err = IfByNetwork(selectorParam, inputIfAddrs)
	case "port":
		includedIfs, _, err = IfByPort(selectorParam, inputIfAddrs)
	case "rfc", "rfcs":
		includedIfs, _, err = IfByRFCs(selectorParam, inputIfAddrs)
	case "size":
		includedIfs, _, err = IfByMaskSize(selectorParam, inputIfAddrs)
	case "type":
		includedIfs, _, err = IfByType(selectorParam, inputIfAddrs)
	default:
		return IfAddrs{}, fmt.Errorf("invalid include selector %q", selectorName)
	}

	if err != nil {
		return IfAddrs{}, err
	}

	return includedIfs, nil
}

// ExcludeIfs returns an IfAddrs based on the passed in selector.
func ExcludeIfs(selectorName, selectorParam string, inputIfAddrs IfAddrs) (IfAddrs, error) {
	var excludedIfs IfAddrs
	var err error

	switch strings.ToLower(selectorName) {
	case "address":
		_, excludedIfs, err = IfByAddress(selectorParam, inputIfAddrs)
	case "flag", "flags":
		_, excludedIfs, err = IfByFlag(selectorParam, inputIfAddrs)
	case "name":
		_, excludedIfs, err = IfByName(selectorParam, inputIfAddrs)
	case "network":
		_, excludedIfs, err = IfByNetwork(selectorParam, inputIfAddrs)
	case "port":
		_, excludedIfs, err = IfByPort(selectorParam, inputIfAddrs)
	case "rfc", "rfcs":
		_, excludedIfs, err = IfByRFCs(selectorParam, inputIfAddrs)
	case "size":
		_, excludedIfs, err = IfByMaskSize(selectorParam, inputIfAddrs)
	case "type":
		_, excludedIfs, err = IfByType(selectorParam, inputIfAddrs)
	default:
		return IfAddrs{}, fmt.Errorf("invalid exclude selector %q", selectorName)
	}

	if err != nil {
		return IfAddrs{}, err
	}

	return excludedIfs, nil
}

// SortIfBy returns an IfAddrs sorted based on the passed in selector.  Multiple
// sort clauses can be passed in as a comma delimited list without whitespace.
func SortIfBy(selectorParam string, inputIfAddrs IfAddrs) (IfAddrs, error) {
	sortedIfs := append(IfAddrs(nil), inputIfAddrs...)

	clauses := strings.Split(selectorParam, ",")
	sortFuncs := make([]CmpIfAddrFunc, len(clauses))

	for i, clause := range clauses {
		switch strings.TrimSpace(strings.ToLower(clause)) {
		case "+address", "address":
			// The "address" selector returns an array of IfAddrs
			// ordered by the network address.  IfAddrs that are not
			// comparable will be at the end of the list and in a
			// non-deterministic order.
			sortFuncs[i] = AscIfAddress
		case "-address":
			sortFuncs[i] = DescIfAddress
		case "+default", "default":
			sortFuncs[i] = AscIfDefault
		case "-default":
			sortFuncs[i] = DescIfDefault
		case "+name", "name":
			// The "name" selector returns an array of IfAddrs
			// ordered by the interface name.
			sortFuncs[i] = AscIfName
		case "-name":
			sortFuncs[i] = DescIfName
		case "+port", "port":
			// The "port" selector returns an array of IfAddrs
			// ordered by the port, if included in the IfAddr.
			// IfAddrs that are not comparable will be at the end of
			// the list and in a non-deterministic order.
			sortFuncs[i] = AscIfPort
		case "-port":
			sortFuncs[i] = DescIfPort
		case "+private", "private":
			// The "private" selector returns an array of IfAddrs
			// ordered by private addresses first.  IfAddrs that are
			// not comparable will be at the end of the list and in
			// a non-deterministic order.
			sortFuncs[i] = AscIfPrivate
		case "-private":
			sortFuncs[i] = DescIfPrivate
		case "+size", "size":
			// The "size" selector returns an array of IfAddrs
			// ordered by the size of the network mask, smaller mask
			// (larger number of hosts per network) to largest
			// (e.g. a /24 sorts before a /32).
			sortFuncs[i] = AscIfNetworkSize
		case "-size":
			sortFuncs[i] = DescIfNetworkSize
		case "+type", "type":
			// The "type" selector returns an array of IfAddrs
			// ordered by the type of the IfAddr.  The sort order is
			// Unix, IPv4, then IPv6.
			sortFuncs[i] = AscIfType
		case "-type":
			sortFuncs[i] = DescIfType
		default:
			// Return an empty list for invalid sort types.
			return IfAddrs{}, fmt.Errorf("unknown sort type: %q", clause)
		}
	}

	OrderedIfAddrBy(sortFuncs...).Sort(sortedIfs)

	return sortedIfs, nil
}

// UniqueIfAddrsBy creates a unique set of IfAddrs based on the matching
// selector.  UniqueIfAddrsBy assumes the input has already been sorted.
func UniqueIfAddrsBy(selectorName string, inputIfAddrs IfAddrs) (IfAddrs, error) {
	attrName := strings.ToLower(selectorName)

	ifs := make(IfAddrs, 0, len(inputIfAddrs))
	var lastMatch string
	for _, ifAddr := range inputIfAddrs {
		var out string
		switch attrName {
		case "address":
			out = ifAddr.SockAddr.String()
		case "name":
			out = ifAddr.Name
		default:
			return nil, fmt.Errorf("unsupported unique constraint %+q", selectorName)
		}

		switch {
		case lastMatch == "", lastMatch != out:
			lastMatch = out
			ifs = append(ifs, ifAddr)
		case lastMatch == out:
			continue
		}
	}

	return ifs, nil
}

// JoinIfAddrs joins an IfAddrs and returns a string
func JoinIfAddrs(selectorName string, joinStr string, inputIfAddrs IfAddrs) (string, error) {
	outputs := make([]string, 0, len(inputIfAddrs))
	attrName := AttrName(strings.ToLower(selectorName))

	for _, ifAddr := range inputIfAddrs {
		var attrVal string
		var err error
		attrVal, err = ifAddr.Attr(attrName)
		if err != nil {
			return "", err
		}
		outputs = append(outputs, attrVal)
	}
	return strings.Join(outputs, joinStr), nil
}

// LimitIfAddrs returns a slice of IfAddrs based on the specified limit.
func LimitIfAddrs(lim uint, in IfAddrs) (IfAddrs, error) {
	// Clamp the limit to the length of the array
	if int(lim) > len(in) {
		lim = uint(len(in))
	}

	return in[0:lim], nil
}

// OffsetIfAddrs returns a slice of IfAddrs based on the specified offset.
func OffsetIfAddrs(off int, in IfAddrs) (IfAddrs, error) {
	var end bool
	if off < 0 {
		end = true
		off = off * -1
	}

	if off > len(in) {
		return IfAddrs{}, fmt.Errorf("unable to seek past the end of the interface array: offset (%d) exceeds the number of interfaces (%d)", off, len(in))
	}

	if end {
		return in[len(in)-off:], nil
	}
	return in[off:], nil
}

func (ifAddr IfAddr) String() string {
	return fmt.Sprintf("%s %v", ifAddr.SockAddr, ifAddr.Interface)
}

// parseDefaultIfNameFromRoute parses standard route(8)'s output for the *BSDs
// and Solaris.
func parseDefaultIfNameFromRoute(routeOut string) (string, error) {
	lines := strings.SplitSeq(routeOut, "\n")
	for line := range lines {
		kvs := strings.SplitN(line, ":", 2)
		if len(kvs) != 2 {
			continue
		}

		if strings.TrimSpace(kvs[0]) == "interface" {
			ifName := strings.TrimSpace(kvs[1])
			return ifName, nil
		}
	}

	return "", errors.New("no default interface found")
}

// parseDefaultIfNameFromIPCmd parses the default interface from ip(8) for
// Linux.
func parseDefaultIfNameFromIPCmd(routeOut string) (string, error) {
	inDefaultRoute := false
	for _, line := range strings.Split(routeOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if fields[0] == "default" {
			inDefaultRoute = true
		} else if inDefaultRoute {
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				inDefaultRoute = false
			}
		}

		if !inDefaultRoute {
			continue
		}

		// Linux supports both gateway routes ("default via ... dev eth0")
		// and direct routes ("default dev eth0").  ECMP routes put the
		// interfaces on subsequent nexthop lines.
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return strings.TrimSpace(fields[i+1]), nil
			}
		}
	}

	return "", errors.New("no default interface found")
}

// parseIfNameFromIPCmd parses interfaces from ip(8) for
// Linux.
func parseIfNameFromIPCmd(routeOut string) [][]string {
	lines := strings.Split(routeOut, "\n")
	parsedLines := make([][]string, 0, len(lines))
	for _, line := range lines {
		kvs := whitespaceRE.Split(line, -1)
		if len(kvs) < 2 {
			continue
		}
		parsedLines = append(parsedLines, kvs)
	}
	return parsedLines
}

// parseDefaultIfNameWindows parses the default interface from `netstat -rn` and
// `ipconfig` on Windows.
//
// This has been deprecated in favor of a Powershell-based solution because of
// issues with localized Windows versions, but is currently retained for backward
// compatibility
func parseDefaultIfNameWindows(routeOut, ipconfigOut string) (string, error) {
	defaultIPAddr, err := parseDefaultIPAddrWindowsRoute(routeOut)
	if err != nil {
		return "", err
	}

	ifName, err := parseDefaultIfNameWindowsIPConfig(defaultIPAddr, ipconfigOut)
	if err != nil {
		return "", err
	}

	return ifName, nil
}

// parseDefaultIPAddrWindowsRoute parses the IP address on the default interface
// `netstat -rn`.
//
// NOTES(sean): Only IPv4 addresses are parsed at this time.  If you have an
// IPv6 connected host, submit an issue on github.com/hashicorp/go-sockaddr with
// the output from `netstat -rn`, `ipconfig`, and version of Windows to see IPv6
// support added.
//
// This has been deprecated in favor of a Powershell-based solution because of
// issues with localized Windows versions, but is currently retained for backward
// compatibility.
func parseDefaultIPAddrWindowsRoute(routeOut string) (string, error) {
	lines := strings.SplitSeq(routeOut, "\n")
	for line := range lines {
		kvs := whitespaceRE.Split(strings.TrimSpace(line), -1)
		if len(kvs) < 3 {
			continue
		}

		if kvs[0] == "0.0.0.0" && kvs[1] == "0.0.0.0" {
			defaultIPAddr := strings.TrimSpace(kvs[3])
			return defaultIPAddr, nil
		}
	}

	return "", errors.New("no IP on default interface found")
}

// parseDefaultIfNameWindowsIPConfig parses the output of `ipconfig` to find the
// interface name forwarding traffic to the default gateway.
//
// This has been deprecated in favor of a Powershell-based solution because of
// issues with localized Windows versions, but is currently retained for backward
// compatibility
func parseDefaultIfNameWindowsIPConfig(defaultIPAddr, routeOut string) (string, error) {
	lines := strings.Split(routeOut, "\n")
	var ifName string
	for _, line := range lines {
		switch ifNameMatches := ifNameRE.FindStringSubmatch(line); {
		case len(ifNameMatches) > 1:
			ifName = ifNameMatches[1]
			continue
		}

		switch ipAddrMatches := ipAddrRE.FindStringSubmatch(line); {
		case len(ipAddrMatches) > 1 && ipAddrMatches[1] == defaultIPAddr:
			return ifName, nil
		}
	}

	return "", errors.New("no default interface found with matching IP")
}
