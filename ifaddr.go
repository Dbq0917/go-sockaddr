// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package sockaddr

import "strings"

// ifAddrAttrMap is a map of the IfAddr type-specific attributes.
var ifAddrAttrMap map[AttrName]func(IfAddr) string
var ifAddrAttrs []AttrName

func init() {
	ifAddrAttrInit()
}

// GetPrivateIP returns a string with a single IP address that is part of RFC
// 6890 and has a default route.  If the system can't determine its IP address
// or find an RFC 6890 IP address, an empty string will be returned instead.
// This function is the `eval` equivalent of:
//
// ```
// $ sockaddr eval -r '{{GetPrivateInterfaces | attr "address"}}'
// ```
func GetPrivateIP() (string, error) {
	privateIfs, err := GetPrivateInterfaces()
	if err != nil {
		return "", err
	}
	if len(privateIfs) < 1 {
		return "", nil
	}

	ifAddr := privateIfs[0]
	ip := *ToIPAddr(ifAddr.SockAddr)
	return ip.NetIP().String(), nil
}

// GetPrivateIPs returns a string with all IP addresses that are part of RFC
// 6890 (regardless of whether or not there is a default route, unlike
// GetPublicIP).  If the system can't find any RFC 6890 IP addresses, an empty
// string will be returned instead.  This function is the `eval` equivalent of:
//
// ```
// $ sockaddr eval -r '{{GetAllInterfaces | include "RFC" "6890" | join "address" " "}}'
// ```
func GetPrivateIPs() (string, error) {
	ifAddrs, err := GetAllInterfaces()
	if err != nil {
		return "", err
	} else if len(ifAddrs) < 1 {
		return "", nil
	}

	ifAddrs, _ = FilterIfByType(ifAddrs, TypeIP)
	if len(ifAddrs) == 0 {
		return "", nil
	}

	OrderedIfAddrBy(AscIfType, AscIfNetworkSize).Sort(ifAddrs)

	ifAddrs, _, err = IfByRFC("6890", ifAddrs)
	if err != nil {
		return "", err
	} else if len(ifAddrs) == 0 {
		return "", nil
	}

	_, ifAddrs, err = IfByRFC(ForwardingBlacklistRFC, ifAddrs)
	if err != nil {
		return "", err
	} else if len(ifAddrs) == 0 {
		return "", nil
	}

	ips := make([]string, 0, len(ifAddrs))
	for _, ifAddr := range ifAddrs {
		ip := *ToIPAddr(ifAddr.SockAddr)
		s := ip.NetIP().String()
		ips = append(ips, s)
	}

	return strings.Join(ips, " "), nil
}

// GetPublicIP returns a string with a single IP address that is NOT part of RFC
// 6890 and has a default route.  If the system can't determine its IP address
// or find a non RFC 6890 IP address, an empty string will be returned instead.
// This function is the `eval` equivalent of:
//
// ```
// $ sockaddr eval -r '{{GetPublicInterfaces | attr "address"}}'
// ```
func GetPublicIP() (string, error) {
	publicIfs, err := GetPublicInterfaces()
	if err != nil {
		return "", err
	} else if len(publicIfs) < 1 {
		return "", nil
	}

	ifAddr := publicIfs[0]
	ip := *ToIPAddr(ifAddr.SockAddr)
	return ip.NetIP().String(), nil
}

// GetPublicIPs returns a string with all IP addresses that are NOT part of RFC
// 6890 (regardless of whether or not there is a default route, unlike
// GetPublicIP).  If the system can't find any non RFC 6890 IP addresses, an
// empty string will be returned instead.  This function is the `eval`
// equivalent of:
//
// ```
// $ sockaddr eval -r '{{GetAllInterfaces | exclude "RFC" "6890" | join "address" " "}}'
// ```
func GetPublicIPs() (string, error) {
	ifAddrs, err := GetAllInterfaces()
	if err != nil {
		return "", err
	} else if len(ifAddrs) < 1 {
		return "", nil
	}

	ifAddrs, _ = FilterIfByType(ifAddrs, TypeIP)
	if len(ifAddrs) == 0 {
		return "", nil
	}

	OrderedIfAddrBy(AscIfType, AscIfNetworkSize).Sort(ifAddrs)

	_, ifAddrs, err = IfByRFC("6890", ifAddrs)
	if err != nil {
		return "", err
	} else if len(ifAddrs) == 0 {
		return "", nil
	}

	ips := make([]string, 0, len(ifAddrs))
	for _, ifAddr := range ifAddrs {
		ip := *ToIPAddr(ifAddr.SockAddr)
		s := ip.NetIP().String()
		ips = append(ips, s)
	}

	return strings.Join(ips, " "), nil
}

// IfAddrSelectOption configures the candidate selection used by
// GetInterfaceIP and GetInterfaceIPs.
type IfAddrSelectOption func(*ifAddrSelectConfig)

type ifAddrSelectConfig struct {
	allowLoopback bool
}

// AllowLoopback explicitly allows loopback addresses and addresses attached
// to loopback interfaces to be selected by GetInterfaceIP and
// GetInterfaceIPs.  Loopback candidates are excluded by default because a
// service bound to a loopback address is unreachable from other hosts (e.g.
// from outside a container).  Only use this option for special scenarios
// such as single-node testing where loopback is the intended bind address.
func AllowLoopback() IfAddrSelectOption {
	return func(cfg *ifAddrSelectConfig) {
		cfg.allowLoopback = true
	}
}

// GetInterfaceIP returns a string with a single, forwardable IP address from
// the named interface.  Candidates are ordered by usability: addresses on
// the interface with the default route sort first, then by address type,
// then by the size of the network (i.e. IP addresses with a smaller netmask,
// larger network size, are sorted first).  Loopback addresses and addresses
// on interfaces that are down are never selected; pass AllowLoopback to
// explicitly allow loopback candidates.  This function is the `eval`
// equivalent of:
//
// ```
// $ sockaddr eval -r '{{GetAllInterfaces | include "name" <<ARG>> | include "flag" "up" | include "flag" "forwardable" | sort "default,type,size" | attr "address" }}'
// ```
func GetInterfaceIP(namedIfRE string, opts ...IfAddrSelectOption) (string, error) {
	ifAddrs, err := selectInterfaceIfAddrs(namedIfRE, true, opts...)
	if err != nil {
		return "", err
	}

	if len(ifAddrs) == 0 {
		return "", nil
	}

	ip := ToIPAddr(ifAddrs[0].SockAddr)
	if ip == nil {
		return "", nil
	}

	return IPAddrAttr(*ip, "address"), nil
}

// GetInterfaceIPs returns a string with all usable IPs on a named interface,
// ordered by usability: addresses on the interface with the default route
// sort first, then by address type, then by the size of the network (i.e. IP
// addresses with a smaller netmask, larger network size, are sorted first).
// Loopback addresses and addresses on interfaces that are down are excluded
// so that the first result is always safe to bind to and reach from other
// hosts; pass AllowLoopback to explicitly allow loopback candidates.  This
// function is the `eval` equivalent of:
//
// ```
// $ sockaddr eval -r '{{GetAllInterfaces | include "name" <<ARG>> | include "flag" "up" | sort "default,type,size" | join "address" " "}}'
// ```
func GetInterfaceIPs(namedIfRE string, opts ...IfAddrSelectOption) (string, error) {
	ifAddrs, err := selectInterfaceIfAddrs(namedIfRE, false, opts...)
	if err != nil {
		return "", err
	}

	if len(ifAddrs) == 0 {
		return "", nil
	}

	ips := make([]string, 0, len(ifAddrs))
	for _, ifAddr := range ifAddrs {
		ip := *ToIPAddr(ifAddr.SockAddr)
		s := ip.NetIP().String()
		ips = append(ips, s)
	}

	return strings.Join(ips, " "), nil
}

// selectInterfaceIfAddrs returns the candidate IfAddrs for the named
// interface, filtered and ordered by usability.  Interfaces are enumerated
// on every call so that addresses on interfaces that have gone down are
// never selected, even by callers that cache an earlier result.
func selectInterfaceIfAddrs(namedIfRE string, forwardableOnly bool, opts ...IfAddrSelectOption) (IfAddrs, error) {
	var cfg ifAddrSelectConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	ifAddrs, err := GetAllInterfaces()
	if err != nil {
		return nil, err
	}

	ifAddrs, _, err = IfByName(namedIfRE, ifAddrs)
	if err != nil {
		return nil, err
	}

	return filterUsableIfAddrs(ifAddrs, forwardableOnly, cfg.allowLoopback)
}

// filterUsableIfAddrs filters out IfAddrs that are not usable as a bind
// address reachable from other hosts and orders the remainder by usability:
// addresses on the interface with the default route sort first, then by
// address type, then by network size.
func filterUsableIfAddrs(ifAddrs IfAddrs, forwardableOnly, allowLoopback bool) (IfAddrs, error) {
	// Never select an address from an interface that is down.
	ifAddrs, _, err := IfByFlag("up", ifAddrs)
	if err != nil {
		return nil, err
	}

	if forwardableOnly {
		ifAddrs, _, err = IfByFlag("forwardable", ifAddrs)
		if err != nil {
			return nil, err
		}
	}

	if !allowLoopback {
		ifAddrs, _ = IfWithoutLoopback(ifAddrs)
	}

	OrderedIfAddrBy(AscIfDefault, AscIfType, AscIfNetworkSize).Sort(ifAddrs)

	return ifAddrs, nil
}

// IfAddrAttrs returns a list of attributes supported by the IfAddr type
func IfAddrAttrs() []AttrName {
	return ifAddrAttrs
}

// IfAddrAttr returns a string representation of an attribute for the given
// IfAddr.
func IfAddrAttr(ifAddr IfAddr, attrName AttrName) string {
	fn, found := ifAddrAttrMap[attrName]
	if !found {
		return ""
	}

	return fn(ifAddr)
}

// ifAddrAttrInit is called once at init()
func ifAddrAttrInit() {
	// Sorted for human readability
	ifAddrAttrs = []AttrName{
		"flags",
		"name",
	}

	ifAddrAttrMap = map[AttrName]func(ifAddr IfAddr) string{
		"flags": func(ifAddr IfAddr) string {
			return ifAddr.Flags.String()
		},
		"name": func(ifAddr IfAddr) string {
			return ifAddr.Name
		},
	}
}
