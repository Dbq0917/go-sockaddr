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
	for attempt := 0; attempt < 2; attempt++ {
		defaultIfs, cached, err := getDefaultInterfacesCached()
		if err != nil {
			return "", err
		}

		privateIfs, err := privateInterfacesFrom(defaultIfs, "")
		if err != nil {
			return "", err
		}

		if len(privateIfs) > 0 {
			if !cached || cachedIfAddrsStillUsable(privateIfs) {
				return firstIPAddress(privateIfs), nil
			}
		}

		if !cached {
			return "", nil
		}

		InvalidateInterfaceCache()
	}

	return "", nil
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
	ifAddrs, _, err := getInterfacesCached(func(all IfAddrs) (IfAddrs, error) {
		return privateInterfacesFrom(all, "")
	})
	if err != nil {
		return "", err
	}

	return joinIPAddresses(ifAddrs), nil
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
	for attempt := 0; attempt < 2; attempt++ {
		defaultIfs, cached, err := getDefaultInterfacesCached()
		if err != nil {
			return "", err
		}

		publicIfs, err := publicInterfacesFrom(defaultIfs, "")
		if err != nil {
			return "", err
		}

		if len(publicIfs) > 0 {
			if !cached || cachedIfAddrsStillUsable(publicIfs) {
				return firstIPAddress(publicIfs), nil
			}
		}

		if !cached {
			return "", nil
		}

		InvalidateInterfaceCache()
	}

	return "", nil
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
	ifAddrs, _, err := getInterfacesCached(func(all IfAddrs) (IfAddrs, error) {
		return publicInterfacesFrom(all, "")
	})
	if err != nil {
		return "", err
	}

	return joinIPAddresses(ifAddrs), nil
}

// GetInterfaceIP returns a string with a single IP address sorted by the size
// of the network (i.e. IP addresses with a smaller netmask, larger network
// size, are sorted first).  This function is the `eval` equivalent of:
//
// ```
// $ sockaddr eval -r '{{GetAllInterfaces | include "name" <<ARG>> | sort "type,size" | include "flag" "forwardable" | attr "address" }}'
// ```
func GetInterfaceIP(namedIfRE string) (string, error) {
	ifAddrs, _, err := getNamedInterfacesCached(namedIfRE)
	if err != nil {
		return "", err
	}

	return firstIPAddress(ifAddrs), nil
}

// GetInterfaceIPs returns a string with all IPs, sorted by the size of the
// network (i.e. IP addresses with a smaller netmask, larger network size, are
// sorted first), on a named interface.  This function is the `eval` equivalent
// of:
//
// ```
// $ sockaddr eval -r '{{GetAllInterfaces | include "name" <<ARG>> | sort "type,size" | join "address" " "}}'
// ```
func GetInterfaceIPs(namedIfRE string) (string, error) {
	ifAddrs, _, err := getNamedInterfacesCached(namedIfRE)
	if err != nil {
		return "", err
	}

	return joinIPAddresses(ifAddrs), nil
}

func getNamedInterfacesCached(namedIfRE string) (IfAddrs, bool, error) {
	return getInterfacesCached(func(all IfAddrs) (IfAddrs, error) {
		matched, _, err := IfByName(namedIfRE, all)
		if err != nil || len(matched) == 0 {
			return IfAddrs{}, err
		}

		matched, err = selectableInterfaces(matched)
		if err != nil {
			return IfAddrs{}, err
		}

		return SortIfBy("+type,+size", matched)
	})
}

func firstIPAddress(ifAddrs IfAddrs) string {
	if len(ifAddrs) == 0 {
		return ""
	}

	ip := ToIPAddr(ifAddrs[0].SockAddr)
	if ip == nil {
		return ""
	}

	return IPAddrAttr(*ip, "address")
}

func joinIPAddresses(ifAddrs IfAddrs) string {
	ips := make([]string, 0, len(ifAddrs))
	for _, ifAddr := range ifAddrs {
		ip := ToIPAddr(ifAddr.SockAddr)
		if ip == nil {
			continue
		}
		ips = append(ips, (*ip).NetIP().String())
	}

	return strings.Join(ips, " ")
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
