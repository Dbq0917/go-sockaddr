// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

//go:build !linux

package sockaddr

import "net"

func interfaceIsUsable(name string) bool {
	intf, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}

	return intf.Flags&net.FlagUp != 0 && intf.Flags&net.FlagLoopback == 0
}
