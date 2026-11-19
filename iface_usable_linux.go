// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

//go:build linux

package sockaddr

import (
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func interfaceIsUsable(name string) bool {
	data, err := os.ReadFile("/sys/class/net/" + name + "/flags")
	if err == nil {
		flags, parseErr := strconv.ParseUint(strings.TrimSpace(string(data)), 0, 64)
		if parseErr == nil {
			return flags&syscall.IFF_UP != 0 && flags&syscall.IFF_LOOPBACK == 0
		}
	}

	intf, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}

	return intf.Flags&net.FlagUp != 0 && intf.Flags&net.FlagLoopback == 0
}
