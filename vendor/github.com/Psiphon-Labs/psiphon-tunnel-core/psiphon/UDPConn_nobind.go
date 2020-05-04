// +build windows

/*
 * Copyright (c) 2018, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package psiphon

import (
	"net"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func newUDPConn(domain int, config *DialConfig) (net.PacketConn, error) {

	if config.DeviceBinder != nil {
		return nil, errors.TraceNew("newUDPConn with DeviceBinder not supported on this platform")
	}

	network := "udp4"

	if domain == syscall.AF_INET6 {
		network = "udp6"
	}

	return net.ListenUDP(network, nil)
}
