//go:build !darwin && !linux

package proxy

import (
	"fmt"
	"net"
	"strings"
)

func listenProxy(address string) (net.Listener, error) {
	if strings.HasPrefix(address, "unix://") {
		return nil, fmt.Errorf("proxy Unix sockets are not supported on this platform")
	}
	return net.Listen("tcp", address)
}
