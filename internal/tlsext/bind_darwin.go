//go:build darwin

package tlsext

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// BindToInterface binds the given socket file descriptor to the named
// network interface on macOS. Unlike Linux's SO_BINDTODEVICE, macOS
// uses IP_BOUND_IF (IPv4) and IPV6_BOUND_IF (IPv6) which take an
// interface index rather than a name.
func BindToInterface(fd uintptr, network, ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}

	switch network {
	case "tcp6", "udp6":
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index)
	default:
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
	}
}
