//go:build linux

package tlsext

import "syscall"

// BindToInterface binds the given socket file descriptor to the named
// network interface using Linux's SO_BINDTODEVICE. The interface name
// must be 15 characters or fewer (IFNAMSIZ = 16 including null).
// Requires CAP_NET_RAW (root).
func BindToInterface(fd uintptr, network, ifaceName string) error {
	return syscall.BindToDevice(int(fd), ifaceName)
}
