//go:build !linux && !darwin

package tlsext

import "fmt"

// BindToInterface is not yet supported on this platform.
// Linux (SO_BINDTODEVICE) and macOS (IP_BOUND_IF) are supported.
func BindToInterface(fd uintptr, network, ifaceName string) error {
	return fmt.Errorf("interface binding is not supported on this platform (requires Linux or macOS)")
}
