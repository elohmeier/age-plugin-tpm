//go:build !linux && !darwin

package plugin

import (
	"errors"
	"net"
)

func peerUID(c *net.UnixConn) (int, error) {
	return -1, errors.New("peer credentials are not supported on this platform")
}

func HardenProcess() error { return nil }

func lockMemory(b []byte)   {}
func unlockMemory(b []byte) {}
