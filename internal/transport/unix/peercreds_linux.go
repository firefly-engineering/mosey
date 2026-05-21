//go:build linux

package unix

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredsRemoteID reads the peer's (uid, pid) via SO_PEERCRED and
// formats it as the canonical RemoteID for unix-socket peers.
// SO_PEERCRED is the right syscall on Linux specifically — macOS
// exposes the same data via different sockopts; see the darwin
// build sibling.
func peerCredsRemoteID(c *net.UnixConn) (string, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var (
		ucred   *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return "", err
	}
	if credErr != nil {
		return "", credErr
	}
	return fmt.Sprintf("unix:uid=%d:pid=%d", ucred.Uid, ucred.Pid), nil
}
