//go:build darwin

package unix

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredsRemoteID reads (uid, pid) using darwin's split surface:
// LOCAL_PEERCRED returns an Xucred carrying the uid; LOCAL_PEERPID
// returns the peer's pid via getsockopt. macOS has no single
// SO_PEERCRED-style sockopt, so we do both calls under one Control
// to keep the syscalls bounded.
func peerCredsRemoteID(c *net.UnixConn) (string, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var (
		xucred  *unix.Xucred
		pid     int
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr != nil {
			return
		}
		pid, credErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return "", err
	}
	if credErr != nil {
		return "", credErr
	}
	return fmt.Sprintf("unix:uid=%d:pid=%d", xucred.Uid, pid), nil
}
