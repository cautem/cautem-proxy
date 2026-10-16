//go:build darwin || linux

package proxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func listenProxy(address string) (net.Listener, error) {
	if !strings.HasPrefix(address, "unix://") {
		return net.Listen("tcp", address)
	}
	path := strings.TrimPrefix(address, "unix://")
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 || len(path) > 96 {
		return nil, fmt.Errorf("proxy Unix socket path must be a clean absolute path within the portable socket path limit")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect proxy Unix socket directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(parentInfo) {
		return nil, fmt.Errorf("proxy Unix socket directory must be owned by the current user and private")
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to remove non-socket proxy path %q", path)
		}
		if connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond); dialErr == nil {
			_ = connection.Close()
			return nil, fmt.Errorf("proxy Unix socket is already in use")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale proxy Unix socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect proxy Unix socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("secure proxy Unix socket: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("inspect proxy Unix socket: %w", err)
	}
	return &ownedUnixListener{Listener: listener, path: path, info: info}, nil
}

type ownedUnixListener struct {
	net.Listener
	path string
	info os.FileInfo
}

func (l *ownedUnixListener) Close() error {
	closeErr := l.Listener.Close()
	if current, err := os.Lstat(l.path); err == nil && os.SameFile(l.info, current) {
		if err := os.Remove(l.path); err != nil && closeErr == nil {
			return err
		}
	} else if err != nil && !os.IsNotExist(err) && closeErr == nil {
		return err
	}
	return closeErr
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}
