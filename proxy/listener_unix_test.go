//go:build darwin || linux

package proxy

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListenProxyUnixCreatesPrivateSocketAndRemovesIt(t *testing.T) {
	dir := privateUnixSocketTestDir(t)
	path := filepath.Join(dir, "proxy.sock")
	listener, err := listenProxy("unix://" + path)
	if err != nil {
		t.Fatalf("listenProxy() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v; want private mode 0600 socket", info.Mode())
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to proxy socket: %v", err)
	}
	_ = connection.Close()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remains after close: %v", err)
	}
}

func TestServerServesHealthOnPrivateUnixSocket(t *testing.T) {
	dir := privateUnixSocketTestDir(t)
	path := filepath.Join(dir, "health.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	server := NewServer(nil, nil)
	go func() { done <- server.ListenAndServe(ctx, "unix://"+path) }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	deadline := time.Now().Add(2 * time.Second)
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://proxy/healthz", nil)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				cancel()
				t.Fatalf("health response status = %s", response.Status)
			}
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("Unix proxy health endpoint did not become ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("ListenAndServe() error = %v; want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy server did not stop after cancellation")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("Unix socket remains after server shutdown: %v", err)
	}
}

func TestListenProxyUnixRejectsUnsafePathsAndActiveSocket(t *testing.T) {
	dir := privateUnixSocketTestDir(t)
	for _, address := range []string{"unix://relative.sock", "unix:///tmp/../proxy.sock"} {
		if _, err := listenProxy(address); err == nil {
			t.Errorf("listenProxy(%q) unexpectedly succeeded", address)
		}
	}
	unsafeDir := filepath.Join(dir, "shared")
	if err := os.Mkdir(unsafeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := listenProxy("unix://" + filepath.Join(unsafeDir, "proxy.sock")); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("insecure socket directory error = %v", err)
	}
	path := filepath.Join(dir, "active.sock")
	active, err := listenProxy("unix://" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if _, err := listenProxy("unix://" + path); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("active socket error = %v", err)
	}
}

func privateUnixSocketTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cp-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
