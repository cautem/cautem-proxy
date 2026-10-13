package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cautem/cautem-core/engine"
	"github.com/cautem/cautem-core/policy"
)

const maxRawTunnelLifetime = 30 * time.Minute

func (s *Server) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		http.Error(w, "bad port", http.StatusBadRequest)
		s.logAudit(auditEvent{Action: "reject", Host: r.Host, Reason: "bad port", Allow: false})
		return
	}

	s.mu.RLock()
	eng := s.eng
	allowLoop := s.allowLoopback
	ca := s.ca
	policyGen := s.policyGen
	s.mu.RUnlock()
	if eng == nil {
		http.Error(w, "proxy not configured", http.StatusServiceUnavailable)
		return
	}
	bin := callerBinary(r)
	// inference.local / policy.local are managed sandbox-local adapters.
	if s.isInferenceLocal(host) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, "hijack failed", http.StatusInternalServerError)
			return
		}
		defer client.Close()
		s.handleInferenceLocal(w, r, client)
		return
	}
	if s.isPolicyLocal(host) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		client, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, "hijack failed", http.StatusInternalServerError)
			return
		}
		defer client.Close()
		s.handlePolicyLocal(w, r, client)
		return
	}
	dec, err := eng.Decide(r.Context(), engine.EgressRequest{Host: host, Port: port, Binary: bin})
	if err != nil {
		http.Error(w, "policy error", http.StatusInternalServerError)
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: err.Error(), Allow: false, Binary: bin})
		return
	}
	if !dec.Allow {
		body := DenyBodyJSON(host, port, dec.Reason)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(body)
		s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: dec.Reason, Allow: false, Binary: bin})
		return
	}
	if dec.Audit {
		s.logAudit(auditEvent{Action: "audit", Host: host, Port: port, Reason: dec.Reason, Allow: true, Binary: bin})
	}

	var allowedIPs []string
	if dec.Matched != nil {
		allowedIPs = dec.Matched.AllowedIPs
	}

	needsL7 := dec.Matched != nil && dec.Matched.Rule.NeedsL7()
	credentialed := dec.Matched != nil && blocksUninspectedCredentials(dec.Matched.Rule)
	tlsMode := ""
	if dec.Matched != nil {
		tlsMode = strings.ToLower(strings.TrimSpace(dec.Matched.Rule.TLS))
	}
	if credentialed {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cautem-proxy: credentialed endpoint requires L7 inspection\n"))
		s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: "credentialed endpoint requires L7 inspection", Allow: false, Binary: bin})
		return
	}

	backend, err := DialSSRF(r.Context(), host, portStr, SSRFOptions{AllowedIPs: allowedIPs, allowLoopback: allowLoop})
	if err != nil {
		http.Error(w, "dial failed", http.StatusBadGateway)
		s.logAudit(auditEvent{Action: "dial_error", Host: host, Port: port, Reason: err.Error(), Allow: true})
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = backend.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		_ = backend.Close()
		return
	}
	releaseTunnel, current := s.trackTunnel(clientConn, policyGen)
	if !current {
		_ = backend.Close()
		_ = clientConn.Close()
		return
	}
	_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = bufrw.Flush()

	if needsL7 && tlsMode != "skip" {
		if ca == nil {
			_ = backend.Close()
			_ = clientConn.Close()
			releaseTunnel()
			s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "mitm ca missing", Allow: false})
			return
		}
		reason := dec.Reason + " tls:auto"
		if tlsMode == policy.TLSTerminate {
			reason += "; 'tls: terminate' is deprecated; TLS termination is now automatic"
		}
		if tlsMode == policy.TLSPassthrough {
			reason += "; 'tls: passthrough' is deprecated; TLS termination is now automatic"
		}
		s.logAudit(auditEvent{Action: "allow", Host: host, Port: port, Reason: reason, Allow: true, Binary: bin})
		go func() { defer releaseTunnel(); s.mitmHTTPS(clientConn, bufrw.Reader, backend, host, port, eng, bin) }()
		return
	}
	protocol := ""
	if dec.Matched != nil {
		protocol = strings.ToLower(strings.TrimSpace(dec.Matched.Rule.Protocol))
	}
	// OpenShell v1 has no SQL parser/relay. SQL audit policies pass database
	// TLS bytes through untouched; classifying them as HTTPS would corrupt SQL.
	if !needsL7 && tlsMode != "skip" && protocol != policy.ProtocolSQL {
		tlsPayload, err := tunnelStartsTLS(clientConn, bufrw.Reader)
		if err != nil {
			_ = backend.Close()
			_ = clientConn.Close()
			releaseTunnel()
			s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS auto-detection: " + err.Error(), Allow: false, Binary: bin})
			return
		}
		if tlsPayload {
			if ca == nil {
				_ = backend.Close()
				_ = clientConn.Close()
				releaseTunnel()
				s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS auto-detection requires MITM CA", Allow: false, Binary: bin})
				return
			}
			s.logAudit(auditEvent{Action: "allow", Host: host, Port: port, Reason: dec.Reason + " tls:auto-detected", Allow: true, Binary: bin})
			go func() { defer releaseTunnel(); s.mitmHTTPS(clientConn, bufrw.Reader, backend, host, port, eng, bin) }()
			return
		}
	}

	allowReason := dec.Reason
	if needsL7 && tlsMode == "skip" {
		allowReason += " tls:skip (L7 bypass)"
	}
	s.logAudit(auditEvent{Action: "allow", Host: host, Port: port, Reason: allowReason, Allow: true, Binary: bin})
	// Drain any buffered bytes into the tunnel.
	deadline := time.AfterFunc(maxRawTunnelLifetime, func() { _ = clientConn.Close() })
	go func() {
		defer deadline.Stop()
		defer releaseTunnel()
		tunnelWithBuf(backend, clientConn, bufrw.Reader)
	}()
}

// tunnelStartsTLS performs the same narrow TLS record-prefix check used by
// OpenShell's CONNECT classifier. The read deadline bounds how long a client
// without payload bytes can hold an established CONNECT open before raw relay.

// tunnelStartsTLS performs the same narrow TLS record-prefix check used by
// OpenShell's CONNECT classifier. The read deadline bounds how long a client
// without payload bytes can hold an established CONNECT open before raw relay.
func tunnelStartsTLS(conn net.Conn, reader *bufio.Reader) (bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return false, err
	}
	prefix, _ := reader.Peek(2)
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return false, err
	}
	return len(prefix) >= 2 && prefix[0] == 0x16 && prefix[1] == 0x03, nil
}

// bufConn wraps a net.Conn so leftover buffered CONNECT bytes are read first.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	if c.r != nil && c.r.Buffered() > 0 {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

func tunnelWithBuf(backend, client net.Conn, clientBuf *bufio.Reader) {
	defer backend.Close()
	defer client.Close()
	errCh := make(chan struct{}, 2)
	go func() {
		if clientBuf != nil && clientBuf.Buffered() > 0 {
			_, _ = io.Copy(backend, clientBuf)
		}
		_, _ = io.Copy(backend, client)
		errCh <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, backend)
		errCh <- struct{}{}
	}()
	<-errCh
}

// CA returns the active MITM CA (may be nil until NewServer succeeds).

// CA returns the active MITM CA (may be nil until NewServer succeeds).
func (s *Server) CA() *MitmCA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ca
}

// SetCA installs a MITM CA.

// SetCA installs a MITM CA.
func (s *Server) SetCA(ca *MitmCA) {
	s.mu.Lock()
	s.ca = ca
	s.mu.Unlock()
}
