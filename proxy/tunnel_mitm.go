package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cautem/cautem-core/engine"
	"github.com/cautem/cautem-proxy/proxy/middleware"
)

func (s *Server) mitmHTTPS(client net.Conn, clientBuf *bufio.Reader, backend net.Conn, host string, port int, eng engine.PolicyEngine, binary string) {
	defer client.Close()
	defer backend.Close()

	s.mu.RLock()
	ca := s.ca
	upTLSCfg := ClientTLSConfig(host)
	if s.UpstreamTLS != nil {
		upTLSCfg = s.UpstreamTLS.Clone()
		if upTLSCfg.ServerName == "" {
			upTLSCfg.ServerName = host
		}
		if len(upTLSCfg.NextProtos) == 0 {
			upTLSCfg.NextProtos = []string{"http/1.1"}
		}
	}
	s.mu.RUnlock()
	if ca == nil {
		return
	}
	tlsCfg, err := ca.ServerTLSConfig(host)
	if err != nil {
		return
	}
	clientTLS := tls.Server(&bufConn{Conn: client, r: clientBuf}, tlsCfg)
	if err := clientTLS.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
		return
	}
	if err := clientTLS.Handshake(); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "client tls: " + err.Error(), Allow: false})
		return
	}
	if err := clientTLS.SetDeadline(time.Time{}); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
		return
	}

	upTLS := tls.Client(backend, upTLSCfg)
	if err := upTLS.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
		return
	}
	if err := upTLS.Handshake(); err != nil {
		s.logAudit(auditEvent{Action: "dial_error", Host: host, Port: port, Reason: "upstream tls: " + err.Error(), Allow: true})
		return
	}
	if err := upTLS.SetDeadline(time.Time{}); err != nil {
		s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
		return
	}

	clientBR := bufio.NewReader(clientTLS)
	upBR := bufio.NewReader(upTLS)

	s.mu.RLock()
	secrets := s.secrets
	s.mu.RUnlock()

	for {
		if err := clientTLS.SetReadDeadline(time.Now().Add(upstreamIdleTimeout)); err != nil {
			s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
			return
		}
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			return
		}
		pathOnly := req.URL.EscapedPath()
		if pathOnly == "" {
			pathOnly = "/"
		}
		dec, err := s.decideHTTP(req, eng, host, port, pathOnly, binary)
		pathOnly = req.URL.EscapedPath()
		if pathOnly == "" {
			pathOnly = "/"
		}
		if err != nil || !dec.Allow {
			var reason string
			if err == nil {
				reason = dec.Reason
			} else {
				reason = err.Error()
			}
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: reason, Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("cautem-proxy: denied\n")),
			}
			resp.Header.Set("Content-Type", "text/plain")
			resp.Header.Set("Connection", "close")
			resp.ContentLength = int64(len("cautem-proxy: denied\n"))
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}
		if dec.Audit {
			s.logAudit(auditEvent{
				Action: "audit", Host: host, Port: port, Reason: dec.Reason, Allow: true,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
		}

		if err := s.runMiddleware(req.Context(), req, "https", host, port, pathOnly); err != nil {
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: err.Error(), Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			msg := "cautem-proxy: middleware denied\n"
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header),
				Body:   io.NopCloser(strings.NewReader(msg)),
			}
			resp.Header.Set("Content-Type", "text/plain")
			resp.Header.Set("Connection", "close")
			resp.ContentLength = int64(len(msg))
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}

		bound := []string(nil)
		if dec.Matched != nil {
			bound = dec.Matched.Rule.CredentialKeys
		}
		used := PlaceholderKeysInRequest(req)
		secrets, bindErr := s.resolveTokenGrantPlaceholders(req.Context(), host, port, pathOnly, req, bound, secrets)
		if bindErr != nil {
			s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: "token grant failed", Allow: false, Method: req.Method, Path: pathOnly, Binary: binary})
			msg := "cautem-proxy: token grant failed\n"
			resp := &http.Response{StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(msg))}
			resp.Header.Set("Connection", "close")
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}
		rewSecrets, bindErr := SecretsForEndpoint(secrets, bound, used)
		if bindErr != nil {
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: bindErr.Error(), Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			s.logAudit(auditEvent{
				Action: "finding", Host: host, Port: port, Reason: "credential_endpoint_mismatch", Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			msg := "cautem-proxy: credential_endpoint_mismatch\n"
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header),
				Body:   io.NopCloser(strings.NewReader(msg)),
			}
			resp.Header.Set("Connection", "close")
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}
		rewriteBody := dec.Matched != nil && dec.Matched.Rule.Protocol == "rest" && dec.Matched.Rule.RequestBodyCredentialRewrite
		if err := RewriteHTTPRequestWithOptions(req, rewSecrets, rewriteBody); err != nil {
			s.logAudit(auditEvent{
				Action: "deny", Host: host, Port: port, Reason: "credential rewrite: " + err.Error(), Allow: false,
				Method: req.Method, Path: pathOnly, Binary: binary,
			})
			msg := "cautem-proxy: credential rewrite failed\n"
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header),
				Body:   io.NopCloser(strings.NewReader(msg)),
			}
			resp.Header.Set("Connection", "close")
			_ = resp.Write(clientTLS)
			_ = req.Body.Close()
			return
		}

		outReq := &http.Request{
			Method: req.Method,
			URL: &url.URL{
				Scheme:   "https",
				Host:     net.JoinHostPort(host, strconv.Itoa(port)),
				Path:     req.URL.Path,
				RawPath:  req.URL.RawPath,
				RawQuery: req.URL.RawQuery,
			},
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        req.Header.Clone(),
			Body:          req.Body,
			ContentLength: req.ContentLength,
			Host:          req.Host,
		}
		if outReq.Host == "" {
			outReq.Host = host
		}
		outReq.RequestURI = ""

		wantWS := isWebsocketUpgrade(req)
		var wsSessions []middleware.WebSocketSession
		if wantWS {
			wsSessions, err = s.openWebSocketMiddlewareSessions(req.Context(), req, host, port, pathOnly)
			if err != nil {
				_ = req.Body.Close()
				msg := "cautem-proxy: websocket middleware denied\n"
				_, _ = clientTLS.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: " + strconv.Itoa(len(msg)) + "\r\nConnection: close\r\n\r\n" + msg))
				return
			}
		}
		if err := outReq.Write(upTLS); err != nil {
			_ = req.Body.Close()
			return
		}
		if err := upTLS.SetReadDeadline(time.Now().Add(upstreamIdleTimeout)); err != nil {
			s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "TLS deadline: " + err.Error(), Allow: false})
			return
		}
		resp, err := http.ReadResponse(upBR, outReq)
		if err != nil {
			for _, session := range wsSessions {
				_ = session.Close("upstream failure")
			}
			_ = req.Body.Close()
			return
		}
		if wantWS && resp.StatusCode != http.StatusSwitchingProtocols {
			for _, session := range wsSessions {
				_ = session.Close("upgrade rejected")
			}
		}
		if !wantWS || resp.StatusCode != http.StatusSwitchingProtocols {
			if err := s.runMiddlewareResponse(req.Context(), req, host, port, pathOnly, resp); err != nil {
				_ = resp.Body.Close()
				msg := "cautem-proxy: response middleware denied\n"
				_, _ = clientTLS.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: " + strconv.Itoa(len(msg)) + "\r\nConnection: close\r\n\r\n" + msg))
				return
			}
		}
		s.logAudit(auditEvent{
			Action: "allow", Host: host, Port: port, Reason: dec.Reason, Allow: true,
			Method: req.Method, Path: pathOnly, Binary: binary,
		})
		err = resp.Write(clientTLS)
		_ = resp.Body.Close()
		_ = req.Body.Close()
		if err != nil {
			return
		}
		if wantWS && resp.StatusCode == http.StatusSwitchingProtocols {
			wsRewrite := false
			proto := ""
			bound := []string(nil)
			graphqlOperations := false
			if mr := dec.Matched; mr != nil {
				wsRewrite = mr.Rule.WebsocketCredentialRewrite
				proto = mr.Rule.Protocol
				graphqlOperations = mr.Rule.UsesGraphQLOperationRules()
				bound = mr.Rule.CredentialKeys
			}
			query, err := parsePolicyQuery(req.URL.RawQuery)
			if err != nil {
				s.logAudit(auditEvent{Action: "error", Host: host, Port: port, Reason: "websocket query: " + err.Error(), Allow: false, Binary: binary})
				return
			}
			s.relayWebsocket(req.Context(), clientBR, clientTLS, upBR, upTLS, host, port, pathOnly, query, eng, secrets, bound, wsRewrite, proto, graphqlOperations, binary, wsSessions)
			return
		}
		if strings.EqualFold(resp.Header.Get("Connection"), "close") || req.Close || resp.Close {
			return
		}
	}
}
