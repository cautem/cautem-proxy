package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cautem/quarshell-core/engine"
	"github.com/cautem/quarshell-core/policy"
	"github.com/cautem/quarshell-proxy/proxy/middleware"
)

func isWebsocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
}

func (s *Server) openWebSocketMiddlewareSessions(ctx context.Context, req *http.Request, host string, port int, pathOnly string) ([]middleware.WebSocketSession, error) {
	s.mu.RLock()
	pipe := s.Middleware
	s.mu.RUnlock()
	if pipe == nil {
		return nil, nil
	}
	return pipe.OpenWebSocketSessions(ctx, middleware.WebSocketRequest{SessionID: fmt.Sprintf("%d", time.Now().UnixNano()), Scheme: "wss", Host: host, Port: port, Path: pathOnly, RequestedSubprotocols: websocketSubprotocols(req.Header)})
}

func websocketSubprotocols(headers http.Header) []string {
	var out []string
	for _, value := range headers.Values("Sec-WebSocket-Protocol") {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func (s *Server) relayWebsocket(ctx context.Context, clientBR *bufio.Reader, client io.Writer, upBR *bufio.Reader, up io.Writer, host string, port int, pathOnly string, query map[string][]string, eng engine.PolicyEngine, secrets SecretStore, boundKeys []string, rewriteText bool, protocol string, graphqlOperations bool, binary string, wsSessions []middleware.WebSocketSession) {
	for _, session := range wsSessions {
		if err := session.Start(ctx, ""); err != nil {
			_ = session.Close("session start failure")
			return
		}
	}
	defer func() {
		for _, session := range wsSessions {
			_ = session.Close("session ended")
		}
	}()
	var sequence uint64
	var fragments wsFragmentBuffer
	errCh := make(chan struct{}, 2)
	go func() {
		defer func() { errCh <- struct{}{} }()
		for {
			fr, err := readWSFrame(clientBR)
			if err != nil {
				return
			}
			logical, ready, err := fragments.accept(fr)
			if err != nil {
				_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xea}, false)
				return
			}
			if !ready {
				continue
			}
			fr = logical
			switch fr.Opcode {
			case wsOpcodeText:
				sequence++
				for _, session := range wsSessions {
					allow, replacement, err := session.Message(ctx, sequence, fr.Payload, true)
					if err != nil || !allow {
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					fr.Payload = replacement
				}
				method := policy.MethodWebsocketText
				payload := fr.Payload
				var graphqlOperation *policy.GraphQLOperation
				if strings.EqualFold(protocol, policy.ProtocolGraphQL) || graphqlOperations {
					okPass, operation, err := classifyGraphQLWS(payload)
					if err != nil {
						s.logAudit(auditEvent{
							Action: "deny", Host: host, Port: port, Reason: err.Error(), Allow: false,
							Method: "graphql", Path: pathOnly,
						})
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					if okPass {
						if err := writeWSFrame(up, fr.Opcode, payload, false); err != nil {
							return
						}
						continue
					}
					graphqlOperation = operation
				}
				dec, err := eng.DecideHTTP(context.Background(), engine.HTTPRequest{
					Host: host, Port: port, Method: method, Path: pathOnly, Binary: binary, GraphQL: graphqlOperation, Query: query,
				})
				if err != nil || !dec.Allow {
					reason := "websocket text denied"
					if err == nil {
						reason = dec.Reason
					}
					s.logAudit(auditEvent{
						Action: "deny", Host: host, Port: port, Reason: reason, Allow: false,
						Method: method, Path: pathOnly, Binary: binary,
					})
					_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
					return
				}
				if dec.Audit {
					s.logAudit(auditEvent{
						Action: "audit", Host: host, Port: port, Reason: dec.Reason, Allow: true,
						Method: method, Path: pathOnly, Binary: binary,
					})
				}
				if rewriteText && ContainsPlaceholder(string(payload)) {
					used := placeholderKeysInString(string(payload))
					dynamicSecrets, bindErr := s.resolveTokenGrantKeys(ctx, host, port, pathOnly, used, boundKeys, secrets)
					if bindErr != nil {
						s.logAudit(auditEvent{Action: "deny", Host: host, Port: port, Reason: "token grant failed", Allow: false, Method: method, Path: pathOnly})
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					rew, bindErr := SecretsForEndpoint(dynamicSecrets, boundKeys, used)
					if bindErr != nil {
						s.logAudit(auditEvent{
							Action: "deny", Host: host, Port: port, Reason: bindErr.Error(), Allow: false,
							Method: method, Path: pathOnly,
						})
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					text, err := RewriteText(string(payload), rew)
					if err != nil {
						s.logAudit(auditEvent{
							Action: "deny", Host: host, Port: port, Reason: "ws credential rewrite: " + err.Error(), Allow: false,
							Method: method, Path: pathOnly,
						})
						return
					}
					payload = []byte(text)
				}
				if err := writeWSFrame(up, fr.Opcode, payload, false); err != nil {
					return
				}
			case wsOpcodeBinary:
				sequence++
				for _, session := range wsSessions {
					allow, replacement, err := session.Message(ctx, sequence, fr.Payload, false)
					if err != nil || !allow {
						_ = writeWSFrame(client, wsOpcodeClose, []byte{0x03, 0xef}, false)
						return
					}
					fr.Payload = replacement
				}
				if err := writeWSFrame(up, fr.Opcode, fr.Payload, false); err != nil {
					return
				}
			case wsOpcodePing, wsOpcodePong:
				if err := writeWSFrame(up, fr.Opcode, fr.Payload, false); err != nil {
					return
				}
			case wsOpcodeClose:
				_ = writeWSFrame(up, wsOpcodeClose, fr.Payload, false)
				return
			default:
				if err := writeWSFrame(up, fr.Opcode, fr.Payload, false); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer func() { errCh <- struct{}{} }()
		for {
			fr, err := readWSFrame(upBR)
			if err != nil {
				return
			}
			if err := writeWSFrame(client, fr.Opcode, fr.Payload, false); err != nil {
				return
			}
			if fr.Opcode == wsOpcodeClose {
				return
			}
		}
	}()
	<-errCh
}

// classifyGraphQLWS returns control messages separately and extracts the
// operation envelope from GraphQL-over-WebSocket client messages.

// classifyGraphQLWS returns control messages separately and extracts the
// operation envelope from GraphQL-over-WebSocket client messages.
func classifyGraphQLWS(payload []byte) (pass bool, operation *policy.GraphQLOperation, err error) {
	var msg struct {
		ID      string          `json:"id"`
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return false, nil, fmt.Errorf("graphql-ws: invalid json")
	}
	switch msg.Type {
	case "connection_init", "ping", "pong", "complete", "stop", "connection_terminate":
		return true, nil, nil
	case "subscribe", "start":
		if strings.TrimSpace(msg.ID) == "" || len(msg.Payload) == 0 || msg.Payload[0] != '{' {
			return false, nil, fmt.Errorf("graphql-ws: operation requires a non-empty id and object payload")
		}
		envelope, err := decodeGraphQLEnvelope(msg.Payload)
		if err != nil {
			return false, nil, err
		}
		operations, err := classifyGraphQLEnvelopes([]graphqlEnvelope{envelope})
		if err != nil || len(operations) != 1 {
			return false, nil, fmt.Errorf("graphql-ws: invalid operation payload")
		}
		return false, &operations[0], nil
	default:
		return false, nil, fmt.Errorf("graphql-ws: unsupported type %q", msg.Type)
	}
}

// bufConn wraps a net.Conn so leftover buffered CONNECT bytes are read first.
