package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/cautem/cautem-core/policy"
)

// parseMCPRequest extracts JSON-RPC method and optional tools/call name from an HTTP body.
// Returns method, tool, restored body reader, error. Fail-closed on invalid JSON for MCP.

const defaultMCPMaxBodyBytes = 64 << 10

var mcpToolName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func parseMCPRequest(req *http.Request, config *policy.MCPConfig) (method, tool string, err error) {
	messages, err := parseMCPMessages(req, config)
	if err != nil {
		return "", "", err
	}
	if len(messages) != 1 || messages[0].response {
		return "", "", fmt.Errorf("mcp: expected one request message")
	}
	return messages[0].method, messages[0].tool, nil
}

type mcpMessage struct {
	method        string
	tool          string
	response      bool
	receiveStream bool
}

func parseMCPMessages(req *http.Request, config *policy.MCPConfig) ([]mcpMessage, error) {
	if req == nil {
		return nil, fmt.Errorf("mcp: missing request")
	}
	noBody := req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0
	if strings.EqualFold(req.Method, http.MethodGet) && noBody && requestAcceptsJSONRPCStream(req) {
		if err := validateMCPProtocolVersion(req, config, "2.0", nil, "", nil); err != nil {
			return nil, err
		}
		return []mcpMessage{{receiveStream: true}}, nil
	}
	if req.Body == nil {
		return nil, fmt.Errorf("mcp: empty body")
	}
	maxBytes := uint32(defaultMCPMaxBodyBytes)
	strictToolNames := true
	if config != nil {
		if config.MaxBodyBytes > 0 {
			maxBytes = config.MaxBodyBytes
		}
		if config.StrictToolNames != nil {
			strictToolNames = *config.StrictToolNames
		}
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, int64(maxBytes)+1))
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil
	req.Header.Del("Transfer-Encoding")
	if uint64(len(body)) > uint64(maxBytes) {
		return nil, fmt.Errorf("mcp: request body exceeds %d bytes", maxBytes)
	}
	var payload json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("mcp: invalid json-rpc: %w", err)
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 {
		return nil, fmt.Errorf("mcp: empty JSON-RPC message")
	}
	items := []json.RawMessage{payload}
	batched := payload[0] == '['
	if batched {
		if err := json.Unmarshal(payload, &items); err != nil || len(items) == 0 {
			return nil, fmt.Errorf("mcp: batch must be a non-empty array")
		}
	}
	messages := make([]mcpMessage, 0, len(items))
	for _, item := range items {
		var object map[string]json.RawMessage
		if len(item) == 0 || item[0] != '{' || json.Unmarshal(item, &object) != nil {
			return nil, fmt.Errorf("mcp: batch item must be an object")
		}
		var version string
		if json.Unmarshal(object["jsonrpc"], &version) != nil || version != "2.0" {
			return nil, fmt.Errorf("mcp: jsonrpc must be \"2.0\"")
		}
		if rawMethod, exists := object["method"]; exists {
			var method string
			if json.Unmarshal(rawMethod, &method) != nil || strings.TrimSpace(method) == "" {
				return nil, fmt.Errorf("mcp: method must be a non-empty string")
			}
			_, hasID := object["id"]
			if strings.HasPrefix(method, "notifications/") {
				if hasID {
					return nil, fmt.Errorf("mcp: notification must not contain an id")
				}
			} else if err := validateMCPRequestID(object["id"], hasID); err != nil {
				return nil, err
			}
			if _, result := object["result"]; result {
				return nil, fmt.Errorf("mcp: request cannot contain result")
			}
			if _, rpcError := object["error"]; rpcError {
				return nil, fmt.Errorf("mcp: request cannot contain error")
			}
			if batched && method == "initialize" {
				return nil, fmt.Errorf("mcp: initialize must not appear in a batch")
			}
			var params struct {
				Name            string `json:"name"`
				ProtocolVersion string `json:"protocolVersion"`
			}
			var paramPointer *struct {
				Name            string `json:"name"`
				ProtocolVersion string `json:"protocolVersion"`
			}
			if rawParams, ok := object["params"]; ok && string(rawParams) != "null" {
				if rawParams[0] != '{' || json.Unmarshal(rawParams, &params) != nil {
					return nil, fmt.Errorf("mcp: params must be an object")
				}
				paramPointer = &params
			}
			if err := validateMCPMethodParams(method, paramPointer, object["params"]); err != nil {
				return nil, err
			}
			tool := ""
			if method == "tools/call" {
				if paramPointer == nil || params.Name == "" {
					return nil, fmt.Errorf("mcp: tools/call requires params.name")
				}
				tool = params.Name
				if strictToolNames && !mcpToolName.MatchString(tool) {
					return nil, fmt.Errorf("mcp: invalid tool name")
				}
			}
			if method == "initialize" && paramPointer != nil {
				if _, supported := supportedMCPVersions[params.ProtocolVersion]; !supported {
					return nil, fmt.Errorf("mcp: unsupported initialize protocol version %q", params.ProtocolVersion)
				}
			}
			if method == "initialize" {
				var clientInfo struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}
				var initParams map[string]json.RawMessage
				var capabilities map[string]json.RawMessage
				rawParams, hasParams := object["params"]
				if !hasParams || json.Unmarshal(rawParams, &initParams) != nil || initParams == nil || paramPointer == nil ||
					params.ProtocolVersion == "" || json.Unmarshal(initParams["capabilities"], &capabilities) != nil || capabilities == nil ||
					json.Unmarshal(initParams["clientInfo"], &clientInfo) != nil || clientInfo.Name == "" || clientInfo.Version == "" {
					return nil, fmt.Errorf("mcp: initialize requires protocolVersion, capabilities, and clientInfo")
				}
			}
			if err := validateMCPProtocolVersion(req, config, version, rawJSONPointer(object, "id"), method, paramPointer); err != nil {
				return nil, err
			}
			messages = append(messages, mcpMessage{method: method, tool: tool})
			continue
		}
		if _, result := object["result"]; result {
			if _, rpcError := object["error"]; rpcError {
				return nil, fmt.Errorf("mcp: response cannot contain both result and error")
			}
			if err := validateMCPResponseID(object["id"], false); err != nil {
				return nil, err
			}
			if err := validateMCPProtocolVersion(req, config, version, nil, "", nil); err != nil {
				return nil, err
			}
			messages = append(messages, mcpMessage{response: true})
			continue
		}
		if _, rpcError := object["error"]; rpcError {
			if err := validateMCPResponseID(object["id"], true); err != nil {
				return nil, err
			}
			var errorFields map[string]json.RawMessage
			var code int32
			var message string
			if json.Unmarshal(object["error"], &errorFields) != nil || errorFields == nil ||
				len(errorFields["code"]) == 0 || isJSONNull(errorFields["code"]) || json.Unmarshal(errorFields["code"], &code) != nil ||
				len(errorFields["message"]) == 0 || isJSONNull(errorFields["message"]) || json.Unmarshal(errorFields["message"], &message) != nil {
				return nil, fmt.Errorf("mcp: response error requires int32 code and string message")
			}
			if err := validateMCPProtocolVersion(req, config, version, nil, "", nil); err != nil {
				return nil, err
			}
			messages = append(messages, mcpMessage{response: true})
			continue
		}
		return nil, fmt.Errorf("mcp: message requires method or response")
	}
	return messages, nil
}

func validateMCPRequestID(raw json.RawMessage, present bool) error {
	if !present {
		return fmt.Errorf("mcp: request method requires an id")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return fmt.Errorf("mcp: invalid request id")
	}
	switch value := value.(type) {
	case string:
		return nil
	case json.Number:
		if _, err := strconv.ParseInt(string(value), 10, 64); err == nil {
			return nil
		}
		return fmt.Errorf("mcp: request id number must be a signed integer")
	default:
		return fmt.Errorf("mcp: request id must be a string or signed integer")
	}
}
