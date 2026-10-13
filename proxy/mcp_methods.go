package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cautem/cautem-core/policy"
)

func validateMCPMethodParams(method string, params *struct {
	Name            string `json:"name"`
	ProtocolVersion string `json:"protocolVersion"`
}, raw json.RawMessage) error {
	if strings.HasPrefix(method, "notifications/") {
		if method == "notifications/cancelled" {
			var value struct {
				RequestID json.RawMessage `json:"requestId"`
				Reason    *string         `json:"reason"`
			}
			if json.Unmarshal(raw, &value) != nil || validateMCPRequestID(value.RequestID, len(value.RequestID) > 0) != nil {
				return fmt.Errorf("mcp: notifications/cancelled requires params.requestId")
			}
		}
		if method == "notifications/progress" {
			var value struct {
				Token    json.RawMessage `json:"progressToken"`
				Progress *float64        `json:"progress"`
				Total    *float64        `json:"total"`
				Message  *string         `json:"message"`
			}
			if json.Unmarshal(raw, &value) != nil || len(value.Token) == 0 || value.Progress == nil {
				return fmt.Errorf("mcp: notifications/progress requires progressToken and progress")
			}
			if err := validateMCPRequestID(value.Token, true); err != nil {
				return fmt.Errorf("mcp: notifications/progress progressToken must be a string or signed integer")
			}
		}
		if method == "notifications/message" {
			var value struct {
				Level  string          `json:"level"`
				Logger *string         `json:"logger"`
				Data   json.RawMessage `json:"data"`
			}
			if json.Unmarshal(raw, &value) != nil || len(value.Data) == 0 ||
				!map[string]bool{
					"debug": true, "info": true, "notice": true, "warning": true,
					"error": true, "critical": true, "alert": true, "emergency": true,
				}[value.Level] {
				return fmt.Errorf("mcp: notifications/message requires a valid level and data")
			}
		}
		if method == "notifications/resources/updated" {
			var value struct {
				URI json.RawMessage `json:"uri"`
			}
			var uri string
			if json.Unmarshal(raw, &value) != nil || len(value.URI) == 0 || json.Unmarshal(value.URI, &uri) != nil {
				return fmt.Errorf("mcp: notifications/resources/updated requires params.uri")
			}
		}
		if method == "notifications/elicitation/complete" {
			var value struct {
				ElicitationID string `json:"elicitationId"`
			}
			if json.Unmarshal(raw, &value) != nil || value.ElicitationID == "" {
				return fmt.Errorf("mcp: notifications/elicitation/complete requires elicitationId")
			}
		}
		if method == "notifications/tasks/status" {
			var value struct {
				TaskID        string  `json:"taskId"`
				Status        string  `json:"status"`
				CreatedAt     string  `json:"createdAt"`
				LastUpdatedAt string  `json:"lastUpdatedAt"`
				TTL           *uint64 `json:"ttl"`
				StatusMessage *string `json:"statusMessage"`
				PollInterval  *uint64 `json:"pollInterval"`
			}
			if json.Unmarshal(raw, &value) != nil || value.TaskID == "" || value.CreatedAt == "" || value.LastUpdatedAt == "" ||
				!map[string]bool{"working": true, "input_required": true, "completed": true, "failed": true, "cancelled": true}[value.Status] {
				return fmt.Errorf("mcp: notifications/tasks/status has invalid task status params")
			}
		}
		return nil
	}
	if method == "initialize" {
		return nil // Full required fields and version are checked below.
	}
	if method == "tools/call" {
		if params == nil || params.Name == "" {
			return fmt.Errorf("mcp: tools/call requires params.name")
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return fmt.Errorf("mcp: tools/call params must be an object")
		}
		if arguments, ok := object["arguments"]; ok {
			var args map[string]json.RawMessage
			if json.Unmarshal(arguments, &args) != nil || args == nil {
				return fmt.Errorf("mcp: tools/call params.arguments must be an object")
			}
		}
		if task, ok := object["task"]; ok && !isJSONNull(task) {
			if err := validateMCPTaskParams(task); err != nil {
				return err
			}
		}
		return nil
	}
	requiredField := map[string]string{
		"resources/read": "uri", "resources/subscribe": "uri", "resources/unsubscribe": "uri", "prompts/get": "name",
		"tasks/get": "taskId", "tasks/result": "taskId", "tasks/cancel": "taskId", "tasks/update": "taskId",
	}[method]
	requiresObject := requiredField != "" || method == "logging/setLevel" || method == "completion/complete" ||
		method == "sampling/createMessage" || method == "elicitation/create"
	if raw == nil || string(raw) == "null" {
		if requiresObject {
			return fmt.Errorf("mcp: %s requires an object params", method)
		}
		return nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return fmt.Errorf("mcp: params must be an object")
	}
	for _, key := range []string{"cursor", "uri", "name", "level", "taskId"} {
		if value, ok := object[key]; ok {
			var text string
			if json.Unmarshal(value, &text) != nil || text == "" {
				return fmt.Errorf("mcp: params.%s must be a non-empty string", key)
			}
		}
	}
	if requiredField != "" {
		if _, ok := object[requiredField]; !ok {
			return fmt.Errorf("mcp: %s requires params.%s", method, requiredField)
		}
	}
	if method == "logging/setLevel" {
		var level string
		if json.Unmarshal(object["level"], &level) != nil || !map[string]bool{
			"debug": true, "info": true, "notice": true, "warning": true, "error": true, "critical": true, "alert": true, "emergency": true,
		}[level] {
			return fmt.Errorf("mcp: logging/setLevel has invalid params.level")
		}
	}
	if method == "tasks/list" {
		if status, ok := object["status"]; ok && !isJSONNull(status) {
			var value string
			if json.Unmarshal(status, &value) != nil || !isMapValue(value, "working", "input_required", "completed", "failed", "cancelled") {
				return fmt.Errorf("mcp: tasks/list has invalid params.status")
			}
		}
	}
	if method == "tasks/cancel" {
		if reason, ok := object["reason"]; ok && !isJSONNull(reason) {
			var value string
			if json.Unmarshal(reason, &value) != nil {
				return fmt.Errorf("mcp: tasks/cancel params.reason must be a string")
			}
		}
	}
	if method == "tasks/update" {
		if responses, ok := object["inputResponses"]; ok {
			var values map[string]json.RawMessage
			if json.Unmarshal(responses, &values) != nil || values == nil {
				return fmt.Errorf("mcp: tasks/update params.inputResponses must be an object")
			}
		}
	}
	if method == "completion/complete" {
		var completion map[string]json.RawMessage
		if json.Unmarshal(raw, &completion) != nil || completion == nil {
			return fmt.Errorf("mcp: completion/complete requires ref and argument")
		}
		var ref struct {
			Type string          `json:"type"`
			Name json.RawMessage `json:"name"`
			URI  json.RawMessage `json:"uri"`
		}
		var argument struct {
			Name  json.RawMessage `json:"name"`
			Value json.RawMessage `json:"value"`
		}
		if json.Unmarshal(completion["ref"], &ref) != nil || json.Unmarshal(completion["argument"], &argument) != nil {
			return fmt.Errorf("mcp: completion/complete requires ref and argument")
		}
		var name, value string
		if ref.Type == "ref/prompt" && json.Unmarshal(ref.Name, &name) != nil ||
			ref.Type == "ref/resource" && json.Unmarshal(ref.URI, &name) != nil ||
			ref.Type != "ref/prompt" && ref.Type != "ref/resource" ||
			json.Unmarshal(argument.Name, &name) != nil || json.Unmarshal(argument.Value, &value) != nil {
			return fmt.Errorf("mcp: completion/complete has invalid ref")
		}
		if contextRaw, ok := completion["context"]; ok && string(contextRaw) != "null" {
			var context map[string]json.RawMessage
			if json.Unmarshal(contextRaw, &context) != nil || context == nil {
				return fmt.Errorf("mcp: completion/complete context must be an object")
			}
			if arguments, ok := context["arguments"]; ok && string(arguments) != "null" {
				if err := validateMCPStringMap(arguments, "completion context arguments"); err != nil {
					return err
				}
			}
		}
	}
	if method == "prompts/get" {
		var prompt map[string]json.RawMessage
		if json.Unmarshal(raw, &prompt) != nil || prompt == nil {
			return fmt.Errorf("mcp: prompts/get params must be an object")
		}
		if arguments, ok := prompt["arguments"]; ok && string(arguments) != "null" {
			if err := validateMCPStringMap(arguments, "prompts/get arguments"); err != nil {
				return err
			}
		}
	}
	if method == "sampling/createMessage" {
		var sampling struct {
			Messages  []json.RawMessage `json:"messages"`
			MaxTokens uint32            `json:"maxTokens"`
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields["maxTokens"]) == 0 || isJSONNull(fields["maxTokens"]) ||
			json.Unmarshal(raw, &sampling) != nil || len(sampling.Messages) == 0 {
			return fmt.Errorf("mcp: sampling/createMessage requires messages and maxTokens")
		}
		for _, message := range sampling.Messages {
			if err := validateMCPSamplingMessage(message); err != nil {
				return err
			}
		}
		if err := validateMCPSamplingOptions(raw); err != nil {
			return err
		}
	}
	if method == "elicitation/create" {
		var elicitation struct {
			Mode            string          `json:"mode"`
			Message         string          `json:"message"`
			RequestedSchema json.RawMessage `json:"requestedSchema"`
			URL             json.RawMessage `json:"url"`
			ElicitationID   json.RawMessage `json:"elicitationId"`
		}
		if json.Unmarshal(raw, &elicitation) != nil || strings.TrimSpace(elicitation.Message) == "" {
			return fmt.Errorf("mcp: elicitation/create requires message")
		}
		switch elicitation.Mode {
		case "", "form":
			var schema map[string]json.RawMessage
			if json.Unmarshal(elicitation.RequestedSchema, &schema) != nil || schema == nil {
				return fmt.Errorf("mcp: form elicitation requires requestedSchema object")
			}
		case "url":
			var target, id string
			if json.Unmarshal(elicitation.URL, &target) != nil || target == "" ||
				json.Unmarshal(elicitation.ElicitationID, &id) != nil || id == "" {
				return fmt.Errorf("mcp: URL elicitation requires url and elicitationId")
			}
		default:
			return fmt.Errorf("mcp: elicitation/create has invalid mode")
		}
	}
	return nil
}

func validateMCPProtocolVersion(req *http.Request, config *policy.MCPConfig, jsonrpc string, id *json.RawMessage, method string, params *struct {
	Name            string `json:"name"`
	ProtocolVersion string `json:"protocolVersion"`
}) error {
	// OpenShell negotiates a standalone initialize request through its JSON-RPC
	// body. All other requests select exactly one allowed HTTP header revision,
	// with the pinned legacy fallback when the header is absent.
	if jsonrpc == "2.0" && id != nil && method == "initialize" && params != nil && params.ProtocolVersion != "" {
		return nil
	}
	values := req.Header.Values("MCP-Protocol-Version")
	if len(values) > 1 {
		return fmt.Errorf("mcp: protocol version header must have one value")
	}
	for _, connectionValue := range req.Header.Values("Connection") {
		for _, nominated := range strings.Split(connectionValue, ",") {
			if strings.EqualFold(strings.TrimSpace(nominated), "MCP-Protocol-Version") {
				return fmt.Errorf("mcp: protocol version header cannot be connection-nominated")
			}
		}
	}
	version := mcpLegacyFallbackVersion
	if len(values) == 1 {
		version = strings.Trim(values[0], " \t")
		if version == "" {
			return fmt.Errorf("mcp: protocol version header must not be empty")
		}
	}
	if _, ok := supportedMCPVersions[version]; !ok {
		return fmt.Errorf("mcp: unsupported protocol version %q", version)
	}
	allowed := []string{defaultMCPAllowedVersion}
	if config != nil && config.Versions != nil {
		allowed = config.Versions
	}
	for _, candidate := range allowed {
		if version == candidate {
			return nil
		}
	}
	return fmt.Errorf("mcp: protocol version %q is not allowed by endpoint policy", version)
}

// mcpDecidePath builds MatchHTTP path: URL path + NUL + tool (tool may be empty).

// mcpDecidePath builds MatchHTTP path: URL path + NUL + tool (tool may be empty).
func mcpDecidePath(urlPath, tool string) string {
	if urlPath == "" {
		urlPath = "/"
	}
	if tool == "" {
		return urlPath
	}
	return urlPath + "\x00" + tool
}

func isMCPRule(rule *policy.AllowRule) bool {
	return rule != nil && strings.EqualFold(strings.TrimSpace(rule.Protocol), policy.ProtocolMCP)
}
