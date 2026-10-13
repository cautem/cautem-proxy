package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func validateMCPSamplingOptions(raw json.RawMessage) error {
	var params map[string]json.RawMessage
	if json.Unmarshal(raw, &params) != nil || params == nil {
		return fmt.Errorf("mcp: sampling/createMessage params must be an object")
	}
	if value, ok := params["systemPrompt"]; ok && !isJSONNull(value) {
		var prompt string
		if json.Unmarshal(value, &prompt) != nil {
			return fmt.Errorf("mcp: sampling systemPrompt must be a string")
		}
	}
	if value, ok := params["includeContext"]; ok && !isJSONNull(value) {
		var context string
		if json.Unmarshal(value, &context) != nil ||
			context != "none" && context != "thisServer" && context != "allServers" {
			return fmt.Errorf("mcp: sampling includeContext has an invalid value")
		}
	}
	if value, ok := params["temperature"]; ok && !isJSONNull(value) {
		var temperature float64
		if json.Unmarshal(value, &temperature) != nil {
			return fmt.Errorf("mcp: sampling temperature must be a number")
		}
	}
	if value, ok := params["stopSequences"]; ok && !isJSONNull(value) {
		var sequences []string
		if json.Unmarshal(value, &sequences) != nil || sequences == nil {
			return fmt.Errorf("mcp: sampling stopSequences must be an array of strings")
		}
	} else if value, ok := params["stopSequences"]; ok && isJSONNull(value) {
		return fmt.Errorf("mcp: sampling stopSequences must be an array of strings")
	}
	if value, ok := params["metadata"]; ok && !isJSONNull(value) {
		var metadata map[string]json.RawMessage
		if json.Unmarshal(value, &metadata) != nil || metadata == nil {
			return fmt.Errorf("mcp: sampling metadata must be an object")
		}
	}
	if value, ok := params["modelPreferences"]; ok && !isJSONNull(value) {
		if err := validateMCPModelPreferences(value); err != nil {
			return err
		}
	}
	if value, ok := params["toolChoice"]; ok && !isJSONNull(value) {
		var choice struct {
			Mode *string `json:"mode"`
			Name *string `json:"name"`
		}
		if json.Unmarshal(value, &choice) != nil || choice.Mode == nil {
			return fmt.Errorf("mcp: sampling toolChoice requires a mode string")
		}
	}
	if value, ok := params["tools"]; ok && !isJSONNull(value) {
		var tools []map[string]json.RawMessage
		if json.Unmarshal(value, &tools) != nil || tools == nil {
			return fmt.Errorf("mcp: sampling tools must be an array of tool objects")
		}
		for i, tool := range tools {
			var name string
			var inputSchema map[string]json.RawMessage
			if json.Unmarshal(tool["name"], &name) != nil ||
				json.Unmarshal(tool["inputSchema"], &inputSchema) != nil || inputSchema == nil {
				return fmt.Errorf("mcp: sampling tools[%d] requires name and inputSchema object", i)
			}
			for _, key := range []string{"title", "description"} {
				if field, ok := tool[key]; ok && !isJSONNull(field) {
					var text string
					if json.Unmarshal(field, &text) != nil {
						return fmt.Errorf("mcp: sampling tools[%d].%s must be a string", i, key)
					}
				}
			}
			if icons, ok := tool["icons"]; ok && !isJSONNull(icons) {
				if err := validateMCPToolIcons(icons); err != nil {
					return fmt.Errorf("mcp: sampling tools[%d].icons: %w", i, err)
				}
			}
			if annotations, ok := tool["annotations"]; ok && !isJSONNull(annotations) {
				if err := validateMCPToolAnnotations(annotations); err != nil {
					return fmt.Errorf("mcp: sampling tools[%d].annotations: %w", i, err)
				}
			}
			if execution, ok := tool["execution"]; ok && !isJSONNull(execution) {
				var fields map[string]json.RawMessage
				if json.Unmarshal(execution, &fields) != nil || fields == nil {
					return fmt.Errorf("mcp: sampling tools[%d].execution must be an object", i)
				}
				if support, ok := fields["taskSupport"]; ok && !isJSONNull(support) {
					var value string
					if json.Unmarshal(support, &value) != nil || value != "required" && value != "optional" && value != "forbidden" {
						return fmt.Errorf("mcp: sampling tools[%d].execution.taskSupport is invalid", i)
					}
				}
			}
		}
	}
	if value, ok := params["task"]; ok && !isJSONNull(value) {
		if err := validateMCPTaskParams(value); err != nil {
			return fmt.Errorf("mcp: sampling %w", err)
		}
	}
	return nil
}

func validateMCPModelPreferences(raw json.RawMessage) error {
	var prefs map[string]json.RawMessage
	if json.Unmarshal(raw, &prefs) != nil || prefs == nil {
		return fmt.Errorf("mcp: modelPreferences must be an object")
	}
	if value, ok := prefs["hints"]; ok && !isJSONNull(value) {
		var hints []map[string]json.RawMessage
		if json.Unmarshal(value, &hints) != nil || hints == nil {
			return fmt.Errorf("mcp: modelPreferences hints must be an array of objects")
		}
		for i, hint := range hints {
			if name, ok := hint["name"]; ok && !isJSONNull(name) {
				var text string
				if json.Unmarshal(name, &text) != nil {
					return fmt.Errorf("mcp: modelPreferences hints[%d].name must be a string", i)
				}
			}
		}
	} else if value, ok := prefs["hints"]; ok && isJSONNull(value) {
		return fmt.Errorf("mcp: modelPreferences hints must be an array of objects")
	}
	for _, key := range []string{"costPriority", "speedPriority", "intelligencePriority"} {
		value, ok := prefs[key]
		if !ok || isJSONNull(value) {
			continue
		}
		var priority float64
		if json.Unmarshal(value, &priority) != nil || priority < 0 || priority > 1 {
			return fmt.Errorf("mcp: modelPreferences.%s must be a number from 0 to 1", key)
		}
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func validateMCPToolIcons(raw json.RawMessage) error {
	var icons []map[string]json.RawMessage
	if json.Unmarshal(raw, &icons) != nil || icons == nil {
		return fmt.Errorf("must be an array")
	}
	for i, icon := range icons {
		var source string
		if json.Unmarshal(icon["src"], &source) != nil {
			return fmt.Errorf("item %d requires src string", i)
		}
		for _, key := range []string{"mimeType", "theme"} {
			if value, ok := icon[key]; ok && !isJSONNull(value) {
				var text string
				if json.Unmarshal(value, &text) != nil || key == "theme" && text != "light" && text != "dark" {
					return fmt.Errorf("item %d has invalid %s", i, key)
				}
			}
		}
		if sizes, ok := icon["sizes"]; ok && !isJSONNull(sizes) {
			var values []string
			if json.Unmarshal(sizes, &values) != nil || values == nil {
				return fmt.Errorf("item %d sizes must be an array of strings", i)
			}
		}
	}
	return nil
}

func validateMCPToolAnnotations(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return fmt.Errorf("must be an object")
	}
	if title, ok := fields["title"]; ok && !isJSONNull(title) {
		var value string
		if json.Unmarshal(title, &value) != nil {
			return fmt.Errorf("title must be a string")
		}
	}
	for _, key := range []string{"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"} {
		if value, ok := fields[key]; ok {
			var flag bool
			if isJSONNull(value) || json.Unmarshal(value, &flag) != nil {
				return fmt.Errorf("%s must be a boolean", key)
			}
		}
	}
	return nil
}

func validateMCPContentAnnotations(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return fmt.Errorf("mcp: content annotations must be an object")
	}
	if audience, ok := fields["audience"]; ok && !isJSONNull(audience) {
		var roles []string
		if json.Unmarshal(audience, &roles) != nil || roles == nil {
			return fmt.Errorf("mcp: content annotations audience must be an array")
		}
		for _, role := range roles {
			if role != "user" && role != "assistant" {
				return fmt.Errorf("mcp: content annotations audience has an invalid role")
			}
		}
	}
	if priority, ok := fields["priority"]; ok && !isJSONNull(priority) {
		var value float64
		if json.Unmarshal(priority, &value) != nil {
			return fmt.Errorf("mcp: content annotations priority must be numeric")
		}
	}
	if modified, ok := fields["lastModified"]; ok && !isJSONNull(modified) {
		var value string
		if json.Unmarshal(modified, &value) != nil {
			return fmt.Errorf("mcp: content annotations lastModified must be a string")
		}
	}
	return nil
}

func validateMCPStringMap(raw json.RawMessage, field string) error {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return fmt.Errorf("mcp: %s must be an object of strings", field)
	}
	for key, value := range values {
		var text string
		if json.Unmarshal(value, &text) != nil {
			return fmt.Errorf("mcp: %s.%s must be a string", field, key)
		}
	}
	return nil
}

func validateMCPTaskParams(raw json.RawMessage) error {
	var task map[string]json.RawMessage
	if json.Unmarshal(raw, &task) != nil || task == nil {
		return fmt.Errorf("mcp: task params must be an object")
	}
	if ttl, ok := task["ttl"]; ok && !isJSONNull(ttl) {
		var value uint64
		if json.Unmarshal(ttl, &value) != nil {
			return fmt.Errorf("mcp: task.ttl must be an unsigned integer")
		}
	}
	return nil
}

func isMapValue(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func validateMCPSamplingMessage(raw json.RawMessage) error {
	var message struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &message) != nil || message.Role != "user" && message.Role != "assistant" {
		return fmt.Errorf("mcp: sampling message requires user or assistant role")
	}
	content := bytes.TrimSpace(message.Content)
	if len(content) == 0 {
		return fmt.Errorf("mcp: sampling message requires content")
	}
	blocks := []json.RawMessage{content}
	if content[0] == '[' {
		if json.Unmarshal(content, &blocks) != nil || len(blocks) == 0 {
			return fmt.Errorf("mcp: sampling message content must not be empty")
		}
	} else if content[0] != '{' {
		return fmt.Errorf("mcp: sampling message content must be a content block")
	}
	for _, block := range blocks {
		if err := validateMCPSamplingContentBlock(block); err != nil {
			return err
		}
	}
	return nil
}

func validateMCPSamplingContentBlock(raw json.RawMessage) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return fmt.Errorf("mcp: sampling content block must be an object")
	}
	var kind string
	if json.Unmarshal(object["type"], &kind) != nil {
		return fmt.Errorf("mcp: sampling content block requires type")
	}
	if annotations, ok := object["annotations"]; ok && !isJSONNull(annotations) && kind != "tool_use" && kind != "tool_result" {
		if err := validateMCPContentAnnotations(annotations); err != nil {
			return err
		}
	}
	switch kind {
	case "text":
		var text string
		if json.Unmarshal(object["text"], &text) != nil {
			return fmt.Errorf("mcp: text content block requires text")
		}
	case "image", "audio":
		var data, mimeType string
		if json.Unmarshal(object["data"], &data) != nil || json.Unmarshal(object["mimeType"], &mimeType) != nil {
			return fmt.Errorf("mcp: %s content block requires data and mimeType", kind)
		}
	case "tool_use":
		var id, name string
		var input map[string]json.RawMessage
		if json.Unmarshal(object["id"], &id) != nil || id == "" || json.Unmarshal(object["name"], &name) != nil || name == "" ||
			json.Unmarshal(object["input"], &input) != nil || input == nil {
			return fmt.Errorf("mcp: tool_use content block requires id, name and input object")
		}
	case "tool_result":
		var toolUseID string
		var result struct {
			Content           []json.RawMessage          `json:"content"`
			StructuredContent map[string]json.RawMessage `json:"structuredContent"`
			IsError           *bool                      `json:"isError"`
		}
		if json.Unmarshal(object["toolUseId"], &toolUseID) != nil || toolUseID == "" ||
			json.Unmarshal(raw, &result) != nil || result.Content == nil {
			return fmt.Errorf("mcp: tool_result content block requires toolUseId and content array")
		}
		for _, item := range result.Content {
			if err := validateMCPSamplingContentBlock(item); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("mcp: unsupported sampling content block type")
	}
	return nil
}

func rawJSONPointer(object map[string]json.RawMessage, key string) *json.RawMessage {
	value, ok := object[key]
	if !ok {
		return nil
	}
	return &value
}

func validateMCPResponseID(raw json.RawMessage, allowNull bool) error {
	if len(raw) == 0 {
		return fmt.Errorf("mcp: response id required")
	}
	if isJSONNull(raw) && allowNull {
		return nil
	}
	if err := validateMCPRequestID(raw, true); err != nil {
		return fmt.Errorf("mcp: response id must be string or signed integer")
	}
	return nil
}

const (
	defaultMCPAllowedVersion = "2025-11-25"
	mcpLegacyFallbackVersion = "2025-03-26"
)

var supportedMCPVersions = map[string]struct{}{
	"2025-03-26": {},
	"2025-06-18": {},
	"2025-11-25": {},
}
