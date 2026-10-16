package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cautem/quarshell-core/policy"
)

const defaultGraphQLMaxBodyBytes = 64 << 10

type graphqlEnvelope struct {
	query         string
	operationName string
	hash          string
	id            string
}

// parseGraphQLRequest inspects one GraphQL-over-HTTP request and restores its
// body for the upstream relay. Every operation in a batch is returned so each
// operation must satisfy endpoint policy.
func parseGraphQLRequest(req *http.Request, endpoint policy.AllowRule) ([]policy.GraphQLOperation, error) {
	if req == nil {
		return nil, fmt.Errorf("graphql: missing request")
	}
	for _, encoding := range req.Header.Values("Content-Encoding") {
		encoding = strings.TrimSpace(encoding)
		if encoding != "" && !strings.EqualFold(encoding, "identity") {
			return nil, fmt.Errorf("graphql: content encoding is not supported")
		}
	}
	for _, contentType := range req.Header.Values("Content-Type") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "multipart/") {
			return nil, fmt.Errorf("graphql: multipart requests are not supported")
		}
	}
	maxBytes := uint32(defaultGraphQLMaxBodyBytes)
	if endpoint.GraphQLMaxBodyBytes != nil {
		maxBytes = *endpoint.GraphQLMaxBodyBytes
	}
	switch strings.ToUpper(req.Method) {
	case http.MethodGet:
		envelopes, err := graphqlGETEnvelope(req.URL.RawQuery)
		if err != nil {
			return nil, err
		}
		return classifyGraphQLEnvelopes(envelopes)
	case http.MethodPost:
	default:
		return nil, fmt.Errorf("graphql: unsupported HTTP method")
	}
	if req.Body == nil || req.Body == http.NoBody {
		return nil, fmt.Errorf("graphql: POST body is required")
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, int64(maxBytes)+1))
	_ = req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("graphql: unable to read request body")
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	if uint64(len(body)) > uint64(maxBytes) {
		return nil, fmt.Errorf("graphql: request body exceeds %d bytes", maxBytes)
	}
	if req.ContentLength < 0 || len(req.TransferEncoding) > 0 {
		req.ContentLength = int64(len(body))
		req.TransferEncoding = nil
		req.Header.Del("Transfer-Encoding")
		req.Header.Set("Content-Length", fmt.Sprint(len(body)))
	}
	var payload json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("graphql: invalid JSON envelope")
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 {
		return nil, fmt.Errorf("graphql: empty request envelope")
	}
	var values []json.RawMessage
	if payload[0] == '[' {
		if err := json.Unmarshal(payload, &values); err != nil || len(values) == 0 {
			return nil, fmt.Errorf("graphql: batch must be a non-empty array")
		}
	} else {
		values = []json.RawMessage{payload}
	}
	envelopes := make([]graphqlEnvelope, 0, len(values))
	for _, value := range values {
		envelope, err := decodeGraphQLEnvelope(value)
		if err != nil {
			return nil, err
		}
		envelopes = append(envelopes, envelope)
	}
	return classifyGraphQLEnvelopes(envelopes)
}

func graphqlGETEnvelope(rawQuery string) ([]graphqlEnvelope, error) {
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, fmt.Errorf("graphql: invalid GET query parameters")
	}
	unique := func(key string) (string, error) {
		values, ok := params[key]
		if !ok {
			return "", nil
		}
		if len(values) > 1 {
			return "", fmt.Errorf("graphql: GET parameter %s must not repeat", key)
		}
		return values[0], nil
	}
	query, err := unique("query")
	if err != nil {
		return nil, err
	}
	name, err := unique("operationName")
	if err != nil {
		return nil, err
	}
	extensions, err := unique("extensions")
	if err != nil {
		return nil, err
	}
	id := ""
	for _, key := range []string{"id", "documentId", "queryId"} {
		value, err := unique(key)
		if err != nil {
			return nil, err
		}
		if value != "" {
			if id != "" {
				return nil, fmt.Errorf("graphql: persisted-query id parameters cannot be combined")
			}
			id = value
		}
	}
	return []graphqlEnvelope{{query: query, operationName: name, hash: graphqlPersistedHash([]byte(extensions)), id: id}}, nil
}

func decodeGraphQLEnvelope(raw json.RawMessage) (graphqlEnvelope, error) {
	var data map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &data) != nil {
		return graphqlEnvelope{}, fmt.Errorf("graphql: each batch item must be an object")
	}
	var envelope graphqlEnvelope
	_ = json.Unmarshal(data["query"], &envelope.query)
	_ = json.Unmarshal(data["operationName"], &envelope.operationName)
	_ = json.Unmarshal(data["id"], &envelope.id)
	if envelope.id == "" {
		_ = json.Unmarshal(data["documentId"], &envelope.id)
	}
	if envelope.id == "" {
		_ = json.Unmarshal(data["queryId"], &envelope.id)
	}
	envelope.hash = graphqlPersistedHash(data["extensions"])
	return envelope, nil
}

func graphqlPersistedHash(raw []byte) string {
	var extensions struct {
		PersistedQuery struct {
			Hash string `json:"sha256Hash"`
		} `json:"persistedQuery"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &extensions) != nil {
		return ""
	}
	return extensions.PersistedQuery.Hash
}

func classifyGraphQLEnvelopes(envelopes []graphqlEnvelope) ([]policy.GraphQLOperation, error) {
	operations := make([]policy.GraphQLOperation, 0, len(envelopes))
	for _, envelope := range envelopes {
		query := strings.TrimSpace(envelope.query)
		if query == "" {
			if envelope.hash == "" && envelope.id == "" {
				return nil, fmt.Errorf("graphql: request has no query or persisted identifier")
			}
			operations = append(operations, policy.GraphQLOperation{
				OperationName:      envelope.operationName,
				Persisted:          true,
				PersistedQueryHash: envelope.hash,
				PersistedQueryID:   envelope.id,
			})
			continue
		}
		definitions, err := parseGraphQLDocument(query)
		if err != nil {
			return nil, fmt.Errorf("graphql: invalid document")
		}
		var selected *policy.GraphQLOperation
		for i := range definitions {
			if envelope.operationName != "" && definitions[i].OperationName == envelope.operationName {
				selected = &definitions[i]
				break
			}
		}
		if envelope.operationName == "" && len(definitions) == 1 {
			selected = &definitions[0]
		}
		if selected == nil {
			return nil, fmt.Errorf("graphql: operationName is missing or unknown")
		}
		selected.Persisted = envelope.hash != "" || envelope.id != ""
		selected.PersistedQueryHash = envelope.hash
		selected.PersistedQueryID = envelope.id
		operations = append(operations, *selected)
	}
	return operations, nil
}
