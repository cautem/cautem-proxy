package proxy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cautem/cautem-core/policy"
)

type graphqlToken struct {
	value string
	kind  byte // n=name, s=string, p=punctuation, v=value
}

type graphqlSelection struct {
	fields    []string
	fragments []string
}

type graphqlParser struct {
	tokens    []graphqlToken
	position  int
	fragments map[string]graphqlSelection
	depth     int
}

func parseGraphQLDocument(source string) ([]policy.GraphQLOperation, error) {
	tokens, err := lexGraphQL(source)
	if err != nil {
		return nil, err
	}
	parser := &graphqlParser{tokens: tokens, fragments: map[string]graphqlSelection{}}
	var operations []policy.GraphQLOperation
	var selections []graphqlSelection
	for !parser.done() {
		switch parser.peek() {
		case "{":
			selection, err := parser.selectionSet()
			if err != nil {
				return nil, err
			}
			operations = append(operations, policy.GraphQLOperation{OperationType: "query", Fields: nil})
			selections = append(selections, selection)
		case "query", "mutation", "subscription":
			opType := parser.take()
			name := ""
			if parser.peekKind('n') {
				name = parser.take()
			}
			if parser.peek() == "(" {
				if err := parser.skipBalanced("("); err != nil {
					return nil, err
				}
			}
			if err := parser.skipDirectives(); err != nil {
				return nil, err
			}
			selection, err := parser.selectionSet()
			if err != nil {
				return nil, err
			}
			operations = append(operations, policy.GraphQLOperation{OperationType: opType, OperationName: name})
			selections = append(selections, selection)
		case "fragment":
			parser.take()
			name, ok := parser.takeName()
			if !ok || parser.peek() != "on" {
				return nil, fmt.Errorf("invalid fragment")
			}
			parser.take()
			if _, ok := parser.takeName(); !ok {
				return nil, fmt.Errorf("invalid fragment type")
			}
			if err := parser.skipDirectives(); err != nil {
				return nil, err
			}
			selection, err := parser.selectionSet()
			if err != nil {
				return nil, err
			}
			parser.fragments[name] = selection
		default:
			return nil, fmt.Errorf("unsupported GraphQL definition")
		}
		if len(parser.tokens)-parser.position < 0 {
			return nil, fmt.Errorf("invalid parser position")
		}
	}
	if len(operations) == 0 {
		return nil, fmt.Errorf("GraphQL document has no operation")
	}
	for i := range operations {
		operations[i].Fields = parser.expandRootFields(selections[i])
	}
	return operations, nil
}

func (p *graphqlParser) expandRootFields(selection graphqlSelection) []string {
	fields := map[string]struct{}{}
	visited := map[string]struct{}{}
	var visit func(graphqlSelection)
	visit = func(current graphqlSelection) {
		for _, field := range current.fields {
			fields[field] = struct{}{}
		}
		for _, name := range current.fragments {
			if _, ok := visited[name]; ok {
				continue
			}
			visited[name] = struct{}{}
			if fragment, ok := p.fragments[name]; ok {
				visit(fragment)
			}
		}
	}
	visit(selection)
	out := make([]string, 0, len(fields))
	for field := range fields {
		out = append(out, field)
	}
	sort.Strings(out)
	return out
}

func (p *graphqlParser) selectionSet() (graphqlSelection, error) {
	if p.depth >= 128 || p.peek() != "{" {
		return graphqlSelection{}, fmt.Errorf("selection set required")
	}
	p.depth++
	defer func() { p.depth-- }()
	p.take()
	selection := graphqlSelection{}
	for !p.done() && p.peek() != "}" {
		if p.peek() == "..." {
			p.take()
			if p.peek() == "on" {
				p.take()
				if _, ok := p.takeName(); !ok {
					return graphqlSelection{}, fmt.Errorf("inline fragment type required")
				}
				if err := p.skipDirectives(); err != nil {
					return graphqlSelection{}, err
				}
				inline, err := p.selectionSet()
				if err != nil {
					return graphqlSelection{}, err
				}
				selection.fields = append(selection.fields, inline.fields...)
				selection.fragments = append(selection.fragments, inline.fragments...)
				continue
			}
			if p.peek() == "@" {
				if err := p.skipDirectives(); err != nil {
					return graphqlSelection{}, err
				}
				inline, err := p.selectionSet()
				if err != nil {
					return graphqlSelection{}, err
				}
				selection.fields = append(selection.fields, inline.fields...)
				selection.fragments = append(selection.fragments, inline.fragments...)
				continue
			}
			name, ok := p.takeName()
			if !ok {
				return graphqlSelection{}, fmt.Errorf("fragment spread name required")
			}
			selection.fragments = append(selection.fragments, name)
			if err := p.skipDirectives(); err != nil {
				return graphqlSelection{}, err
			}
			continue
		}
		field, ok := p.takeName()
		if !ok {
			return graphqlSelection{}, fmt.Errorf("field name required")
		}
		if p.peek() == ":" {
			p.take()
			field, ok = p.takeName()
			if !ok {
				return graphqlSelection{}, fmt.Errorf("aliased field name required")
			}
		}
		if p.peek() == "(" {
			if err := p.skipBalanced("("); err != nil {
				return graphqlSelection{}, err
			}
		}
		if err := p.skipDirectives(); err != nil {
			return graphqlSelection{}, err
		}
		selection.fields = append(selection.fields, field)
		if p.peek() == "{" {
			if _, err := p.selectionSet(); err != nil {
				return graphqlSelection{}, err
			}
		}
	}
	if p.peek() != "}" {
		return graphqlSelection{}, fmt.Errorf("unterminated selection set")
	}
	p.take()
	return selection, nil
}

func (p *graphqlParser) skipDirectives() error {
	for p.peek() == "@" {
		p.take()
		if _, ok := p.takeName(); !ok {
			return fmt.Errorf("directive name required")
		}
		if p.peek() == "(" {
			if err := p.skipBalanced("("); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *graphqlParser) skipBalanced(open string) error {
	if p.peek() != open {
		return fmt.Errorf("opening delimiter required")
	}
	closer := map[string]string{"(": ")", "[": "]", "{": "}"}[open]
	stack := []string{closer}
	p.take()
	for len(stack) > 0 && !p.done() {
		token := p.take()
		switch token {
		case "(":
			stack = append(stack, ")")
		case "[":
			stack = append(stack, "]")
		case "{":
			stack = append(stack, "}")
		default:
			if token == stack[len(stack)-1] {
				stack = stack[:len(stack)-1]
			} else if token == ")" || token == "]" || token == "}" {
				return fmt.Errorf("mismatched delimiter")
			}
		}
	}
	if len(stack) > 0 {
		return fmt.Errorf("unclosed delimiter")
	}
	return nil
}

func (p *graphqlParser) done() bool { return p.position >= len(p.tokens) }
func (p *graphqlParser) peek() string {
	if p.done() {
		return ""
	}
	return p.tokens[p.position].value
}
func (p *graphqlParser) peekKind(kind byte) bool {
	return !p.done() && p.tokens[p.position].kind == kind
}
func (p *graphqlParser) take() string {
	value := p.peek()
	if !p.done() {
		p.position++
	}
	return value
}
func (p *graphqlParser) takeName() (string, bool) {
	if !p.peekKind('n') {
		return "", false
	}
	return p.take(), true
}

func lexGraphQL(source string) ([]graphqlToken, error) {
	tokens := make([]graphqlToken, 0, len(source)/3)
	for i := 0; i < len(source); {
		c := source[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' {
			i++
			continue
		}
		if c == '#' {
			for i < len(source) && source[i] != '\n' && source[i] != '\r' {
				i++
			}
			continue
		}
		if c == '"' {
			start := i
			block := strings.HasPrefix(source[i:], `"""`)
			if block {
				i += 3
			} else {
				i++
			}
			closed := false
			for i < len(source) {
				if block && strings.HasPrefix(source[i:], `"""`) {
					i += 3
					closed = true
					break
				}
				if !block && source[i] == '"' {
					i++
					closed = true
					break
				}
				if source[i] == '\\' && !block {
					i += 2
					continue
				}
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated GraphQL string")
			}
			tokens = append(tokens, graphqlToken{value: source[start:i], kind: 's'})
		} else if isGraphQLNameStart(c) {
			start := i
			i++
			for i < len(source) && isGraphQLNameContinue(source[i]) {
				i++
			}
			tokens = append(tokens, graphqlToken{value: source[start:i], kind: 'n'})
		} else if c == '.' && strings.HasPrefix(source[i:], "...") {
			tokens = append(tokens, graphqlToken{value: "...", kind: 'p'})
			i += 3
		} else if strings.ContainsRune("!$():=@[]{|}&", rune(c)) {
			tokens = append(tokens, graphqlToken{value: string(c), kind: 'p'})
			i++
		} else if c == '-' || (c >= '0' && c <= '9') {
			start := i
			i++
			for i < len(source) && ((source[i] >= '0' && source[i] <= '9') || source[i] == '.' || source[i] == 'e' || source[i] == 'E' || source[i] == '+' || source[i] == '-') {
				i++
			}
			tokens = append(tokens, graphqlToken{value: source[start:i], kind: 'v'})
		} else {
			return nil, fmt.Errorf("invalid GraphQL token")
		}
		if len(tokens) > 20_000 {
			return nil, fmt.Errorf("GraphQL document token limit exceeded")
		}
	}
	return tokens, nil
}

func isGraphQLNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isGraphQLNameContinue(c byte) bool { return isGraphQLNameStart(c) || (c >= '0' && c <= '9') }
