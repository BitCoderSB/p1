package audit

import (
	"fmt"
	"regexp"
)

var builtInRedactions = []string{
	`(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+`,
	`(?i)["']?\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|token|secret|password|passwd|pwd)\b["']?\s*[:=]\s*["']?[^"'\s,;}\]]+["']?`,
	`\b(?:sk|pk)-[A-Za-z0-9_-]{16,}\b`,
	`\bgh[opusr]_[A-Za-z0-9]{20,}\b`,
	`\bAKIA[0-9A-Z]{16}\b`,
}

type Redactor struct {
	patterns []*regexp.Regexp
}

func NewRedactor(enabled bool, custom []string) (*Redactor, error) {
	if !enabled {
		return &Redactor{}, nil
	}
	patterns := make([]*regexp.Regexp, 0, len(builtInRedactions)+len(custom))
	for _, pattern := range append(append([]string{}, builtInRedactions...), custom...) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid redaction expression: %w", err)
		}
		patterns = append(patterns, re)
	}
	return &Redactor{patterns: patterns}, nil
}

func (r *Redactor) Redact(value string) string {
	for _, pattern := range r.patterns {
		value = pattern.ReplaceAllStringFunc(value, func(string) string { return "[REDACTED]" })
	}
	return value
}
