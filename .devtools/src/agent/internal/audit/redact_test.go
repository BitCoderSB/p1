package audit

import (
	"strings"
	"testing"
)

func TestRedactorRemovesBuiltInSecretForms(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		input  string
	}{
		{
			name:   "bearer authorization",
			secret: "eyJhbGciOiJIUzI1NiJ9.payload.signature",
			input:  "send Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature to the API",
		},
		{
			name:   "api key assignment",
			secret: "top-secret-value",
			input:  "configure API_KEY=top-secret-value before running",
		},
		{
			name:   "password assignment",
			secret: "hunter2",
			input:  "use password: hunter2 for the fixture",
		},
		{
			name:   "JSON password assignment",
			secret: "json-secret-value",
			input:  `use {"password":"json-secret-value"} only in the fixture`,
		},
		{
			name:   "bare token assignment",
			secret: "abc123secreto",
			input:  "añade recuérdame con token=abc123secreto por favor",
		},
		{
			name:   "client secret assignment",
			secret: "s3cr3t-value",
			input:  `set client_secret: "s3cr3t-value" in the config`,
		},
		{
			name:   "OpenAI style token",
			secret: "sk-1234567890abcdefghijklmnop",
			input:  "the token is sk-1234567890abcdefghijklmnop",
		},
		{
			name:   "GitHub token",
			secret: "ghp_1234567890abcdefghijklmnopqrst",
			input:  "clone with ghp_1234567890abcdefghijklmnopqrst please",
		},
		{
			name:   "AWS access key",
			secret: "AKIA1234567890ABCDEF",
			input:  "AWS key AKIA1234567890ABCDEF is compromised",
		},
	}

	redactor, err := NewRedactor(true, nil)
	if err != nil {
		t.Fatalf("NewRedactor() error = %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactor.Redact(tt.input)
			if strings.Contains(got, tt.secret) {
				t.Fatalf("Redact() left secret %q in %q", tt.secret, got)
			}
			if !strings.Contains(got, "[REDACTED]") {
				t.Fatalf("Redact() = %q, want redaction marker", got)
			}
		})
	}
}

func TestRedactorAppliesEveryMatchAndCustomPatterns(t *testing.T) {
	redactor, err := NewRedactor(true, []string{`EMPLOYEE-SECRET-[0-9]+`})
	if err != nil {
		t.Fatalf("NewRedactor() error = %v", err)
	}
	input := "password=first password=second EMPLOYEE-SECRET-42 EMPLOYEE-SECRET-99"
	got := redactor.Redact(input)
	for _, secret := range []string{"first", "second", "EMPLOYEE-SECRET-42", "EMPLOYEE-SECRET-99"} {
		if strings.Contains(got, secret) {
			t.Errorf("Redact() left %q in %q", secret, got)
		}
	}
	if count := strings.Count(got, "[REDACTED]"); count != 4 {
		t.Fatalf("Redact() markers = %d in %q, want 4", count, got)
	}
}

func TestRedactorDisabledPreservesPromptExactly(t *testing.T) {
	const prompt = "keep password=hunter2 and CUSTOM-123 exactly"
	redactor, err := NewRedactor(false, []string{"[invalid"})
	if err != nil {
		t.Fatalf("disabled NewRedactor() unexpectedly compiled patterns: %v", err)
	}
	if got := redactor.Redact(prompt); got != prompt {
		t.Fatalf("disabled Redact() = %q, want exact input %q", got, prompt)
	}
}

func TestRedactorRejectsInvalidCustomExpression(t *testing.T) {
	redactor, err := NewRedactor(true, []string{"[unterminated"})
	if err == nil {
		t.Fatalf("NewRedactor() = %#v, nil; want invalid expression error", redactor)
	}
	if !strings.Contains(err.Error(), "invalid redaction expression") {
		t.Fatalf("error = %q, want safe context", err)
	}
}

func TestBoundRedactedPromptPreventsRegexExpansionFromBlockingQueue(t *testing.T) {
	redactor, err := NewRedactor(true, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	expanded := redactor.Redact(strings.Repeat("x", maxQueuedPromptBytes))
	if len(expanded) <= 8*1024*1024 {
		t.Fatalf("fixture did not exceed queue line risk: %d bytes", len(expanded))
	}
	bounded := boundRedactedPrompt(expanded)
	if len(bounded) > maxQueuedPromptBytes || !strings.HasSuffix(bounded, redactionTruncationMarker) {
		t.Fatalf("bounded output length/suffix = %d / %q", len(bounded), bounded[len(bounded)-64:])
	}
}
