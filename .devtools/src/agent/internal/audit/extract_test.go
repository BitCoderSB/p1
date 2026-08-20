package audit

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/acme/prompt-audit-template/internal/model"
)

func TestExtractPromptClaudeUserPromptOnly(t *testing.T) {
	raw := []byte(`{
		"hook_event_name":"UserPromptSubmit",
		"transcript_path":"/tmp/claude-session-123.jsonl",
		"permission_mode":"default",
		"prompt":"  create a login screen\nwith tests  ",
		"session_id":"claude-session-123",
		"cwd":"/work/repository",
		"response":"assistant output must be ignored",
		"assistant_response":"another assistant output"
	}`)

	got, err := ExtractPrompt(model.ToolClaudeCode, raw)
	if err != nil {
		t.Fatalf("ExtractPrompt() error = %v", err)
	}
	want := ExtractedPrompt{
		Prompt:         "  create a login screen\nwith tests  ",
		SessionID:      "claude-session-123",
		TranscriptPath: "/tmp/claude-session-123.jsonl",
		CWD:            "/work/repository",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractPrompt() = %#v, want %#v", got, want)
	}
	if strings.Contains(got.Prompt, "assistant output") {
		t.Fatal("assistant response was mixed into the extracted prompt")
	}
}

func TestExtractPromptClaudeRootAgentTypeIsStillHumanPrompt(t *testing.T) {
	raw := []byte(`{
		"hook_event_name":"UserPromptSubmit",
		"transcript_path":"/tmp/claude-root-agent.jsonl",
		"permission_mode":"default",
		"agent_type":"security-reviewer",
		"prompt":"review this repository",
		"session_id":"claude-root-agent",
		"cwd":"/work/repository"
	}`)

	got, err := ExtractPrompt(model.ToolClaudeCode, raw)
	if err != nil {
		t.Fatalf("ExtractPrompt() rejected a root --agent prompt: %v", err)
	}
	if got.Prompt != "review this repository" || got.SessionID != "claude-root-agent" {
		t.Fatalf("ExtractPrompt() = %#v, want the root human prompt", got)
	}
}

func TestExtractPromptRejectsDuplicateFields(t *testing.T) {
	raw := []byte(`{"hook_event_name":"UserPromptSubmit","prompt":"first","prompt":"second","session_id":"session","cwd":"/work"}`)
	if _, err := ExtractPrompt(model.ToolCopilotCLI, raw); err == nil ||
		!strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("ExtractPrompt() with duplicate prompt fields = %v", err)
	}
}

func TestExtractPromptClaudeRejectsNonPromptEventsAndResponses(t *testing.T) {
	const sensitiveResponse = "ASSISTANT-RESPONSE-MUST-NOT-LEAK"
	tests := []struct {
		name        string
		raw         string
		wantErrIs   error
		wantErrText string
	}{
		{
			name:      "missing event discriminator",
			raw:       `{"prompt":"looks like a prompt"}`,
			wantErrIs: ErrNotUserPrompt,
		},
		{
			name:      "assistant event even if it has prompt-shaped data",
			raw:       `{"hook_event_name":"Stop","prompt":"do not capture","response":"` + sensitiveResponse + `"}`,
			wantErrIs: ErrNotUserPrompt,
		},
		{
			name:      "tool result event",
			raw:       `{"hook_event_name":"PostToolUse","prompt":"do not capture"}`,
			wantErrIs: ErrNotUserPrompt,
		},
		{
			name:      "subagent event",
			raw:       `{"hook_event_name":"UserPromptSubmit","transcript_path":"/tmp/session.jsonl","permission_mode":"default","agent_id":"child","prompt":"do not capture"}`,
			wantErrIs: ErrNotUserPrompt,
		},
		{
			name:        "response only",
			raw:         `{"hook_event_name":"UserPromptSubmit","transcript_path":"/tmp/session.jsonl","permission_mode":"default","response":"` + sensitiveResponse + `"}`,
			wantErrText: "has no prompt",
		},
		{
			name:        "blank prompt",
			raw:         `{"hook_event_name":"UserPromptSubmit","transcript_path":"/tmp/session.jsonl","permission_mode":"default","prompt":"  \n\t "}`,
			wantErrText: "has no prompt",
		},
		{
			name:        "non-string prompt",
			raw:         `{"hook_event_name":"UserPromptSubmit","transcript_path":"/tmp/session.jsonl","permission_mode":"default","prompt":{"text":"do not infer nested schemas"}}`,
			wantErrText: "has no prompt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractPrompt(model.ToolClaudeCode, []byte(tt.raw))
			if err == nil {
				t.Fatalf("ExtractPrompt() = %#v, nil; want rejection", got)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("error = %v, want errors.Is(%v)", err, tt.wantErrIs)
			}
			if tt.wantErrText != "" && !strings.Contains(err.Error(), tt.wantErrText) {
				t.Fatalf("error = %q, want substring %q", err, tt.wantErrText)
			}
			if strings.Contains(err.Error(), sensitiveResponse) || strings.Contains(err.Error(), "do not capture") {
				t.Fatalf("rejected payload content leaked through error: %q", err)
			}
		})
	}
}

func TestExtractPromptClaudeRejectsCopilotCrossToolPayload(t *testing.T) {
	// Copilot reads .claude/settings.json but its documented VS-compatible
	// payload deliberately has no transcript_path. It must not be recorded as a
	// second, incorrectly labelled Claude event.
	raw := []byte(`{
		"hook_event_name":"UserPromptSubmit",
		"session_id":"copilot-session",
		"timestamp":"2026-07-19T18:30:00Z",
		"cwd":"/work/repository",
		"prompt":"must only be captured by the Copilot hook"
	}`)
	if got, err := ExtractPrompt(model.ToolClaudeCode, raw); !errors.Is(err, ErrNotUserPrompt) {
		t.Fatalf("ExtractPrompt() = %#v, %v; want ErrNotUserPrompt", got, err)
	}
}

func TestExtractPromptCopilotUserPromptOnly(t *testing.T) {
	raw := []byte(`{
		"prompt":"explain this package",
		"sessionId":"copilot-chat-456",
		"cwd":"C:/work/repository",
		"response":"assistant response is ignored",
		"assistant_response":"also ignored"
	}`)

	got, err := ExtractPrompt(model.ToolCopilotCLI, raw)
	if err != nil {
		t.Fatalf("ExtractPrompt() error = %v", err)
	}
	want := ExtractedPrompt{
		Prompt:    "explain this package",
		SessionID: "copilot-chat-456",
		CWD:       "C:/work/repository",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractPrompt() = %#v, want %#v", got, want)
	}
}

func TestExtractPromptCopilotUsesSnakeCaseSessionID(t *testing.T) {
	// The real GitHub Copilot (VS Code) payload uses a Claude-style snake_case
	// session_id; prompts in one chat share it and must group together.
	raw := []byte(`{
		"hook_event_name":"UserPromptSubmit",
		"session_id":"967a40df-4a25-4e32-9eb5-c7357a58f105",
		"transcript_path":"C:/x/967a40df.jsonl",
		"prompt":"synthetic prompt",
		"cwd":"C:/work/project"
	}`)
	got, err := ExtractPrompt(model.ToolCopilotCLI, raw)
	if err != nil {
		t.Fatalf("ExtractPrompt() error = %v", err)
	}
	if got.SessionID != "967a40df-4a25-4e32-9eb5-c7357a58f105" {
		t.Fatalf("SessionID = %q, want the snake_case session_id", got.SessionID)
	}
	if got.Prompt != "synthetic prompt" {
		t.Fatalf("Prompt = %q", got.Prompt)
	}
}

func TestExtractPromptCodexUserPromptOnly(t *testing.T) {
	raw := []byte(`{
		"hook_event_name":"UserPromptSubmit",
		"prompt":"add idempotency tests",
		"session_id":"codex-session-789",
		"turn_id":"codex-turn-1",
		"transcript_path":"/home/test/.codex/sessions/rollout.jsonl",
		"cwd":"/work/repository",
		"permission_mode":"default",
		"last_assistant_message":"must be ignored"
	}`)

	got, err := ExtractPrompt(model.ToolCodex, raw)
	if err != nil {
		t.Fatalf("ExtractPrompt() error = %v", err)
	}
	want := ExtractedPrompt{
		Prompt:         "add idempotency tests",
		SessionID:      "codex-session-789",
		TranscriptPath: "/home/test/.codex/sessions/rollout.jsonl",
		CWD:            "/work/repository",
		SourceEventKey: "turn_id:codex-session-789\x00codex-turn-1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractPrompt() = %#v, want %#v", got, want)
	}
}

func TestExtractPromptCodexRejectsSubagentMarkerFields(t *testing.T) {
	subagent := []byte(`{
		"hook_event_name":"UserPromptSubmit",
		"prompt":"internal delegation",
		"session_id":"codex-child",
		"turn_id":"child-turn",
		"agent_id":"codex-child",
		"agent_type":"explorer",
		"transcript_path":"/tmp/child.jsonl",
		"cwd":"/work/repository"
	}`)
	if _, err := ExtractPrompt(model.ToolCodex, subagent); !errors.Is(err, ErrNotUserPrompt) {
		t.Fatalf("subagent ExtractPrompt() error = %v, want ErrNotUserPrompt", err)
	}
}

func TestExtractPromptCopilotRejectsResponseOnlyPayloads(t *testing.T) {
	const sensitiveResponse = "COPILOT-ASSISTANT-OUTPUT-MUST-NOT-LEAK"
	for _, raw := range []string{
		`{"response":"` + sensitiveResponse + `","sessionId":"chat-1"}`,
		`{"assistant_response":"` + sensitiveResponse + `","sessionId":"chat-1"}`,
		`{"prompt":"   ","response":"` + sensitiveResponse + `"}`,
		`{"prompt":["not","the","official","schema"],"response":"` + sensitiveResponse + `"}`,
	} {
		got, err := ExtractPrompt(model.ToolCopilotCLI, []byte(raw))
		if err == nil {
			t.Fatalf("ExtractPrompt(%s) = %#v, nil; want rejection", raw, got)
		}
		if strings.Contains(err.Error(), sensitiveResponse) {
			t.Fatalf("assistant response leaked through error: %q", err)
		}
	}
}

func TestExtractPromptRejectsInvalidContainersAndUnsupportedTools(t *testing.T) {
	for _, raw := range []string{"", "not-json", "[]", `"string"`, `{"prompt":"unterminated"`} {
		if _, err := ExtractPrompt(model.ToolClaudeCode, []byte(raw)); err == nil {
			t.Errorf("ExtractPrompt(%q) unexpectedly succeeded", raw)
		}
	}

	validPrompt := []byte(`{"prompt":"hello"}`)
	for _, tool := range []string{model.ToolAntigravity} {
		if _, err := ExtractPrompt(tool, validPrompt); !errors.Is(err, ErrUnsupportedIntegration) {
			t.Errorf("ExtractPrompt(%q) error = %v, want ErrUnsupportedIntegration", tool, err)
		}
	}
	if _, err := ExtractPrompt("unknown-tool", validPrompt); err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("unknown tool error = %v", err)
	}
}

func TestEventWireContractHasNoAssistantResponseField(t *testing.T) {
	event := sampleEvent("event-contract", "user prompt")
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal(Event): %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("json.Unmarshal(Event): %v", err)
	}

	wantKeys := []string{
		"event_id", "timestamp", "user_id", "user_email", "tool",
		"repository_name", "repository_remote", "branch", "commit_hash",
		"session_id", "prompt",
	}
	if len(fields) != len(wantKeys) {
		t.Fatalf("Event JSON fields = %v; want exactly %v", mapKeys(fields), wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := fields[key]; !ok {
			t.Errorf("Event JSON omitted %q", key)
		}
	}
	for _, forbidden := range []string{"response", "assistant_response", "completion", "messages", "environment"} {
		if _, ok := fields[forbidden]; ok {
			t.Errorf("Event JSON unexpectedly contains forbidden field %q", forbidden)
		}
	}
}

func mapKeys(values map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
