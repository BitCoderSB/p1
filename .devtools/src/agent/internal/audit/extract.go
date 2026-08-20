package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

var (
	ErrUnsupportedIntegration = errors.New("tool has no enabled, officially verified prompt hook")
	ErrNotUserPrompt          = errors.New("hook input is not a supported user-prompt event")
	errKnownSubagentPrompt    = errors.New("hook input belongs to a known subagent")
)

type ExtractedPrompt struct {
	Prompt         string
	SessionID      string
	TranscriptPath string
	CWD            string
	SourceEventKey string
	Timestamp      time.Time
}

func ExtractPrompt(tool string, raw []byte) (ExtractedPrompt, error) {
	if !json.Valid(raw) || validateUniqueJSONKeys(raw) != nil {
		return ExtractedPrompt{}, errors.New("hook input is not valid JSON")
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&fields); err != nil {
		return ExtractedPrompt{}, errors.New("hook input must be a JSON object")
	}
	switch tool {
	case model.ToolClaudeCode:
		return extractClaude(fields)
	case model.ToolCodex:
		return extractSnakeCaseUserPrompt(fields, "Codex")
	case model.ToolCopilotCLI:
		return extractCopilot(fields)
	case model.ToolAntigravity:
		return ExtractedPrompt{}, ErrUnsupportedIntegration
	default:
		return ExtractedPrompt{}, fmt.Errorf("unknown tool %q", tool)
	}
}

func extractClaude(fields map[string]json.RawMessage) (ExtractedPrompt, error) {
	// Copilot CLI also discovers repository .claude/settings.json files and can
	// invoke UserPromptSubmit hooks with its VS Code-compatible payload. Claude's
	// documented common input always includes transcript_path; Copilot's
	// documented compatible payload does not. Requiring that field prevents the
	// Claude project hook from double-capturing and mislabelling a Copilot prompt.
	event, ok := stringField(fields, "hook_event_name")
	if !ok || event != "UserPromptSubmit" {
		return ExtractedPrompt{}, ErrNotUserPrompt
	}
	// Claude documents agent_id as the field that is present for hooks running
	// inside a spawned subagent. A root session started with `claude --agent`
	// may still carry agent_type, so that field alone must not suppress a human
	// prompt.
	if _, subagent := fields["agent_id"]; subagent {
		return ExtractedPrompt{}, errors.Join(ErrNotUserPrompt, errKnownSubagentPrompt)
	}
	transcriptPath, ok := stringField(fields, "transcript_path")
	if !ok || strings.TrimSpace(transcriptPath) == "" {
		return ExtractedPrompt{}, ErrNotUserPrompt
	}
	// VS Code can also load .claude/settings.json and may expose a transcript
	// path. Claude Code's documented payload additionally carries its permission
	// mode; require that provider marker before interpreting the payload.
	permissionMode, ok := stringField(fields, "permission_mode")
	if !ok || strings.TrimSpace(permissionMode) == "" {
		return ExtractedPrompt{}, ErrNotUserPrompt
	}
	extracted, err := extractSnakeCaseUserPrompt(fields, "Claude")
	if err != nil {
		return ExtractedPrompt{}, err
	}
	if promptID, ok := stringField(fields, "prompt_id"); ok && strings.TrimSpace(promptID) != "" {
		extracted.SourceEventKey = "prompt_id:" + extracted.SessionID + "\x00" + promptID
	}
	extracted.Timestamp = timestampField(fields, "timestamp")
	return extracted, nil
}

func extractSnakeCaseUserPrompt(fields map[string]json.RawMessage, source string) (ExtractedPrompt, error) {
	event, ok := stringField(fields, "hook_event_name")
	if !ok || event != "UserPromptSubmit" {
		if source == "Codex" {
			return ExtractedPrompt{}, errors.New("Codex hook input is not a UserPromptSubmit event")
		}
		return ExtractedPrompt{}, ErrNotUserPrompt
	}
	prompt, ok := stringField(fields, "prompt")
	if !ok || strings.TrimSpace(prompt) == "" {
		return ExtractedPrompt{}, fmt.Errorf("%s UserPromptSubmit payload has no prompt", source)
	}
	session, _ := stringField(fields, "session_id")
	transcriptPath, _ := stringField(fields, "transcript_path")
	cwd, _ := stringField(fields, "cwd")
	extracted := ExtractedPrompt{
		Prompt:         prompt,
		SessionID:      session,
		TranscriptPath: transcriptPath,
		CWD:            cwd,
	}
	if source == "Codex" {
		// Current Codex releases attach these fields when a normal lifecycle
		// hook is running inside a thread-spawned subagent and omit both for the
		// root thread. Any presence is therefore a fail-closed non-user signal.
		for _, key := range []string{"agent_id", "agent_type"} {
			if _, present := fields[key]; present {
				return ExtractedPrompt{}, errors.Join(ErrNotUserPrompt, errKnownSubagentPrompt)
			}
		}
		// Use only the documented hook envelope for direct capture. Rollout
		// transcripts are an implementation detail and their record format can
		// change independently of the hook contract.
		if strings.TrimSpace(session) == "" || strings.TrimSpace(cwd) == "" {
			return ExtractedPrompt{}, errors.New("Codex UserPromptSubmit payload is missing its session or repository context")
		}
		permissionMode, ok := stringField(fields, "permission_mode")
		if !ok || strings.TrimSpace(permissionMode) == "" {
			return ExtractedPrompt{}, errors.New("Codex UserPromptSubmit payload is missing permission_mode")
		}
		turnID, ok := stringField(fields, "turn_id")
		if !ok || strings.TrimSpace(turnID) == "" {
			return ExtractedPrompt{}, errors.New("Codex UserPromptSubmit payload is missing turn_id")
		}
		extracted.SourceEventKey = "turn_id:" + session + "\x00" + turnID
		extracted.Timestamp = timestampField(fields, "timestamp")
	}
	return extracted, nil
}

func extractCopilot(fields map[string]json.RawMessage) (ExtractedPrompt, error) {
	if event, ok := stringField(fields, "hook_event_name"); ok && event != "UserPromptSubmit" {
		return ExtractedPrompt{}, ErrNotUserPrompt
	}
	if event, ok := stringField(fields, "eventName"); ok &&
		event != "UserPromptSubmit" && event != "userPromptSubmitted" {
		return ExtractedPrompt{}, ErrNotUserPrompt
	}
	prompt, ok := stringField(fields, "prompt")
	if !ok || strings.TrimSpace(prompt) == "" {
		return ExtractedPrompt{}, errors.New("Copilot userPromptSubmitted payload has no prompt")
	}
	// GitHub Copilot in VS Code delivers a Claude-style payload with a snake_case
	// session_id; the documented CLI schema uses camelCase sessionId. Accept both
	// so prompts from the same Copilot chat share one session and group together.
	session, ok := stringField(fields, "session_id")
	if !ok || strings.TrimSpace(session) == "" {
		session, _ = stringField(fields, "sessionId")
	}
	cwd, _ := stringField(fields, "cwd")
	extracted := ExtractedPrompt{
		Prompt:    prompt,
		SessionID: session,
		CWD:       cwd,
		Timestamp: timestampField(fields, "timestamp"),
	}
	if timestampKey := canonicalScalarField(fields, "timestamp"); timestampKey != "" &&
		strings.TrimSpace(session) != "" {
		extracted.SourceEventKey = "submission:" + session + "\x00" + timestampKey + "\x00" + prompt
	}
	return extracted, nil
}

func stringField(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := fields[key]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func canonicalScalarField(fields map[string]json.RawMessage, key string) string {
	raw, ok := fields[key]
	if !ok {
		return ""
	}
	if value, ok := stringField(fields, key); ok {
		return "string:" + value
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		if _, err := strconv.ParseFloat(number.String(), 64); err == nil {
			return "number:" + number.String()
		}
	}
	return ""
}

func timestampField(fields map[string]json.RawMessage, key string) time.Time {
	raw, ok := fields[key]
	if !ok {
		return time.Time{}
	}
	if value, ok := stringField(fields, key); ok {
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed.UTC()
			}
		}
		if number, err := strconv.ParseFloat(value, 64); err == nil {
			return unixTimestamp(number)
		}
		return time.Time{}
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return time.Time{}
	}
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil {
		return time.Time{}
	}
	return unixTimestamp(value)
}

func unixTimestamp(value float64) time.Time {
	// Values above this threshold are milliseconds since Unix epoch; smaller
	// values are seconds. Preserve sub-second precision in either form.
	if value > 100_000_000_000 {
		seconds := int64(value / 1000)
		nanos := int64((value - float64(seconds)*1000) * float64(time.Millisecond))
		return time.Unix(seconds, nanos).UTC()
	}
	seconds := int64(value)
	nanos := int64((value - float64(seconds)) * float64(time.Second))
	return time.Unix(seconds, nanos).UTC()
}
