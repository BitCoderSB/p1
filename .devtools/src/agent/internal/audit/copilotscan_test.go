package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCopilotRecord(t *testing.T, file *os.File, value any) {
	t.Helper()
	line, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}

func TestCopilotTranscriptScannerKeepsOnlyUserMessagesAroundCorruption(t *testing.T) {
	const assistantSecret = "COPILOT-ASSISTANT-MUST-NOT-BE-STORED"
	path := filepath.Join(t.TempDir(), "copilot-session.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writeCopilotRecord(t, file, map[string]any{
		"type": "user.message", "timestamp": "2026-07-21T00:00:01Z",
		"data": map[string]any{"content": "first Copilot user prompt"},
	})
	writeCopilotRecord(t, file, map[string]any{
		"type": "assistant.message", "timestamp": "2026-07-21T00:00:02Z",
		"data": map[string]any{"content": assistantSecret},
	})
	if _, err := file.WriteString("{malformed}\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	writeCopilotRecord(t, file, map[string]any{
		"type": "user.message", "timestamp": "2026-07-21T00:00:03Z",
		"data": map[string]any{"content": "second Copilot user prompt"},
	})
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	prompts, scanErr := scanCopilotFile(path, "copilot-fixture")
	if scanErr == nil || len(prompts) != 2 {
		t.Fatalf("scanCopilotFile() = %d prompts, %v; want 2 plus warning", len(prompts), scanErr)
	}
	var joined strings.Builder
	for _, prompt := range prompts {
		joined.WriteString(prompt.Prompt)
		joined.WriteByte('\n')
		if prompt.SessionID != "copilot-fixture" {
			t.Fatalf("Copilot session = %q", prompt.SessionID)
		}
	}
	if strings.Contains(joined.String(), assistantSecret) {
		t.Fatalf("Copilot scanner captured assistant output: %q", joined.String())
	}
	if !strings.Contains(joined.String(), "first Copilot user prompt") ||
		!strings.Contains(joined.String(), "second Copilot user prompt") {
		t.Fatalf("Copilot scanner lost valid user prompts: %q", joined.String())
	}
}

func TestCopilotTranscriptScannerReportsMalformedUserData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "copilot-malformed-data.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writeCopilotRecord(t, file, map[string]any{
		"type": "user.message", "timestamp": "2026-07-21T00:00:01Z", "data": nil,
	})
	writeCopilotRecord(t, file, map[string]any{
		"type": "user.message", "timestamp": "2026-07-21T00:00:02Z",
		"data": map[string]any{"content": "valid prompt after malformed data"},
	})
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	prompts, scanErr := scanCopilotFile(path, "copilot-fixture")
	if scanErr == nil || len(prompts) != 1 || prompts[0].Prompt != "valid prompt after malformed data" {
		t.Fatalf("scanCopilotFile() = %#v, %v; want one prompt plus health error", prompts, scanErr)
	}
}

func TestCopilotFilePagingEventuallyReturnsEveryPrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "copilot-paged.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 5; index++ {
		writeCopilotRecord(t, file, map[string]any{
			"type":      "user.message",
			"timestamp": fmt.Sprintf("2026-07-21T00:00:0%dZ", index+1),
			"data":      map[string]any{"content": fmt.Sprintf("copilot-page-%d", index+1)},
		})
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	startLine := 1
	var positions []int
	for page := 0; page < 3; page++ {
		prompts, nextLine, scanErr := scanCopilotFilePage(
			path,
			"copilot-page-session",
			startLine,
			newRecoveredPromptCollectorWithLimits(2, 1024, 512),
		)
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		for _, prompt := range prompts {
			positions = append(positions, prompt.Position)
		}
		startLine = nextLine
	}
	if fmt.Sprint(positions) != "[1 2 3 4 5]" || startLine != 0 {
		t.Fatalf("Copilot pages = %v, next=%d; want all prompts and completion", positions, startLine)
	}
}

func TestCopilotWorkspaceMetadataIsBoundedAndUnambiguous(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "duplicate folder",
			data: []byte(`{"folder":"file:///first","folder":"file:///second"}`),
		},
		{
			name: "trailing JSON",
			data: []byte(`{"folder":"file:///first"}{"folder":"file:///second"}`),
		},
		{
			name: "oversized",
			data: []byte(`{"folder":"file:///` +
				strings.Repeat("a", maxCopilotWorkspaceMetadataBytes) + `"}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := t.TempDir()
			if err := os.WriteFile(filepath.Join(storage, "workspace.json"), tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if folder, err := copilotWorkspaceFolder(storage); err == nil {
				t.Fatalf("copilotWorkspaceFolder() = %q, nil; want rejection", folder)
			}
		})
	}
}

func TestCopilotWorkspaceMetadataRejectsSymlink(t *testing.T) {
	storage := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside-workspace.json")
	if err := os.WriteFile(target, []byte(`{"folder":"file:///outside"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	requireFileSymlink(t, target, filepath.Join(storage, "workspace.json"))
	if folder, err := copilotWorkspaceFolder(storage); err == nil {
		t.Fatalf("copilotWorkspaceFolder() = %q, nil; want symlink rejection", folder)
	}
}
