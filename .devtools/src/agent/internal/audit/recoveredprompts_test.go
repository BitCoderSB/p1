package audit

import (
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

func TestRecoveredPromptCollectorSignalsFullBatchWithoutRetainingOverflow(t *testing.T) {
	collector := newRecoveredPromptCollectorWithLimits(3, 8, 6)
	if result := collector.TryAdd(scannedPrompt{Prompt: "1234"}); result != recoveredPromptAdded {
		t.Fatal("collector rejected an in-budget prompt")
	}
	if result := collector.TryAdd(scannedPrompt{Prompt: "56789"}); result != recoveredPromptBatchFull {
		t.Fatalf("collector result = %v; want batch-full signal", result)
	}
	if len(collector.Values()) != 1 {
		t.Fatalf("collector retained %d prompts, want 1", len(collector.Values()))
	}
	if err := collector.Err("test recovery"); err != nil {
		t.Fatalf("batch-full collector returned permanent error: %v", err)
	}
}

func TestRecoveredPromptCollectorAddsFileBatchAtomically(t *testing.T) {
	collector := newRecoveredPromptCollectorWithLimits(3, 16, 8)
	first := []scannedPrompt{{Prompt: "one"}, {Prompt: "two"}}
	if !collector.AddAll(first) {
		t.Fatal("collector rejected an in-budget file batch")
	}
	before := len(collector.Values())
	if collector.AddAll([]scannedPrompt{{Prompt: "three"}, {Prompt: "four"}}) {
		t.Fatal("collector partially accepted a batch beyond the count budget")
	}
	if len(collector.Values()) != before {
		t.Fatalf("collector retained %d prompts after rejected batch, want %d", len(collector.Values()), before)
	}
}

func TestRecoveredPromptCollectorRejectsOversizedSinglePrompt(t *testing.T) {
	collector := newRecoveredPromptCollectorWithLimits(2, 32, 4)
	if result := collector.TryAdd(scannedPrompt{Prompt: "12345"}); result != recoveredPromptOversized {
		t.Fatalf("collector result = %v; want oversized signal", result)
	}
	if err := collector.Err("test recovery"); err == nil {
		t.Fatal("collector omitted the oversized-prompt health error")
	}
}

func TestRecoveredPromptDeduperReservesExactHistoryMatch(t *testing.T) {
	timestamp := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	existing := model.Event{
		EventID:   "codex-h-exact-second",
		Timestamp: timestamp,
		Tool:      model.ToolCodex,
		SessionID: "session",
		Prompt:    "same prompt",
	}
	build := func(prompt scannedPrompt) model.Event {
		eventID := "codex-h-first"
		if prompt.Position == 2 {
			eventID = existing.EventID
		}
		return model.Event{
			EventID:   eventID,
			Timestamp: prompt.Timestamp,
			Tool:      model.ToolCodex,
			SessionID: prompt.SessionID,
			Prompt:    prompt.Prompt,
		}
	}
	deduper := newRecoveredPromptDeduper([]model.Event{existing}, build, nil)
	first := scannedPrompt{
		SessionID: "session", Position: 1, Prompt: "same prompt", Timestamp: timestamp,
	}
	second := first
	second.Position = 2
	if deduper.Skip(first) {
		t.Fatal("history correlation suppressed a distinct prompt before an exact match")
	}
	if !deduper.Skip(second) {
		t.Fatal("deduper did not skip the exact durable history event")
	}
}

func TestRecoveredPromptDeduperConsumesDirectMatchesOneToOne(t *testing.T) {
	timestamp := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	existing := model.Event{
		EventID:   "hook-e-direct",
		Timestamp: timestamp,
		Tool:      model.ToolClaudeCode,
		SessionID: "session",
		Prompt:    "same prompt",
	}
	build := func(prompt scannedPrompt) model.Event {
		return model.Event{
			EventID:   "claude-h-candidate",
			Timestamp: prompt.Timestamp,
			Tool:      model.ToolClaudeCode,
			SessionID: prompt.SessionID,
			Prompt:    prompt.Prompt,
		}
	}
	deduper := newRecoveredPromptDeduper([]model.Event{existing}, build, nil)
	candidate := scannedPrompt{
		SessionID: "session", Position: 1, Prompt: "same prompt", Timestamp: timestamp,
	}
	if !deduper.Skip(candidate) {
		t.Fatal("deduper did not correlate the first direct capture")
	}
	candidate.Position = 2
	if deduper.Skip(candidate) {
		t.Fatal("one direct capture suppressed two history candidates")
	}
}

func TestRecoveredPromptDeduperConsumesPersistedHistoryAliasOnce(t *testing.T) {
	timestamp := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	build := func(prompt scannedPrompt) model.Event {
		return model.Event{
			EventID:   "codex-h-current",
			Timestamp: prompt.Timestamp,
			Tool:      model.ToolCodex,
			SessionID: prompt.SessionID,
			Prompt:    prompt.Prompt,
		}
	}
	deduper := newRecoveredPromptDeduper(nil, build, nil)
	deduper.AddHistoryAliases(map[string]string{
		"codex-h-current": "codex-h-legacy",
	})
	candidate := scannedPrompt{
		SessionID: "session", Position: 1, Prompt: "legacy prompt", Timestamp: timestamp,
	}
	if !deduper.Skip(candidate) {
		t.Fatal("deduper did not consume a durable legacy-history alias")
	}
	if deduper.Skip(candidate) {
		t.Fatal("one history alias suppressed the same candidate twice")
	}
}
