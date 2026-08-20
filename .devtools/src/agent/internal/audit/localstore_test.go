package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

func enableTestLocalStore(t *testing.T, repository testRepository) {
	t.Helper()
	project, err := loadProjectConfig(repository.Root)
	if err != nil {
		t.Fatalf("load project configuration: %v", err)
	}
	project.LocalStore = true
	encoded, err := json.MarshalIndent(project, "", "  ")
	if err != nil {
		t.Fatalf("encode project configuration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repository.Root, filepath.FromSlash(projectConfigPath)), encoded, 0o600); err != nil {
		t.Fatalf("write project configuration: %v", err)
	}
	runGit(t, repository.Root, "add", filepath.FromSlash(projectConfigPath))
	runGit(t, repository.Root, "commit", "-m", "enable local registry")
}

func newPromptRegistryStagingRepository(t *testing.T) testRepository {
	t.Helper()
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	return repository
}

func appendPromptRegistryStagingEvent(
	t *testing.T,
	repository testRepository,
	eventID, prompt string,
) (string, string, []byte) {
	t.Helper()
	discovered, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("discover staging fixture repository: %v", err)
	}
	const userEmail = "tests@example.invalid"
	userID := localUserID(userEmail)
	event := sampleEvent(eventID, prompt)
	event.UserID = userID
	event.UserEmail = userEmail
	event.RepositoryName = discovered.Name
	event.RepositoryRemote = discovered.Remote
	event.Branch = repository.Branch
	event.CommitHash = repository.CommitHash
	event.SessionID = "synthetic-staging-session"
	if err := writeLocalEvent(repository.Root, event); err != nil {
		t.Fatalf("write synthetic staging event: %v", err)
	}
	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatalf("publish synthetic staging registry: %v", err)
	}
	path := registryPath(repository.Root, userID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read synthetic staging registry: %v", err)
	}
	relative := filepath.ToSlash(filepath.Join(".devtools", "registry", filepath.Base(path)))
	return path, relative, data
}

func assertStagedRegistryBytes(t *testing.T, root, relative string, expected []byte) {
	t.Helper()
	index, err := readRegistryIndex(root)
	if err != nil {
		t.Fatalf("read staged registry index: %v", err)
	}
	entries := index[relative]
	if len(entries) != 1 || entries[0].stage != "0" || entries[0].mode != "100644" {
		t.Fatalf("staged registry metadata = %#v, want one regular stage-0 entry", entries)
	}
	actual, err := runGitBytes(root, nil, "cat-file", "blob", entries[0].oid)
	if err != nil {
		t.Fatalf("read staged registry blob: %v", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("staged registry is %d bytes, want the exact %d-byte worktree snapshot", len(actual), len(expected))
	}
}

func TestStagePromptRegistryBypassesCleanAndEOLFilters(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	_, relative, expected := appendPromptRegistryStagingEvent(
		t,
		repository,
		"stage-filter-event",
		"synthetic prompt for exact-byte filter staging",
	)
	if !bytes.Contains(expected, []byte{'\n'}) || bytes.Contains(expected, []byte("\r\n")) {
		t.Fatal("synthetic registry fixture must contain LF-only JSONL")
	}

	attributes := []byte(".devtools/registry/*.jsonl text eol=crlf filter=prompt-audit-stage-test\n")
	if err := os.WriteFile(filepath.Join(repository.Root, ".gitattributes"), attributes, 0o600); err != nil {
		t.Fatalf("write adversarial Git attributes: %v", err)
	}
	runGit(t, repository.Root, "config", "filter.prompt-audit-stage-test.clean", "exit 91")
	runGit(t, repository.Root, "config", "filter.prompt-audit-stage-test.required", "true")
	active := runGit(t, repository.Root, "check-attr", "filter", "eol", "--", relative)
	if !strings.Contains(active, "prompt-audit-stage-test") || !strings.Contains(active, "crlf") {
		t.Fatalf("adversarial Git attributes are not active: %q", active)
	}

	if err := stagePromptRegistry(repository.Root); err != nil {
		t.Fatalf("stagePromptRegistry() with clean/EOL attributes = %v", err)
	}
	assertStagedRegistryBytes(t, repository.Root, relative, expected)
}

func TestStagePromptRegistryClearsUnsafeIndexFlagsAndStagesExactBytes(t *testing.T) {
	tests := []struct {
		name       string
		setFlag    string
		inspectTag string
		wantTag    byte
	}{
		{
			name:       "assume-unchanged",
			setFlag:    "--assume-unchanged",
			inspectTag: "-v",
			wantTag:    'h',
		},
		{
			name:       "skip-worktree",
			setFlag:    "--skip-worktree",
			inspectTag: "-t",
			wantTag:    'S',
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newPromptRegistryStagingRepository(t)
			_, relative, baseline := appendPromptRegistryStagingEvent(
				t,
				repository,
				"stage-flag-baseline",
				"synthetic baseline prompt for index flag staging",
			)
			if err := stagePromptRegistry(repository.Root); err != nil {
				t.Fatalf("stage baseline registry: %v", err)
			}
			runGit(t, repository.Root, "commit", "-m", "commit synthetic registry baseline")
			runGit(t, repository.Root, "update-index", test.setFlag, "--", relative)
			tagged, err := runGitBytes(
				repository.Root,
				nil,
				"ls-files", test.inspectTag, "-z", "--", relative,
			)
			if err != nil || len(tagged) < 2 || tagged[0] != test.wantTag {
				t.Fatalf("Git index flag %s was not established: %q, %v", test.setFlag, tagged, err)
			}

			_, _, expected := appendPromptRegistryStagingEvent(
				t,
				repository,
				"stage-flag-update",
				"synthetic updated prompt that must replace the flagged index blob",
			)
			if bytes.Equal(expected, baseline) {
				t.Fatal("synthetic registry update did not change the staged fixture")
			}
			if err := stagePromptRegistry(repository.Root); err != nil {
				t.Fatalf("stagePromptRegistry() with %s = %v", test.setFlag, err)
			}
			if err := verifyRegistryIndexFlags(repository.Root, relative); err != nil {
				t.Fatalf("unsafe Git index flag remains after staging: %v", err)
			}
			assertStagedRegistryBytes(t, repository.Root, relative, expected)
		})
	}
}

func TestStagePromptRegistryRejectsSymlinkJSONL(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	path, relative, data := appendPromptRegistryStagingEvent(
		t,
		repository,
		"stage-symlink-event",
		"synthetic prompt behind an untrusted symbolic link",
	)
	target := filepath.Join(t.TempDir(), "outside-registry.jsonl")
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatalf("write synthetic symlink target: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("replace synthetic registry with symlink: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symbolic links are unavailable for this test: %v", err)
	}

	if err := stagePromptRegistry(repository.Root); err == nil {
		t.Fatal("stagePromptRegistry() accepted a symbolic-link JSONL entry")
	}
	index, err := readRegistryIndex(repository.Root)
	if err != nil {
		t.Fatalf("read registry index after symlink rejection: %v", err)
	}
	if _, staged := index[relative]; staged {
		t.Fatal("symbolic-link JSONL entry mutated the Git index")
	}
}

func TestStagePromptRegistryRejectsOversizedJSONLBeforeReadingIt(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	path, relative, _ := appendPromptRegistryStagingEvent(
		t,
		repository,
		"stage-oversized-event",
		"synthetic prompt before sparse oversized staging input",
	)
	if err := os.Truncate(path, maxRegistryStageFile+1); err != nil {
		t.Fatal(err)
	}
	if err := stagePromptRegistry(repository.Root); err == nil ||
		!strings.Contains(err.Error(), "bounded staging size") {
		t.Fatalf("stagePromptRegistry() oversized error = %v", err)
	}
	index, err := readRegistryIndex(repository.Root)
	if err != nil {
		t.Fatalf("read registry index after oversized rejection: %v", err)
	}
	if _, staged := index[relative]; staged {
		t.Fatal("oversized JSONL entry mutated the Git index")
	}
}

func TestStagePromptRegistryRejectsMissingTrackedJSONLWithoutStagingDeletion(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	path, relative, _ := appendPromptRegistryStagingEvent(
		t,
		repository,
		"stage-missing-event",
		"synthetic prompt in a tracked registry file",
	)
	if err := stagePromptRegistry(repository.Root); err != nil {
		t.Fatalf("stage tracked registry baseline: %v", err)
	}
	runGit(t, repository.Root, "commit", "-m", "commit tracked synthetic registry")
	before, err := readRegistryIndex(repository.Root)
	if err != nil || len(before[relative]) != 1 {
		t.Fatalf("read tracked registry baseline: %#v, %v", before[relative], err)
	}
	baseline := before[relative][0]
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove tracked synthetic registry fixture: %v", err)
	}

	// A registry file the worker deleted is left exactly as the index has it.
	// Staging continues so one missing file cannot stop delivery for everyone,
	// and it must still never stage the deletion.
	if err := stagePromptRegistry(repository.Root); err != nil {
		t.Fatalf("stagePromptRegistry() with a missing tracked JSONL entry: %v", err)
	}
	after, err := readRegistryIndex(repository.Root)
	if err != nil {
		t.Fatalf("read registry index after missing-file rejection: %v", err)
	}
	if len(after[relative]) != 1 || after[relative][0] != baseline {
		t.Fatalf("missing tracked JSONL changed the index: before=%#v after=%#v", baseline, after[relative])
	}
	deleted := runGit(
		t,
		repository.Root,
		"diff", "--cached", "--name-only", "--diff-filter=D", "--", ".devtools/registry",
	)
	if deleted != "" {
		t.Fatalf("missing tracked JSONL staged a deletion: %q", deleted)
	}
}

func TestLocalRegistryRecordsOnlyUserPromptsGroupedByUserAndChat(t *testing.T) {
	const (
		promptSecret    = "PROMPT-PASSWORD-MUST-NOT-LEAK"
		assistantSecret = "ASSISTANT-RESPONSE-MUST-NOT-BE-STORED"
	)
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	configDir := useTestConfigDirectory(t)

	payload, err := json.Marshal(map[string]any{
		"hook_event_name":    "UserPromptSubmit",
		"transcript_path":    filepath.Join(repository.Root, "t.jsonl"),
		"permission_mode":    "default",
		"prompt":             "build login; password=" + promptSecret,
		"session_id":         "demo-chat-1",
		"cwd":                repository.Nested,
		"response":           assistantSecret,
		"assistant_response": assistantSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_PROJECT_DIR", repository.Root)
	result, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if !result.Sent || result.Queued {
		t.Fatalf("Capture() result = %#v, want stored locally and marked delivered", result)
	}

	for _, step := range []struct{ session, prompt string }{
		{"demo-chat-1", "add password validation"},
		{"demo-chat-2", "refactor the payments module"},
	} {
		if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, step.session, step.prompt))); err != nil {
			t.Fatalf("Capture() error = %v", err)
		}
	}
	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatalf("publishAllRegistryBackups() error = %v", err)
	}

	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("registry events = %d, want 3", len(events))
	}

	// Exactly one per-user registry file was created (single Git identity here).
	userID := localUserID("tests@example.invalid")
	if _, err := os.Stat(registryPath(repository.Root, userID)); err != nil {
		t.Fatalf("expected per-user registry file for %s: %v", userID, err)
	}
	registryEntries, _ := os.ReadDir(registryDir(repository.Root))
	jsonlCount := 0
	for _, entry := range registryEntries {
		if strings.HasSuffix(entry.Name(), ".jsonl") {
			jsonlCount++
		}
	}
	if jsonlCount != 1 {
		t.Fatalf("registry files = %d, want 1 per-user file", jsonlCount)
	}

	raw, err := os.ReadFile(registryPath(repository.Root, userID))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), assistantSecret) {
		t.Fatal("assistant response was stored in the registry")
	}
	if strings.Contains(string(raw), promptSecret) || !strings.Contains(string(raw), "[REDACTED]") {
		t.Fatal("prompt secret was not redacted in the registry")
	}

	sessions := map[string]int{}
	for _, event := range events {
		if event.UserEmail != "tests@example.invalid" {
			t.Fatalf("event identity = %q, want the Git identity", event.UserEmail)
		}
		sessions[event.SessionID]++
	}
	if sessions["demo-chat-1"] != 2 || sessions["demo-chat-2"] != 1 {
		t.Fatalf("session grouping = %#v; want same session merged and distinct session separated", sessions)
	}

	// Local mode must not create any external credential profile.
	if entries, _ := os.ReadDir(filepath.Join(configDir, profilesDirectory)); len(entries) != 0 {
		t.Fatalf("local registry mode created %d external profile(s)", len(entries))
	}

	var out bytes.Buffer
	if err := LocalLog(&out, repository.Nested); err != nil {
		t.Fatalf("LocalLog() error = %v", err)
	}
	for _, want := range []string{"tests@example.invalid", "demo-chat-1", "demo-chat-2", "add password validation", "refactor the payments module"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("LocalLog output missing %q:\n%s", want, out.String())
		}
	}
}

func TestProviderPromptIDDeduplicatesProjectAndManagedHookInvocations(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	t.Setenv("CLAUDE_PROJECT_DIR", repository.Root)
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "UserPromptSubmit",
		"transcript_path": filepath.Join(repository.Root, "managed-and-project.jsonl"),
		"permission_mode": "default",
		"prompt_id":       "provider-stable-prompt-id",
		"prompt":          "same provider submission",
		"session_id":      "same-provider-session",
		"cwd":             repository.Root,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if first.EventID != second.EventID || !strings.HasPrefix(first.EventID, "hook-e-") {
		t.Fatalf("provider IDs = %q / %q; want the same deterministic hook ID", first.EventID, second.EventID)
	}
	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatal(err)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Prompt != "same provider submission" {
		t.Fatalf("logical registry events = %#v; want one provider submission", events)
	}
}

func TestClaudeCaptureFailsClosedWithoutClaudeProjectEnvironment(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	t.Setenv("CLAUDE_PROJECT_DIR", "")
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "UserPromptSubmit",
		"transcript_path": filepath.Join(repository.Root, "vscode-transcript.jsonl"),
		"permission_mode": "default",
		"prompt":          "must fail closed before durable capture",
		"session_id":      "vscode-session",
		"cwd":             repository.Root,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload)); err == nil ||
		errors.Is(err, ErrNotUserPrompt) {
		t.Fatalf("Capture() error = %v, want blocking integration failure", err)
	}
	events, err := readAllAuthoritativeEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("cross-provider Claude hook stored %d event(s), want 0", len(events))
	}
}

func TestLocalRegistrySurvivesDeletedRegistryFile(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	userID := localUserID("tests@example.invalid")

	for _, prompt := range []string{"primer prompt", "segundo prompt"} {
		if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "chat-1", prompt))); err != nil {
			t.Fatalf("Capture() error = %v", err)
		}
	}
	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatal(err)
	}

	// Simulate returning to an older commit: Git reverts the tracked registry
	// file, so it disappears. The git-ignored backup must still hold everything.
	if err := os.Remove(registryPath(repository.Root, userID)); err != nil {
		t.Fatalf("remove registry to simulate checkout: %v", err)
	}

	// The pre-commit reconcile path must rebuild the full registry from backup.
	if err := ReconcileRegistry(repository.Nested); err != nil {
		t.Fatalf("ReconcileRegistry() error = %v", err)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("registry after reconcile = %d events, want 2 (nothing lost)", len(events))
	}

	// A new capture after "going back" keeps prior prompts and adds the new one.
	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "chat-1", "tercer prompt tras volver"))); err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatal(err)
	}
	events, err = readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("registry after new capture = %d events, want 3", len(events))
	}
}

func TestDirectCaptureDoesNotWaitForDeliveryBarrier(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	discovered, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	const userEmail = "tests@example.invalid"
	userID := localUserID(userEmail)
	event := sampleEvent("delivery-barrier-event", "synthetic delivery barrier prompt")
	event.UserID = userID
	event.UserEmail = userEmail
	event.RepositoryName = discovered.Name
	event.RepositoryRemote = repositoryRemoteForEvent(discovered)
	event.Branch = repository.Branch
	event.CommitHash = repository.CommitHash
	event.SessionID = "delivery-barrier-session"

	barrierHeld := make(chan struct{})
	releaseBarrier := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- withFileLock(
			localStoreDeliveryBarrierLockPath(repository.Root),
			2*time.Second,
			func() error {
				close(barrierHeld)
				<-releaseBarrier
				return nil
			},
		)
	}()
	<-barrierHeld

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeLocalEvent(repository.Root, event)
	}()

	select {
	case err := <-writeDone:
		if err != nil {
			close(releaseBarrier)
			<-lockDone
			t.Fatalf("writeLocalEvent() behind delivery barrier = %v", err)
		}
	case <-time.After(2 * time.Second):
		close(releaseBarrier)
		<-lockDone
		t.Fatal("direct capture waited for the delivery barrier")
	}
	authoritative, err := readEventsFile(authoritativePath(repository.Root, userID))
	if err != nil {
		close(releaseBarrier)
		<-lockDone
		t.Fatalf("read authoritative capture: %v", err)
	}
	if len(authoritative) != 1 || authoritative[0].EventID != event.EventID {
		close(releaseBarrier)
		<-lockDone
		t.Fatalf("authoritative capture = %#v, want the direct event", authoritative)
	}
	close(releaseBarrier)
	if err := <-lockDone; err != nil {
		t.Fatalf("release synthetic delivery barrier: %v", err)
	}
	if err := ReconcileRegistry(repository.Root); err != nil {
		t.Fatalf("ReconcileRegistry() after durable capture = %v", err)
	}

	relative := filepath.ToSlash(filepath.Join(
		".devtools", "registry", userID+registryFileExt,
	))
	index, err := readRegistryIndex(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	entries := index[relative]
	if len(entries) != 1 || entries[0].stage != "0" {
		t.Fatalf("staged delivery entry = %#v, want one stage-0 entry", entries)
	}
	blob, err := runGitBytes(repository.Root, nil, "cat-file", "blob", entries[0].oid)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := decodeStoredEventsBytes(filepath.Base(relative), blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) != 1 || staged[0].EventID != event.EventID {
		t.Fatalf("staged delivery contains %d events, want the concurrent event", len(staged))
	}
}

func TestLocalRegistryKeepsDifferentUsersInSeparateFiles(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)

	runGit(t, repository.Root, "config", "user.name", "Ana")
	runGit(t, repository.Root, "config", "user.email", "ana@example.invalid")
	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "ana-chat", "prompt de Ana"))); err != nil {
		t.Fatal(err)
	}
	runGit(t, repository.Root, "config", "user.name", "Beto")
	runGit(t, repository.Root, "config", "user.email", "beto@example.invalid")
	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "beto-chat", "prompt de Beto"))); err != nil {
		t.Fatal(err)
	}
	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(registryPath(repository.Root, localUserID("ana@example.invalid"))); err != nil {
		t.Fatalf("missing Ana's registry file: %v", err)
	}
	if _, err := os.Stat(registryPath(repository.Root, localUserID("beto@example.invalid"))); err != nil {
		t.Fatalf("missing Beto's registry file: %v", err)
	}

	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	emails := map[string]bool{}
	for _, event := range events {
		emails[event.UserEmail] = true
	}
	if !emails["ana@example.invalid"] || !emails["beto@example.invalid"] || len(emails) != 2 {
		t.Fatalf("expected both users classified separately, got %v", emails)
	}
}

func TestLocalRegistryDeduplicatesUnionMergeDuplicates(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	userID := localUserID("tests@example.invalid")

	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "chat-1", "único prompt"))); err != nil {
		t.Fatal(err)
	}
	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatal(err)
	}
	// A merge=union merge can concatenate the same line twice. Simulate that by
	// duplicating every line in the registry file, then confirm the reader
	// collapses it back to one event per event_id.
	path := registryPath(repository.Root, userID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte{}, raw...), raw...), 0o644); err != nil {
		t.Fatal(err)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("deduplicated events = %d, want 1", len(events))
	}
}

func TestGenerateReportRendersUserChatPromptWithoutAssistantResponse(t *testing.T) {
	const assistantSecret = "ASSISTANT-RESPONSE-MUST-NOT-BE-IN-REPORT"
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)

	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "UserPromptSubmit",
		"transcript_path": filepath.Join(repository.Root, "t.jsonl"),
		"permission_mode": "default",
		"prompt":          "diseña el <panel> de <control>",
		"session_id":      "chat-report",
		"cwd":             repository.Nested,
		"response":        assistantSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_PROJECT_DIR", repository.Root)
	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(t.TempDir(), "report.html")
	path, err := GenerateReport(repository.Nested, output)
	if err != nil {
		t.Fatalf("GenerateReport() error = %v", err)
	}
	if path != output {
		t.Fatalf("report path = %q, want %q", path, output)
	}
	html, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	content := string(html)
	// The data is embedded as JSON (drill-down rendered client-side); the user,
	// chat and prompt must be present in that payload.
	for _, want := range []string{"tests@example.invalid", "chat-report", "claude-code", "diseña el"} {
		if !strings.Contains(content, want) {
			t.Fatalf("report missing %q", want)
		}
	}
	if strings.Contains(content, assistantSecret) {
		t.Fatal("report rendered an assistant response")
	}
	// json.Marshal escapes angle brackets to < / >, so the prompt can
	// never break out of the <script> block as raw markup.
	if strings.Contains(content, "<panel>") {
		t.Fatal("prompt text was not escaped in the report payload")
	}
}

func TestEnsurePreCommitHookInstallsOnceAndRespectsForeignHook(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)

	if err := ensurePreCommitHook(repository.Root); err != nil {
		t.Fatalf("first ensurePreCommitHook() error = %v", err)
	}
	hookPath := filepath.Join(repository.Root, ".git", "hooks", "pre-commit")
	body, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("hook not installed: %v", err)
	}
	if !strings.Contains(string(body), preCommitHookMarker) {
		t.Fatal("installed hook missing marker")
	}
	// Idempotent: a second call leaves our hook untouched.
	if err := ensurePreCommitHook(repository.Root); err != nil {
		t.Fatalf("second ensurePreCommitHook() error = %v", err)
	}
	// A foreign hook that merely mentions the marker phrase is still foreign.
	incidental := []byte("#!/bin/sh\n# mentions devtools environment hook in documentation\nexit 0\n")
	if err := os.WriteFile(hookPath, incidental, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePreCommitHook(repository.Root); err == nil {
		t.Fatal("ensurePreCommitHook overwrote a foreign hook with an incidental marker phrase")
	}
	body, err = os.ReadFile(hookPath)
	if err != nil || !bytes.Equal(body, incidental) {
		t.Fatalf("incidental-marker hook was changed: %v", err)
	}
	if err := os.Remove(hookPath); err != nil {
		t.Fatal(err)
	}
	if err := ensurePreCommitHook(repository.Root); err != nil {
		t.Fatalf("restore canonical hook: %v", err)
	}

	// A foreign hook must never be overwritten.
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho worker hook\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePreCommitHook(repository.Root); err == nil {
		t.Fatal("ensurePreCommitHook overwrote a foreign hook")
	}
	body, _ = os.ReadFile(hookPath)
	if !strings.Contains(string(body), "worker hook") {
		t.Fatal("foreign hook content was lost")
	}
}

func TestActivateFailsClosedWhenProviderCaptureHookIsAltered(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{
		model.ToolClaudeCode,
		model.ToolCodex,
		model.ToolCopilotCLI,
	})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() with canonical provider hooks = %v", err)
	}

	path := filepath.Join(repository.Root, ".github", "hooks", "prompt-audit.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"hooks":{"UserPromptSubmit":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A removed capture hook is restored rather than reported: the session
	// continues and the next prompt is captured again.
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() after Copilot hook removal = %v", err)
	}
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("discover repository: %v", err)
	}
	if err := verifyProviderCaptureConfiguration(repo); err != nil {
		t.Fatalf("the Copilot capture hook must be restored: %v", err)
	}
}

func TestActivateFailsClosedWhenLocalStorePathIsNotDirectory(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	if err := os.WriteFile(localStoreDir(repository.Root), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err == nil ||
		!strings.Contains(err.Error(), "durable local prompt storage") {
		t.Fatalf("Activate() with invalid local store path = %v, want storage error", err)
	}
}

func TestActivateFailsClosedWhenLocalStoreDirectoryIsSymlink(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	target := filepath.Join(t.TempDir(), "outside-local-store")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, localStoreDir(repository.Root)); err != nil {
		t.Skipf("symbolic links are unavailable for this test: %v", err)
	}
	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err == nil ||
		!strings.Contains(err.Error(), "durable local prompt storage") {
		t.Fatalf("Activate() with symlinked local store = %v, want storage error", err)
	}
}

func TestActivateKeepsCaptureActiveWhenPreCommitHookIsUnavailable(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	hookPath := filepath.Join(repository.Root, ".git", "hooks", "pre-commit")
	foreignHook := []byte("#!/bin/sh\n# synthetic worker hook\nexit 0\n")
	if err := os.WriteFile(hookPath, foreignHook, 0o700); err != nil {
		t.Fatalf("write foreign pre-commit fixture: %v", err)
	}

	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() with unavailable delivery hook = %v", err)
	}
	if strings.Contains(strings.ToLower(out.String()), "advertencia") {
		t.Fatalf("Activate() exposed a delivery warning: %q", out.String())
	}
	after, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read foreign pre-commit fixture: %v", err)
	}
	if !bytes.Equal(after, foreignHook) {
		t.Fatal("Activate() modified a foreign pre-commit hook")
	}
}

func TestActivateKeepsCaptureActiveWhenGitIndexIsUnavailable(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	indexDirectory := filepath.Join(t.TempDir(), "not-an-index")
	if err := os.MkdirAll(indexDirectory, 0o700); err != nil {
		t.Fatalf("create invalid Git index fixture: %v", err)
	}
	t.Setenv("GIT_INDEX_FILE", indexDirectory)

	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() with unavailable Git index = %v", err)
	}
	if strings.Contains(strings.ToLower(out.String()), "advertencia") {
		t.Fatalf("Activate() exposed a Git staging warning: %q", out.String())
	}
}

func TestLocalCaptureStoresDurablyWithoutGitDeliveryHookOrWarning(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	hookPath := filepath.Join(repository.Root, ".git", "hooks", "pre-commit")
	foreignHook := []byte("#!/bin/sh\n# synthetic worker hook\nexit 0\n")
	if err := os.WriteFile(hookPath, foreignHook, 0o700); err != nil {
		t.Fatalf("write foreign pre-commit fixture: %v", err)
	}

	const prompt = "synthetic prompt captured without Git metadata writes"
	result, err := Capture(
		model.ToolClaudeCode,
		bytes.NewReader(claudePayload(
			t,
			repository.Nested,
			"sandbox-delivery-session",
			prompt,
		)),
	)
	if err != nil {
		t.Fatalf("Capture() with unavailable delivery hook = %v", err)
	}
	if result.Warning != "" {
		t.Fatalf("Capture() exposed a recoverable delivery warning: %q", result.Warning)
	}

	// Capture writes only the git-ignored authoritative backup. Writing the
	// tracked public copy on every prompt is what left the worker's tree
	// permanently dirty; publication now happens at commit time.
	backup, err := readAuthoritativeEventsForPublish(
		repository.Root,
		localUserID("tests@example.invalid"),
	)
	if err != nil {
		t.Fatalf("read authoritative backup: %v", err)
	}
	if len(backup) != 1 || backup[0].Prompt != prompt {
		t.Fatalf("authoritative backup events = %#v, want the direct prompt", backup)
	}
	if published, err := readRegistryEvents(repository.Root); err != nil {
		t.Fatalf("read registry: %v", err)
	} else if len(published) != 0 {
		t.Fatalf("capture must not write the tracked public copy: %#v", published)
	}

	// The commit-time path publishes it, and it must do so without touching a
	// hook the worker wrote.
	if err := StageDirectRegistry(repository.Root); err != nil {
		t.Fatalf("commit-time delivery: %v", err)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatalf("read published registry: %v", err)
	}
	if len(events) != 1 || events[0].Prompt != prompt {
		t.Fatalf("published registry events = %#v, want the direct prompt", events)
	}
	after, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read foreign pre-commit fixture: %v", err)
	}
	if !bytes.Equal(after, foreignHook) {
		t.Fatal("Capture() modified a foreign pre-commit hook")
	}
}

// The scope checks that used to guard the direct working-tree append still
// guard the durable path that replaced it: a user_id not derived from the
// e-mail, or an identity from another project, must never reach storage — and
// the rejection must not depend on running Git.
func TestDurableAppendUsesValidatedRepositorySnapshotWithoutGit(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	discovered, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	const userEmail = "snapshot@example.invalid"
	event := sampleEvent("direct-snapshot-event", "synthetic snapshot prompt")
	event.UserID = localUserID(userEmail)
	event.UserEmail = userEmail
	event.RepositoryName = discovered.Name
	event.RepositoryRemote = repositoryRemoteForEvent(discovered)
	event.Branch = discovered.Branch
	event.CommitHash = discovered.CommitHash
	event.SessionID = "direct-snapshot-session"

	context := storedEventContext{
		projectName:      discovered.Name,
		repositoryRemote: repositoryRemoteForEvent(discovered),
	}
	// The expected identifier is always derived from the e-mail, exactly as
	// storage derives it; comparing a forged value against itself would prove
	// nothing.
	unsafe := event
	unsafe.EventID = "unsafe-user-event"
	unsafe.UserID = "../../outside"
	if err := validateStoredEventContext(context, localUserID(unsafe.UserEmail), unsafe); err == nil {
		t.Fatal("storage accepted a user_id not derived from user_email")
	}
	wrongProject := event
	wrongProject.EventID = "wrong-project-event"
	wrongProject.RepositoryRemote = "local-project/other/project"
	if err := validateStoredEventContext(context, localUserID(wrongProject.UserEmail), wrongProject); err == nil {
		t.Fatal("storage accepted a mismatched repository identity")
	}
	if _, err := os.Lstat(registryPath(repository.Root, event.UserID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a rejected event created a registry file: %v", err)
	}

	// A regression that reached for Git here would fail: nothing is on PATH.
	t.Setenv("PATH", t.TempDir())
	if err := writeLocalEvent(repository.Root, event); err != nil {
		t.Fatalf("durable append rediscovered repository state: %v", err)
	}
	stored, err := readEventsFile(authoritativePath(repository.Root, event.UserID))
	if err != nil {
		t.Fatalf("read durable append: %v", err)
	}
	if len(stored) != 1 || stored[0].EventID != event.EventID {
		t.Fatalf("durable events = %#v, want the validated event", stored)
	}
}

func TestLocalCaptureDoesNotWaitForBusyRegistryReconciliation(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	acquired := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- withFileLock(
			localStoreReconcileLockPath(repository.Root),
			5*time.Second,
			func() error {
				close(acquired)
				<-release
				return nil
			},
		)
	}()
	<-acquired
	released := false
	defer func() {
		if !released {
			close(release)
			<-lockDone
		}
	}()

	start := time.Now()
	result, err := Capture(
		model.ToolClaudeCode,
		bytes.NewReader(claudePayload(
			t,
			repository.Nested,
			"busy-registry-session",
			"synthetic prompt while registry reconciliation is busy",
		)),
	)
	elapsed := time.Since(start)
	close(release)
	released = true
	if lockErr := <-lockDone; lockErr != nil {
		t.Fatalf("hold registry reconciliation lock: %v", lockErr)
	}

	if err != nil {
		t.Fatalf("Capture() with busy registry reconciliation = %v", err)
	}
	if result.Warning != "" {
		t.Fatalf("Capture() exposed a recoverable publication warning: %q", result.Warning)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Capture() waited %v for secondary registry publication", elapsed)
	}
	events, err := readEventsFile(authoritativePath(
		repository.Root,
		localUserID("tests@example.invalid"),
	))
	if err != nil {
		t.Fatalf("read authoritative capture after registry contention: %v", err)
	}
	if len(events) != 1 ||
		events[0].Prompt != "synthetic prompt while registry reconciliation is busy" {
		t.Fatalf("authoritative events = %#v, want the durable prompt", events)
	}
}

func TestActivateDoesNotReadCorruptAuthoritativeStore(t *testing.T) {
	repository := newPromptRegistryStagingRepository(t)
	const userEmail = "tests@example.invalid"
	if _, err := Capture(
		model.ToolClaudeCode,
		bytes.NewReader(claudePayload(
			t, repository.Nested, "activate-storage-repair", "synthetic valid prompt",
		)),
	); err != nil {
		t.Fatal(err)
	}
	path := authoritativePath(repository.Root, localUserID(userEmail))
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("{\"event_id\":\"invalid\",\"assistant_response\":\"forbidden\"}\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("append synthetic corrupt row: %v, %v", writeErr, closeErr)
	}

	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() read or failed on existing authoritative bytes: %v", err)
	}
	if err := ReconcileRegistry(repository.Root); err != nil {
		t.Fatalf("ReconcileRegistry() did not repair strict authoritative storage: %v", err)
	}
	events, err := readEventsFile(path)
	if err != nil {
		t.Fatalf("read repaired authoritative store: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("repaired authoritative store has %d valid events, want 1", len(events))
	}
	relative := filepath.ToSlash(filepath.Join(
		".devtools", "registry", localUserID(userEmail)+registryFileExt,
	))
	index, err := readRegistryIndex(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if entries := index[relative]; len(entries) != 1 {
		t.Fatalf("ReconcileRegistry() staged registry entries = %#v, want one", entries)
	}
}

func TestActivateRestoresMissingBootstrapInstruction(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	path := filepath.Join(repository.Root, ".claude", "CLAUDE.md")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() without the Claude instruction = %v", err)
	}
	// The monitoring notice is what the worker was told they agreed to; it is
	// restored rather than merely reported.
	if err := verifyBootstrapInstruction(repository.Root, path, canonicalInstructionSHA); err != nil {
		t.Fatalf("the bootstrap instruction must be restored: %v", err)
	}
}

func TestActivateRepairsFilteredCodexCaptureHook(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolCodex})
	enableTestLocalStore(t, repository)
	command := providerCaptureCommand + model.ToolCodex
	altered := fmt.Sprintf(
		`{"hooks":{"UserPromptSubmit":[{"matcher":"never","hooks":[{"type":"command","command":%q,"commandWindows":%q,"timeout":30}]}]}}`,
		command, command,
	)
	if err := os.WriteFile(filepath.Join(repository.Root, ".codex", "hooks.json"), []byte(altered), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Activate(&out, repository.Root); err != nil {
		t.Fatalf("Activate() with a filtered Codex hook = %v", err)
	}
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("discover repository: %v", err)
	}
	// A matcher that never fires is indistinguishable from a removed hook, so
	// the canonical unfiltered definition is restored.
	if err := verifyProviderCaptureConfiguration(repo); err != nil {
		t.Fatalf("the Codex capture hook must be restored unfiltered: %v", err)
	}
}

func TestLocalRegistryRepairsIncompleteTrailingRecordBeforeAppend(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	useTestConfigDirectory(t)
	userID := localUserID("tests@example.invalid")

	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "repair-chat", "first prompt"))); err != nil {
		t.Fatal(err)
	}
	backup := authoritativePath(repository.Root, userID)
	file, err := os.OpenFile(backup, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	const forbiddenTail = "TAIL-ASSISTANT-RESPONSE-MUST-NOT-SURVIVE"
	if _, err := file.WriteString(`{"event_id":"interrupted","assistant_response":"` + forbiddenTail); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "repair-chat", "second prompt"))); err != nil {
		t.Fatalf("Capture() after interrupted append = %v", err)
	}
	events, err := readEventsFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("repaired backup contains %d events, want 2", len(events))
	}
	matches, err := filepath.Glob(backup + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("quarantined tails = %v, %v; want one", matches, err)
	}
	evidence, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence), forbiddenTail) || !strings.Contains(string(evidence), "sha256=") {
		t.Fatalf("tail quarantine retained forbidden payload: %q", evidence)
	}
	health, err := os.ReadFile(filepath.Join(localStoreDir(repository.Root), healthLogFileName))
	if err != nil || !strings.Contains(string(health), "repaired an incomplete trailing JSONL record") {
		t.Fatalf("health log did not report generic recovery: %v", err)
	}
}

func TestLocalRegistryRepairsOversizedIncompleteTailWithoutRetainingPayload(t *testing.T) {
	root := t.TempDir()
	userID := "local-oversized-tail"
	first := sampleEvent("oversized-tail-first", "first safe prompt")
	first.UserID = userID
	if err := writeLocalEvent(root, first); err != nil {
		t.Fatal(err)
	}
	backup := authoritativePath(root, userID)
	file, err := os.OpenFile(backup, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	const forbidden = "OVERSIZED-ASSISTANT-PAYLOAD-MUST-NOT-SURVIVE"
	if _, err := file.WriteString(`{"assistant_response":"` + forbidden); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte("x"), 8*1024*1024+1)
	if _, err := file.Write(oversized); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	second := sampleEvent("oversized-tail-second", "second safe prompt")
	second.UserID = userID
	if err := writeLocalEvent(root, second); err != nil {
		t.Fatalf("writeLocalEvent() after oversized torn tail = %v", err)
	}
	events, err := readEventsFile(backup)
	if err != nil || len(events) != 2 {
		t.Fatalf("repaired events = %d, %v; want 2, nil", len(events), err)
	}
	matches, err := filepath.Glob(backup + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("oversized tail evidence = %v, %v; want one", matches, err)
	}
	evidence, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence), forbidden) ||
		!strings.Contains(string(evidence), "bytes=") ||
		!strings.Contains(string(evidence), "sha256=") {
		t.Fatalf("oversized tail evidence leaked payload or lacks digest: %q", evidence)
	}
}

func TestReadEventsFileRejectsCorruptionInsteadOfDroppingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	valid := sampleEvent("valid-event", "safe prompt")
	line, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	content := append(append(append([]byte{}, line...), '\n'), []byte("{invalid-json}\n")...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEventsFile(path); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("readEventsFile() error = %v, want explicit line-2 corruption", err)
	}
}

func TestReadEventsFileRejectsAssistantOrUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	event := sampleEvent("strict-event", "only this user prompt is allowed")
	line, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(line, &fields); err != nil {
		t.Fatal(err)
	}
	fields["assistant_response"] = "must never enter the prompt registry"
	line, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEventsFile(path); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("readEventsFile() error = %v, want strict unknown-field rejection", err)
	}
}

func TestReadEventsFileRejectsUnsupportedToolAndOversizedPrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	event := sampleEvent("unsupported-tool", "user prompt")
	event.Tool = "assistant"
	line, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEventsFile(path); err == nil {
		t.Fatal("readEventsFile accepted an unverified tool")
	}

	event.Tool = model.ToolCodex
	event.Prompt = strings.Repeat("x", maxQueuedPromptBytes+1)
	line, err = json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEventsFile(path); err == nil {
		t.Fatal("readEventsFile accepted an oversized prompt")
	}
}

func TestPublishRejectsEventWhoseIdentityOrProjectDoesNotMatchFile(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	userID := localUserID("tests@example.invalid")
	authoritative := sampleEvent("context-authoritative", "authoritative prompt")
	authoritative.UserID = userID
	authoritative.UserEmail = "tests@example.invalid"
	discovered, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	authoritative.RepositoryName = discovered.Name
	authoritative.RepositoryRemote = discovered.Remote
	if err := writeLocalEvent(repository.Root, authoritative); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(registryDir(repository.Root), 0o755); err != nil {
		t.Fatal(err)
	}
	injected := sampleEvent("context-injected", "copied from another project")
	injected.UserID = "different-user"
	injected.RepositoryName = "different-project"
	line, err := json.Marshal(injected)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath(repository.Root, userID), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatal(err)
	}
	events, err := readRegistryEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].EventID != authoritative.EventID {
		t.Fatalf("context repair retained out-of-scope event: %#v", events)
	}
}

func TestSingleLineNeutralizesTerminalAndBidiControls(t *testing.T) {
	input := "safe\x1b]52;c;clipboard\x07\nnext\u202Espoof"
	got := singleLine(input)
	for _, forbidden := range []string{"\x1b", "\x07", "\n", "\u202E"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("singleLine() retained control %q in %q", forbidden, got)
		}
	}
	for _, marker := range []string{`\u001B`, `\u0007`, "⏎", `\u202E`} {
		if !strings.Contains(got, marker) {
			t.Fatalf("singleLine() = %q, want marker %q", got, marker)
		}
	}
}

func TestLocalStoreSerializesConcurrentDurableCaptures(t *testing.T) {
	root := t.TempDir()
	const writers = 24
	var wait sync.WaitGroup
	errorsSeen := make(chan error, writers)
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			event := sampleEvent(fmt.Sprintf("concurrent-%02d", index), fmt.Sprintf("prompt-%02d", index))
			event.UserID = "local-concurrent-user"
			event.UserEmail = "concurrent@example.invalid"
			errorsSeen <- writeLocalEvent(root, event)
		}(index)
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent writeLocalEvent() error = %v", err)
		}
	}
	events, err := readEventsFile(authoritativePath(root, "local-concurrent-user"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != writers {
		t.Fatalf("concurrent durable events = %d, want %d", len(events), writers)
	}
	if _, err := dedupeAndSortChecked(events); err != nil {
		t.Fatalf("concurrent store contains conflicting IDs: %v", err)
	}
}

func TestHistoryImportCorrelatesDirectCapturesOneToOne(t *testing.T) {
	root := t.TempDir()
	userID := "local-test-user"
	base := time.Now().UTC().Add(-time.Minute)
	direct := []model.Event{
		sampleEvent("direct-one", "repeated prompt"),
		sampleEvent("direct-two", "repeated prompt"),
	}
	for index := range direct {
		direct[index].Timestamp = base.Add(time.Duration(index) * 5 * time.Second)
		direct[index].UserID = userID
		direct[index].UserEmail = "tests@example.invalid"
		direct[index].Tool = model.ToolCodex
		direct[index].SessionID = "same-session"
		if err := writeLocalEvent(root, direct[index]); err != nil {
			t.Fatal(err)
		}
	}
	history := []model.Event{direct[0], direct[1]}
	history[0].EventID = "codex-h-first"
	history[1].EventID = "codex-h-second"

	added, err := appendNewLocalEvents(root, userID, history)
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Fatalf("history import added %d duplicate events, want 0", added)
	}
	events, err := readEventsFile(authoritativePath(root, userID))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("one-to-one correlation kept %d events, want both genuine repeats", len(events))
	}
}

func TestHistoryImportPairsRepeatedPromptWithExactDirectTurn(t *testing.T) {
	root := t.TempDir()
	userID := "local-nearest-user"
	base := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	direct := sampleEvent("direct-later-turn", "repeated prompt")
	direct.Timestamp = base.Add(10 * time.Second)
	direct.UserID = userID
	direct.Tool = model.ToolCodex
	direct.SessionID = "same-session"
	if err := writeLocalEvent(root, direct); err != nil {
		t.Fatal(err)
	}
	first := direct
	first.EventID = "codex-h-first-turn"
	first.Timestamp = base
	second := direct
	second.EventID = "codex-h-second-turn"

	added, err := appendNewLocalEvents(root, userID, []model.Event{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("history import added %d events, want the unmatched earlier turn", added)
	}
	events, err := readEventsFile(authoritativePath(root, userID))
	if err != nil {
		t.Fatal(err)
	}
	timestamps := make(map[string]time.Time, len(events))
	for _, event := range events {
		timestamps[event.EventID] = event.Timestamp
	}
	if len(events) != 2 ||
		!timestamps["codex-h-first-turn"].Equal(base) ||
		!timestamps["direct-later-turn"].Equal(base.Add(10*time.Second)) {
		t.Fatalf("exact-turn correlation produced %#v", events)
	}
}

func TestHistoryImportDoesNotFuzzilyCollapseRepeatedPrompt(t *testing.T) {
	root := t.TempDir()
	userID := "local-distinct-repeat-user"
	base := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	direct := sampleEvent("hook-e-direct-repeat", "repeated prompt")
	direct.Timestamp = base.Add(5 * time.Second)
	direct.UserID = userID
	direct.Tool = model.ToolCodex
	direct.SessionID = "same-session"
	if err := writeLocalEvent(root, direct); err != nil {
		t.Fatal(err)
	}
	history := direct
	history.EventID = "codex-h-distinct-repeat"
	history.Timestamp = base.Add(10 * time.Second)

	added, err := appendNewLocalEvents(root, userID, []model.Event{history})
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("history import added %d events, want the distinct repeated turn", added)
	}
	events, err := readEventsFile(authoritativePath(root, userID))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("fuzzy correlation retained %d events, want both genuine repeats", len(events))
	}
}

func TestHistoryImportConsumesConcurrentDirectCaptureOnlyOnceAcrossBatches(t *testing.T) {
	root := t.TempDir()
	userID := "local-concurrent-batch-user"
	base := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	history := make([]model.Event, 100)
	for index := range history {
		history[index] = sampleEvent(fmt.Sprintf("claude-h-batch-%03d", index), "same repeated prompt")
		history[index].UserID = userID
		history[index].UserEmail = "batch@example.invalid"
		history[index].SessionID = "batch-session"
		history[index].Timestamp = base
		if index < 25 {
			history[index].Timestamp = base.Add(-2 * time.Minute)
		}
	}
	importDone := make(chan struct {
		added int
		err   error
	}, 1)
	go func() {
		added, err := appendNewLocalEvents(root, userID, history)
		importDone <- struct {
			added int
			err   error
		}{added: added, err: err}
	}()

	backup := authoritativePath(root, userID)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if info, err := os.Stat(backup); err == nil && info.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first history batch was not persisted")
		}
		time.Sleep(time.Millisecond)
	}
	direct := sampleEvent("hook-e-concurrent-batch", "same repeated prompt")
	direct.UserID = userID
	direct.UserEmail = "batch@example.invalid"
	direct.SessionID = "batch-session"
	direct.Timestamp = base
	if err := writeLocalEvent(root, direct); err != nil {
		t.Fatalf("concurrent direct capture = %v", err)
	}
	result := <-importDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	events, err := readEventsFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	historyCount := 0
	directCount := 0
	for _, event := range events {
		if isHistoryEventID(event.EventID) {
			historyCount++
		}
		if event.EventID == direct.EventID {
			directCount++
		}
	}
	if historyCount != 99 || directCount != 1 || len(events) != 100 || result.added != 99 {
		t.Fatalf(
			"concurrent batch correlation stored history=%d direct=%d total=%d added=%d; want 99/1/100/99",
			historyCount, directCount, len(events), result.added,
		)
	}
}

func TestHistoryIDMigrationDoesNotDuplicateExistingPrompt(t *testing.T) {
	root := t.TempDir()
	userID := "local-history-migration"
	legacy := sampleEvent("codex-h-legacy-ordinal", "prompt from legacy scanner")
	legacy.UserID = userID
	legacy.Tool = model.ToolCodex
	legacy.SessionID = "migration-session"
	if err := writeLocalEvent(root, legacy); err != nil {
		t.Fatal(err)
	}
	migrated := legacy
	migrated.EventID = "codex-h-v2-line"

	added, err := appendNewLocalEvents(root, userID, []model.Event{migrated})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Fatalf("history ID migration added %d duplicate prompts", added)
	}
	events, err := readEventsFile(authoritativePath(root, userID))
	if err != nil || len(events) != 1 || events[0].EventID != legacy.EventID {
		t.Fatalf("history ID migration rewrote authoritative event: %#v, %v", events, err)
	}
}

func TestHistoryIDMigrationReservesExistingExactCandidate(t *testing.T) {
	root := t.TempDir()
	userID := "local-history-exact-priority"
	exact := sampleEvent("codex-h-exact-second", "repeated prompt")
	exact.UserID = userID
	exact.Tool = model.ToolCodex
	exact.SessionID = "migration-session"
	if err := writeLocalEvent(root, exact); err != nil {
		t.Fatal(err)
	}
	first := exact
	first.EventID = "codex-h-distinct-first"
	second := exact

	added, err := appendNewLocalEvents(root, userID, []model.Event{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("history exact-priority import added %d events, want 1", added)
	}
	events, err := readEventsFile(authoritativePath(root, userID))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("history exact-priority import retained %d events, want 2", len(events))
	}
}

func TestHistoryIDMigrationHonorsProviderWideExactReservation(t *testing.T) {
	timestamp := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	exactSecond := model.Event{
		EventID:   "codex-h-exact-second",
		Timestamp: timestamp,
		Tool:      model.ToolCodex,
		SessionID: "session",
		Prompt:    "same prompt",
	}
	distinctFirst := exactSecond
	distinctFirst.EventID = "codex-h-distinct-first"
	matched := correlateHistoryIDMigrationPairs(
		[]model.Event{distinctFirst},
		[]model.Event{exactSecond},
		map[string]bool{exactSecond.EventID: true},
	)
	if len(matched) != 0 {
		t.Fatalf("provider-wide exact reservation matched a distinct candidate: %#v", matched)
	}
}

func TestRecoverySnapshotRevalidationRejectsRemovedDurableEvent(t *testing.T) {
	root := t.TempDir()
	userID := "local-recovery-revalidation"
	event := sampleEvent("codex-h-durable-before-scan", "durable prompt")
	event.UserID = userID
	event.Tool = model.ToolCodex
	event.SessionID = "revalidation-session"
	if err := writeLocalEvent(root, event); err != nil {
		t.Fatal(err)
	}
	existing, used, err := readAuthoritativeRecoverySnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(existing) != 1 || len(used) != 1 {
		t.Fatalf("recovery snapshot = %d events, %d files; want 1, 1", len(existing), len(used))
	}
	transcript := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(transcript, []byte("prompt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := providerScanState{
		Version:            currentProviderScanStateVersion,
		AuthoritativeFiles: cloneAuthoritativeFileState(used),
		Files:              map[string]scanFingerprint{},
		Cursors:            map[string]scanCursor{},
	}
	if err := updateScanState(
		&state,
		model.ToolCodex,
		transcript,
		mustFileIdentity(t, transcript),
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authoritativePath(root, userID), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	safe, err := revalidateScanStateStoreSet(root, used, &state)
	if err != nil {
		t.Fatal(err)
	}
	if safe {
		t.Fatal("revalidation accepted removal of a pre-deduplicated durable event")
	}
	if len(state.Files) != 0 || len(state.Cursors) != 0 {
		t.Fatalf("unsafe revalidation retained provider state: %#v", state)
	}
}

func TestHistoryImportDoesNotReplayOldPromptsAfterIdentityChange(t *testing.T) {
	root := t.TempDir()
	oldUserID := "local-old-identity"
	newUserID := "local-new-identity"
	old := sampleEvent("codex-h-same-session-0", "prompt before identity change")
	old.Timestamp = time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	old.UserID = oldUserID
	old.UserEmail = "old@example.invalid"
	old.Tool = model.ToolCodex
	old.SessionID = "same-session"
	old.Branch = "before"
	old.CommitHash = "old-commit"
	if err := writeLocalEvent(root, old); err != nil {
		t.Fatal(err)
	}

	replayed := old
	replayed.UserID = newUserID
	replayed.UserEmail = "new@example.invalid"
	replayed.Branch = "after"
	replayed.CommitHash = "new-commit"
	fresh := replayed
	fresh.EventID = "codex-h-same-session-1"
	fresh.Timestamp = fresh.Timestamp.Add(time.Minute)
	fresh.Prompt = "prompt after identity change"

	added, err := appendNewLocalEvents(root, newUserID, []model.Event{replayed, fresh})
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("history import added %d events, want only the fresh prompt", added)
	}
	oldEvents, err := readEventsFile(authoritativePath(root, oldUserID))
	if err != nil {
		t.Fatal(err)
	}
	newEvents, err := readEventsFile(authoritativePath(root, newUserID))
	if err != nil {
		t.Fatal(err)
	}
	if len(oldEvents) != 1 || len(newEvents) != 1 || newEvents[0].EventID != fresh.EventID {
		t.Fatalf("identity split stored old=%d new=%v; old prompt was replayed", len(oldEvents), newEvents)
	}
}

func TestHistoryTransformDriftDoesNotBlockLaterPrompts(t *testing.T) {
	root := t.TempDir()
	userID := "local-policy-upgrade"
	original := sampleEvent("codex-h-policy-session-0", "original transformed prompt")
	original.UserID = userID
	original.UserEmail = "policy@example.invalid"
	original.Tool = model.ToolCodex
	original.SessionID = "policy-session"
	if err := writeLocalEvent(root, original); err != nil {
		t.Fatal(err)
	}

	rederived := original
	rederived.Prompt = "[REDACTED BY NEW POLICY]"
	fresh := rederived
	fresh.EventID = "codex-h-policy-session-1"
	fresh.Timestamp = fresh.Timestamp.Add(time.Minute)
	fresh.Prompt = "new prompt after policy upgrade"
	added, err := appendNewLocalEvents(root, userID, []model.Event{rederived, fresh})
	if err != nil {
		t.Fatalf("appendNewLocalEvents() blocked later prompt: %v", err)
	}
	if added != 1 {
		t.Fatalf("appendNewLocalEvents() added %d, want only the new prompt", added)
	}
	events, err := readEventsFile(authoritativePath(root, userID))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Prompt != original.Prompt || events[1].EventID != fresh.EventID {
		t.Fatalf("policy drift result = %#v; authoritative old event or fresh event was lost", events)
	}
	health, err := os.ReadFile(filepath.Join(localStoreDir(root), healthLogFileName))
	if err != nil || !strings.Contains(string(health), "history transform drift") {
		t.Fatalf("health drift signal missing: %v", err)
	}
}

func TestPublishQuarantinesConflictingRegistryAndKeepsAuthoritativePayload(t *testing.T) {
	root := t.TempDir()
	userID := "local-test-user"
	backupEvent := sampleEvent("conflicting-id", "authoritative prompt")
	backupEvent.UserID = userID
	registryEvent := backupEvent
	registryEvent.Prompt = "modified registry prompt"
	if err := os.MkdirAll(localStoreDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(registryDir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path string, event model.Event) {
		t.Helper()
		line, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(authoritativePath(root, userID), backupEvent)
	write(registryPath(root, userID), registryEvent)
	if err := publishRegistryUnlocked(root, userID); err != nil {
		t.Fatalf("publishRegistryUnlocked() error = %v", err)
	}
	events, err := readEventsFile(registryPath(root, userID))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Prompt != backupEvent.Prompt {
		t.Fatalf("rebuilt registry = %#v; want authoritative payload", events)
	}
	matches, err := filepath.Glob(filepath.Join(localStoreDir(root), "quarantine", "*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("registry conflict quarantines = %v, %v; want one", matches, err)
	}
}

func TestPublishQuarantinesRegistryContainingAssistantField(t *testing.T) {
	root := t.TempDir()
	userID := "local-strict-registry"
	event := sampleEvent("strict-registry-event", "authoritative user prompt")
	event.UserID = userID
	if err := os.MkdirAll(localStoreDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(registryDir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authoritativePath(root, userID), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(line, &fields); err != nil {
		t.Fatal(err)
	}
	fields["assistant_response"] = "forbidden response"
	invalid, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath(root, userID), append(invalid, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := publishRegistryUnlocked(root, userID); err != nil {
		t.Fatal(err)
	}
	events, err := readEventsFile(registryPath(root, userID))
	if err != nil || len(events) != 1 || events[0] != event {
		t.Fatalf("strict rebuilt registry = %#v, %v; want authoritative event", events, err)
	}
	matches, err := filepath.Glob(filepath.Join(localStoreDir(root), "quarantine", "*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("invalid registry quarantines = %v, %v; want one", matches, err)
	}
	evidence, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence), "forbidden response") || !strings.Contains(string(evidence), "sha256=") {
		t.Fatalf("invalid-registry evidence retained forbidden content: %q", evidence)
	}
}

func TestPublishSalvagesStrictRowsAroundInvalidRegistryRow(t *testing.T) {
	root := t.TempDir()
	userID := "local-mixed-registry"
	backupEvent := sampleEvent("mixed-backup-event", "authoritative user prompt")
	backupEvent.UserID = userID
	remoteEvent := sampleEvent("mixed-remote-event", "valid remote user prompt")
	remoteEvent.UserID = userID
	remoteEvent.Timestamp = backupEvent.Timestamp.Add(time.Second)

	if err := os.MkdirAll(localStoreDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(registryDir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	backupLine, err := json.Marshal(backupEvent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authoritativePath(root, userID), append(backupLine, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	remoteLine, err := json.Marshal(remoteEvent)
	if err != nil {
		t.Fatal(err)
	}
	const forbidden = "ASSISTANT-ROW-MUST-NOT-BE-PRESERVED"
	invalidLine := []byte(`{"event_id":"invalid","assistant_response":"` + forbidden + `"}`)
	registryContents := append(append(append([]byte{}, remoteLine...), '\n'), invalidLine...)
	registryContents = append(registryContents, '\n')
	if err := os.WriteFile(registryPath(root, userID), registryContents, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := publishRegistryUnlocked(root, userID); err != nil {
		t.Fatal(err)
	}
	events, err := readEventsFile(registryPath(root, userID))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].EventID != backupEvent.EventID || events[1].EventID != remoteEvent.EventID {
		t.Fatalf("salvaged registry = %#v; want authoritative and valid remote events", events)
	}
	matches, err := filepath.Glob(filepath.Join(localStoreDir(root), "quarantine", "*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("invalid registry quarantines = %v, %v; want one digest", matches, err)
	}
	evidence, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence), forbidden) || !strings.Contains(string(evidence), "sha256=") {
		t.Fatalf("invalid-registry evidence retained forbidden content: %q", evidence)
	}
}

func TestPublishSalvagesStrictRowsAroundInvalidAuthoritativeRow(t *testing.T) {
	root := t.TempDir()
	userID := "local-invalid-authoritative"
	first := sampleEvent("authoritative-valid-one", "first valid user prompt")
	first.UserID = userID
	second := sampleEvent("authoritative-valid-two", "second valid user prompt")
	second.UserID = userID
	second.Timestamp = first.Timestamp.Add(time.Second)
	if err := os.MkdirAll(localStoreDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	firstLine, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondLine, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	const forbidden = "AUTHORITATIVE-ASSISTANT-CONTENT-MUST-NOT-SURVIVE"
	invalidLine := []byte(`{"event_id":"invalid","assistant_response":"` + forbidden + `"}`)
	contents := append(append(append(append(append([]byte{}, firstLine...), '\n'), invalidLine...), '\n'), secondLine...)
	contents = append(contents, '\n')
	if err := os.WriteFile(authoritativePath(root, userID), contents, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := publishRegistryUnlocked(root, userID); err != nil {
		t.Fatal(err)
	}
	authoritative, err := readEventsFile(authoritativePath(root, userID))
	if err != nil || len(authoritative) != 2 {
		t.Fatalf("rebuilt authoritative backup = %#v, %v; want two strict rows", authoritative, err)
	}
	registry, err := readEventsFile(registryPath(root, userID))
	if err != nil || len(registry) != 2 {
		t.Fatalf("published registry = %#v, %v; want two strict rows", registry, err)
	}
	matches, err := filepath.Glob(filepath.Join(localStoreDir(root), "quarantine", "*authoritative.digest-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("authoritative quarantines = %v, %v; want one digest", matches, err)
	}
	evidence, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence), forbidden) || !strings.Contains(string(evidence), "sha256=") {
		t.Fatalf("authoritative evidence retained forbidden content: %q", evidence)
	}
}
