package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

func TestCaptureAutomaticallyEnrollsFromGitIdentityWithoutSetup(t *testing.T) {
	const canonicalUserID = "11111111-1111-4111-8111-111111111111"
	var enrollment EnrollmentRequest
	var enrollmentToken string
	var received model.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll":
			authorization := r.Header.Get("Authorization")
			if !strings.HasPrefix(authorization, "Enrollment pa_") {
				t.Errorf("enrollment authorization = %q", authorization)
			}
			enrollmentToken = strings.TrimPrefix(authorization, "Enrollment ")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read enrollment: %v", err)
			}
			if strings.Contains(string(body), enrollmentToken) {
				t.Error("enrollment body persisted the transport token")
			}
			if err := json.Unmarshal(body, &enrollment); err != nil {
				t.Errorf("decode enrollment: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"user_id":"`+canonicalUserID+`"}`)
		case "/api/v1/events":
			if got := r.Header.Get("Authorization"); got != "Bearer "+enrollmentToken {
				t.Errorf("event authorization = %q", got)
			}
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Errorf("decode event: %v", err)
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			writeEventAcknowledgement(w, received.EventID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	repository := newTestRepository(t, server.URL, []string{model.ToolClaudeCode})
	project := setTestProjectAutoEnroll(t, repository, true)
	configDir := useTestConfigDirectory(t)
	payload := claudePayload(t, repository.Nested, "automatic-session", "automatic prompt")

	result, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if !result.Sent || result.Queued {
		t.Fatalf("Capture() result = %#v, want automatically enrolled and sent", result)
	}
	if enrollment.Name != "Prompt Audit Tests" || enrollment.Email != "tests@example.invalid" ||
		enrollment.OrganizationID != compiledOrganizationID {
		t.Fatalf("automatic enrollment identity = %#v", enrollment)
	}
	if !regexp.MustCompile(`^[0-9a-f-]{36}$`).MatchString(enrollment.InstallationID) {
		t.Fatalf("installation_id = %q", enrollment.InstallationID)
	}
	if received.UserID != canonicalUserID || received.UserEmail != enrollment.Email || received.Prompt != "automatic prompt" {
		t.Fatalf("received event identity/prompt = %#v", received)
	}
	cfg, profile, err := loadUserConfigForProject(project)
	if err != nil {
		t.Fatalf("load automatic profile: %v", err)
	}
	if !cfg.enrolled() || cfg.IdentitySource != "git" || cfg.Token != enrollmentToken || profile == "" {
		t.Fatalf("automatic profile = %#v, profile %q", cfg, profile)
	}
	if _, err := os.Stat(filepath.Join(configDir, userConfigFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("automatic enrollment wrote legacy/global config: %v", err)
	}
	queue := openTestProjectQueue(t, project)
	if count, err := queue.Count(); err != nil || count != 0 {
		t.Fatalf("automatic queue count = %d, %v", count, err)
	}
}

func TestCaptureRefusesCredentialStorageInsideRepository(t *testing.T) {
	repository := newTestRepository(t, "http://127.0.0.1:1", []string{model.ToolClaudeCode})
	setTestProjectAutoEnroll(t, repository, true)
	inside := filepath.Join(repository.Root, "accidental credential directory")
	t.Setenv("PROMPT_AUDIT_CONFIG_DIR", inside)
	_, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "session", "must not leak")))
	if err == nil || !strings.Contains(err.Error(), "inside the repository") {
		t.Fatalf("Capture error = %v, want repository credential-storage refusal", err)
	}
	if _, statErr := os.Stat(inside); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("capture created in-repository credential directory: %v", statErr)
	}
}

func TestCaptureRejectsPayloadFromDifferentInvocationRepository(t *testing.T) {
	payloadRepository := newTestRepository(t, "http://127.0.0.1:1", []string{model.ToolClaudeCode})
	payload := claudePayload(t, payloadRepository.Nested, "mismatched-repository", "must stay scoped")
	invocationRepository := newTestRepository(t, "http://127.0.0.1:1", []string{model.ToolClaudeCode})
	t.Setenv(captureRepositoryRootEnv, invocationRepository.Root)

	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload)); err == nil ||
		!strings.Contains(err.Error(), "different repository") {
		t.Fatalf("Capture() error = %v, want repository-context rejection", err)
	}
	if _, err := os.Stat(localStoreDir(payloadRepository.Root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched capture created a local store: %v", err)
	}
}

func TestCaptureAcceptsEscapedPromptWhoseJSONEnvelopeExceedsOneMiB(t *testing.T) {
	repository := newTestRepository(t, "http://127.0.0.1:1", []string{model.ToolCopilotCLI})
	enableTestLocalStore(t, repository)
	prompt := strings.Repeat("\"", 700*1024)
	if len(prompt) >= maxQueuedPromptBytes {
		t.Fatal("test prompt must remain within the stored prompt limit")
	}
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "UserPromptSubmit",
		"session_id":      "escaped-envelope-session",
		"timestamp":       time.Now().UTC().Format(time.RFC3339Nano),
		"cwd":             repository.Nested,
		"prompt":          prompt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= 1024*1024 || len(payload) > maxHookInputBytes {
		t.Fatalf("escaped hook envelope length = %d, want between one MiB and the bounded envelope", len(payload))
	}

	result, err := Capture(model.ToolCopilotCLI, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Capture() rejected escaped in-contract prompt: %v", err)
	}
	if !result.Sent {
		t.Fatalf("Capture() result = %#v, want durable local capture", result)
	}
	events, err := readAllAuthoritativeEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Prompt != prompt {
		t.Fatalf("stored escaped prompt count/length = %d/%d, want 1/%d", len(events), func() int {
			if len(events) == 0 {
				return 0
			}
			return len(events[0].Prompt)
		}(), len(prompt))
	}
}

func TestCaptureRequiresWrapperRepositoryContext(t *testing.T) {
	repository := newTestRepository(t, "http://127.0.0.1:1", []string{model.ToolClaudeCode})
	payload := claudePayload(t, repository.Nested, "missing-context", "must not be captured")
	t.Setenv(captureRepositoryRootEnv, "")

	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload)); err == nil ||
		!strings.Contains(err.Error(), "context is missing") {
		t.Fatalf("Capture() error = %v, want missing-context rejection", err)
	}
}

func TestEnrollmentTransitionKeepsConcurrentEventsDurableAndBindsAtSend(t *testing.T) {
	repository := newTestRepository(t, "http://127.0.0.1:1", []string{model.ToolClaudeCode})
	project := setTestProjectAutoEnroll(t, repository, true)
	useTestConfigDirectory(t)
	pending := UserConfig{
		UserID: "11111111-1111-4111-8111-111111111111", Name: "Pending", Email: "pending@example.invalid",
		ServerURL: project.ServerURL, OrganizationID: project.OrganizationID,
		InstallationID: "33333333-3333-4333-8333-333333333333", EnrollmentState: pendingEnrollmentState,
		Token: "pa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	if _, err := saveUserConfigForProject(project, pending); err != nil {
		t.Fatal(err)
	}
	queue := openTestProjectQueue(t, project)
	enrolled := pending
	enrolled.UserID = "22222222-2222-4222-8222-222222222222"
	enrolled.Email = "enrolled@example.invalid"
	enrolled.EnrollmentState = enrolledEnrollmentState

	start := make(chan struct{})
	errorsFound := make(chan error, 33)
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			event := sampleEvent(fmt.Sprintf("transition-event-%02d", index), "concurrent prompt")
			event.UserID, event.UserEmail = pending.UserID, pending.Email
			errorsFound <- queue.EnqueueBound(event, project)
		}(index)
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		errorsFound <- queue.RebindIdentityAndSave(project, enrolled)
	}()
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count, err := queue.Count(); err != nil || count != 32 {
		t.Fatalf("durable concurrent events = %d, %v; want 32", count, err)
	}
	stored, _, err := loadUserConfigForProject(project)
	if err != nil || stored.UserID != enrolled.UserID || stored.Email != enrolled.Email {
		t.Fatalf("canonical profile = %#v, %v", stored, err)
	}

	var received []model.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		received = append(received, event)
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()
	client, err := NewAPIClient(server.URL, enrolled.Token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	canonicalClient := client.WithEventIdentity(enrolled.UserID, enrolled.Email)
	flushed := 0
	for {
		batch, flushErr := queue.Flush(canonicalClient, 0)
		flushed += batch
		if flushErr != nil {
			t.Fatalf("canonical Flush = %d, %v; want 32, nil", flushed, flushErr)
		}
		pending, countErr := queue.HasPending()
		if countErr != nil {
			t.Fatal(countErr)
		}
		if !pending {
			break
		}
	}
	if flushed != 32 {
		t.Fatalf("canonical Flush = %d; want 32", flushed)
	}
	for _, event := range received {
		if event.UserID != enrolled.UserID || event.UserEmail != enrolled.Email {
			t.Fatalf("transmitted event escaped canonical identity binding: %#v", event)
		}
	}
}

func TestEnrollmentTransitionDoesNotRewriteLargeOfflineBacklog(t *testing.T) {
	repository := newTestRepository(t, "http://127.0.0.1:1", []string{model.ToolClaudeCode})
	project := setTestProjectAutoEnroll(t, repository, true)
	useTestConfigDirectory(t)
	pending := UserConfig{
		UserID: "11111111-1111-4111-8111-111111111111", Name: "Pending", Email: "pending@example.invalid",
		ServerURL: project.ServerURL, OrganizationID: project.OrganizationID,
		InstallationID: "33333333-3333-4333-8333-333333333333", EnrollmentState: pendingEnrollmentState,
		Token: "pa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	if _, err := saveUserConfigForProject(project, pending); err != nil {
		t.Fatal(err)
	}
	queue := openTestProjectQueue(t, project)
	if err := queue.withLock(func() error {
		file, err := os.OpenFile(queue.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(file)
		for index := 0; index < 5_000; index++ {
			event := sampleEvent(fmt.Sprintf("pending-backlog-%05d", index), "offline prompt")
			event.UserID, event.UserEmail = pending.UserID, pending.Email
			if err := encoder.Encode(event); err != nil {
				_ = file.Close()
				return err
			}
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(queue.path)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := pending
	enrolled.UserID = "22222222-2222-4222-8222-222222222222"
	enrolled.Email = "enrolled@example.invalid"
	enrolled.EnrollmentState = enrolledEnrollmentState
	if err := queue.RebindIdentityAndSave(project, enrolled); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(queue.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("enrollment rewrote the offline backlog instead of binding identity at send time")
	}
}

func TestAutomaticEnrollmentCannotOverwriteConcurrentManagedSetup(t *testing.T) {
	const automaticUserID = "22222222-2222-4222-8222-222222222222"
	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		close(requestStarted)
		<-releaseResponse
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"user_id":"`+automaticUserID+`"}`)
	}))
	defer server.Close()
	repository := newTestRepository(t, server.URL, []string{model.ToolCodex})
	project := setTestProjectAutoEnroll(t, repository, true)
	useTestConfigDirectory(t)
	pending := UserConfig{
		UserID: "11111111-1111-4111-8111-111111111111", Name: "Pending", Email: "pending@example.invalid",
		ServerURL: server.URL, OrganizationID: project.OrganizationID,
		InstallationID: "33333333-3333-4333-8333-333333333333", EnrollmentState: pendingEnrollmentState,
		Token: "pa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	if _, err := saveUserConfigForProject(project, pending); err != nil {
		t.Fatal(err)
	}
	queue := openTestProjectQueue(t, project)
	repo, err := DiscoverRepository(repository.Nested)
	if err != nil {
		t.Fatal(err)
	}
	type enrollmentResult struct {
		config UserConfig
		err    error
	}
	done := make(chan enrollmentResult, 1)
	go func() {
		config, err := enrollProfile(repo, queue, pending)
		done <- enrollmentResult{config: config, err: err}
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("automatic enrollment request did not start")
	}
	managed := pending
	managed.UserID = "44444444-4444-4444-8444-444444444444"
	managed.Email = "managed@example.invalid"
	managed.IdentitySource = "manual"
	managed.EnrollmentState = enrolledEnrollmentState
	managed.Token = "managed-registration-token"
	if err := queue.RebindIdentityAndSave(project, managed); err != nil {
		t.Fatal(err)
	}
	close(releaseResponse)
	result := <-done
	if result.err != nil || result.config.Token != managed.Token || result.config.UserID != managed.UserID {
		t.Fatalf("enrollment result overwrote managed setup: %#v, %v", result.config, result.err)
	}
	stored, _, err := loadUserConfigForProject(project)
	if err != nil || stored.Token != managed.Token || stored.UserID != managed.UserID {
		t.Fatalf("stored managed profile = %#v, %v", stored, err)
	}
}

func TestPendingAutomaticEnrollmentRefreshesGitIdentity(t *testing.T) {
	repository := newTestRepository(t, "https://audit.example.invalid", []string{model.ToolCodex})
	project := setTestProjectAutoEnroll(t, repository, true)
	useTestConfigDirectory(t)
	pending := UserConfig{
		UserID: "11111111-1111-4111-8111-111111111111", Name: "Device User",
		Email: "device-0123456789abcdef@prompt-audit.invalid", ServerURL: project.ServerURL,
		OrganizationID: project.OrganizationID, InstallationID: "33333333-3333-4333-8333-333333333333",
		IdentitySource: "device", EnrollmentState: pendingEnrollmentState,
		Token: "pa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	if _, err := saveUserConfigForProject(project, pending); err != nil {
		t.Fatal(err)
	}
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, profile, err := captureProfile(repo)
	if err != nil {
		t.Fatal(err)
	}
	if profile == "" || refreshed.IdentitySource != "git" || refreshed.Email != "tests@example.invalid" {
		t.Fatalf("refreshed identity = %#v, profile=%q", refreshed, profile)
	}
	if refreshed.Token == pending.Token || refreshed.InstallationID == pending.InstallationID || refreshed.UserID == pending.UserID {
		t.Fatalf("refresh did not rotate provisional credentials: %#v", refreshed)
	}
}

func TestPendingIdentityRefreshInvalidatesEnrollmentAlreadyInFlight(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		close(requestStarted)
		<-releaseResponse
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"user_id":"22222222-2222-4222-8222-222222222222"}`)
	}))
	defer server.Close()
	repository := newTestRepository(t, server.URL, []string{model.ToolCodex})
	project := setTestProjectAutoEnroll(t, repository, true)
	useTestConfigDirectory(t)
	pending := UserConfig{
		UserID: "11111111-1111-4111-8111-111111111111", Name: "Device User",
		Email: "device-0123456789abcdef@prompt-audit.invalid", ServerURL: project.ServerURL,
		OrganizationID: project.OrganizationID, InstallationID: "33333333-3333-4333-8333-333333333333",
		IdentitySource: "device", EnrollmentState: pendingEnrollmentState,
		Token: "pa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	if _, err := saveUserConfigForProject(project, pending); err != nil {
		t.Fatal(err)
	}
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	queue := openTestProjectQueue(t, project)
	enrollmentDone := make(chan error, 1)
	go func() {
		_, enrollErr := enrollProfile(repo, queue, pending)
		enrollmentDone <- enrollErr
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("automatic enrollment request did not start")
	}
	refreshed, _, err := captureProfile(repo)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.IdentitySource != "git" || refreshed.Token == pending.Token || refreshed.InstallationID == pending.InstallationID {
		t.Fatalf("pending profile was not refreshed and rotated: %#v", refreshed)
	}
	close(releaseResponse)
	if err := <-enrollmentDone; err == nil {
		t.Fatal("stale in-flight enrollment unexpectedly won the credential CAS")
	}
	stored, _, err := loadUserConfigForProject(project)
	if err != nil || stored.Token != refreshed.Token || stored.enrolled() || stored.Email != "tests@example.invalid" {
		t.Fatalf("stored refreshed profile = %#v, %v", stored, err)
	}
}

func TestFirstAutomaticProfileCannotOverwriteManagedSetup(t *testing.T) {
	repository := newTestRepository(t, "https://audit.example.invalid", []string{model.ToolCodex})
	project := setTestProjectAutoEnroll(t, repository, true)
	useTestConfigDirectory(t)
	repo, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := projectProfileKey(project)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := openQueueForProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		config UserConfig
		err    error
	}
	created := make(chan result, 1)
	managed := UserConfig{
		UserID: "44444444-4444-4444-8444-444444444444", Name: "Managed User",
		Email: "managed@example.invalid", ServerURL: project.ServerURL,
		OrganizationID: project.OrganizationID, InstallationID: "55555555-5555-4555-8555-555555555555",
		IdentitySource: "manual", EnrollmentState: enrolledEnrollmentState,
		Token: "pa_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	}
	if err := queue.withLock(func() error {
		go func() {
			cfg, _, createErr := createPendingProfile(repo)
			created <- result{config: cfg, err: createErr}
		}()
		select {
		case early := <-created:
			return fmt.Errorf("automatic profile bypassed the credential lock: %#v, %v", early.config, early.err)
		case <-time.After(50 * time.Millisecond):
		}
		_, saveErr := saveUserConfigForProject(project, managed)
		return saveErr
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-created:
		if got.err != nil || got.config.Token != managed.Token || !got.config.enrolled() {
			t.Fatalf("automatic profile overwrote managed setup: %#v, %v", got.config, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("automatic profile did not resume after credential lock release")
	}
	stored, _, err := loadUserConfigForProject(project)
	if err != nil || stored.Token != managed.Token || stored.UserID != managed.UserID {
		t.Fatalf("stored managed profile = %#v, %v", stored, err)
	}
}

func TestAutomaticCaptureStaysBoundedWithLargeOfflineBacklog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(acknowledgeEventRequest))
	defer server.Close()
	repository := newTestRepository(t, server.URL, []string{model.ToolClaudeCode})
	configDir := useTestConfigDirectory(t)
	writeTestUserConfig(t, configDir, UserConfig{
		UserID: "worker-backlog", Name: "Backlog Worker", Email: "backlog@example.invalid",
		ServerURL: server.URL, Token: "backlog-token",
	})
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.withLock(func() error {
		file, err := os.OpenFile(queue.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(file)
		for index := 0; index < 2_000; index++ {
			if err := encoder.Encode(sampleEvent(fmt.Sprintf("backlog-%04d", index), "offline prompt")); err != nil {
				_ = file.Close()
				return err
			}
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "backlog-session", "new prompt")))
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2500*time.Millisecond {
		t.Fatalf("capture with 2,000 queued events took %v; hook budget is three seconds", elapsed)
	}
	if result.Sent || !result.Queued {
		t.Fatalf("Capture result = %#v, want current backlog preserved", result)
	}
	if count, err := queue.Count(); err != nil || count != 1_998 {
		t.Fatalf("remaining backlog = %d, %v; want 1,998", count, err)
	}
}

func TestFirstAutomaticCaptureOfflineIsReboundAndRetried(t *testing.T) {
	const canonicalUserID = "22222222-2222-4222-8222-222222222222"
	available := false
	var enrollmentToken string
	var received []model.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll":
			if !available {
				http.Error(w, "offline", http.StatusServiceUnavailable)
				return
			}
			enrollmentToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Enrollment ")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"user_id":"`+canonicalUserID+`"}`)
		case "/api/v1/events":
			if got := r.Header.Get("Authorization"); got != "Bearer "+enrollmentToken {
				t.Errorf("event authorization = %q", got)
			}
			var event model.Event
			if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			received = append(received, event)
			writeEventAcknowledgement(w, event.EventID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	repository := newTestRepository(t, server.URL, []string{model.ToolClaudeCode})
	project := setTestProjectAutoEnroll(t, repository, true)
	useTestConfigDirectory(t)
	first, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "offline-auto", "first offline automatic prompt")))
	if err != nil {
		t.Fatalf("first Capture() error = %v", err)
	}
	if !first.Queued || first.Sent {
		t.Fatalf("first Capture() = %#v, want durable pending event", first)
	}
	queue := openTestProjectQueue(t, project)
	queued := readQueueForTest(t, queue)
	if len(queued) != 1 || queued[0].EventID != first.EventID {
		t.Fatalf("offline automatic queue = %#v", queued)
	}
	provisionalUserID := queued[0].UserID

	available = true
	second, err := Capture(model.ToolClaudeCode, bytes.NewReader(claudePayload(t, repository.Nested, "offline-auto", "second online automatic prompt")))
	if err != nil {
		t.Fatalf("second Capture() error = %v", err)
	}
	if !second.Sent || second.Queued {
		t.Fatalf("second Capture() = %#v, want enrollment and complete flush", second)
	}
	if len(received) != 2 || received[0].EventID != first.EventID || received[1].EventID != second.EventID {
		t.Fatalf("received events = %#v", received)
	}
	for _, event := range received {
		if event.UserID != canonicalUserID || event.UserID == provisionalUserID {
			t.Errorf("event was not rebound to canonical identity: %#v", event)
		}
	}
	if count, err := queue.Count(); err != nil || count != 0 {
		t.Fatalf("queue count after enrollment = %d, %v", count, err)
	}
}

func TestCaptureFromNestedPathWithSpacesSendsOnlyRedactedPrompt(t *testing.T) {
	const (
		transportToken    = "LOCAL-TRANSPORT-TOKEN-MUST-NOT-LEAK"
		promptSecret      = "PROMPT-PASSWORD-MUST-NOT-LEAK"
		assistantSecret   = "ASSISTANT-RESPONSE-MUST-NOT-BE-SENT"
		environmentSecret = "ENVIRONMENT-MUST-NOT-BE-SENT"
	)

	var rawBody []byte
	var received model.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+transportToken {
			t.Errorf("Authorization = %q", got)
		}
		var err error
		rawBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read event: %v", err)
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(rawBody, &received); err != nil {
			t.Errorf("decode event: %v", err)
			http.Error(w, "JSON", http.StatusBadRequest)
			return
		}
		writeEventAcknowledgement(w, received.EventID)
	}))
	defer server.Close()

	repository := newTestRepository(t, server.URL, []string{model.ToolClaudeCode})
	configDir := useTestConfigDirectory(t)
	writeTestUserConfig(t, configDir, UserConfig{
		UserID:    "worker-uuid",
		Name:      "Worker Name",
		Email:     "worker@example.invalid",
		ServerURL: server.URL + "/",
		Token:     transportToken,
	})
	payload, err := json.Marshal(map[string]any{
		"hook_event_name":    "UserPromptSubmit",
		"transcript_path":    filepath.Join(repository.Root, "claude-transcript.jsonl"),
		"permission_mode":    "default",
		"prompt":             "build login; password=" + promptSecret,
		"session_id":         "claude-chat-official-id",
		"cwd":                repository.Nested,
		"response":           assistantSecret,
		"assistant_response": assistantSecret,
		"environment":        map[string]string{"SECRET": environmentSecret},
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
		t.Fatalf("Capture() result = %#v, want sent and not queued", result)
	}
	if result.EventID == "" || result.EventID != received.EventID {
		t.Fatalf("result EventID = %q, received EventID = %q", result.EventID, received.EventID)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(received.EventID) {
		t.Errorf("event_id = %q, want UUID v4", received.EventID)
	}
	if received.Timestamp.IsZero() || time.Since(received.Timestamp) > time.Minute {
		t.Errorf("timestamp = %v, want recent nonzero UTC time", received.Timestamp)
	}
	if received.Timestamp.Location() != time.UTC {
		t.Errorf("timestamp location = %v, want UTC", received.Timestamp.Location())
	}
	if received.UserID != "worker-uuid" || received.UserEmail != "worker@example.invalid" {
		t.Errorf("worker identity = %q <%s>", received.UserID, received.UserEmail)
	}
	if received.Tool != model.ToolClaudeCode {
		t.Errorf("tool = %q", received.Tool)
	}
	if received.RepositoryName != compiledProjectName {
		t.Errorf("repository_name = %q", received.RepositoryName)
	}
	if received.RepositoryRemote != "example.invalid/acme/repository" {
		t.Errorf("repository_remote = %q; want credentials removed", received.RepositoryRemote)
	}
	if received.Branch != repository.Branch || received.CommitHash != repository.CommitHash {
		t.Errorf("Git metadata = branch %q commit %q, want %q %q", received.Branch, received.CommitHash, repository.Branch, repository.CommitHash)
	}
	if received.SessionID != "claude-chat-official-id" {
		t.Errorf("session_id = %q", received.SessionID)
	}
	if !strings.Contains(received.Prompt, "build login") || !strings.Contains(received.Prompt, "[REDACTED]") {
		t.Errorf("redacted prompt = %q", received.Prompt)
	}
	assertTextExcludes(t, string(rawBody), transportToken, promptSecret, assistantSecret, environmentSecret, "remote-user", "remote-password")

	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	if count, err := queue.Count(); err != nil || count != 0 {
		t.Fatalf("queue count = %d, %v; want empty after successful send", count, err)
	}
	if status := runGit(t, repository.Root, "status", "--porcelain"); status != "" {
		t.Fatalf("Capture() modified repository contents: %q", status)
	}
}

func TestCaptureOfflineReturnsSuccessQueuesAndAutomaticallyRetries(t *testing.T) {
	available := false
	var attemptedIDs []string
	var successfulIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		attemptedIDs = append(attemptedIDs, event.EventID)
		if !available {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		successfulIDs = append(successfulIDs, event.EventID)
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()

	repository := newTestRepository(t, server.URL, []string{model.ToolClaudeCode})
	configDir := useTestConfigDirectory(t)
	writeTestUserConfig(t, configDir, UserConfig{
		UserID:    "worker-1",
		Name:      "Worker",
		Email:     "worker@example.invalid",
		ServerURL: server.URL,
		Token:     "transport-token",
	})

	firstPayload := claudePayload(t, repository.Nested, "session-offline", "first offline prompt")
	started := time.Now()
	first, err := Capture(model.ToolClaudeCode, bytes.NewReader(firstPayload))
	if err != nil {
		t.Fatalf("offline Capture() error = %v; hook capture must remain non-blocking", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("offline Capture() took %v, want bounded completion", elapsed)
	}
	if first.EventID == "" || !first.Queued || first.Sent {
		t.Fatalf("offline Capture() result = %#v, want durable queue", first)
	}
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	queued := readQueueForTest(t, queue)
	if len(queued) != 1 || queued[0].EventID != first.EventID {
		t.Fatalf("offline queue = %#v, want event_id %q", queued, first.EventID)
	}

	available = true
	secondPayload := claudePayload(t, repository.Nested, "session-offline", "second online prompt")
	second, err := Capture(model.ToolClaudeCode, bytes.NewReader(secondPayload))
	if err != nil {
		t.Fatalf("online Capture() error = %v", err)
	}
	if !second.Sent || second.Queued {
		t.Fatalf("online Capture() result = %#v, want queue fully flushed", second)
	}
	if second.EventID == first.EventID {
		t.Fatalf("two captures reused event_id %q", first.EventID)
	}
	if count, err := queue.Count(); err != nil || count != 0 {
		t.Fatalf("queue count = %d, %v after automatic retry", count, err)
	}
	wantAttempts := []string{first.EventID, first.EventID, second.EventID}
	if !equalStrings(attemptedIDs, wantAttempts) {
		t.Fatalf("attempted IDs = %v, want %v", attemptedIDs, wantAttempts)
	}
	wantSuccessful := []string{first.EventID, second.EventID}
	if !equalStrings(successfulIDs, wantSuccessful) {
		t.Fatalf("successful IDs = %v, want %v", successfulIDs, wantSuccessful)
	}
}

func TestCaptureFallbackSessionsNeverMixUnknownCopilotChats(t *testing.T) {
	var received []model.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		received = append(received, event)
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()
	repository := newTestRepository(t, server.URL, []string{model.ToolCopilotCLI})
	configDir := useTestConfigDirectory(t)
	writeTestUserConfig(t, configDir, UserConfig{
		UserID:    "worker-1",
		Name:      "Worker",
		Email:     "worker@example.invalid",
		ServerURL: server.URL,
		Token:     "token",
	})

	for _, prompt := range []string{"first unknown chat", "second unknown chat"} {
		payload, err := json.Marshal(map[string]string{"prompt": prompt, "cwd": repository.Nested})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Capture(model.ToolCopilotCLI, bytes.NewReader(payload)); err != nil {
			t.Fatalf("Capture() error = %v", err)
		}
	}
	if len(received) != 2 {
		t.Fatalf("received %d events, want 2", len(received))
	}
	if received[0].SessionID == received[1].SessionID {
		t.Fatalf("fallback session IDs were mixed: %q", received[0].SessionID)
	}
	for _, event := range received {
		want := "fallback:" + model.ToolCopilotCLI + ":" + event.EventID
		if event.SessionID != want {
			t.Errorf("fallback session_id = %q, want %q", event.SessionID, want)
		}
	}
}

func TestCapturePreservesOfficialCopilotSessionIDs(t *testing.T) {
	var received []model.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		received = append(received, event)
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()
	repository := newTestRepository(t, server.URL, []string{model.ToolCopilotCLI})
	configDir := useTestConfigDirectory(t)
	writeTestUserConfig(t, configDir, UserConfig{
		UserID:    "worker-copilot",
		Name:      "Copilot Worker",
		Email:     "copilot@example.invalid",
		ServerURL: server.URL,
		Token:     "token",
	})

	for index, sessionID := range []string{"official-chat-a", "official-chat-a", "official-chat-b"} {
		payload, err := json.Marshal(map[string]string{
			"prompt":    fmt.Sprintf("prompt %d", index),
			"sessionId": sessionID,
			"cwd":       repository.Nested,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Capture(model.ToolCopilotCLI, bytes.NewReader(payload)); err != nil {
			t.Fatalf("Capture() error = %v", err)
		}
	}
	if len(received) != 3 {
		t.Fatalf("received %d events, want 3", len(received))
	}
	if received[0].SessionID != "official-chat-a" || received[1].SessionID != "official-chat-a" {
		t.Errorf("same official chat was not preserved: %q, %q", received[0].SessionID, received[1].SessionID)
	}
	if received[2].SessionID != "official-chat-b" || received[2].SessionID == received[0].SessionID {
		t.Errorf("different official chat was mixed: %#v", received)
	}
	for _, event := range received {
		if event.Tool != model.ToolCopilotCLI {
			t.Errorf("tool = %q, want %q", event.Tool, model.ToolCopilotCLI)
		}
	}
}

func TestCaptureRejectsResponseEventsWithoutWritingQueue(t *testing.T) {
	configDir := useTestConfigDirectory(t)
	t.Setenv("CLAUDE_PROJECT_DIR", "")
	response := []byte(`{"hook_event_name":"Stop","response":"assistant-only-secret","prompt":"not a user event"}`)
	_, err := Capture(model.ToolClaudeCode, bytes.NewReader(response))
	if !errors.Is(err, ErrNotUserPrompt) {
		t.Fatalf("Capture(response event) error = %v, want ErrNotUserPrompt", err)
	}
	if strings.Contains(err.Error(), "assistant-only-secret") || strings.Contains(err.Error(), "not a user event") {
		t.Fatalf("Capture() leaked rejected content: %v", err)
	}
	if _, statErr := osStatQueue(configDir); statErr == nil {
		t.Fatal("response event created a queue file")
	}
}

func TestCaptureClaudeSchemaDriftFailsClosedWithProjectContext(t *testing.T) {
	repository := newTestRepository(t, "http://127.0.0.1:1", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	t.Setenv("CLAUDE_PROJECT_DIR", repository.Root)
	payload, err := json.Marshal(map[string]string{
		"hook_event_name": "UserPromptSubmit",
		"prompt":          "must fail closed instead of disappearing",
		"session_id":      "schema-drift-session",
		"cwd":             repository.Nested,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload)); err == nil ||
		errors.Is(err, ErrNotUserPrompt) ||
		!strings.Contains(err.Error(), "supported UserPromptSubmit schema") {
		t.Fatalf("Capture() with Claude schema drift = %v, want blocking integration error", err)
	}
	events, err := readAllAuthoritativeEvents(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("schema-drift rejection stored %d events, want none", len(events))
	}
}

func TestCaptureClaudeKnownSubagentRemainsIgnoredWithProjectContext(t *testing.T) {
	repository := newTestRepository(t, "http://127.0.0.1:1", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	t.Setenv("CLAUDE_PROJECT_DIR", repository.Root)
	payload, err := json.Marshal(map[string]string{
		"hook_event_name": "UserPromptSubmit",
		"transcript_path": filepath.Join(repository.Root, "subagent.jsonl"),
		"permission_mode": "default",
		"agent_id":        "child",
		"prompt":          "internal delegated prompt",
		"session_id":      "subagent-session",
		"cwd":             repository.Nested,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(model.ToolClaudeCode, bytes.NewReader(payload)); !errors.Is(err, ErrNotUserPrompt) {
		t.Fatalf("Capture() known Claude subagent = %v, want ErrNotUserPrompt", err)
	}
}

func TestCaptureRejectsOversizedHookInputWithoutEchoingIt(t *testing.T) {
	const secret = "OVERSIZED-SECRET-MUST-NOT-LEAK"
	input := strings.Repeat("x", maxHookInputBytes) + secret
	_, err := Capture(model.ToolClaudeCode, strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "exceeds 8 MiB") {
		t.Fatalf("Capture(oversized) error = %v", err)
	}
	assertTextExcludes(t, err.Error(), secret)
}

func TestCaptureRejectsServerMismatchWithoutLeakingPromptOrToken(t *testing.T) {
	repository := newTestRepository(t, "https://project.example.invalid", []string{model.ToolClaudeCode})
	configDir := useTestConfigDirectory(t)
	project, err := loadProjectConfig(repository.Root)
	if err != nil {
		t.Fatalf("load project configuration: %v", err)
	}
	profile, err := projectProfileKey(project)
	if err != nil {
		t.Fatalf("project profile key: %v", err)
	}
	const (
		token  = "MISMATCH-TOKEN-MUST-NOT-LEAK"
		prompt = "MISMATCH-PROMPT-MUST-NOT-LEAK"
	)
	// A mismatched v0.1 global credential is intentionally ignored by the
	// project-profile isolation layer. Put the malformed credential in this
	// project's profile so this test reaches the mismatch validator it targets.
	writeTestUserConfig(t, filepath.Join(configDir, profilesDirectory, profile), UserConfig{
		UserID:         "worker-1",
		Name:           "Worker",
		Email:          "worker@example.invalid",
		ServerURL:      "https://different.example.invalid",
		OrganizationID: project.OrganizationID,
		Token:          token,
	})
	payload := claudePayload(t, repository.Nested, "session", prompt)
	_, err = Capture(model.ToolClaudeCode, bytes.NewReader(payload))
	if err == nil || !strings.Contains(err.Error(), "server URLs do not match") {
		t.Fatalf("Capture() error = %v, want server mismatch", err)
	}
	assertTextExcludes(t, err.Error(), token, prompt)
}

func claudePayload(t *testing.T, cwd, sessionID, prompt string) []byte {
	t.Helper()
	repositoryRoot, err := gitOutput(cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatalf("discover Claude test project: %v", err)
	}
	t.Setenv("CLAUDE_PROJECT_DIR", repositoryRoot)
	payload, err := json.Marshal(map[string]string{
		"hook_event_name": "UserPromptSubmit",
		"transcript_path": filepath.Join(cwd, "claude-transcript.jsonl"),
		"permission_mode": "default",
		"prompt":          prompt,
		"session_id":      sessionID,
		"cwd":             cwd,
	})
	if err != nil {
		t.Fatalf("encode Claude payload: %v", err)
	}
	return payload
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func osStatQueue(configDir string) (bool, error) {
	_, err := os.Stat(filepath.Join(configDir, "queue", "events.jsonl"))
	return err == nil, err
}
