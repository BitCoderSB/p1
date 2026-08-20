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
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

func TestQueueOfflineRetryPreservesEventIDAndPayload(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatalf("OpenQueue() error = %v", err)
	}
	event := sampleEvent("stable-event-id", "redacted prompt")
	if err := queue.Enqueue(event); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	var mu sync.Mutex
	available := false
	var attempts []model.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var received model.Event
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "bad JSON", http.StatusBadRequest)
			return
		}
		mu.Lock()
		attempts = append(attempts, received)
		isAvailable := available
		mu.Unlock()
		if !isAvailable {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		writeEventAcknowledgement(w, received.EventID)
	}))
	defer server.Close()
	client, err := NewAPIClient(server.URL, "transport-token", time.Second)
	if err != nil {
		t.Fatalf("NewAPIClient() error = %v", err)
	}

	flushed, err := queue.Flush(client, 0)
	if err == nil {
		t.Fatal("offline Flush() error = nil, want delivery error")
	}
	if flushed != 0 {
		t.Fatalf("offline Flush() flushed = %d, want 0", flushed)
	}
	queued := readQueueForTest(t, queue)
	if !reflect.DeepEqual(queued, []model.Event{event}) {
		t.Fatalf("queue after failed delivery = %#v, want original %#v", queued, event)
	}

	mu.Lock()
	available = true
	mu.Unlock()
	flushed, err = queue.Flush(client, 0)
	if err != nil {
		t.Fatalf("retry Flush() error = %v", err)
	}
	if flushed != 1 {
		t.Fatalf("retry Flush() flushed = %d, want 1", flushed)
	}
	if count, err := queue.Count(); err != nil || count != 0 {
		t.Fatalf("Count() = %d, %v; want 0, nil", count, err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(attempts) != 2 {
		t.Fatalf("delivery attempts = %d, want 2", len(attempts))
	}
	for index, attempt := range attempts {
		if !reflect.DeepEqual(attempt, event) {
			t.Errorf("attempt %d changed queued event: %#v, want %#v", index, attempt, event)
		}
	}
}

func TestQueueStopsAtFirstFailureAndKeepsOrder(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	events := []model.Event{
		sampleEvent("event-1", "first"),
		sampleEvent("event-2", "second"),
		sampleEvent("event-3", "third"),
	}
	for _, event := range events {
		if err := queue.Enqueue(event); err != nil {
			t.Fatal(err)
		}
	}

	failSecond := true
	var delivered []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		delivered = append(delivered, event.EventID)
		if failSecond && event.EventID == "event-2" {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()
	client, err := NewAPIClient(server.URL, "token", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	flushed, err := queue.Flush(client, 0)
	if err == nil || flushed != 1 {
		t.Fatalf("first Flush() = (%d, %v), want (1, error)", flushed, err)
	}
	remaining := readQueueForTest(t, queue)
	if got := eventIDs(remaining); !reflect.DeepEqual(got, []string{"event-2", "event-3"}) {
		t.Fatalf("remaining IDs = %v, want [event-2 event-3]", got)
	}

	failSecond = false
	flushed, err = queue.Flush(client, 0)
	if err != nil || flushed != 2 {
		t.Fatalf("retry Flush() = (%d, %v), want (2, nil)", flushed, err)
	}
	wantDelivered := []string{"event-1", "event-2", "event-2", "event-3"}
	if !reflect.DeepEqual(delivered, wantDelivered) {
		t.Fatalf("delivery order = %v, want %v", delivered, wantDelivered)
	}
}

func TestQueueFlushHonorsLimit(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 3; index++ {
		if err := queue.Enqueue(sampleEvent(fmt.Sprintf("event-%d", index), "prompt")); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(acknowledgeEventRequest))
	defer server.Close()
	client, err := NewAPIClient(server.URL, "token", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	flushed, err := queue.Flush(client, 2)
	if err != nil || flushed != 2 {
		t.Fatalf("Flush(limit=2) = (%d, %v), want (2, nil)", flushed, err)
	}
	if got := eventIDs(readQueueForTest(t, queue)); !reflect.DeepEqual(got, []string{"event-3"}) {
		t.Fatalf("remaining IDs = %v, want [event-3]", got)
	}
}

func TestQueuePreservesPermanentRejectionWithoutBlockingLaterEvents(t *testing.T) {
	configDir := useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	rejected := sampleEvent("event-invalid-for-server", "prompt preserved locally")
	accepted := sampleEvent("event-valid-for-server", "later prompt")
	if err := queue.Enqueue(rejected); err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(accepted); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		if event.EventID == rejected.EventID {
			http.Error(w, "validation", http.StatusUnprocessableEntity)
			return
		}
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()
	client, err := NewAPIClient(server.URL, "transport-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	flushed, err := queue.Flush(client, 0)
	if err == nil || flushed != 1 {
		t.Fatalf("Flush = (%d, %v), want one accepted plus rejection report", flushed, err)
	}
	if count, countErr := queue.Count(); countErr != nil || count != 0 {
		t.Fatalf("pending count = %d, %v", count, countErr)
	}
	if count, countErr := queue.RejectedCount(); countErr != nil || count != 1 {
		t.Fatalf("rejected count = %d, %v", count, countErr)
	}
	contents, readErr := os.ReadFile(filepath.Join(configDir, "queue", "rejected.jsonl"))
	if readErr != nil || !strings.Contains(string(contents), rejected.Prompt) {
		t.Fatalf("rejected queue did not preserve prompt: %q, %v", contents, readErr)
	}
	assertTextExcludes(t, string(contents), "transport-token")
}

func TestRetryRejectedRecoversAnOrphanedEventMarker(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	event := sampleEvent("orphaned-marker-event", "must survive crash recovery")
	if err := queue.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	if err := queue.withLock(func() error {
		if err := queue.appendRejectedUnlocked([]rejectedEvent{{
			Event: event, HTTPStatus: http.StatusUnprocessableEntity, RejectedAt: time.Now().UTC(),
		}}); err != nil {
			return err
		}
		// Simulate termination after the main queue was advanced/truncated but
		// before the old marker could be removed.
		return os.Truncate(queue.path, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if retried, err := queue.RetryRejected(); err != nil || retried != 1 {
		t.Fatalf("RetryRejected = %d, %v; want 1, nil", retried, err)
	}
	if got := eventIDs(readQueueForTest(t, queue)); !reflect.DeepEqual(got, []string{event.EventID}) {
		t.Fatalf("recovered queue IDs = %v, want %q", got, event.EventID)
	}
	if rejected, err := queue.RejectedCount(); err != nil || rejected != 0 {
		t.Fatalf("rejected count = %d, %v; want 0, nil", rejected, err)
	}
}

func TestRetryRejectedRepairsPartialMainQueueBeforeMovingOnlyCopy(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatalf("OpenQueue() error = %v", err)
	}
	event := sampleEvent("retry-after-partial-main", "must remain durable")
	if err := queue.withLock(func() error {
		return queue.appendRejectedUnlocked([]rejectedEvent{{
			Event: event, HTTPStatus: http.StatusUnprocessableEntity, RejectedAt: time.Now().UTC(),
		}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queue.path, []byte(`{"event_id":"interrupted`), 0o600); err != nil {
		t.Fatal(err)
	}

	retried, err := queue.RetryRejected()
	if err != nil || retried != 1 {
		t.Fatalf("RetryRejected() = %d, %v; want 1, nil", retried, err)
	}
	queued := readQueueForTest(t, queue)
	if !reflect.DeepEqual(queued, []model.Event{event}) {
		t.Fatalf("queue after repair = %#v, want the rejected event", queued)
	}
	if rejected, err := queue.RejectedCount(); err != nil || rejected != 0 {
		t.Fatalf("RejectedCount() = %d, %v; want 0, nil", rejected, err)
	}
	matches, err := filepath.Glob(queue.path + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("main-queue quarantines = %v, %v; want one", matches, err)
	}
}

func TestRejectedCountRepairsPartialTailWithoutDroppingValidRows(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatalf("OpenQueue() error = %v", err)
	}
	event := sampleEvent("valid-rejected-before-partial", "valid rejected prompt")
	if err := queue.withLock(func() error {
		return queue.appendRejectedUnlocked([]rejectedEvent{{
			Event: event, HTTPStatus: http.StatusUnprocessableEntity, RejectedAt: time.Now().UTC(),
		}})
	}); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(queue.rejectedPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"event":`); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if count, err := queue.RejectedCount(); err != nil || count != 1 {
		t.Fatalf("RejectedCount() = %d, %v; want 1, nil", count, err)
	}
	matches, err := filepath.Glob(queue.rejectedPath + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("rejected-queue quarantines = %v, %v; want one", matches, err)
	}
}

func TestQueueSalvagesValidRowsAroundCompleteInvalidRow(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	first := sampleEvent("strict-queue-first", "first queued user prompt")
	second := sampleEvent("strict-queue-second", "second queued user prompt")
	second.Timestamp = first.Timestamp.Add(time.Second)
	firstLine, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondLine, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	const forbidden = "QUEUE-ASSISTANT-RESPONSE-MUST-NOT-SURVIVE"
	invalidLine := []byte(`{"event_id":"invalid","assistant_response":"` + forbidden + `"}`)
	contents := append(append(append(append(append([]byte{}, firstLine...), '\n'), invalidLine...), '\n'), secondLine...)
	contents = append(contents, '\n')
	if err := os.WriteFile(queue.path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	if count, err := queue.Count(); err != nil || count != 2 {
		t.Fatalf("Count after strict salvage = %d, %v; want 2, nil", count, err)
	}
	raw, err := os.ReadFile(queue.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), forbidden) {
		t.Fatal("strict queue salvage retained an assistant response field")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(queue.path), ".corrupt-events.jsonl-*.digest"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("queue digest evidence = %v, %v; want one", matches, err)
	}
	evidence, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence), forbidden) || !strings.Contains(string(evidence), "sha256=") {
		t.Fatalf("queue digest leaked invalid payload: %q", evidence)
	}
}

func TestQueueSalvagesValidRowsAroundOversizedInvalidRow(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	first := sampleEvent("oversized-queue-first", "first queued prompt")
	second := sampleEvent("oversized-queue-second", "second queued prompt")
	second.Timestamp = first.Timestamp.Add(time.Second)
	firstLine, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondLine, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	const forbidden = "OVERSIZED-QUEUE-ASSISTANT-MUST-NOT-SURVIVE"
	invalidLine := append([]byte(`{"assistant_response":"`+forbidden), bytes.Repeat([]byte("x"), 8*1024*1024+1)...)
	invalidLine = append(invalidLine, []byte(`"}`)...)
	contents := make([]byte, 0, len(firstLine)+len(invalidLine)+len(secondLine)+3)
	contents = append(contents, firstLine...)
	contents = append(contents, '\n')
	contents = append(contents, invalidLine...)
	contents = append(contents, '\n')
	contents = append(contents, secondLine...)
	contents = append(contents, '\n')
	if err := os.WriteFile(queue.path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	if count, err := queue.Count(); err != nil || count != 2 {
		t.Fatalf("Count after oversized strict salvage = %d, %v; want 2, nil", count, err)
	}
	raw, err := os.ReadFile(queue.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), forbidden) {
		t.Fatal("oversized queue salvage retained an assistant response field")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(queue.path), ".corrupt-events.jsonl-*.digest"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("oversized queue digest evidence = %v, %v; want one", matches, err)
	}
	evidence, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence), forbidden) || !strings.Contains(string(evidence), "sha256=") {
		t.Fatalf("oversized queue digest leaked invalid payload: %q", evidence)
	}
}

func TestRejectedQueueSalvagesValidRowsAroundCompleteInvalidRow(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	first := rejectedEvent{
		Event:      sampleEvent("strict-rejected-first", "first rejected user prompt"),
		HTTPStatus: http.StatusUnprocessableEntity, RejectedAt: time.Now().UTC(),
	}
	second := rejectedEvent{
		Event:      sampleEvent("strict-rejected-second", "second rejected user prompt"),
		HTTPStatus: http.StatusUnprocessableEntity, RejectedAt: time.Now().UTC(),
	}
	firstLine, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondLine, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	const forbidden = "REJECTED-ASSISTANT-RESPONSE-MUST-NOT-SURVIVE"
	invalidLine := []byte(`{"event":{"assistant_response":"` + forbidden + `"}}`)
	contents := append(append(append(append(append([]byte{}, firstLine...), '\n'), invalidLine...), '\n'), secondLine...)
	contents = append(contents, '\n')
	if err := os.WriteFile(queue.rejectedPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	if count, err := queue.RejectedCount(); err != nil || count != 2 {
		t.Fatalf("RejectedCount after strict salvage = %d, %v; want 2, nil", count, err)
	}
	raw, err := os.ReadFile(queue.rejectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), forbidden) {
		t.Fatal("strict rejected-queue salvage retained an assistant response field")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(queue.rejectedPath), ".corrupt-rejected.jsonl-*.digest"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("rejected queue digest evidence = %v, %v; want one", matches, err)
	}
}

func TestQueueResetsImpossibleCursorConservatively(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	event := sampleEvent("cursor-recovery-event", "prompt behind impossible cursor")
	if err := queue.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queue.cursorPath, []byte("999999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if count, err := queue.Count(); err != nil || count != 1 {
		t.Fatalf("Count after impossible cursor = %d, %v; want 1, nil", count, err)
	}
	if _, err := os.Stat(queue.cursorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("impossible cursor still exists: %v", err)
	}
}

func TestQueueResetsCursorInsideJSONRecord(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	event := sampleEvent("cursor-middle-event", "prompt behind mid-record cursor")
	if err := queue.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queue.cursorPath, []byte("5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if count, err := queue.Count(); err != nil || count != 1 {
		t.Fatalf("Count after mid-record cursor = %d, %v; want 1, nil", count, err)
	}
	if _, err := os.Stat(queue.cursorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mid-record cursor still exists: %v", err)
	}
}

func TestRetryRejectedReleasesEnqueueLockBetweenEvents(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	items := make([]rejectedEvent, 500)
	for index := range items {
		items[index] = rejectedEvent{
			Event:      sampleEvent(fmt.Sprintf("rejected-backlog-%04d", index), "rejected prompt"),
			HTTPStatus: http.StatusUnprocessableEntity, RejectedAt: time.Now().UTC(),
		}
	}
	if err := queue.withLock(func() error { return queue.appendRejectedUnlocked(items) }); err != nil {
		t.Fatal(err)
	}
	retryDone := make(chan error, 1)
	go func() {
		_, retryErr := queue.RetryRejected()
		retryDone <- retryErr
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if info, statErr := os.Stat(queue.path); statErr == nil && info.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rejected retry did not begin")
		}
		time.Sleep(time.Millisecond)
	}
	if err := queue.Enqueue(sampleEvent("live-capture", "live prompt")); err != nil {
		t.Fatalf("concurrent live enqueue was lost: %v", err)
	}
	if err := <-retryDone; err != nil {
		t.Fatal(err)
	}
	if count, err := queue.Count(); err != nil || count != 501 {
		t.Fatalf("queue count = %d, %v; want 501", count, err)
	}
}

func TestRetryRejectedKeepsLargeBacklogFromBlockingLiveCapture(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	const pendingEvents = 2_000
	if err := queue.withLock(func() error {
		file, err := os.OpenFile(queue.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(file)
		for index := 0; index < pendingEvents; index++ {
			if err := encoder.Encode(sampleEvent(fmt.Sprintf("pending-%05d", index), strings.Repeat("p", 512))); err != nil {
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
	largeRejected := make([]rejectedEvent, 6)
	for index := range largeRejected {
		largeRejected[index] = rejectedEvent{
			Event:      sampleEvent(fmt.Sprintf("large-rejected-%02d", index), strings.Repeat("\x00", 400_000)),
			HTTPStatus: http.StatusUnprocessableEntity, RejectedAt: time.Now().UTC(),
		}
	}
	if err := queue.withLock(func() error { return queue.appendRejectedUnlocked(largeRejected) }); err != nil {
		t.Fatal(err)
	}
	initial, err := os.Stat(queue.path)
	if err != nil {
		t.Fatal(err)
	}
	retryDone := make(chan error, 1)
	go func() {
		_, retryErr := queue.RetryRejected()
		retryDone <- retryErr
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		info, statErr := os.Stat(queue.path)
		if statErr == nil && info.Size() > initial.Size() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("large rejected retry did not begin")
		}
		time.Sleep(time.Millisecond)
	}
	if err := queue.Enqueue(sampleEvent("live-during-large-retry", "live prompt")); err != nil {
		t.Fatalf("live capture was blocked by rejected retry: %v", err)
	}
	if err := <-retryDone; err != nil {
		t.Fatal(err)
	}
	if count, err := queue.Count(); err != nil || count != pendingEvents+len(largeRejected)+1 {
		t.Fatalf("queue count = %d, %v", count, err)
	}
}

func TestQueueCanReadWorstCaseEscapedHookPayload(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	event := sampleEvent("large-escaped-event", strings.Repeat("\x00", 400_000))
	if err := queue.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	if count, err := queue.Count(); err != nil || count != 1 {
		t.Fatalf("Count = %d, %v; queue line exceeds legacy 2 MiB scanner limit", count, err)
	}
}

func TestQueueFlushDoesNotBlockConcurrentDurableEnqueue(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	first := sampleEvent("event-being-sent", "first")
	second := sampleEvent("event-enqueued-concurrently", "second")
	if err := queue.Enqueue(first); err != nil {
		t.Fatal(err)
	}

	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		close(requestStarted)
		<-releaseRequest
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()
	client, err := NewAPIClient(server.URL, "token", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	flushDone := make(chan error, 1)
	go func() {
		_, flushErr := queue.Flush(client, 1)
		flushDone <- flushErr
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("flush did not start its request")
	}

	enqueueDone := make(chan error, 1)
	go func() { enqueueDone <- queue.Enqueue(second) }()
	select {
	case err := <-enqueueDone:
		if err != nil {
			t.Fatalf("concurrent enqueue: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("network delivery held the queue lock")
	}
	close(releaseRequest)
	if err := <-flushDone; err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got := eventIDs(readQueueForTest(t, queue)); !reflect.DeepEqual(got, []string{second.EventID}) {
		t.Fatalf("remaining IDs = %v, want only concurrent event", got)
	}
}

func TestConcurrentFlushesAreSerializedAndAdvanceDistinctEvents(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	first := sampleEvent("concurrent-flush-first", "first")
	second := sampleEvent("concurrent-flush-second", "second")
	if err := queue.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(second); err != nil {
		t.Fatal(err)
	}
	requests := make(chan string, 2)
	releaseFirst := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		requests <- event.EventID
		if event.EventID == first.EventID {
			<-releaseFirst
		}
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()
	client, err := NewAPIClient(server.URL, "token", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	type flushResult struct {
		flushed int
		err     error
	}
	firstDone := make(chan flushResult, 1)
	go func() {
		flushed, flushErr := queue.Flush(client, 1)
		firstDone <- flushResult{flushed: flushed, err: flushErr}
	}()
	select {
	case id := <-requests:
		if id != first.EventID {
			t.Fatalf("first request event = %q, want %q", id, first.EventID)
		}
	case <-time.After(time.Second):
		t.Fatal("first flush did not reach server")
	}

	secondStarted := make(chan struct{})
	secondDone := make(chan flushResult, 1)
	go func() {
		close(secondStarted)
		flushed, flushErr := queue.Flush(client, 1)
		secondDone <- flushResult{flushed: flushed, err: flushErr}
	}()
	<-secondStarted
	select {
	case id := <-requests:
		t.Fatalf("second Flush reached server with event %q before first Flush completed", id)
	case result := <-secondDone:
		t.Fatalf("second Flush returned before first Flush completed: %#v", result)
	case <-time.After(100 * time.Millisecond):
		// Release well before the 750 ms flush-lock deadline.
	}
	close(releaseFirst)
	select {
	case result := <-firstDone:
		if result.err != nil || result.flushed != 1 {
			t.Fatalf("first Flush = (%d, %v), want (1, nil)", result.flushed, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("first Flush did not finish")
	}
	select {
	case id := <-requests:
		if id != second.EventID {
			t.Fatalf("second request event = %q, want %q", id, second.EventID)
		}
	case <-time.After(time.Second):
		t.Fatal("second Flush did not reach server after first completed")
	}
	select {
	case result := <-secondDone:
		if result.err != nil || result.flushed != 1 {
			t.Fatalf("second Flush = (%d, %v), want (1, nil)", result.flushed, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Flush did not finish")
	}
	if got := eventIDs(readQueueForTest(t, queue)); len(got) != 0 {
		t.Fatalf("remaining IDs = %v, want empty queue", got)
	}
}

func TestFlushCommandSemanticsUseConfiguredCredentials(t *testing.T) {
	configDir := useTestConfigDirectory(t)
	const token = "flush-transport-token"
	var authorization string
	var receivedID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		receivedID = event.EventID
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()
	writeTestUserConfig(t, configDir, UserConfig{
		UserID:    "worker-flush",
		Name:      "Flush Worker",
		Email:     "flush@example.invalid",
		ServerURL: server.URL,
		Token:     token,
	})
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(sampleEvent("event-explicit-flush", "queued prompt")); err != nil {
		t.Fatal(err)
	}

	flushed, remaining, rejected, err := Flush()
	if err != nil || flushed != 1 || remaining != 0 || rejected != 0 {
		t.Fatalf("Flush() = (%d, %d, %d, %v), want (1, 0, 0, nil)", flushed, remaining, rejected, err)
	}
	if receivedID != "event-explicit-flush" {
		t.Errorf("received event ID = %q", receivedID)
	}
	if authorization != "Bearer "+token {
		t.Errorf("Authorization = %q", authorization)
	}
}

func TestFlushCommandDrainsBacklogAcrossBoundedBatches(t *testing.T) {
	configDir := useTestConfigDirectory(t)
	server := httptest.NewServer(http.HandlerFunc(acknowledgeEventRequest))
	defer server.Close()
	writeTestUserConfig(t, configDir, UserConfig{
		UserID: "worker-flush", Name: "Flush Worker", Email: "flush@example.invalid",
		ServerURL: server.URL, Token: "flush-transport-token",
	})
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxExplicitFlushBatch*3+1; index++ {
		if err := queue.Enqueue(sampleEvent(fmt.Sprintf("bounded-flush-%03d", index), "queued prompt")); err != nil {
			t.Fatal(err)
		}
	}
	flushed, remaining, rejected, err := Flush()
	if err != nil || flushed != maxExplicitFlushBatch*3+1 || remaining != 0 || rejected != 0 {
		t.Fatalf("Flush = (%d, %d, %d, %v)", flushed, remaining, rejected, err)
	}
}

func TestFlushDrainsLegacyQueueAlongsideProjectProfile(t *testing.T) {
	const legacyToken = "legacy-upgrade-token"
	var received []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+legacyToken && r.Header.Get("Authorization") != "Bearer profile-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var event model.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		received = append(received, event.EventID)
		writeEventAcknowledgement(w, event.EventID)
	}))
	defer server.Close()
	repository := newTestRepository(t, server.URL, []string{model.ToolClaudeCode})
	project := setTestProjectAutoEnroll(t, repository, true)
	configDir := useTestConfigDirectory(t)
	writeTestUserConfig(t, configDir, UserConfig{
		UserID: "legacy-worker", Name: "Legacy", Email: "legacy@example.invalid",
		ServerURL: server.URL, Token: legacyToken,
	})
	legacyQueue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	if err := legacyQueue.Enqueue(sampleEvent("legacy-pending-event", "upgrade prompt")); err != nil {
		t.Fatal(err)
	}
	if _, err := saveUserConfigForProject(project, UserConfig{
		UserID: "11111111-1111-4111-8111-111111111111", Name: "Profile", Email: "profile@example.invalid",
		ServerURL: server.URL, OrganizationID: project.OrganizationID,
		EnrollmentState: enrolledEnrollmentState, Token: "profile-token",
	}); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repository.Nested)
	flushed, remaining, rejected, err := Flush()
	if err != nil || flushed != 1 || remaining != 0 || rejected != 0 {
		t.Fatalf("Flush = (%d, %d, %d, %v), want legacy queue drained", flushed, remaining, rejected, err)
	}
	if !reflect.DeepEqual(received, []string{"legacy-pending-event"}) {
		t.Fatalf("received IDs = %v", received)
	}
}

func TestQueueDeduplicatesEventID(t *testing.T) {
	useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	original := sampleEvent("same-event-id", "original prompt")
	if err := queue.Enqueue(original); err != nil {
		t.Fatal(err)
	}
	duplicate := sampleEvent("same-event-id", "duplicate must not replace the original")
	if err := queue.Enqueue(duplicate); err != nil {
		t.Fatal(err)
	}

	queued := readQueueForTest(t, queue)
	if len(queued) != 1 {
		t.Fatalf("queue contains %d copies of event_id %q, want 1", len(queued), original.EventID)
	}
	if !reflect.DeepEqual(queued[0], original) {
		t.Fatalf("duplicate enqueue changed original event: %#v, want %#v", queued[0], original)
	}
}

func TestAPIClientSendsNarrowAuthenticatedRequest(t *testing.T) {
	const token = "TOKEN-MUST-STAY-IN-HEADER"
	event := sampleEvent("event-http", "only the user prompt")
	var received model.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/events" {
			t.Errorf("path = %q, want /api/v1/events", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		if strings.Contains(string(body), token) {
			t.Errorf("transport token was copied into event body: %s", body)
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("decode event: %v", err)
			return
		}
		writeEventAcknowledgement(w, received.EventID)
	}))
	defer server.Close()
	client, err := NewAPIClient(server.URL+"/", token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendEvent(event); err != nil {
		t.Fatalf("SendEvent() error = %v", err)
	}
	if !reflect.DeepEqual(received, event) {
		t.Fatalf("received event = %#v, want %#v", received, event)
	}
}

func TestQueueKeepsEventWhenSuccessfulHTTPResponseHasNoValidAcknowledgement(t *testing.T) {
	responses := []struct {
		name string
		body string
	}{
		{name: "HTML proxy page", body: "<html>not the audit API</html>"},
		{name: "wrong event ID", body: `{"accepted":true,"event_id":"different-event"}`},
		{name: "not accepted", body: `{"accepted":false,"event_id":"ack-required-event"}`},
	}
	for _, response := range responses {
		t.Run(response.name, func(t *testing.T) {
			useTestConfigDirectory(t)
			queue, err := OpenQueue()
			if err != nil {
				t.Fatal(err)
			}
			event := sampleEvent("ack-required-event", "must stay durable")
			if err := queue.Enqueue(event); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, response.body)
			}))
			defer server.Close()
			client, err := NewAPIClient(server.URL, "token", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if flushed, err := queue.Flush(client, 0); err == nil || flushed != 0 {
				t.Fatalf("Flush = %d, %v; want 0 and invalid acknowledgement error", flushed, err)
			}
			if count, err := queue.Count(); err != nil || count != 1 {
				t.Fatalf("durable queue count = %d, %v; want 1, nil", count, err)
			}
		})
	}
}

func TestAPIClientNeverFollowsAuthenticatedRedirects(t *testing.T) {
	destinationCalled := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationCalled = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/api/v1/events", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, err := NewAPIClient(redirect.URL, "redirect-sensitive-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = client.SendEvent(sampleEvent("redirect-event", "prompt"))
	if err == nil || err.Error() != "event server returned HTTP 307" {
		t.Fatalf("SendEvent redirect error = %v", err)
	}
	if destinationCalled {
		t.Fatal("authenticated audit request followed a redirect")
	}
}

func TestAPIClientErrorsNeverIncludeTokenPromptOrResponseBody(t *testing.T) {
	const (
		token  = "VERY-SENSITIVE-TRANSPORT-TOKEN"
		prompt = "VERY-SENSITIVE-USER-PROMPT"
		body   = "VERY-SENSITIVE-SERVER-RESPONSE"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, body+" "+token+" "+prompt)
	}))
	client, err := NewAPIClient(server.URL, token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = client.SendEvent(sampleEvent("event-secret", prompt))
	server.Close()
	if err == nil {
		t.Fatal("SendEvent() error = nil, want HTTP error")
	}
	assertTextExcludes(t, err.Error(), token, prompt, body)

	err = client.SendEvent(sampleEvent("event-secret", prompt))
	if err == nil {
		t.Fatal("SendEvent() against closed server error = nil")
	}
	assertTextExcludes(t, err.Error(), token, prompt, body)
}

func TestAPIClientTimeoutIsBoundedAndGeneric(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-releaseRequest
	}))
	defer server.Close()
	defer close(releaseRequest)
	client, err := NewAPIClient(server.URL, "timeout-token", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = client.SendEvent(sampleEvent("event-timeout", "timeout-prompt"))
	if err == nil {
		t.Fatal("SendEvent() error = nil, want timeout")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("SendEvent() took %v despite short timeout", elapsed)
	}
	select {
	case <-requestStarted:
	default:
		t.Fatal("test server never received request")
	}
	if err.Error() != "event server unavailable" {
		t.Fatalf("timeout error = %q, want generic availability error", err)
	}
}

func TestAPIClientResanitizesQueuedRepositoryRemote(t *testing.T) {
	var received model.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		writeEventAcknowledgement(w, received.EventID)
	}))
	defer server.Close()
	client, err := NewAPIClient(server.URL, "transport-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	event := sampleEvent("resanitize-backlog", "queued prompt")
	event.RepositoryRemote = "https://worker:old-secret@example.invalid/acme/inventory.git?token=secret#fragment"
	if err := client.SendEvent(event); err != nil {
		t.Fatal(err)
	}
	if received.RepositoryRemote != "example.invalid/acme/inventory" || strings.Contains(received.RepositoryRemote, "secret") {
		t.Fatalf("transmitted repository remote = %q", received.RepositoryRemote)
	}
}

func TestRegisterDoesNotLeakRejectedResponseOrRegistrationCode(t *testing.T) {
	const (
		registrationCode = "REGISTRATION-CODE-SECRET"
		responseSecret   = "SERVER-BODY-SECRET"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, responseSecret)
	}))
	defer server.Close()
	_, err := Register(server.URL, model.RegistrationRequest{
		Name:             "Worker",
		Email:            "worker@example.invalid",
		OrganizationID:   "org-test",
		RegistrationCode: registrationCode,
	})
	if err == nil {
		t.Fatal("Register() error = nil, want HTTP error")
	}
	assertTextExcludes(t, err.Error(), registrationCode, responseSecret)
}

func TestRegisterRejectsMalformedSuccessCredentials(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid user ID", body: `{"user_id":"not-a-uuid","token":"pa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`},
		{name: "invalid token", body: `{"user_id":"11111111-1111-4111-8111-111111111111","token":"short-token"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			if _, err := Register(server.URL, model.RegistrationRequest{
				Name: "Worker", Email: "worker@example.invalid", OrganizationID: "org-test",
				RegistrationCode: "registration-secret",
			}); err == nil {
				t.Fatal("Register() accepted malformed credentials")
			}
		})
	}
}

func TestQueueFileContainsEventsButNeverTransportToken(t *testing.T) {
	configDir := useTestConfigDirectory(t)
	const transportToken = "TRANSPORT-TOKEN-MUST-NOT-BE-QUEUED"
	writeTestUserConfig(t, configDir, UserConfig{
		UserID:    "worker-queue",
		Name:      "Queue Worker",
		Email:     "queue@example.invalid",
		ServerURL: "https://audit.example.invalid",
		Token:     transportToken,
	})
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	event := sampleEvent("event-no-token", "password=hunter2")
	if err := queue.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(configDir, "queue", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), event.EventID) {
		t.Fatalf("queue did not persist event ID: %s", contents)
	}
	if strings.Contains(string(contents), transportToken) {
		t.Fatalf("queue persisted transport token: %s", contents)
	}
}

func TestQueueRecoversInterruptedWindowsStyleReplacement(t *testing.T) {
	configDir := useTestConfigDirectory(t)
	queue, err := OpenQueue()
	if err != nil {
		t.Fatal(err)
	}
	event := sampleEvent("event-backup-recovery", "prompt survives replacement")
	if err := queue.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	backup := queue.path + ".bak"
	if err := os.Rename(queue.path, backup); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(queue.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("queue path still exists after simulated interruption: %v", err)
	}
	if count, err := queue.Count(); err != nil || count != 1 {
		t.Fatalf("recovered queue count = %d, %v; want 1", count, err)
	}
	contents, err := os.ReadFile(filepath.Join(configDir, "queue", "events.jsonl"))
	if err != nil || !strings.Contains(string(contents), event.EventID) {
		t.Fatalf("recovered queue = %q, %v; missing event", contents, err)
	}
}

func readQueueForTest(t *testing.T, queue *Queue) []model.Event {
	t.Helper()
	var events []model.Event
	if err := queue.withLock(func() error {
		var err error
		events, err = queue.readUnlocked()
		return err
	}); err != nil {
		t.Fatalf("read queue: %v", err)
	}
	return events
}

func eventIDs(events []model.Event) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.EventID)
	}
	return ids
}

func assertTextExcludes(t *testing.T, text string, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if value != "" && strings.Contains(text, value) {
			t.Errorf("%q leaked in %q", value, text)
		}
	}
}
