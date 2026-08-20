package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

// Keep automatic retries comfortably inside the three-second hook deadline.
// A backlog drains over subsequent prompts or immediately through `flush`.
const maxAutomaticFlush = 3

// Explicit flush drains in bounded batches. This keeps snapshots and memory
// bounded and, more importantly, prevents a long queue scan from monopolizing
// the enqueue lock used by AI-tool hooks.
const maxExplicitFlushBatch = 10

// A cursor is one non-negative base-10 int64 plus optional surrounding
// whitespace. Bound the read so corrupt metadata cannot allocate arbitrary
// memory in a prompt hook.
const maxQueueCursorBytes = 64

// Rejected events are moved back in small, fsynced batches. The pause between
// batches is deliberately longer than the lock poll interval so a live hook
// that is already waiting gets a fair chance to persist its prompt.
const (
	retryRejectedBatchSize  = 25
	retryRejectedBatchBytes = 1024 * 1024
	retryRejectedYield      = 15 * time.Millisecond
)

type Queue struct {
	authorityRoot string
	path          string
	rejectedPath  string
	cursorPath    string
	idsDirectory  string
	lockPath      string
	flushLockPath string
}

type rejectedEvent struct {
	Event      model.Event `json:"event"`
	HTTPStatus int         `json:"http_status"`
	RejectedAt time.Time   `json:"rejected_at"`
}

type encodedRetry struct {
	eventID string
	line    []byte
}

var errQueueSchema = errors.New("queue contains an invalid event")

type rejectedEventsError struct {
	count int
}

func (e *rejectedEventsError) Error() string {
	return fmt.Sprintf("%d event(s) were preserved in rejected.jsonl after permanent server rejection", e.count)
}

func OpenQueue() (*Queue, error) {
	return openQueueForProfile("")
}

func openQueueForProfile(profile string) (*Queue, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	configRoot := dir
	if profile != "" {
		dir = filepath.Join(dir, profilesDirectory, profile)
	}
	dir = filepath.Join(dir, "queue")
	if err := ensureDirectoryDurableUnder(configRoot, dir, 0o700); err != nil {
		return nil, fmt.Errorf("create queue directory: %w", err)
	}
	if err := protectPrivateDirectory(configRoot, dir); err != nil {
		return nil, fmt.Errorf("protect queue directory: %w", err)
	}
	idsDirectory := filepath.Join(dir, "ids")
	if err := ensureDirectoryDurableUnder(configRoot, idsDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create queue ID directory: %w", err)
	}
	if err := protectPrivateDirectory(configRoot, idsDirectory); err != nil {
		return nil, fmt.Errorf("protect queue ID directory: %w", err)
	}
	return &Queue{
		authorityRoot: configRoot,
		path:          filepath.Join(dir, "events.jsonl"),
		rejectedPath:  filepath.Join(dir, "rejected.jsonl"),
		cursorPath:    filepath.Join(dir, "events.cursor"),
		idsDirectory:  idsDirectory,
		lockPath:      filepath.Join(dir, "events.lock"),
		flushLockPath: filepath.Join(dir, "flush.lock"),
	}, nil
}

func (q *Queue) RebindIdentityAndSave(project ProjectConfig, cfg UserConfig) error {
	if cfg.UserID == "" || cfg.Email == "" {
		return errors.New("queue identity is incomplete")
	}
	return q.withLock(func() error {
		// EnqueueBound reads the profile under this same lock. Events written
		// before this atomic credential transition can retain their provisional
		// local identity: APIClient overwrites it in memory at send time.
		_, err := saveUserConfigForProject(project, cfg)
		return err
	})
}

func (q *Queue) completeEnrollmentIfCurrent(project ProjectConfig, expected, enrolled UserConfig) (UserConfig, error) {
	result := enrolled
	err := q.withLock(func() error {
		current, _, err := loadUserConfigForProject(project)
		if err != nil {
			return err
		}
		if current.enrolled() {
			result = current
			return nil
		}
		if current.Token != expected.Token || current.InstallationID != expected.InstallationID {
			return errors.New("enrollment profile changed while the request was in flight")
		}
		_, err = saveUserConfigForProject(project, enrolled)
		return err
	})
	return result, err
}

func (q *Queue) Enqueue(event model.Event) error {
	return q.withLock(func() error {
		return q.enqueueUnlocked(event)
	})
}

func (q *Queue) EnqueueBound(event model.Event, project ProjectConfig) error {
	return q.withLock(func() error {
		cfg, _, err := loadUserConfigForProject(project)
		if err != nil {
			return err
		}
		event.UserID = cfg.UserID
		event.UserEmail = cfg.Email
		return q.enqueueUnlocked(event)
	})
}

func (q *Queue) enqueueUnlocked(event model.Event) error {
	if err := validateStoredEvent(event); err != nil {
		return fmt.Errorf("refuse invalid queued event before durable append: %w", err)
	}
	if err := q.recoverQueueUnlocked(); err != nil {
		return err
	}
	marker := q.eventMarkerPath(event.EventID)
	if _, err := os.Stat(marker); err == nil {
		pending, pendingErr := q.pendingContainsEventIDUnlocked(event.EventID)
		if pendingErr != nil {
			return pendingErr
		}
		if pending {
			return nil
		}
		// A crash after advancing the queue but before removing its marker can
		// leave an orphan. A marker is only a fast-path hint; never let it discard
		// the sole remaining copy of an event being retried.
		if removeErr := os.Remove(marker); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("remove stale queued event ID: %w", removeErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check queued event ID: %w", err)
	}
	line, err := json.Marshal(event)
	if err != nil {
		return errors.New("encode queued event")
	}
	queueInfo, statErr := os.Lstat(q.path)
	newFile := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !newFile {
		return fmt.Errorf("stat queue before append: %w", statErr)
	}
	if !newFile &&
		(queueInfo.Mode()&os.ModeSymlink != 0 || !queueInfo.Mode().IsRegular()) {
		return errors.New("queue is not a regular file")
	}
	if newFile {
		created, createErr := os.OpenFile(q.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return fmt.Errorf("create queue: %w", createErr)
		}
		if closeErr := created.Close(); closeErr != nil {
			return fmt.Errorf("close new queue: %w", closeErr)
		}
	}
	if newFile {
		if err := syncDirectory(filepath.Dir(q.path)); err != nil {
			return fmt.Errorf("sync queue directory: %w", err)
		}
	}
	// Enforce private ACLs and bind the writer to that exact object before
	// persisting prompt data.
	f, err := openProtectedRegularFile(
		q.authorityRoot,
		q.path,
		os.O_APPEND|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open queue: %w", err)
	}
	if _, err = f.Write(append(line, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("persist queued event: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close queue: %w", closeErr)
	}
	// The event is fsynced before its O(1) ID marker. If a process dies between
	// these writes, the event is still safe; a later duplicate is harmless at
	// the server because event_id is unique.
	markerFile, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		// The marker is only an optimization. The queue entry is already fsynced;
		// a missing marker can cause an idempotent duplicate, never data loss.
		return nil
	}
	if err := markerFile.Close(); err != nil {
		return nil
	}
	return nil
}

func (q *Queue) Flush(client *APIClient, limit int) (int, error) {
	flushed := 0
	err := withFileLock(q.flushLockPath, 750*time.Millisecond, func() error {
		var flushErr error
		flushed, flushErr = q.flushSerial(client, limit)
		return flushErr
	})
	return flushed, err
}

func (q *Queue) flushSerial(client *APIClient, limit int) (int, error) {
	if limit <= 0 {
		limit = maxExplicitFlushBatch
	}
	var batch []model.Event
	var offsets []int64
	var startOffset int64
	if err := q.withLock(func() error {
		var err error
		batch, offsets, startOffset, err = q.readBatchUnlocked(limit)
		return err
	}); err != nil {
		return 0, err
	}

	// Never hold the queue lock during network I/O. That lets simultaneous hooks
	// durably enqueue their prompt even when delivery is slow. A crash after the
	// server accepts an event can only cause a harmless event_id retry.
	flushed := 0
	processed := 0
	rejected := make([]rejectedEvent, 0)
	var sendErr error
	for _, event := range batch {
		if err := client.SendEvent(event); err != nil {
			if status, permanent := permanentEventRejection(err); permanent {
				rejected = append(rejected, rejectedEvent{
					Event: event, HTTPStatus: status, RejectedAt: time.Now().UTC(),
				})
				processed++
				continue
			}
			sendErr = err
			break
		}
		flushed++
		processed++
	}
	if processed == 0 {
		return 0, sendErr
	}
	if err := q.withLock(func() error {
		currentOffset, err := q.readCursorUnlocked()
		if err != nil {
			return err
		}
		if currentOffset != startOffset {
			// Another hook advanced the same snapshot while network I/O was in
			// flight. Its server writes are idempotent, so no local rewrite is needed.
			return nil
		}
		if err := q.appendRejectedUnlocked(rejected); err != nil {
			return err
		}
		// Removing markers first is the conservative crash order: an interruption
		// can cause a duplicate retry, but it cannot leave a marker that suppresses
		// the only durable copy of a rejected event.
		for _, event := range batch[:processed] {
			_ = os.Remove(q.eventMarkerPath(event.EventID))
		}
		return q.advanceCursorUnlocked(offsets[processed-1])
	}); err != nil {
		return flushed, err
	}
	if len(rejected) > 0 {
		return flushed, &rejectedEventsError{count: len(rejected)}
	}
	return flushed, sendErr
}

func (q *Queue) Count() (int, error) {
	count := 0
	err := withFileLock(q.flushLockPath, 750*time.Millisecond, func() error {
		for attempt := 0; attempt < 2; attempt++ {
			// Snapshot the complete-line boundary under the enqueue lock, then
			// decode outside it so a large offline queue never starves captures.
			var file *os.File
			var length int64
			if err := q.withLock(func() error {
				if err := q.recoverQueueUnlocked(); err != nil {
					return err
				}
				start, err := q.readCursorUnlocked()
				if err != nil {
					return err
				}
				file, err = openExistingRegularFile(q.path, os.O_RDONLY, 0)
				if errors.Is(err, os.ErrNotExist) {
					file = nil
					return nil
				}
				if err != nil {
					return fmt.Errorf("read queue: %w", err)
				}
				info, err := file.Stat()
				if err != nil {
					_ = file.Close()
					file = nil
					return fmt.Errorf("stat queue: %w", err)
				}
				if start < 0 || start > info.Size() {
					_ = file.Close()
					file = nil
					return errors.New("queue cursor is outside the event file")
				}
				if _, err := file.Seek(start, io.SeekStart); err != nil {
					_ = file.Close()
					file = nil
					return fmt.Errorf("seek queue: %w", err)
				}
				length = info.Size() - start
				return nil
			}); err != nil {
				return err
			}
			if file == nil {
				count = 0
				return nil
			}
			count = 0
			invalid := false
			scanner := bufio.NewScanner(io.LimitReader(file, length))
			scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
			for scanner.Scan() {
				if len(scanner.Bytes()) == 0 {
					continue
				}
				if _, decodeErr := decodeStoredEventLine(scanner.Bytes()); decodeErr != nil {
					invalid = true
					continue
				}
				count++
			}
			scanErr := scanner.Err()
			closeErr := file.Close()
			if closeErr != nil {
				return fmt.Errorf("close queue after count: %w", closeErr)
			}
			if scanErr == nil && !invalid {
				return nil
			}
			if attempt == 1 {
				if scanErr != nil {
					return fmt.Errorf("scan queue after strict repair: %w", scanErr)
				}
				return errQueueSchema
			}
			if err := q.withLock(q.repairQueueSchemaUnlocked); err != nil {
				return err
			}
		}
		return nil
	})
	return count, err
}

func (q *Queue) HasPending() (bool, error) {
	pending := false
	err := q.withLock(func() error {
		events, _, _, err := q.readBatchUnlocked(1)
		pending = len(events) > 0
		return err
	})
	return pending, err
}

func (q *Queue) RejectedCount() (int, error) {
	count := 0
	err := withFileLock(q.flushLockPath, 750*time.Millisecond, func() error {
		if err := q.repairRejectedSchemaUnlocked(); err != nil {
			return fmt.Errorf("repair rejected queue before counting: %w", err)
		}
		file, err := openExistingRegularFile(q.rejectedPath, os.O_RDONLY, 0)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read rejected queue: %w", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			if len(scanner.Bytes()) > 0 {
				count++
			}
		}
		return scanner.Err()
	})
	return count, err
}

func (q *Queue) RetryRejected() (int, error) {
	retried := 0
	err := withFileLock(q.flushLockPath, 750*time.Millisecond, func() error {
		if err := q.repairRejectedSchemaUnlocked(); err != nil {
			return fmt.Errorf("repair rejected queue before retry: %w", err)
		}
		file, err := openExistingRegularFile(q.rejectedPath, os.O_RDONLY, 0)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read rejected queue: %w", err)
		}
		batch := make([]encodedRetry, 0, retryRejectedBatchSize)
		batchBytes := 0
		flushBatch := func(yield bool) error {
			if len(batch) == 0 {
				return nil
			}
			if err := q.appendRetryBatch(batch); err != nil {
				return err
			}
			retried += len(batch)
			batch = make([]encodedRetry, 0, retryRejectedBatchSize)
			batchBytes = 0
			if yield {
				time.Sleep(retryRejectedYield)
			}
			return nil
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			if len(scanner.Bytes()) == 0 {
				continue
			}
			var item rejectedEvent
			if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
				_ = file.Close()
				return errors.New("rejected queue contains an invalid event")
			}
			line, err := json.Marshal(item.Event)
			if err != nil {
				_ = file.Close()
				return errors.New("encode rejected event for retry")
			}
			if len(batch) > 0 && (len(batch) >= retryRejectedBatchSize || batchBytes+len(line)+1 > retryRejectedBatchBytes) {
				if err := flushBatch(true); err != nil {
					_ = file.Close()
					return err
				}
			}
			batch = append(batch, encodedRetry{eventID: item.Event.EventID, line: line})
			batchBytes += len(line) + 1
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return fmt.Errorf("scan rejected queue: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close rejected queue: %w", err)
		}
		if err := flushBatch(false); err != nil {
			return err
		}
		if retried > 0 {
			return q.writeRejectedUnlocked(nil)
		}
		return nil
	})
	return retried, err
}

func (q *Queue) appendRetryBatch(batch []encodedRetry) error {
	if len(batch) == 0 {
		return nil
	}
	// A failed prior retry may already have appended this event. Removing its
	// marker and appending again is conservative: duplicates retain the same
	// event_id and are idempotent at the server, while a full queue scan here
	// would block live hooks for an unbounded amount of time.
	for _, item := range batch {
		marker := q.eventMarkerPath(item.eventID)
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale queued event ID: %w", err)
		}
	}
	if err := q.withLock(func() error {
		if err := q.recoverQueueUnlocked(); err != nil {
			return err
		}
		queueInfo, statErr := os.Lstat(q.path)
		newFile := errors.Is(statErr, os.ErrNotExist)
		if statErr != nil && !newFile {
			return fmt.Errorf("stat queue: %w", statErr)
		}
		if !newFile &&
			(queueInfo.Mode()&os.ModeSymlink != 0 || !queueInfo.Mode().IsRegular()) {
			return errors.New("queue is not a regular file")
		}
		if newFile {
			created, createErr := os.OpenFile(q.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if createErr != nil {
				return fmt.Errorf("create queue: %w", createErr)
			}
			if closeErr := created.Close(); closeErr != nil {
				return fmt.Errorf("close new queue: %w", closeErr)
			}
		}
		if newFile {
			if err := syncDirectory(filepath.Dir(q.path)); err != nil {
				return fmt.Errorf("sync queue directory: %w", err)
			}
		}
		file, err := openProtectedRegularFile(
			q.authorityRoot,
			q.path,
			os.O_APPEND|os.O_WRONLY,
			0o600,
		)
		if err != nil {
			return fmt.Errorf("open queue: %w", err)
		}
		writer := bufio.NewWriterSize(file, 64*1024)
		for _, item := range batch {
			_, writeErr := writer.Write(item.line)
			if writeErr == nil {
				writeErr = writer.WriteByte('\n')
			}
			if writeErr != nil {
				_ = file.Close()
				return fmt.Errorf("persist queued events: %w", writeErr)
			}
		}
		persistErr := writer.Flush()
		if persistErr == nil {
			persistErr = file.Sync()
		}
		closeErr := file.Close()
		if persistErr != nil {
			return fmt.Errorf("persist queued events: %w", persistErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close queue: %w", closeErr)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, item := range batch {
		marker, err := os.OpenFile(q.eventMarkerPath(item.eventID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			// The fsynced queue is authoritative; markers only accelerate
			// duplicate checks. Keep rejected cleanup progressing even if this
			// optimization cannot be written.
			continue
		}
		if err := marker.Close(); err != nil {
			continue
		}
	}
	return nil
}

func (q *Queue) readUnlocked() ([]model.Event, error) {
	events, _, _, err := q.readBatchUnlocked(int(^uint(0) >> 1))
	return events, err
}

func (q *Queue) pendingContainsEventIDUnlocked(eventID string) (bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if err := q.recoverQueueUnlocked(); err != nil {
			return false, err
		}
		start, err := q.readCursorUnlocked()
		if err != nil {
			return false, err
		}
		file, err := openExistingRegularFile(q.path, os.O_RDONLY, 0)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("read queue for event ID: %w", err)
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return false, fmt.Errorf("stat queue for event ID: %w", err)
		}
		if start < 0 || start > info.Size() {
			_ = file.Close()
			return false, errors.New("queue cursor is outside the event file")
		}
		if _, err := file.Seek(start, io.SeekStart); err != nil {
			_ = file.Close()
			return false, fmt.Errorf("seek queue for event ID: %w", err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		invalid := false
		for scanner.Scan() {
			if len(scanner.Bytes()) == 0 {
				continue
			}
			candidate, decodeErr := decodeStoredEventLine(scanner.Bytes())
			if decodeErr != nil {
				invalid = true
				continue
			}
			if candidate.EventID == eventID {
				_ = file.Close()
				return true, nil
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if closeErr != nil {
			return false, fmt.Errorf("close queue after event ID scan: %w", closeErr)
		}
		if scanErr == nil && !invalid {
			return false, nil
		}
		var validationErr error
		if scanErr != nil {
			validationErr = fmt.Errorf("scan queue for event ID: %w", scanErr)
		} else {
			validationErr = errors.New("queue contains an invalid stored event")
		}
		if attempt == 1 {
			return false, validationErr
		}
		if repairErr := q.repairQueueSchemaUnlocked(); repairErr != nil {
			return false, errors.Join(validationErr, repairErr)
		}
	}
	return false, errors.New("queue validation retry was exhausted")
}

func (q *Queue) recoverQueueUnlocked() error {
	// Recover conservatively from an interrupted Windows replacement. Restoring
	// the old queue can resend an already accepted event, but event_id makes that
	// harmless; losing a prompt would not be harmless.
	backup := q.path + ".bak"
	if _, err := os.Lstat(q.path); errors.Is(err, os.ErrNotExist) {
		if _, backupErr := regularFileInfo(backup); backupErr == nil {
			if renameErr := os.Rename(backup, q.path); renameErr != nil {
				return fmt.Errorf("recover queue backup: %w", renameErr)
			}
		} else if !errors.Is(backupErr, os.ErrNotExist) {
			return fmt.Errorf("inspect queue backup: %w", backupErr)
		} else if _, tmpErr := regularFileInfo(q.path + ".tmp"); tmpErr == nil {
			if renameErr := os.Rename(q.path+".tmp", q.path); renameErr != nil {
				return fmt.Errorf("recover queue rewrite: %w", renameErr)
			}
		} else if !errors.Is(tmpErr, os.ErrNotExist) {
			return fmt.Errorf("inspect queue rewrite: %w", tmpErr)
		}
	} else if err != nil {
		return fmt.Errorf("inspect queue before recovery: %w", err)
	}
	if _, err := repairTrailingJSONL(q.authorityRoot, q.path); err != nil {
		return fmt.Errorf("repair interrupted queue append: %w", err)
	}
	start, cursorErr := q.readCursorUnlocked()
	info, queueErr := os.Lstat(q.path)
	if errors.Is(queueErr, os.ErrNotExist) {
		info = nil
		queueErr = nil
	}
	if queueErr != nil {
		return fmt.Errorf("stat recovered queue: %w", queueErr)
	}
	if info != nil &&
		(info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("recovered queue is not a regular file")
	}
	cursorOnBoundary := true
	if cursorErr == nil && info != nil && start > 0 && start <= info.Size() {
		file, openErr := openExistingRegularFile(q.path, os.O_RDONLY, 0)
		if openErr != nil {
			return fmt.Errorf("open queue to validate cursor boundary: %w", openErr)
		}
		var previous [1]byte
		_, readErr := file.ReadAt(previous[:], start-1)
		closeErr := file.Close()
		if readErr != nil {
			return fmt.Errorf("read queue cursor boundary: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close queue cursor boundary check: %w", closeErr)
		}
		cursorOnBoundary = previous[0] == '\n'
	}
	if cursorErr != nil || !cursorOnBoundary || start < 0 ||
		(info == nil && start != 0) || (info != nil && start > info.Size()) {
		// The cursor is only progress metadata. Resetting it can resend accepted
		// event IDs, which is safe; retaining an impossible cursor can strand
		// every pending prompt after a power loss.
		if err := os.Remove(q.cursorPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("reset invalid queue cursor: %w", err)
		}
		if err := syncDirectory(filepath.Dir(q.cursorPath)); err != nil {
			return fmt.Errorf("sync invalid queue cursor reset: %w", err)
		}
	}
	return nil
}

func (q *Queue) repairQueueSchemaUnlocked() error {
	events, invalid, err := readStrictQueueEvents(q.path)
	if err != nil {
		return fmt.Errorf("validate queue schema: %w", err)
	}
	if !invalid {
		return nil
	}
	if err := writeQueueDigestEvidence(q.authorityRoot, q.path); err != nil {
		return err
	}
	if err := q.writeUnlocked(events); err != nil {
		return fmt.Errorf("rebuild strict queue: %w", err)
	}
	return nil
}

func (q *Queue) repairRejectedSchemaUnlocked() error {
	if _, err := repairTrailingJSONL(q.authorityRoot, q.rejectedPath); err != nil {
		return err
	}
	items, invalid, err := readStrictRejectedEvents(q.rejectedPath)
	if err != nil {
		return fmt.Errorf("validate rejected queue schema: %w", err)
	}
	if !invalid {
		return nil
	}
	if err := writeQueueDigestEvidence(q.authorityRoot, q.rejectedPath); err != nil {
		return err
	}
	if err := q.writeRejectedUnlocked(items); err != nil {
		return fmt.Errorf("rebuild strict rejected queue: %w", err)
	}
	return nil
}

func readStrictQueueEvents(path string) ([]model.Event, bool, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	var events []model.Event
	invalid := false
	if err := forEachBoundedJSONLLine(file, 8*1024*1024, func(line []byte, oversized bool) error {
		if oversized {
			invalid = true
			return nil
		}
		event, decodeErr := decodeStoredEventLine(line)
		if decodeErr != nil {
			invalid = true
			return nil
		}
		events = append(events, event)
		return nil
	}); err != nil {
		return nil, false, err
	}
	return events, invalid, nil
}

func readStrictRejectedEvents(path string) ([]rejectedEvent, bool, error) {
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	var items []rejectedEvent
	invalid := false
	if err := forEachBoundedJSONLLine(file, 8*1024*1024, func(line []byte, oversized bool) error {
		if oversized {
			invalid = true
			return nil
		}
		var item rejectedEvent
		if err := validateUniqueJSONKeys(line); err != nil {
			invalid = true
			return nil
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&item)
		var trailing any
		if decodeErr == nil {
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				decodeErr = errors.New("multiple JSON values")
			}
		}
		if decodeErr == nil {
			decodeErr = validateStoredEvent(item.Event)
		}
		if decodeErr != nil {
			invalid = true
			return nil
		}
		items = append(items, item)
		return nil
	}); err != nil {
		return nil, false, err
	}
	return items, invalid, nil
}

func writeQueueDigestEvidence(authorityRoot, sourcePath string) error {
	source, err := openExistingRegularFile(sourcePath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open invalid queue for digest: %w", err)
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, source)
	closeErr := source.Close()
	if copyErr != nil {
		return fmt.Errorf("digest invalid queue: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close invalid queue: %w", closeErr)
	}
	directory := filepath.Dir(sourcePath)
	evidencePath := filepath.Join(directory, fmt.Sprintf(
		".corrupt-%s-%d.digest",
		filepath.Base(sourcePath), time.Now().UTC().UnixNano(),
	))
	file, err := os.OpenFile(evidencePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create invalid queue digest: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close empty invalid queue digest: %w", err)
	}
	file, err = openProtectedRegularFile(
		authorityRoot,
		evidencePath,
		os.O_TRUNC|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open invalid queue digest: %w", err)
	}
	payload := []byte(fmt.Sprintf("source=%s\nsha256=%s\n",
		filepath.Base(sourcePath), hex.EncodeToString(hasher.Sum(nil))))
	if _, err = file.Write(payload); err == nil {
		err = file.Sync()
	}
	closeErr = file.Close()
	if err != nil {
		return fmt.Errorf("persist invalid queue digest: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close invalid queue digest: %w", closeErr)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync invalid queue digest directory: %w", err)
	}
	return nil
}

func (q *Queue) readBatchUnlocked(limit int) ([]model.Event, []int64, int64, error) {
	events, offsets, start, err := q.readBatchOnceUnlocked(limit)
	if !errors.Is(err, errQueueSchema) {
		return events, offsets, start, err
	}
	// Complete-schema salvage is exceptional and O(n). Run it only after the
	// bounded reader actually encounters corruption, never before every append
	// or normal flush.
	if repairErr := q.repairQueueSchemaUnlocked(); repairErr != nil {
		return nil, nil, start, repairErr
	}
	return q.readBatchOnceUnlocked(limit)
}

func (q *Queue) readBatchOnceUnlocked(limit int) ([]model.Event, []int64, int64, error) {
	if err := q.recoverQueueUnlocked(); err != nil {
		return nil, nil, 0, err
	}
	start, err := q.readCursorUnlocked()
	if err != nil {
		return nil, nil, 0, err
	}
	f, err := openExistingRegularFile(q.path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, start, nil
	}
	if err != nil {
		return nil, nil, start, fmt.Errorf("read queue: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, start, fmt.Errorf("stat queue: %w", err)
	}
	if start < 0 || start > info.Size() {
		return nil, nil, start, errors.New("queue cursor is outside the event file")
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, nil, start, fmt.Errorf("seek queue: %w", err)
	}
	var events []model.Event
	offsets := make([]int64, 0)
	reader := bufio.NewReaderSize(f, 64*1024)
	position := start
	for len(events) < limit {
		line := make([]byte, 0, 64*1024)
		oversized := false
		var readErr error
		for {
			fragment, fragmentErr := reader.ReadSlice('\n')
			position += int64(len(fragment))
			if !oversized {
				if len(line)+len(fragment) > 8*1024*1024 {
					oversized = true
					line = line[:0]
				} else {
					line = append(line, fragment...)
				}
			}
			if errors.Is(fragmentErr, bufio.ErrBufferFull) {
				continue
			}
			readErr = fragmentErr
			break
		}
		if oversized {
			return nil, nil, start, errQueueSchema
		}
		line = bytes.TrimRight(line, "\r\n")
		if len(line) == 0 {
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				return nil, nil, start, fmt.Errorf("read queue: %w", readErr)
			}
			continue
		}
		event, decodeErr := decodeStoredEventLine(line)
		if decodeErr != nil {
			return nil, nil, start, errQueueSchema
		}
		events = append(events, event)
		offsets = append(offsets, position)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, nil, start, fmt.Errorf("read queue: %w", readErr)
		}
	}
	return events, offsets, start, nil
}

func (q *Queue) readCursorUnlocked() (int64, error) {
	file, err := openExistingRegularFile(q.cursorPath, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read queue cursor: %w", err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, maxQueueCursorBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return 0, fmt.Errorf("read queue cursor: %w", readErr)
	}
	if closeErr != nil {
		return 0, fmt.Errorf("close queue cursor: %w", closeErr)
	}
	if len(contents) > maxQueueCursorBytes {
		return 0, errors.New("queue cursor is invalid")
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(contents)), 10, 64)
	if err != nil || value < 0 {
		return 0, errors.New("queue cursor is invalid")
	}
	return value, nil
}

func (q *Queue) advanceCursorUnlocked(offset int64) error {
	info, err := os.Lstat(q.path)
	if err != nil {
		return fmt.Errorf("stat queue for cursor: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("queue is not a regular file")
	}
	if offset >= info.Size() {
		// Reset the cursor first. A crash before truncation then causes harmless
		// event_id retries; truncating first could leave an impossible cursor.
		if err := os.Remove(q.cursorPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("reset queue cursor: %w", err)
		}
		if err := syncDirectory(filepath.Dir(q.cursorPath)); err != nil {
			return fmt.Errorf("sync reset queue cursor: %w", err)
		}
		file, err := openExistingRegularFile(q.path, os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("truncate delivered queue: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("sync delivered queue: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close delivered queue: %w", err)
		}
		return nil
	}
	dir := filepath.Dir(q.cursorPath)
	file, err := os.CreateTemp(dir, ".cursor-*.tmp")
	if err != nil {
		return fmt.Errorf("create queue cursor: %w", err)
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if _, err := fmt.Fprintf(file, "%d\n", offset); err != nil {
		_ = file.Close()
		return fmt.Errorf("write queue cursor: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync queue cursor: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close queue cursor: %w", err)
	}
	if err := protectFile(q.authorityRoot, tmp); err != nil {
		return fmt.Errorf("protect queue cursor: %w", err)
	}
	if err := replaceFile(tmp, q.cursorPath); err != nil {
		return fmt.Errorf("replace queue cursor: %w", err)
	}
	return syncDirectory(dir)
}

func (q *Queue) eventMarkerPath(eventID string) string {
	sum := sha256.Sum256([]byte(eventID))
	return filepath.Join(q.idsDirectory, hex.EncodeToString(sum[:]))
}

func (q *Queue) appendRejectedUnlocked(items []rejectedEvent) error {
	if len(items) == 0 {
		return nil
	}
	// Keep the capture/flush critical section bounded. Complete-schema salvage
	// is performed by RetryRejected/RejectedCount; here only repair a torn tail
	// before fsyncing the newly rejected prompt. Duplicate event IDs are safe and
	// preferable to scanning an unbounded rejected backlog under the enqueue lock.
	if _, err := repairTrailingJSONL(q.authorityRoot, q.rejectedPath); err != nil {
		return fmt.Errorf("repair interrupted rejected-queue append: %w", err)
	}
	rejectedInfo, statErr := os.Lstat(q.rejectedPath)
	newFile := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !newFile {
		return fmt.Errorf("stat rejected queue: %w", statErr)
	}
	if !newFile &&
		(rejectedInfo.Mode()&os.ModeSymlink != 0 || !rejectedInfo.Mode().IsRegular()) {
		return errors.New("rejected queue is not a regular file")
	}
	if newFile {
		created, createErr := os.OpenFile(q.rejectedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return fmt.Errorf("create rejected queue: %w", createErr)
		}
		if closeErr := created.Close(); closeErr != nil {
			return fmt.Errorf("close new rejected queue: %w", closeErr)
		}
	}
	if newFile {
		if err := syncDirectory(filepath.Dir(q.rejectedPath)); err != nil {
			return fmt.Errorf("sync rejected queue directory: %w", err)
		}
	}
	file, err := openProtectedRegularFile(
		q.authorityRoot,
		q.rejectedPath,
		os.O_APPEND|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open rejected queue: %w", err)
	}
	encoder := json.NewEncoder(file)
	for _, item := range items {
		if err := encoder.Encode(item); err != nil {
			_ = file.Close()
			return fmt.Errorf("write rejected queue: %w", err)
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync rejected queue: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close rejected queue: %w", err)
	}
	return nil
}

func (q *Queue) writeRejectedUnlocked(items []rejectedEvent) error {
	dir := filepath.Dir(q.rejectedPath)
	file, err := os.CreateTemp(dir, ".rejected-*.tmp")
	if err != nil {
		return fmt.Errorf("create rejected queue rewrite: %w", err)
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Close(); err != nil {
		return fmt.Errorf("close empty rejected queue rewrite: %w", err)
	}
	file, err = openProtectedRegularFile(
		q.authorityRoot,
		tmp,
		os.O_TRUNC|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open rejected queue rewrite: %w", err)
	}
	encoder := json.NewEncoder(file)
	for _, item := range items {
		if err := encoder.Encode(item); err != nil {
			_ = file.Close()
			return fmt.Errorf("rewrite rejected queue: %w", err)
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync rejected queue rewrite: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close rejected queue rewrite: %w", err)
	}
	if err := replaceFile(tmp, q.rejectedPath); err != nil {
		return fmt.Errorf("replace rejected queue: %w", err)
	}
	return syncDirectory(dir)
}

func (q *Queue) writeUnlocked(events []model.Event) error {
	tmp := q.path + ".tmp"
	if info, err := os.Lstat(tmp); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("queue rewrite path is not a regular file")
		}
		if err := os.Remove(tmp); err != nil {
			return fmt.Errorf("remove stale queue rewrite: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect queue rewrite: %w", err)
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("rewrite queue: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close empty queue rewrite: %w", err)
	}
	f, err = openProtectedRegularFile(
		q.authorityRoot,
		tmp,
		os.O_TRUNC|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open queue rewrite: %w", err)
	}
	enc := json.NewEncoder(f)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			_ = f.Close()
			return fmt.Errorf("rewrite queue: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync queue: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close queue: %w", err)
	}
	// Clear the cursor before replacing the compacted file. An interruption can
	// then only resend already accepted event IDs; it cannot skip pending prompts.
	if err := os.Remove(q.cursorPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reset queue cursor before rewrite: %w", err)
	}
	if err := syncDirectory(filepath.Dir(q.cursorPath)); err != nil {
		return fmt.Errorf("sync reset queue cursor before rewrite: %w", err)
	}
	if err := replaceFile(tmp, q.path); err != nil {
		return fmt.Errorf("replace queue: %w", err)
	}
	return syncDirectory(filepath.Dir(q.path))
}

func (q *Queue) withLock(fn func() error) error {
	// OS locks are released by the kernel if a hook process is terminated, so a
	// killed tool cannot leave every later prompt blocked behind a stale marker.
	// The wait must outlast a burst of concurrent enqueues: each holder fsyncs
	// while locked, which can take tens of milliseconds on Windows, and giving up
	// here loses a prompt. Provider hooks are configured with thirty seconds, so
	// reserve a bounded portion of that budget for a burst of durable fsyncs.
	return withFileLock(q.lockPath, 8*time.Second, fn)
}
