package audit

import (
	"errors"
	"fmt"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

const (
	maxRecoveredPromptsPerBatch     = 10_000
	maxRecoveredPromptBytesPerBatch = 64 * 1024 * 1024
)

var errProviderRecoveryPending = errors.New(
	"prompt history recovery has additional bounded batches pending; run recovery again",
)

// recoveredPromptCollector bounds both count and retained bytes before
// redaction/event construction. A hostile provider transcript can still make
// one bounded line allocation, but cannot make recovery retain unbounded prompt
// strings across a file or provider-wide scan.
type recoveredPromptCollector struct {
	items          []scannedPrompt
	retainedBytes  uint64
	oversized      uint64
	maxPrompts     int
	maxBytes       uint64
	maxPromptBytes int
}

// A direct hook and a provider transcript record the same prompt at slightly
// different instants: the transcript is written when the client accepts the
// text, the hook event is stamped when the hook process runs. Claude Code does
// not send a timestamp in its UserPromptSubmit payload at all, so the direct
// event carries the hook's own wall clock. Correlating on an exact timestamp
// therefore never matched, and every directly captured Claude prompt was
// imported a second time by recovery.
//
// The tool, the session and the prompt text already identify the event; the
// timestamp only has to distinguish a prompt legitimately repeated much later
// inside the same session.
const recoveredPromptCorrelationWindow = 10 * time.Minute

type recoveredPromptCorrelationKey struct {
	Tool      string
	SessionID string
	Prompt    string
}

// recoveredPromptDeduper keeps already-durable history/direct events from
// consuming the bounded recovery budget again. This is deliberately populated
// only from the authoritative prompt-only store: a crash before durable append
// cannot make a candidate disappear from a later retry.
type recoveredPromptDeduper struct {
	exact              map[string]model.Event
	directCorrelations map[recoveredPromptCorrelationKey][]time.Time
	historyAliases     map[string]struct{}
	build              func(scannedPrompt) model.Event
	onDrift            func()
	onExact            func(string)
	driftReported      bool
}

func (deduper *recoveredPromptDeduper) SetExactObserver(observer func(string)) {
	if deduper != nil {
		deduper.onExact = observer
	}
}

func (deduper *recoveredPromptDeduper) ObserveExact(prompt scannedPrompt) {
	if deduper == nil || deduper.build == nil || deduper.onExact == nil {
		return
	}
	eventID := deduper.build(prompt).EventID
	if _, exists := deduper.exact[eventID]; exists {
		deduper.onExact(eventID)
	}
}

func recoveredPromptKey(event model.Event) recoveredPromptCorrelationKey {
	return recoveredPromptCorrelationKey{
		Tool: event.Tool, SessionID: event.SessionID, Prompt: event.Prompt,
	}
}

func emptyProviderScanState() providerScanState {
	return providerScanState{
		Version:            currentProviderScanStateVersion,
		AuthoritativeFiles: map[string]authoritativeFingerprint{},
		Files:              map[string]scanFingerprint{},
		Cursors:            map[string]scanCursor{},
		HistoryAliases:     map[string]string{},
	}
}

// reserveExactHistoryIDs runs a provider-wide, zero-retention prepass. Only IDs
// already present in the authoritative store are retained, so memory is bounded
// by durable prompt history rather than by provider transcript size. If any
// prepass diagnostic makes completeness uncertain, every existing history ID
// for this tool is reserved and legacy migration is disabled for the pass.
func reserveExactHistoryIDs(
	existing []model.Event,
	tool string,
	build func(scannedPrompt) model.Event,
	scan func(func(scannedPrompt) bool) error,
) map[string]bool {
	available := make(map[string]struct{})
	for _, event := range existing {
		if event.Tool == tool && isHistoryEventID(event.EventID) {
			available[event.EventID] = struct{}{}
		}
	}
	reserved := make(map[string]bool)
	if len(available) == 0 || build == nil || scan == nil {
		return reserved
	}
	observe := func(prompt scannedPrompt) bool {
		eventID := build(prompt).EventID
		if _, exists := available[eventID]; exists {
			reserved[eventID] = true
		}
		return true
	}
	if err := scan(observe); err != nil {
		for eventID := range available {
			reserved[eventID] = true
		}
	}
	return reserved
}

func reserveAllExistingHistoryIDs(
	existing []model.Event,
	tool string,
	reserved map[string]bool,
) {
	for _, event := range existing {
		if event.Tool == tool && isHistoryEventID(event.EventID) {
			reserved[event.EventID] = true
		}
	}
}

func cloneHistoryIDReservations(source map[string]bool) map[string]bool {
	cloned := make(map[string]bool, len(source))
	for eventID, reserved := range source {
		if reserved {
			cloned[eventID] = true
		}
	}
	return cloned
}

func newRecoveredPromptDeduper(
	existing []model.Event,
	build func(scannedPrompt) model.Event,
	onDrift func(),
) *recoveredPromptDeduper {
	deduper := &recoveredPromptDeduper{
		exact:              make(map[string]model.Event, len(existing)),
		directCorrelations: make(map[recoveredPromptCorrelationKey][]time.Time),
		historyAliases:     make(map[string]struct{}),
		build:              build,
		onDrift:            onDrift,
	}
	for _, event := range existing {
		deduper.exact[event.EventID] = event
		if !isHistoryEventID(event.EventID) {
			key := recoveredPromptKey(event)
			deduper.directCorrelations[key] = append(
				deduper.directCorrelations[key],
				event.Timestamp.UTC(),
			)
		}
	}
	return deduper
}

func (deduper *recoveredPromptDeduper) AddHistoryAliases(aliases map[string]string) {
	if deduper == nil {
		return
	}
	for eventID, targetID := range aliases {
		if isHistoryEventID(eventID) && isHistoryEventID(targetID) {
			deduper.historyAliases[eventID] = struct{}{}
		}
	}
}

// consumeRecoveredPromptMatch claims one direct capture of the same prompt
// whose timestamp is within the correlation window, keeping the pairing
// strictly one-to-one. The closest candidate is consumed so a prompt genuinely
// repeated later in the same session still pairs with its own direct capture.
func consumeRecoveredPromptMatch(
	counts map[recoveredPromptCorrelationKey][]time.Time,
	key recoveredPromptCorrelationKey,
	at time.Time,
) bool {
	candidates, present := counts[key]
	if !present || len(candidates) == 0 {
		return false
	}
	best := -1
	var bestDistance time.Duration
	for index, candidate := range candidates {
		distance := candidate.Sub(at.UTC())
		if distance < 0 {
			distance = -distance
		}
		if distance > recoveredPromptCorrelationWindow {
			continue
		}
		if best < 0 || distance < bestDistance {
			best = index
			bestDistance = distance
		}
	}
	if best < 0 {
		return false
	}
	remaining := append(candidates[:best:best], candidates[best+1:]...)
	if len(remaining) == 0 {
		delete(counts, key)
	} else {
		counts[key] = remaining
	}
	return true
}

func (deduper *recoveredPromptDeduper) Skip(prompt scannedPrompt) bool {
	if deduper == nil || deduper.build == nil {
		return false
	}
	candidate := deduper.build(prompt)
	if previous, exists := deduper.exact[candidate.EventID]; exists {
		if deduper.onExact != nil {
			deduper.onExact(candidate.EventID)
		}
		delete(deduper.historyAliases, candidate.EventID)
		delete(deduper.exact, candidate.EventID)
		key := recoveredPromptKey(previous)
		if !isHistoryEventID(previous.EventID) {
			consumeRecoveredPromptMatch(deduper.directCorrelations, key, previous.Timestamp)
		}
		if !sameLogicalStoredEvent(previous, candidate) &&
			!deduper.driftReported &&
			deduper.onDrift != nil {
			deduper.driftReported = true
			deduper.onDrift()
		}
		return true
	}
	if _, aliased := deduper.historyAliases[candidate.EventID]; aliased {
		delete(deduper.historyAliases, candidate.EventID)
		return true
	}
	key := recoveredPromptKey(candidate)
	return consumeRecoveredPromptMatch(deduper.directCorrelations, key, candidate.Timestamp)
}

type recoveredPromptAddResult uint8

const (
	recoveredPromptAdded recoveredPromptAddResult = iota
	recoveredPromptBatchFull
	recoveredPromptOversized
)

func newRecoveredPromptCollector() *recoveredPromptCollector {
	return newRecoveredPromptCollectorWithLimits(
		maxRecoveredPromptsPerBatch,
		maxRecoveredPromptBytesPerBatch,
		maxHookInputBytes,
	)
}

func newRecoveredPromptCollectorWithLimits(
	maxPrompts int,
	maxBytes uint64,
	maxPromptBytes int,
) *recoveredPromptCollector {
	return &recoveredPromptCollector{
		maxPrompts:     maxPrompts,
		maxBytes:       maxBytes,
		maxPromptBytes: maxPromptBytes,
	}
}

func (collector *recoveredPromptCollector) noteOversized(count uint64) {
	maxUint64 := ^uint64(0)
	if count > maxUint64-collector.oversized {
		collector.oversized = maxUint64
		return
	}
	collector.oversized += count
}

func (collector *recoveredPromptCollector) TryAdd(prompt scannedPrompt) recoveredPromptAddResult {
	if collector.maxPromptBytes < 1 || len(prompt.Prompt) > collector.maxPromptBytes {
		collector.noteOversized(1)
		return recoveredPromptOversized
	}
	if collector.maxPrompts < 1 ||
		collector.maxBytes < 1 ||
		len(collector.items) >= collector.maxPrompts ||
		uint64(len(prompt.Prompt)) > collector.maxBytes-collector.retainedBytes {
		return recoveredPromptBatchFull
	}
	collector.items = append(collector.items, prompt)
	collector.retainedBytes += uint64(len(prompt.Prompt))
	return recoveredPromptAdded
}

func (collector *recoveredPromptCollector) Add(prompt scannedPrompt) bool {
	return collector.TryAdd(prompt) == recoveredPromptAdded
}

// AddAll is all-or-nothing so provider scan state is never advanced for a file
// whose batch was only partially retained. On the next recovery pass, earlier
// unchanged files are skipped and the deferred file can use a fresh budget.
func (collector *recoveredPromptCollector) AddAll(prompts []scannedPrompt) bool {
	if len(prompts) == 0 {
		return true
	}
	if collector.maxPrompts < 1 ||
		collector.maxBytes < 1 ||
		len(prompts) > collector.maxPrompts-len(collector.items) {
		return false
	}
	var additionalBytes uint64
	for _, prompt := range prompts {
		if collector.maxPromptBytes < 1 || len(prompt.Prompt) > collector.maxPromptBytes {
			collector.noteOversized(1)
			return false
		}
		promptBytes := uint64(len(prompt.Prompt))
		if promptBytes > collector.maxBytes-additionalBytes ||
			collector.retainedBytes+additionalBytes > collector.maxBytes-promptBytes {
			return false
		}
		additionalBytes += promptBytes
	}
	collector.items = append(collector.items, prompts...)
	collector.retainedBytes += additionalBytes
	return true
}

func (collector *recoveredPromptCollector) Values() []scannedPrompt {
	return collector.items
}

func (collector *recoveredPromptCollector) Err(scope string) error {
	if collector.oversized == 0 {
		return nil
	}
	return fmt.Errorf(
		"%s contains %d prompts larger than the supported recovery input limit",
		scope,
		collector.oversized,
	)
}
