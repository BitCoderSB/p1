package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

// The prompt field is matched exactly. An earlier attempt took "the longest
// string in the payload" and picked an internal allow-list of shell commands in
// four of five real prompts, which would have put machine text in the register.
func TestAntigravityPromptFieldIsExactNotHeuristic(t *testing.T) {
	// A payload whose longest string is NOT the prompt, mirroring the real
	// shape: an unrelated field holds far more text than field 19.2 does.
	payload := protoMessage(
		protoLenField(19, protoLenField(2, []byte("hola"))),
		protoLenField(31, []byte(strings.Repeat("command(adb)\n", 40))),
	)
	raw, ok := protoField(payload, antigravityPromptField...)
	if !ok {
		t.Fatal("the prompt field must resolve")
	}
	if string(raw) != "hola" {
		t.Fatalf("prompt = %q, want the exact field, not the longest string", string(raw))
	}

	// A payload without the field yields nothing rather than a guess.
	if _, ok := protoField(protoMessage(protoLenField(31, []byte("solo ruido"))),
		antigravityPromptField...); ok {
		t.Fatal("a payload without the prompt field must not resolve to anything")
	}
}

// A conversation belonging to another project must never be imported, and the
// decision must be reachable from the metadata alone.
func TestAntigravityScopeRejectsOtherProjects(t *testing.T) {
	repo := t.TempDir()
	other := t.TempDir()

	for _, testCase := range []struct {
		name   string
		uri    string
		inside bool
	}{
		{name: "this repository", uri: fileURI(repo), inside: true},
		{name: "another project", uri: fileURI(other), inside: false},
		{name: "percent-encoded drive", uri: percentEncodeDrive(fileURI(repo)), inside: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			folder, ok := antigravityFolderPath(testCase.uri)
			if !ok {
				t.Fatalf("could not parse %q", testCase.uri)
			}
			got := classifyProviderCWD(folder, repo) == providerPathInside
			if got != testCase.inside {
				t.Fatalf("scope for %q = %v, want %v (folder %q)",
					testCase.uri, got, testCase.inside, folder)
			}
		})
	}

	// A URI that names no folder must never be read as "inside".
	for _, bad := range []string{"", "not a uri", "https://example.invalid/x"} {
		if _, ok := antigravityFolderPath(bad); ok {
			t.Fatalf("%q must not parse as a workspace folder", bad)
		}
	}
}

// The event id must survive a redaction-policy change and a re-read, or every
// pass would re-import the whole history under new identifiers.
func TestAntigravityEventIDIsStableAcrossTextAndTime(t *testing.T) {
	first := antigravityHistoryEventID("conversation-a", 7)
	if first != antigravityHistoryEventID("conversation-a", 7) {
		t.Fatal("the same step must always produce the same event id")
	}
	if first == antigravityHistoryEventID("conversation-a", 8) {
		t.Fatal("different steps must not collide")
	}
	if first == antigravityHistoryEventID("conversation-b", 7) {
		t.Fatal("different conversations must not collide")
	}
	if !strings.HasPrefix(first, "antigravity-h-") {
		t.Fatalf("event id %q must be recognisable as recovered history", first)
	}
	if !isHistoryEventID(first) {
		t.Fatal("the id must be classified as history, or dedupe treats it as a direct capture")
	}
}

// A step with no readable time still has to be storable: the event contract
// requires a timestamp, and dropping the prompt would be the worse outcome.
func TestAntigravityStepTimeFallsBackInsteadOfDroppingThePrompt(t *testing.T) {
	fallback := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	stamped := protoMessage(protoLenField(5, protoLenField(1, protoVarintField64(1, 1787059976))))
	if got := antigravityStepTime(stamped, fallback); !got.Equal(time.Unix(1787059976, 0).UTC()) {
		t.Fatalf("stamped step time = %v, want the recorded instant", got)
	}

	if got := antigravityStepTime(protoMessage(protoLenField(9, []byte("x"))), fallback); !got.Equal(fallback) {
		t.Fatalf("unstamped step time = %v, want the fallback", got)
	}

	// A value outside any plausible capture date is not a date.
	bogus := protoMessage(protoLenField(5, protoLenField(1, protoVarintField64(1, 42))))
	if got := antigravityStepTime(bogus, fallback); !got.Equal(fallback) {
		t.Fatalf("implausible epoch accepted: %v", got)
	}
}

// Antigravity has no hook, so storage is the only gate. It must accept the
// adapter, and must still refuse anything this build cannot capture.
func TestAntigravityIsAVerifiedStorageAdapter(t *testing.T) {
	if !verifiedPromptAdapter(model.ToolAntigravity) {
		t.Fatal("antigravity events must be storable")
	}
	for _, tool := range []string{model.ToolClaudeCode, model.ToolCodex, model.ToolCopilotCLI} {
		if !verifiedPromptAdapter(tool) {
			t.Fatalf("%s must remain storable", tool)
		}
	}
	for _, tool := range []string{"", "cursor", "windsurf", "ANTIGRAVITY"} {
		if verifiedPromptAdapter(tool) {
			t.Fatalf("%q must not be storable: this build cannot capture it", tool)
		}
	}
}

// --- helpers that build protobuf wire format for the fixtures above ---

func protoMessage(parts ...[]byte) []byte {
	out := make([]byte, 0)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func protoLenField(number int, body []byte) []byte {
	out := appendVarint(nil, uint64(number)<<3|2)
	out = appendVarint(out, uint64(len(body)))
	return append(out, body...)
}

func protoVarintField64(number int, value uint64) []byte {
	out := appendVarint(nil, uint64(number)<<3|0)
	return appendVarint(out, value)
}

func appendVarint(out []byte, value uint64) []byte {
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}

func fileURI(path string) string {
	return "file:///" + filepath.ToSlash(path)
}

// percentEncodeDrive encodes the drive colon the way VS Code-derived editors
// sometimes record it, leaving the scheme itself untouched.
func percentEncodeDrive(uri string) string {
	const prefix = "file:///"
	rest := strings.TrimPrefix(uri, prefix)
	if index := strings.Index(rest, ":"); index >= 0 {
		rest = rest[:index] + "%3A" + rest[index+1:]
	}
	return prefix + rest
}

// Every scanner's history prefix must be in the shared registry. A missing one
// makes the dedupe machinery treat recovered rows as direct captures.
func TestEveryScannerHistoryPrefixIsRegistered(t *testing.T) {
	for _, sample := range []string{
		codexHistoryEventID("session", 0, time.Unix(0, 0)),
		antigravityHistoryEventID("conversation", 0),
	} {
		if !isHistoryEventID(sample) {
			t.Fatalf("%q is not recognised as recovered history", sample)
		}
	}
	for _, prefix := range historyEventIDPrefixes {
		if !isHistoryEventID(prefix + "abc") {
			t.Fatalf("registered prefix %q is not honoured", prefix)
		}
	}
	if isHistoryEventID("hook-e-abc") {
		t.Fatal("a direct capture must never be classified as recovered history")
	}
}
