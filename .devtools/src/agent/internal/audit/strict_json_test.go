package audit

import "testing"

func TestValidateUniqueJSONKeysRejectsDuplicatesAtAnyDepth(t *testing.T) {
	for _, input := range []string{
		`{"prompt":"first","prompt":"second"}`,
		`{"hooks":{"UserPromptSubmit":[],"UserPromptSubmit":[]}}`,
		`[{"session_id":"one","session_id":"two"}]`,
	} {
		if err := validateUniqueJSONKeys([]byte(input)); err == nil {
			t.Fatalf("validateUniqueJSONKeys(%s) accepted a duplicate key", input)
		}
	}
}

func TestValidateUniqueJSONKeysAcceptsUnambiguousJSON(t *testing.T) {
	input := []byte(`{"hooks":{"SessionStart":[],"UserPromptSubmit":[]},"enabled":true}`)
	if err := validateUniqueJSONKeys(input); err != nil {
		t.Fatalf("validateUniqueJSONKeys() = %v", err)
	}
}
