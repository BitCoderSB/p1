package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/acme/prompt-audit-template/internal/model"
)

func TestSetupRegistersOnceAndStoresCredentialOutsideRepository(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var request model.RegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		if request.RegistrationCode != "one-time-code" ||
			request.OrganizationID != compiledOrganizationID {
			http.Error(w, "unexpected registration", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(model.RegistrationResponse{
			UserID: "11111111-1111-4111-8111-111111111111", Token: "pa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		})
	}))
	defer server.Close()
	repository := newTestRepository(t, server.URL, []string{model.ToolCodex})
	project := setTestProjectAutoEnroll(t, repository, false)
	configDirectory := useTestConfigDirectory(t)
	t.Chdir(repository.Nested)
	options := SetupOptions{
		Name: "Registered Worker", Email: "worker@example.invalid", ServerURL: server.URL,
		RegistrationCode: "one-time-code", OrganizationID: project.OrganizationID,
	}
	if err := Setup(strings.NewReader(""), io.Discard, options); err != nil {
		t.Fatal(err)
	}
	stored, profile, err := loadUserConfigForProject(project)
	if err != nil || profile == "" || stored.Token != "pa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" || !stored.enrolled() {
		t.Fatalf("stored profile = %#v, profile=%q, err=%v", stored, profile, err)
	}
	relative, err := filepath.Rel(repository.Root, configDirectory)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatal("test credential directory unexpectedly resides inside repository")
	}
	if err := Setup(strings.NewReader(""), io.Discard, options); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("setup registration requests = %d, want exactly one", requests.Load())
	}
}

func TestSetupDoesNotRegisterAnAlreadyEnrolledProfileAgain(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "must not be called", http.StatusInternalServerError)
	}))
	defer server.Close()
	repository := newTestRepository(t, server.URL, []string{model.ToolCodex})
	project := setTestProjectAutoEnroll(t, repository, true)
	useTestConfigDirectory(t)
	if _, err := saveUserConfigForProject(project, UserConfig{
		UserID: "11111111-1111-4111-8111-111111111111", Name: "Already Enrolled",
		Email: "enrolled@example.invalid", ServerURL: server.URL,
		OrganizationID: project.OrganizationID, InstallationID: "22222222-2222-4222-8222-222222222222",
		IdentitySource: "manual", EnrollmentState: enrolledEnrollmentState, Token: "existing-token",
	}); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repository.Nested)
	var output strings.Builder
	if err := Setup(strings.NewReader(""), &output, SetupOptions{}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatalf("setup issued %d registration requests for an enrolled profile", requests.Load())
	}
	if !strings.Contains(output.String(), "ya configurado") {
		t.Fatalf("setup output = %q", output.String())
	}
}
