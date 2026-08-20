package audit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
	"github.com/acme/prompt-audit-template/internal/repositoryidentity"
)

type APIClient struct {
	baseURL   string
	token     string
	userID    string
	userEmail string
	client    *http.Client
}

type eventHTTPError struct {
	statusCode int
}

func (e *eventHTTPError) Error() string {
	return fmt.Sprintf("event server returned HTTP %d", e.statusCode)
}

func permanentEventRejection(err error) (int, bool) {
	var statusErr *eventHTTPError
	if !errors.As(err, &statusErr) {
		return 0, false
	}
	switch statusErr.statusCode {
	case http.StatusBadRequest, http.StatusConflict, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return statusErr.statusCode, true
	default:
		return statusErr.statusCode, false
	}
}

type EnrollmentRequest struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
	OrganizationID string `json:"organization_id"`
	InstallationID string `json:"installation_id"`
}

func NewAPIClient(baseURL, token string, timeout time.Duration) (*APIClient, error) {
	canonicalBaseURL, err := canonicalServerURL(baseURL)
	if err != nil {
		return nil, err
	}
	return &APIClient{
		baseURL: canonicalBaseURL,
		token:   token,
		client: &http.Client{
			Timeout: timeout,
			// Audit endpoints are exact. Following a redirect can transform a POST
			// or carry an Authorization header somewhere it was never configured.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// WithEventIdentity returns a copy that binds every queued event to the
// identity authenticated by this token. This lets an offline, provisionally
// identified backlog be enrolled in O(1) without rewriting the queue file.
func (c *APIClient) WithEventIdentity(userID, email string) *APIClient {
	bound := *c
	bound.userID = strings.TrimSpace(userID)
	bound.userEmail = strings.TrimSpace(email)
	return &bound
}

func (c *APIClient) SendEvent(event model.Event) error {
	if c.userID != "" && c.userEmail != "" {
		event.UserID = c.userID
		event.UserEmail = c.userEmail
	}
	normalizedRemote, err := repositoryidentity.Normalize(event.RepositoryRemote)
	if err != nil {
		return errors.New("queued event contains an invalid repository identity")
	}
	event.RepositoryRemote = normalizedRemote
	body, err := json.Marshal(event)
	if err != nil {
		return errors.New("encode event")
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/v1/events", bytes.NewReader(body))
	if err != nil {
		return errors.New("create event request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return errors.New("event server unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &eventHTTPError{statusCode: resp.StatusCode}
	}
	acknowledgementBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil || len(acknowledgementBody) > 64*1024 {
		return errors.New("event server returned an invalid acknowledgement")
	}
	var acknowledgement model.EventResponse
	if err := json.Unmarshal(acknowledgementBody, &acknowledgement); err != nil ||
		!acknowledgement.Accepted || acknowledgement.EventID != event.EventID {
		return errors.New("event server returned an invalid acknowledgement")
	}
	return nil
}

func Register(baseURL string, request model.RegistrationRequest) (model.RegistrationResponse, error) {
	client, err := NewAPIClient(baseURL, "", 8*time.Second)
	if err != nil {
		return model.RegistrationResponse{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return model.RegistrationResponse{}, errors.New("encode registration")
	}
	req, err := http.NewRequest(http.MethodPost, client.baseURL+"/api/v1/register", bytes.NewReader(body))
	if err != nil {
		return model.RegistrationResponse{}, errors.New("create registration request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.client.Do(req)
	if err != nil {
		return model.RegistrationResponse{}, errors.New("registration server unavailable")
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 64*1024)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, limited)
		return model.RegistrationResponse{}, fmt.Errorf("registration server returned HTTP %d", resp.StatusCode)
	}
	var result model.RegistrationResponse
	if err := json.NewDecoder(limited).Decode(&result); err != nil {
		return model.RegistrationResponse{}, errors.New("invalid registration response")
	}
	if !validUUID(result.UserID) || !validAgentToken(result.Token) {
		return model.RegistrationResponse{}, errors.New("registration response omitted credentials")
	}
	return result, nil
}

func Enroll(baseURL, token string, request EnrollmentRequest, timeout time.Duration) (model.EnrollmentResponse, error) {
	if !validAgentToken(token) {
		return model.EnrollmentResponse{}, errors.New("automatic enrollment token is invalid")
	}
	client, err := NewAPIClient(baseURL, "", timeout)
	if err != nil {
		return model.EnrollmentResponse{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return model.EnrollmentResponse{}, errors.New("encode enrollment")
	}
	req, err := http.NewRequest(http.MethodPost, client.baseURL+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return model.EnrollmentResponse{}, errors.New("create enrollment request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Enrollment "+token)
	resp, err := client.client.Do(req)
	if err != nil {
		return model.EnrollmentResponse{}, errors.New("enrollment server unavailable")
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 64*1024)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, limited)
		return model.EnrollmentResponse{}, fmt.Errorf("enrollment server returned HTTP %d", resp.StatusCode)
	}
	var result model.EnrollmentResponse
	if err := json.NewDecoder(limited).Decode(&result); err != nil {
		return model.EnrollmentResponse{}, errors.New("invalid enrollment response")
	}
	if !validUUID(result.UserID) {
		return model.EnrollmentResponse{}, errors.New("enrollment response omitted user identity")
	}
	return result, nil
}

func validAgentToken(token string) bool {
	if !strings.HasPrefix(token, "pa_") {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "pa_"))
	return err == nil && len(raw) == 32
}
