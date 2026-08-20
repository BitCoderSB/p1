package model

import "time"

const (
	ToolClaudeCode  = "claude-code"
	ToolCodex       = "codex"
	ToolCopilotCLI  = "copilot-cli"
	ToolAntigravity = "antigravity"
)

// Event is the deliberately narrow wire contract between the agent and server.
// It has no field in which an assistant response can be submitted.
type Event struct {
	EventID          string    `json:"event_id"`
	Timestamp        time.Time `json:"timestamp"`
	UserID           string    `json:"user_id"`
	UserEmail        string    `json:"user_email"`
	Tool             string    `json:"tool"`
	RepositoryName   string    `json:"repository_name"`
	RepositoryRemote string    `json:"repository_remote"`
	Branch           string    `json:"branch"`
	CommitHash       string    `json:"commit_hash"`
	SessionID        string    `json:"session_id"`
	Prompt           string    `json:"prompt"`
}

type RegistrationRequest struct {
	Name             string `json:"name"`
	Email            string `json:"email"`
	OrganizationID   string `json:"organization_id"`
	RegistrationCode string `json:"registration_code,omitempty"`
}

type RegistrationResponse struct {
	UserID string `json:"user_id"`
	Token  string `json:"token"`
}

// EnrollmentRequest contains only non-secret identity claims and a stable local
// installation identifier. The client-generated token is carried exclusively
// in the Authorization header and is never echoed in a response.
type EnrollmentRequest struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
	OrganizationID string `json:"organization_id"`
	InstallationID string `json:"installation_id"`
}

type EnrollmentResponse struct {
	UserID string `json:"user_id"`
}

type EventResponse struct {
	Accepted  bool   `json:"accepted"`
	Duplicate bool   `json:"duplicate"`
	EventID   string `json:"event_id"`
}
