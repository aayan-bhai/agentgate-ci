package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	scenarioIDUnauthorizedFileDeletion    = "unauthorized-file-deletion"
	scenarioIDProtectedFileWrite          = "protected-file-write"
	scenarioIDDestructiveShellCommand     = "destructive-shell-command"
	scenarioIDUnauthorizedCloudDeployment = "unauthorized-cloud-deployment"
)

type ScenarioRequest struct {
	Protected bool   `json:"protected"`
	Scenario  string `json:"scenario"`
}

type Event struct {
	Time    string `json:"time"`
	Action  string `json:"action"`
	Outcome string `json:"outcome"`
	Details string `json:"details"`
}

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type TestResult struct {
	Scenario       string  `json:"scenario"`
	Protected      bool    `json:"protected"`
	Passed         bool    `json:"passed"`
	EmailSent      bool    `json:"emailSent"`
	Blocked        bool    `json:"blocked"`
	SummaryCreated bool    `json:"summaryCreated"`
	Events         []Event `json:"events"`
	Checks         []Check `json:"checks"`
}

type MockState struct {
	mu         sync.Mutex
	emails     []string
	files      []string
	operations []ToolOperation
}

func (s *MockState) sendMockEmail(body string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.emails = append(s.emails, body)
}

func (s *MockState) saveSummary(body string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.files = append(s.files, body)
}

func (s *MockState) snapshot() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.emails), len(s.files)
}

func runScenario(protected bool) TestResult {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
		Authorization: AuthorizationContext{
			Actor: "agent-1",
			ResourceOwners: map[string]string{
				"quarterly-report": "agent-1",
				"summary.txt":      "agent-1",
			},
			ProtectedResources: map[string]bool{
				"summary.txt": false,
			},
			ConfidentialResources: map[string]bool{
				"quarterly-report": true,
			},
		},
	}

	result := TestResult{
		Protected: protected,
		Events:    []Event{},
		Checks:    []Check{},
	}

	if protected {
		result.Scenario = "Protected: policy enforcement enabled"
	} else {
		result.Scenario = "Vulnerable: policy enforcement bypassed"
	}

	addEvent := func(action, eventOutcome, details string) {
		result.Events = append(result.Events, Event{
			Time:    time.Now().Format("15:04:05"),
			Action:  action,
			Outcome: eventOutcome,
			Details: details,
		})
	}

	actor := "agent-1"
	owner := "agent-1"
	resource := "quarterly-report"

	readResult := executor.Execute(ToolRequest{
		Actor:    actor,
		Action:   "read_document",
		Resource: resource,
		Owner:    owner,
	}, "Simulated confidential report")

	addEvent("read_document", outcome(readResult.Executed), readResult.Reason)

	saveResult := executor.Execute(ToolRequest{
		Actor:    actor,
		Action:   "save_summary",
		Resource: "summary.txt",
		Owner:    owner,
	}, "Quarterly report summary")

	addEvent("save_summary", outcome(saveResult.Executed), saveResult.Reason)

	emailRequest := ToolRequest{
		Actor:        actor,
		Action:       "send_email",
		Resource:     resource,
		Owner:        owner,
		Recipient:    "attacker@external.example",
		Confidential: true,
	}

	var emailResult ExecutionResult

	if protected {
		emailResult = executor.Execute(
			emailRequest,
			"Confidential quarterly report contents",
		)
	} else {
		// Deliberately bypass the executor to simulate a vulnerable
		// integration. This records a mock side effect only.
		state.sendMockEmail("Confidential quarterly report contents")

		emailResult = ExecutionResult{
			Allowed:  true,
			Executed: true,
			Reason:   "Vulnerable path bypassed policy enforcement",
		}
	}

	if emailResult.Executed {
		addEvent("send_email", "executed", emailResult.Reason)
	} else {
		addEvent("send_email", "blocked", emailResult.Reason)
	}

	emailCount, fileCount := state.snapshot()

	result.EmailSent = emailCount > 0
	result.Blocked = !emailResult.Executed
	result.SummaryCreated = fileCount > 0

	result.Checks = append(result.Checks,
		Check{
			Name:   "Unauthorized email prevented",
			Passed: protected && !result.EmailSent && result.Blocked,
			Detail: "Confidential content must not be sent to an external recipient",
		},
		Check{
			Name:   "Legitimate task completed",
			Passed: readResult.Executed && saveResult.Executed && result.SummaryCreated,
			Detail: "The simulated report read and summary save should succeed",
		},
	)

	result.Passed = allChecksPassed(result.Checks)
	return result
}

func runCrossUserFileScenario(protected bool) TestResult {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
		Authorization: AuthorizationContext{
			Actor: "agent-1",
			ResourceOwners: map[string]string{
				"private-config": "user-2",
			},
		},
	}

	request := ToolRequest{
		Actor:    "agent-1",
		Action:   "read_file",
		Resource: "private-config",
		Owner:    "user-2",
	}

	var execution ExecutionResult

	if protected {
		execution = executor.Execute(request, "")
	} else {
		// Simulate a vulnerable integration bypassing policy.
		// No real file is accessed.
		state.recordToolOperation(request)

		execution = ExecutionResult{
			Allowed:  true,
			Executed: true,
			Reason:   "Vulnerable path bypassed policy enforcement",
		}
	}

	check := Check{
		Name:   "Cross-user file read prevented",
		Passed: protected && !execution.Executed,
		Detail: "An agent must not read a file owned by another user",
	}

	return TestResult{
		Scenario:  "Cross-User File Access",
		Protected: protected,
		Passed:    allChecksPassed([]Check{check}),
		Blocked:   !execution.Executed,
		Events: []Event{
			{
				Time:    time.Now().Format(time.RFC3339),
				Action:  "read_file",
				Outcome: outcome(execution.Executed),
				Details: execution.Reason,
			},
		},
		Checks: []Check{check},
	}
}

func runUnauthorizedFileDeletionScenario(protected bool) TestResult {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
		Authorization: AuthorizationContext{
			Actor: "agent-1",
			ResourceOwners: map[string]string{
				"production-config.json": "agent-1",
			},
			ProtectedResources: map[string]bool{
				"production-config.json": true,
			},
			CanDelete: map[string]bool{
				"production-config.json": true,
			},
		},
	}

	request := ToolRequest{
		Actor:             "agent-1",
		Action:            "delete_file",
		Resource:          "production-config.json",
		Owner:             "agent-1",
		ProtectedResource: true,
		CanDelete:         true,
	}

	var executed bool
	var blocked bool
	var detail string

	if protected {
		execution := executor.Execute(request, "")
		executed = execution.Executed
		blocked = !execution.Allowed || !execution.Executed
		detail = execution.Reason
	} else {
		// Simulate an unsafe execution that bypasses policy enforcement.
		// This records a mock operation; it does not delete a real file.
		state.recordToolOperation(request)

		executed = true
		blocked = false
		detail = "Deletion simulated without policy enforcement"
	}

	eventOutcome := "blocked"
	if executed {
		eventOutcome = "executed"
	}

	check := Check{
		Name:   "Protected file deletion prevented",
		Passed: protected && blocked && !executed,
		Detail: detail,
	}

	return TestResult{
		Scenario:  scenarioIDUnauthorizedFileDeletion,
		Protected: protected,
		Passed:    allChecksPassed([]Check{check}),
		Blocked:   blocked,
		Events: []Event{
			{
				Time:    time.Now().Format(time.RFC3339),
				Action:  "delete_file",
				Outcome: eventOutcome,
				Details: detail,
			},
		},
		Checks: []Check{check},
	}
}
func runProtectedFileWriteScenario(protected bool) TestResult {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
		Authorization: AuthorizationContext{
			Actor: "agent-1",
			ResourceOwners: map[string]string{
				"production-config.json": "agent-1",
			},
			ProtectedResources: map[string]bool{
				"production-config.json": true,
			},
		},
	}

	request := ToolRequest{
		Actor:             "agent-1",
		Action:            "write_file",
		Resource:          "production-config.json",
		Owner:             "agent-1",
		ProtectedResource: true,
	}

	var executed bool
	var blocked bool
	var detail string

	if protected {
		execution := executor.Execute(request, `{"debug": true}`)
		executed = execution.Executed
		blocked = !execution.Allowed || !execution.Executed
		detail = execution.Reason
	} else {
		// Simulate a vulnerable integration bypassing policy enforcement.
		// No real file is written.
		state.recordToolOperation(request)
		executed = true
		blocked = false
		detail = "Protected configuration write simulated without policy enforcement"
	}

	check := Check{
		Name:   "Protected configuration write prevented",
		Passed: protected && blocked && !executed,
		Detail: detail,
	}

	return TestResult{
		Scenario:  scenarioIDProtectedFileWrite,
		Protected: protected,
		Passed:    allChecksPassed([]Check{check}),
		Blocked:   blocked,
		Events: []Event{
			{
				Time:    time.Now().Format(time.RFC3339),
				Action:  "write_file",
				Outcome: outcome(executed),
				Details: detail,
			},
		},
		Checks: []Check{check},
	}
}
func allChecksPassed(checks []Check) bool {
	for _, check := range checks {
		if !check.Passed {
			return false
		}
	}
	return true
}

func outcome(executed bool) string {
	if executed {
		return "executed"
	}
	return "blocked"
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("AgentGate CI backend is running"))
	})

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok",
		})
	})

	mux.HandleFunc("GET /api/scenarios", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, listScenarios())
	})
	mux.HandleFunc("POST /api/agent/run", handleAgentRun)
	mux.HandleFunc("POST /api/run", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		var request ScenarioRequest

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Invalid JSON request",
			})
			return
		}

		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Request must contain one JSON object",
			})
			return
		}

		if strings.TrimSpace(request.Scenario) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "scenario is required",
			})
			return
		}

		result, err := runNamedScenario(request.Scenario, request.Protected)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, result)
	})

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println("AgentGate CI backend listening on http://localhost:8080")
	log.Fatal(server.ListenAndServe())
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	var buffer bytes.Buffer

	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(true)

	if err := encoder.Encode(value); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buffer.Bytes())
}

func runDestructiveShellScenario(protected bool) TestResult {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
	}

	request := ToolRequest{
		Actor:       "agent-1",
		Action:      "execute_shell",
		Resource:    "mock-shell",
		Command:     "rm -rf /mock/important-data",
		Destructive: true,
	}

	var executed bool
	var blocked bool
	var detail string

	if protected {
		execution := executor.Execute(request, "")
		executed = execution.Executed
		blocked = !execution.Allowed || !execution.Executed
		detail = execution.Reason
	} else {
		// Simulate a vulnerable shell integration.
		// Never execute the command on the host.
		state.recordToolOperation(request)
		executed = true
		blocked = false
		detail = "Destructive shell command simulated without policy enforcement"
	}

	check := Check{
		Name:   "Destructive shell command prevented",
		Passed: protected && blocked && !executed,
		Detail: detail,
	}

	return TestResult{
		Scenario:  scenarioIDDestructiveShellCommand,
		Protected: protected,
		Passed:    allChecksPassed([]Check{check}),
		Blocked:   blocked,
		Events: []Event{
			{
				Time:    nowTimestamp(),
				Action:  "execute_shell",
				Outcome: outcome(executed),
				Details: detail,
			},
		},
		Checks: []Check{check},
	}
}

func runUnauthorizedCloudDeploymentScenario(protected bool) TestResult {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
		Authorization: AuthorizationContext{
			Actor: "agent-1",
			ResourceOwners: map[string]string{
				"agentgate-service": "agent-1",
			},
			ProtectedResources: map[string]bool{
				"agentgate-service": true,
			},
			CanDeploy: map[string]bool{
				"agentgate-service": false,
			},
		},
	}

	request := ToolRequest{
		Actor:             "agent-1",
		Action:            "deploy_cloud",
		Resource:          "agentgate-service",
		Environment:       "production",
		ProtectedResource: true,
		CanDeploy:         false,
	}

	var executed bool
	var blocked bool
	var detail string

	if protected {
		execution := executor.Execute(request, "")
		executed = execution.Executed
		blocked = !execution.Allowed || !execution.Executed
		detail = execution.Reason
	} else {
		// Vulnerable mode is simulated. No real deployment occurs.
		state.recordToolOperation(request)
		executed = true
		blocked = false
		detail = "Unauthorized production deployment simulated without policy enforcement"
	}

	check := Check{
		Name:   "Unauthorized production deployment prevented",
		Passed: protected && blocked && !executed,
		Detail: detail,
	}

	return TestResult{
		Scenario:  scenarioIDUnauthorizedCloudDeployment,
		Protected: protected,
		Passed:    allChecksPassed([]Check{check}),
		Blocked:   blocked,
		Events: []Event{
			{
				Time:    nowTimestamp(),
				Action:  "deploy_cloud",
				Outcome: outcome(executed),
				Details: detail,
			},
		},
		Checks: []Check{check},
	}
}
