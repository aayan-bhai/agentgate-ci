package main

import "testing"

func TestProtectedScenarioBlocksUnauthorizedEmail(t *testing.T) {
	result := runScenario(true)

	if !result.Blocked {
		t.Fatal("expected confidential external email to be blocked")
	}

	if !result.Passed {
		t.Fatal("expected protected scenario to pass")
	}

	if result.EmailSent {
		t.Fatal("expected no email to be sent")
	}
}

func TestVulnerableScenarioDetectsUnauthorizedEmail(t *testing.T) {
	result := runScenario(false)

	if result.Blocked {
		t.Fatal("expected vulnerable scenario not to block the email")
	}

	if result.Passed {
		t.Fatal("expected vulnerable scenario to fail")
	}

	if !result.EmailSent {
		t.Fatal("expected simulated email to be recorded")
	}
}

func TestRegisteredScenarios(t *testing.T) {
	scenarios := listScenarios()

	expected := map[string]bool{
		"confidential-email":            false,
		"cross-user-file-read":          false,
		"unauthorized-file-deletion":    false,
		"protected-file-write":          false,
		"destructive-shell-command":     false,
		"unauthorized-cloud-deployment": true,
	}

	if len(scenarios) != 6 {
		t.Fatalf("expected 5 scenarios, got %d", len(scenarios))
	}

	for _, scenario := range scenarios {
		if _, exists := expected[scenario.ID]; !exists {
			t.Errorf("unexpected scenario registered: %s", scenario.ID)
			continue
		}

		expected[scenario.ID] = true
	}

	for id, found := range expected {
		if !found {
			t.Errorf("expected scenario %q was not registered", id)
		}
	}
}

func TestNamedScenariosProtectedAndVulnerable(t *testing.T) {
	ids := []string{
		"confidential-email",
		"cross-user-file-read",
		"unauthorized-file-deletion",
		"protected-file-write",
		"destructive-shell-command",
		"unauthorized-cloud-deployment",
	}

	for _, id := range ids {
		t.Run(id+"/protected", func(t *testing.T) {
			result, err := runNamedScenario(id, true)
			if err != nil {
				t.Fatalf("protected scenario returned an error: %v", err)
			}

			if !result.Passed {
				t.Fatalf("expected protected scenario %q to pass: %+v", id, result)
			}
		})

		t.Run(id+"/vulnerable", func(t *testing.T) {
			result, err := runNamedScenario(id, false)
			if err != nil {
				t.Fatalf("vulnerable scenario returned an error: %v", err)
			}

			if result.Passed {
				t.Fatalf("expected vulnerable scenario %q to fail: %+v", id, result)
			}
		})
	}
}

func TestFileDeletionEventOutcomeMatchesExecution(t *testing.T) {
	protected, err := runNamedScenario("unauthorized-file-deletion", true)
	if err != nil {
		t.Fatalf("protected scenario returned an error: %v", err)
	}

	if len(protected.Events) != 1 || protected.Events[0].Outcome != "blocked" {
		t.Fatalf("expected one blocked deletion event, got %+v", protected.Events)
	}

	vulnerable, err := runNamedScenario("unauthorized-file-deletion", false)
	if err != nil {
		t.Fatalf("vulnerable scenario returned an error: %v", err)
	}

	if len(vulnerable.Events) != 1 || vulnerable.Events[0].Outcome != "executed" {
		t.Fatalf("expected one executed deletion event, got %+v", vulnerable.Events)
	}
}

func TestUnknownScenarioReturnsError(t *testing.T) {
	_, err := runNamedScenario("unknown-scenario", true)

	if err == nil {
		t.Fatal("expected an error for an unknown scenario")
	}
}

func TestProtectedFileWriteScenarioOutcomes(t *testing.T) {
	protected, err := runNamedScenario("protected-file-write", true)
	if err != nil {
		t.Fatalf("protected scenario returned an error: %v", err)
	}

	if !protected.Passed || !protected.Blocked {
		t.Fatalf("protected write should be blocked and pass: %+v", protected)
	}

	if len(protected.Events) != 1 || protected.Events[0].Outcome != "blocked" {
		t.Fatalf("expected one blocked event, got %+v", protected.Events)
	}

	vulnerable, err := runNamedScenario("protected-file-write", false)
	if err != nil {
		t.Fatalf("vulnerable scenario returned an error: %v", err)
	}

	if vulnerable.Passed || vulnerable.Blocked {
		t.Fatalf("vulnerable write should execute and fail: %+v", vulnerable)
	}

	if len(vulnerable.Events) != 1 || vulnerable.Events[0].Outcome != "executed" {
		t.Fatalf("expected one executed event, got %+v", vulnerable.Events)
	}
}

func TestExecutorBlocksProtectedFileWrite(t *testing.T) {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
	}

	result := executor.Execute(ToolRequest{
		Actor:             "agent-1",
		Action:            "write_file",
		Resource:          "production-config.json",
		Owner:             "agent-1",
		ProtectedResource: true,
	}, `{"debug": true}`)

	if result.Allowed || result.Executed {
		t.Fatalf("protected file write should be denied, got %+v", result)
	}

	if len(state.operationSnapshot()) != 0 {
		t.Fatal("denied write must not be recorded as an executed operation")
	}
}

func TestExecutorAllowsUnprotectedOwnedFileWrite(t *testing.T) {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
		Authorization: AuthorizationContext{
			Actor: "agent-1",
			ResourceOwners: map[string]string{
				"notes.txt": "agent-1",
			},
			ProtectedResources: map[string]bool{
				"notes.txt": false,
			},
		},
	}

	result := executor.Execute(ToolRequest{
		Actor:    "agent-1",
		Action:   "write_file",
		Resource: "notes.txt",
		Owner:    "agent-1",
	}, "safe content")

	if !result.Allowed || !result.Executed {
		t.Fatalf("authorized unprotected file write should execute, got %+v", result)
	}

	operations := state.operationSnapshot()
	if len(operations) != 1 || operations[0].Action != "write_file" {
		t.Fatalf("expected one recorded mock write, got %+v", operations)
	}
}

func TestExecutorBlocksDestructiveShellCommand(t *testing.T) {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
	}

	result := executor.Execute(ToolRequest{
		Actor:       "agent-1",
		Action:      "execute_shell",
		Resource:    "mock-shell",
		Command:     "rm -rf /mock/important-data",
		Destructive: true,
	}, "")

	if result.Allowed || result.Executed {
		t.Fatalf("destructive shell command should be denied, got %+v", result)
	}

	if len(state.operationSnapshot()) != 0 {
		t.Fatal("denied shell command must not be recorded as executed")
	}
}
