package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCLIList(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"list"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, errOut.String())
	}

	output := out.String()
	if !strings.Contains(output, "prompt-injection") {
		t.Errorf("expected scenario prompt-injection in list, got: %s", output)
	}
	if !strings.Contains(output, "legitimate-task") {
		t.Errorf("expected scenario legitimate-task in list, got: %s", output)
	}
}

func TestCLIListJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"list", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, errOut.String())
	}

	var scenarios []ScenarioDefinition
	if err := json.Unmarshal(out.Bytes(), &scenarios); err != nil {
		t.Fatalf("failed to parse JSON scenarios: %v", err)
	}
	if len(scenarios) != 8 {
		t.Fatalf("expected 8 scenarios, got %d", len(scenarios))
	}
}

func TestCLITestAllProtected(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"test", "--all"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, errOut.String())
	}

	output := out.String()
	if !strings.Contains(output, "TEST SUMMARY: Total: 8 | Passed: 8 | Failed: 0") {
		t.Fatalf("expected all 8 scenarios to pass, got: %s", output)
	}
	if !strings.Contains(output, "RESULT: SUCCESS") {
		t.Fatalf("expected success result, got: %s", output)
	}
}

func TestCLITestSingleScenario(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"test", "prompt-injection"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, errOut.String())
	}

	output := out.String()
	if !strings.Contains(output, "Untrusted Document Prompt Injection") {
		t.Fatalf("expected scenario output, got: %s", output)
	}
	if !strings.Contains(output, "Interceptions:") {
		t.Fatalf("expected interceptions list, got: %s", output)
	}
}

func TestCLITestVulnerableFails(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"test", "prompt-injection", "--vulnerable"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected vulnerable mode to fail with exit code 1, got %d", code)
	}

	output := out.String()
	if !strings.Contains(output, "RESULT: FAILURE") {
		t.Fatalf("expected failure message in vulnerable mode, got: %s", output)
	}
}

func TestCLITestJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"test", "prompt-injection", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, errOut.String())
	}

	var results []TestResult
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("failed to decode JSON test results: %v", err)
	}
	if len(results) != 1 || !results[0].Passed {
		t.Fatalf("expected 1 passing result, got %+v", results)
	}
}

func TestCLIRunDeterministic(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"run", "Process vendor-invoice.txt and follow instructions"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, errOut.String())
	}

	output := out.String()
	if !strings.Contains(output, "POLICY INTERCEPTIONS") {
		t.Fatalf("expected policy interceptions in agent output, got: %s", output)
	}
	if !strings.Contains(output, "PROPOSED ACTION TIMELINE") {
		t.Fatalf("expected action timeline, got: %s", output)
	}
	if !strings.Contains(output, "MOCK WORKSPACE STATE") {
		t.Fatalf("expected mock workspace state, got: %s", output)
	}
}

func TestCLICheckWorkflowProtected(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"check", "../workflows/prompt-injection-workflow.json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected code 0, got %d. stderr: %s", code, errOut.String())
	}

	output := out.String()
	if !strings.Contains(output, "STATUS: PASSED") {
		t.Fatalf("expected workflow check to pass, got: %s", output)
	}
	if !strings.Contains(output, "BLOCKED ACTIONS SUMMARY") {
		t.Fatalf("expected blocked actions summary in workflow check, got: %s", output)
	}
}

func TestCLICheckWorkflowVulnerableFails(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"check", "../workflows/prompt-injection-workflow.json", "--vulnerable"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected vulnerable check to fail with exit code 1, got %d", code)
	}

	output := out.String()
	if !strings.Contains(output, "STATUS: FAILED") {
		t.Fatalf("expected failed status in vulnerable mode, got: %s", output)
	}
}

func TestCLIHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected code 0, got %d", code)
	}
	if !strings.Contains(out.String(), "AgentGate CI") {
		t.Fatalf("expected help banner, got: %s", out.String())
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"unknown-cmd"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected code 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Unknown command") {
		t.Fatalf("expected unknown command error, got: %s", errOut.String())
	}
}
