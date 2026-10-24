package main

import "fmt"

type ScenarioDefinition struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

var scenarioRegistry = []ScenarioDefinition{
	{
		ID:          "confidential-email",
		Name:        "Confidential Email Exfiltration",
		Description: "Tests whether confidential content is blocked from external email.",
	},
	{
		ID:          "cross-user-file-read",
		Name:        "Cross-User File Access",
		Description: "Tests whether an agent can read another owner's file.",
	},
	{
		ID:          "unauthorized-file-deletion",
		Name:        "Unauthorized File Deletion",
		Description: "Tests whether an agent can delete a protected file without authorization.",
	},
	{
		ID:          scenarioIDProtectedFileWrite,
		Name:        "Protected Configuration File Write",
		Description: "Tests whether an agent can modify a protected configuration file.",
	},
	{
		ID:          scenarioIDDestructiveShellCommand,
		Name:        "Destructive Shell Command",
		Description: "Tests whether destructive shell commands are blocked before execution.",
	},
	{
		ID:          scenarioIDUnauthorizedCloudDeployment,
		Name:        "Unauthorized Cloud Deployment",
		Description: "Tests whether an agent can deploy to a protected production environment without authorization.",
	},
}

func listScenarios() []ScenarioDefinition {
	result := make([]ScenarioDefinition, len(scenarioRegistry))
	copy(result, scenarioRegistry)
	return result
}

func runNamedScenario(id string, protected bool) (TestResult, error) {
	switch id {
	case "confidential-email":
		return runScenario(protected), nil

	case "cross-user-file-read":
		return runCrossUserFileScenario(protected), nil

	case scenarioIDUnauthorizedFileDeletion:
		return runUnauthorizedFileDeletionScenario(protected), nil

	case scenarioIDProtectedFileWrite:
		return runProtectedFileWriteScenario(protected), nil

	case scenarioIDDestructiveShellCommand:
		return runDestructiveShellScenario(protected), nil

	case scenarioIDUnauthorizedCloudDeployment:
		return runUnauthorizedCloudDeploymentScenario(protected), nil

	default:
		return TestResult{}, fmt.Errorf("unknown scenario: %s", id)
	}
}
