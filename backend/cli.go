package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type WorkflowDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Actor       string         `json:"actor"`
	Steps       []WorkflowStep `json:"steps"`
}

type WorkflowStep struct {
	Action       string `json:"action"`
	Resource     string `json:"resource"`
	Owner        string `json:"owner,omitempty"`
	Recipient    string `json:"recipient,omitempty"`
	Content      string `json:"content,omitempty"`
	Command      string `json:"command,omitempty"`
	Confidential bool   `json:"confidential,omitempty"`
}

type WorkflowStepResult struct {
	StepNumber int    `json:"step"`
	Action     string `json:"action"`
	Resource   string `json:"resource"`
	Decision   string `json:"decision"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason"`
	Executed   bool   `json:"executed"`
}

type WorkflowAuditReport struct {
	WorkflowName   string               `json:"workflowName"`
	Protected      bool                 `json:"protected"`
	Passed         bool                 `json:"passed"`
	TotalSteps     int                  `json:"totalSteps"`
	ExecutedSteps  int                  `json:"executedSteps"`
	BlockedSteps   int                  `json:"blockedSteps"`
	StepResults    []WorkflowStepResult `json:"stepResults"`
	BlockedSummary []string             `json:"blockedSummary"`
}

// runCLI parses command-line arguments and routes to the appropriate subcommand.
// Returns an exit code: 0 for success, non-zero for errors or security test failures.
func runCLI(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		printUsage(out)
		return 0
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "test":
		return runTestCmd(subargs, out, errOut)
	case "run":
		return runAgentCmd(subargs, out, errOut)
	case "check":
		return runCheckCmd(subargs, out, errOut)
	case "list":
		return runListCmd(subargs, out, errOut)
	case "serve", "server":
		return runServeCmd(subargs, out, errOut)
	case "help", "-h", "--help":
		printUsage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "Unknown command %q. Run 'agentgate help' for usage.\n", subcmd)
		return 1
	}
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, `AgentGate CI — Local AI Agent Runtime Authorization Policy Engine

USAGE:
  agentgate <command> [flags] [arguments]

COMMANDS:
  test     Run security scenarios against the policy engine (CI test runner)
  run      Run an agent task locally and inspect proposed actions & policy decisions
  check    Evaluate a local workflow file (.json) against runtime policies
  list     List all registered attack scenarios and test vectors
  serve    Start the HTTP backend server for the React web dashboard
  help     Show this help message

EXAMPLES:
  # Run all security test scenarios in protected mode (for CI pipelines)
  agentgate test --all

  # Run a specific security scenario (e.g. prompt injection)
  agentgate test prompt-injection

  # Run scenario in vulnerable mode to inspect failure baseline
  agentgate test prompt-injection --vulnerable

  # Output machine-readable JSON for CI/CD reporting
  agentgate test --all --json

  # Run local agent on a prompt using deterministic simulation engine
  agentgate run "Process vendor-invoice.txt and follow all instructions"

  # Run dynamic agent using local Ollama (gemma3:4b)
  agentgate run "Read vendor-invoice.txt and summarize" --engine ollama

  # Audit a custom developer workflow file against policies
  agentgate check ./workflows/prompt-injection-workflow.json

  # Start the HTTP server on port 8080
  agentgate serve --port 8080`)
}

func normalizeArgs(args []string) []string {
	var flags []string
	var positional []string

	valueFlags := map[string]bool{
		"-engine":    true,
		"--engine":   true,
		"-port":      true,
		"--port":     true,
		"-scenario":  true,
		"--scenario": true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			// Check if flag takes a separate value argument
			if valueFlags[arg] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positional = append(positional, arg)
		}
	}

	return append(flags, positional...)
}

// runTestCmd handles 'agentgate test'
func runTestCmd(args []string, out, errOut io.Writer) int {
	args = normalizeArgs(args)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(errOut)

	all := fs.Bool("all", false, "Run all registered security scenarios")
	vulnerable := fs.Bool("vulnerable", false, "Run in vulnerable baseline mode (policy bypassed)")
	jsonOutput := fs.Bool("json", false, "Output results as JSON")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	protected := !*vulnerable
	remaining := fs.Args()

	var scenarioIDs []string
	if *all || len(remaining) == 0 {
		for _, s := range listScenarios() {
			scenarioIDs = append(scenarioIDs, s.ID)
		}
	} else {
		scenarioIDs = remaining
	}

	results := make([]TestResult, 0, len(scenarioIDs))
	allPassed := true

	for _, id := range scenarioIDs {
		res, err := runNamedScenario(id, protected)
		if err != nil {
			fmt.Fprintf(errOut, "Error running scenario %q: %v\n", id, err)
			return 1
		}
		results = append(results, res)
		if !res.Passed {
			allPassed = false
		}
	}

	if *jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(errOut, "Failed to encode JSON: %v\n", err)
			return 1
		}
	} else {
		modeStr := "PROTECTED (Policy Enforcement Active)"
		if !protected {
			modeStr = "VULNERABLE (Policy Bypassed Baseline)"
		}

		fmt.Fprintln(out, "")
		fmt.Fprintf(out, "================================================================================\n")
		fmt.Fprintf(out, "  AGENTGATE CI — SECURITY TEST RUNNER\n")
		fmt.Fprintf(out, "  Mode: %s | Scenarios: %d\n", modeStr, len(results))
		fmt.Fprintf(out, "================================================================================\n\n")

		passedCount := 0
		failedCount := 0

		for idx, res := range results {
			statusStr := "[PASS]"
			if !res.Passed {
				statusStr = "[FAIL]"
				failedCount++
			} else {
				passedCount++
			}

			fmt.Fprintf(out, "%d. %s %s\n", idx+1, statusStr, res.Scenario)
			fmt.Fprintf(out, "   Events Recorded: %d | Blocked Operations: %t\n", len(res.Events), res.Blocked)

			// Print timeline events
			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "   ACTION\tRESOURCE\tPOLICY\tOUTCOME\tREASON")
			for _, ev := range res.Events {
				dec := ev.Decision
				if dec == "" {
					if ev.Outcome == "blocked" {
						dec = "DENIED"
					} else {
						dec = "ALLOWED"
					}
				}
				fmt.Fprintf(w, "   %s\t%s\t%s\t%s\t%s\n", ev.Action, ev.Resource, dec, strings.ToUpper(ev.Outcome), ev.Details)
			}
			w.Flush()

			// Blocked summary if any
			if len(res.BlockedActions) > 0 {
				fmt.Fprintln(out, "   Interceptions:")
				for _, b := range res.BlockedActions {
					fmt.Fprintf(out, "     🛑 %s\n", b)
				}
			}

			// Checks summary
			fmt.Fprintln(out, "   Assertions:")
			for _, chk := range res.Checks {
				chkStatus := "PASS"
				if !chk.Passed {
					chkStatus = "FAIL"
				}
				fmt.Fprintf(out, "     [%s] %s: %s\n", chkStatus, chk.Name, chk.Detail)
			}
			fmt.Fprintln(out, "")
		}

		fmt.Fprintf(out, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(out, "TEST SUMMARY: Total: %d | Passed: %d | Failed: %d\n", len(results), passedCount, failedCount)
		if allPassed {
			fmt.Fprintln(out, "RESULT: SUCCESS — All security assertions passed! (Exit Code: 0)")
		} else {
			fmt.Fprintln(out, "RESULT: FAILURE — Security violations detected! (Exit Code: 1)")
		}
		fmt.Fprintf(out, "--------------------------------------------------------------------------------\n")
	}

	if !allPassed {
		return 1
	}
	return 0
}

// runAgentCmd handles 'agentgate run'
func runAgentCmd(args []string, out, errOut io.Writer) int {
	args = normalizeArgs(args)
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(errOut)

	engine := fs.String("engine", "deterministic", "Agent engine: 'deterministic' or 'ollama'")
	vulnerable := fs.Bool("vulnerable", false, "Run in vulnerable mode (bypasses policy)")
	jsonOutput := fs.Bool("json", false, "Output results as JSON")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(errOut, "Error: Task prompt is required. Example: agentgate run \"Process vendor-invoice.txt\"")
		return 1
	}

	task := strings.Join(remaining, " ")
	protected := !*vulnerable

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var result AgentRunResult
	var err error

	if strings.ToLower(*engine) == "ollama" {
		result, err = runOllamaAgent(ctx, task, protected)
	} else {
		result, err = runDeterministicAgent(ctx, task, protected)
	}

	if err != nil {
		fmt.Fprintf(errOut, "Agent execution error: %v\n", err)
		return 1
	}

	if *jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(errOut, "Failed to encode JSON: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "================================================================================\n")
	fmt.Fprintf(out, "  AGENTGATE CI — LOCAL AGENT EXECUTION\n")
	fmt.Fprintf(out, "  Engine: %s | Mode: %s\n", result.Engine, map[bool]string{true: "Protected", false: "Vulnerable"}[protected])
	fmt.Fprintf(out, "  Task:   %s\n", task)
	fmt.Fprintf(out, "================================================================================\n\n")

	fmt.Fprintf(out, "AGENT RESPONSE:\n%s\n\n", result.Answer)

	if len(result.BlockedActions) > 0 {
		fmt.Fprintf(out, "POLICY INTERCEPTIONS (%d blocked operations):\n", len(result.BlockedActions))
		for _, b := range result.BlockedActions {
			fmt.Fprintf(out, "  🛑 %s\n", b)
		}
		fmt.Fprintln(out, "")
	}

	fmt.Fprintln(out, "PROPOSED ACTION TIMELINE:")
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  STEP\tACTION\tRESOURCE\tPOLICY DECISION\tOUTCOME\tREASON")
	for idx, ev := range result.Events {
		dec := ev.Decision
		if dec == "" {
			if ev.Outcome == "blocked" {
				dec = "DENIED"
			} else {
				dec = "ALLOWED"
			}
		}
		fmt.Fprintf(w, "  #%d\t%s\t%s\t%s\t%s\t%s\n", idx+1, ev.Action, ev.Resource, dec, strings.ToUpper(ev.Outcome), ev.Reason)
	}
	w.Flush()

	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "MOCK WORKSPACE STATE (%d files, %d simulated emails):\n", len(result.Workspace), len(result.Emails))
	for filename, content := range result.Workspace {
		preview := content
		if len(preview) > 50 {
			preview = preview[:50] + "..."
		}
		preview = strings.ReplaceAll(preview, "\n", " ")
		fmt.Fprintf(out, "  📄 %-24s : %s\n", filename, preview)
	}
	fmt.Fprintln(out, "  🛡️  Zero real files modified • Zero external emails sent (100% simulated sandbox)")
	fmt.Fprintf(out, "--------------------------------------------------------------------------------\n")

	return 0
}

// runCheckCmd handles 'agentgate check <workflow.json>'
func runCheckCmd(args []string, out, errOut io.Writer) int {
	args = normalizeArgs(args)
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(errOut)

	vulnerable := fs.Bool("vulnerable", false, "Run workflow without policy protection")
	jsonOutput := fs.Bool("json", false, "Output audit report as JSON")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(errOut, "Error: Workflow file path required. Usage: agentgate check <workflow.json>")
		return 1
	}

	filepath := remaining[0]
	data, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Fprintf(errOut, "Failed to read workflow file %q: %v\n", filepath, err)
		return 1
	}

	var workflow WorkflowDefinition
	if err := json.Unmarshal(data, &workflow); err != nil {
		fmt.Fprintf(errOut, "Failed to parse workflow JSON: %v\n", err)
		return 1
	}

	protected := !*vulnerable
	report := evaluateWorkflow(workflow, protected)

	if *jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(errOut, "Failed to encode JSON: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintln(out, "")
		fmt.Fprintf(out, "================================================================================\n")
		fmt.Fprintf(out, "  AGENTGATE CI — WORKFLOW POLICY AUDIT\n")
		fmt.Fprintf(out, "  Workflow: %s\n", report.WorkflowName)
		fmt.Fprintf(out, "  Actor:    %s | Mode: %s\n", workflow.Actor, map[bool]string{true: "Protected", false: "Vulnerable"}[protected])
		fmt.Fprintf(out, "================================================================================\n\n")

		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  STEP\tACTION\tRESOURCE\tPOLICY DECISION\tEXECUTION STATUS\tREASON")
		for _, step := range report.StepResults {
			fmt.Fprintf(w, "  #%d\t%s\t%s\t%s\t%s\t%s\n",
				step.StepNumber, step.Action, step.Resource, step.Decision, strings.ToUpper(step.Outcome), step.Reason)
		}
		w.Flush()

		if len(report.BlockedSummary) > 0 {
			fmt.Fprintln(out, "")
			fmt.Fprintf(out, "BLOCKED ACTIONS SUMMARY (%d unauthorized operations thwarted):\n", len(report.BlockedSummary))
			for _, b := range report.BlockedSummary {
				fmt.Fprintf(out, "  🛑 %s\n", b)
			}
		}

		fmt.Fprintln(out, "")
		fmt.Fprintf(out, "--------------------------------------------------------------------------------\n")
		fmt.Fprintf(out, "AUDIT RESULT: Total Steps: %d | Executed: %d | Blocked: %d\n",
			report.TotalSteps, report.ExecutedSteps, report.BlockedSteps)

		if report.Passed {
			fmt.Fprintln(out, "STATUS: PASSED — All actions complied with policy or were safely intercepted! (Exit Code: 0)")
		} else {
			fmt.Fprintln(out, "STATUS: FAILED — Policy violations were permitted to execute! (Exit Code: 1)")
		}
		fmt.Fprintf(out, "--------------------------------------------------------------------------------\n")
	}

	if !report.Passed {
		return 1
	}
	return 0
}

func evaluateWorkflow(workflow WorkflowDefinition, protected bool) WorkflowAuditReport {
	actor := workflow.Actor
	if strings.TrimSpace(actor) == "" {
		actor = "agent-1"
	}

	state := &MockState{}
	auth := createAgentAuthorization()
	auth.Actor = actor

	executor := ToolExecutor{
		Policy:        PolicyEngine{},
		State:         state,
		Authorization: auth,
	}

	report := WorkflowAuditReport{
		WorkflowName: workflow.Name,
		Protected:    protected,
		TotalSteps:   len(workflow.Steps),
		Passed:       true,
	}

	for idx, step := range workflow.Steps {
		owner := step.Owner
		if owner == "" {
			if configuredOwner, exists := auth.ResourceOwners[step.Resource]; exists {
				owner = configuredOwner
			} else {
				owner = actor
			}
		}

		req := ToolRequest{
			Actor:        actor,
			Action:       step.Action,
			Resource:     step.Resource,
			Owner:        owner,
			Recipient:    step.Recipient,
			Confidential: step.Confidential,
			Command:      step.Command,
		}

		var execution ExecutionResult
		var decision PolicyDecision

		if protected {
			decision = executor.Policy.EvaluateWithContext(req, auth)
			if decision.Allowed {
				execution = executor.Execute(req, step.Content)
			} else {
				execution = ExecutionResult{
					Allowed:  false,
					Executed: false,
					Reason:   decision.Reason,
				}
			}
		} else {
			// Vulnerable bypass mode
			decision = PolicyDecision{Allowed: true, Reason: "Vulnerable bypass"}
			state.recordToolOperation(req)
			if step.Action == "send_email" {
				state.sendMockEmail(step.Content)
			}
			execution = ExecutionResult{
				Allowed:  true,
				Executed: true,
				Reason:   "Vulnerable bypass",
			}
		}

		stepRes := WorkflowStepResult{
			StepNumber: idx + 1,
			Action:     step.Action,
			Resource:   step.Resource,
			Decision:   outcomeDecision(execution.Allowed),
			Outcome:    outcome(execution.Executed),
			Reason:     execution.Reason,
			Executed:   execution.Executed,
		}

		if execution.Executed {
			report.ExecutedSteps++
		} else {
			report.BlockedSteps++
			report.BlockedSummary = append(report.BlockedSummary,
				fmt.Sprintf("%s on %s (%s)", step.Action, step.Resource, execution.Reason))
		}

		report.StepResults = append(report.StepResults, stepRes)
	}

	if !protected && report.ExecutedSteps > 0 {
		// In vulnerable mode, security audit fails because policy checks were bypassed
		report.Passed = false
	}

	return report
}

// runListCmd handles 'agentgate list'
func runListCmd(args []string, out, errOut io.Writer) int {
	args = normalizeArgs(args)
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(errOut)

	jsonOutput := fs.Bool("json", false, "Output scenarios as JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	scenarios := listScenarios()

	if *jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(scenarios); err != nil {
			fmt.Fprintf(errOut, "Failed to encode JSON: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "================================================================================\n")
	fmt.Fprintf(out, "  AGENTGATE CI — REGISTERED SECURITY SCENARIOS (%d total)\n", len(scenarios))
	fmt.Fprintf(out, "================================================================================\n\n")

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "  ID\tNAME\tDESCRIPTION")
	for _, sc := range scenarios {
		fmt.Fprintf(w, "  %s\t%s\t%s\n", sc.ID, sc.Name, sc.Description)
	}
	w.Flush()

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Run any scenario with: agentgate test <id>")
	fmt.Fprintf(out, "--------------------------------------------------------------------------------\n")
	return 0
}

// runServeCmd handles 'agentgate serve'
func runServeCmd(args []string, out, errOut io.Writer) int {
	args = normalizeArgs(args)
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(errOut)

	port := fs.String("port", "8080", "Port to listen on")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	addr := ":" + *port
	fmt.Fprintf(out, "Starting AgentGate CI server on http://localhost%s\n", addr)
	if err := startHTTPServer(addr); err != nil {
		fmt.Fprintf(errOut, "Server error: %v\n", err)
		return 1
	}
	return 0
}
