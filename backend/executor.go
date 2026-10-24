package main

import "fmt"

type ExecutionResult struct {
	Allowed  bool
	Executed bool
	Reason   string
}

type ToolExecutor struct {
	Policy        PolicyEngine
	State         *MockState
	Authorization AuthorizationContext
}

func (e *ToolExecutor) Execute(req ToolRequest, body string) ExecutionResult {
	if e.State == nil {
		return ExecutionResult{
			Reason: "Tool state is not configured",
		}
	}

	decision := e.Policy.EvaluateWithContext(req, e.Authorization)
	if !decision.Allowed {
		return ExecutionResult{
			Allowed:  false,
			Executed: false,
			Reason:   decision.Reason,
		}
	}

	// Only mock operations are performed. No real files, databases,
	// emails, or external services are accessed.
	switch req.Action {
	case "send_email":
		e.State.sendMockEmail(body)

	case "save_summary":
		e.State.saveSummary(body)

	case "read_document", "read_file",
		"write_file", "delete_file",
		"query_database", "update_database", "execute_shell", "deploy_cloud":
		// The operation is simulated and recorded below.

	default:
		return ExecutionResult{
			Reason: fmt.Sprintf("Unsupported tool action: %s", req.Action),
		}
	}

	e.State.recordToolOperation(req)

	return ExecutionResult{
		Allowed:  true,
		Executed: true,
		Reason:   decision.Reason,
	}
}
