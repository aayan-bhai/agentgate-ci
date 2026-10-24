package main

import "testing"

func TestExecutorBlocksExternalConfidentialEmail(t *testing.T) {
	state := &MockState{}
	executor := ToolExecutor{Policy: PolicyEngine{}, State: state}

	result := executor.Execute(ToolRequest{
		Actor:        "agent-1",
		Action:       "send_email",
		Recipient:    "attacker@example.com",
		Confidential: true,
	}, "confidential report")

	if result.Allowed || result.Executed {
		t.Fatal("external confidential email should be denied")
	}

	emails, _ := state.snapshot()
	if emails != 0 {
		t.Fatalf("denied operation created %d email side effects", emails)
	}
}

func TestExecutorAllowsAuthorizedSummarySave(t *testing.T) {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
		Authorization: AuthorizationContext{
			Actor: "user-1",
			ResourceOwners: map[string]string{
				"report-1": "user-1",
			},
			ProtectedResources: map[string]bool{
				"report-1": false,
			},
		},
	}

	result := executor.Execute(ToolRequest{
		Actor:    "user-1",
		Action:   "save_summary",
		Resource: "report-1",
		Owner:    "user-1",
	}, "summary")

	if !result.Allowed || !result.Executed {
		t.Fatalf("authorized save should execute: %s", result.Reason)
	}

	_, files := state.snapshot()
	if files != 1 {
		t.Fatalf("expected one saved summary, got %d", files)
	}
}

func TestExecutorBlocksCrossUserRead(t *testing.T) {
	state := &MockState{}
	executor := ToolExecutor{Policy: PolicyEngine{}, State: state}

	result := executor.Execute(ToolRequest{
		Actor:    "user-1",
		Action:   "read_document",
		Resource: "private-report",
		Owner:    "user-2",
	}, "")

	if result.Allowed || result.Executed {
		t.Fatal("cross-user document read should be denied")
	}
}

func TestExecutorBlocksCrossUserFileRead(t *testing.T) {
	state := &MockState{}
	executor := ToolExecutor{Policy: PolicyEngine{}, State: state}

	result := executor.Execute(ToolRequest{
		Actor:    "user-a",
		Action:   "read_file",
		Resource: "private-config",
		Owner:    "user-b",
	}, "")

	if result.Allowed || result.Executed {
		t.Fatalf("expected cross-user file read to be denied, got %+v", result)
	}

	if len(state.operationSnapshot()) != 0 {
		t.Fatal("denied file read must not be recorded as an executed operation")
	}
}

func TestExecutorAllowsAuthorizedDatabaseQuery(t *testing.T) {
	state := &MockState{}
	executor := ToolExecutor{
		Policy: PolicyEngine{},
		State:  state,
		Authorization: AuthorizationContext{
			Actor: "user-a",
			ResourceOwners: map[string]string{
				"customer-records": "user-a",
			},
		},
	}

	result := executor.Execute(ToolRequest{
		Actor:    "user-a",
		Action:   "query_database",
		Resource: "customer-records",
		Owner:    "user-a",
	}, "")

	if !result.Allowed || !result.Executed {
		t.Fatalf("expected authorized database query to succeed, got %+v", result)
	}

	operations := state.operationSnapshot()
	if len(operations) != 1 {
		t.Fatalf("expectedone recorded mock deletion, got %+v", operations)
	}

}

func TestProtectedResourceModificationsAreDenied(t *testing.T) {
	actions := []string{"save_summary", "update_database"}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			decision := (PolicyEngine{}).Evaluate(ToolRequest{
				Actor:             "user-1",
				Action:            action,
				Resource:          "protected-report",
				Owner:             "user-1",
				ProtectedResource: true,
			})

			if decision.Allowed {
				t.Fatalf("expected protected resource modification to be denied: %+v", decision)
			}
		})
	}
}

func TestConfidentialEmailRequiresValidInternalRecipient(t *testing.T) {
	recipients := []string{
		"attacker@example.com",
		"not-an-email",
		"user@@internal.example",
		"user@internal.example.evil.com",
		"User <user@internal.example>",
	}

	for _, recipient := range recipients {
		t.Run(recipient, func(t *testing.T) {
			decision := (PolicyEngine{}).Evaluate(ToolRequest{
				Actor:        "agent-1",
				Action:       "send_email",
				Recipient:    recipient,
				Confidential: true,
			})

			if decision.Allowed {
				t.Fatalf("expected recipient %q to be denied", recipient)
			}
		})
	}
}

func TestConfidentialEmailAllowsValidInternalRecipient(t *testing.T) {
	decision := (PolicyEngine{}).Evaluate(ToolRequest{
		Actor:        "agent-1",
		Action:       "send_email",
		Recipient:    "user@internal.example",
		Confidential: true,
	})

	if !decision.Allowed {
		t.Fatalf("expected valid internal recipient to be allowed: %s", decision.Reason)
	}
}

func TestMalformedNonConfidentialEmailIsDenied(t *testing.T) {
	decision := (PolicyEngine{}).Evaluate(ToolRequest{
		Actor:     "agent-1",
		Action:    "send_email",
		Recipient: "not-an-email",
	})

	if decision.Allowed {
		t.Fatal("expected malformed email recipient to be denied")
	}
}

func TestDeniedOperationsDoNotMutateMockState(t *testing.T) {
	tests := []struct {
		name string
		req  ToolRequest
	}{
		{
			name: "protected summary save",
			req: ToolRequest{
				Actor:             "user-1",
				Action:            "save_summary",
				Resource:          "protected-report",
				Owner:             "user-1",
				ProtectedResource: true,
			},
		},
		{
			name: "protected database update",
			req: ToolRequest{
				Actor:             "user-1",
				Action:            "update_database",
				Resource:          "protected-record",
				Owner:             "user-1",
				ProtectedResource: true,
			},
		},
		{
			name: "unauthorized deletion",
			req: ToolRequest{
				Actor:     "user-1",
				Action:    "delete_file",
				Resource:  "report.txt",
				Owner:     "user-1",
				CanDelete: false,
			},
		},
		{
			name: "unauthorized deployment",
			req: ToolRequest{
				Actor:       "agent-1",
				Action:      "deploy_cloud",
				Resource:    "production",
				Environment: "production",
				CanDeploy:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &MockState{}
			executor := ToolExecutor{
				Policy: PolicyEngine{},
				State:  state,
			}

			beforeEmails, beforeFiles := state.snapshot()
			beforeOperations := len(state.operationSnapshot())

			result := executor.Execute(tt.req, "test payload")

			if result.Allowed || result.Executed {
				t.Fatalf("expected denial, got %+v", result)
			}

			afterEmails, afterFiles := state.snapshot()
			afterOperations := len(state.operationSnapshot())

			if afterEmails != beforeEmails || afterFiles != beforeFiles {
				t.Fatalf(
					"denied operation mutated mock state: emails %d->%d, files %d->%d",
					beforeEmails, afterEmails, beforeFiles, afterFiles,
				)
			}

			if afterOperations != beforeOperations {
				t.Fatalf(
					"denied operation was recorded: operations %d->%d",
					beforeOperations, afterOperations,
				)
			}
		})
	}
}
func TestShellExecutionDeniedByDefault(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		destructive bool
	}{
		{
			name:        "destructive command",
			command:     "rm -rf /",
			destructive: true,
		},
		{
			name:        "dangerous command mislabeled safe",
			command:     "rm -rf /",
			destructive: false,
		},
		{
			name:    "ordinary command",
			command: "echo hello",
		},
		{
			name: "empty command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &MockState{}
			executor := &ToolExecutor{
				Policy: PolicyEngine{},
				State:  state,
			}

			beforeEmails, beforeFiles := state.snapshot()
			beforeOperations := len(state.operationSnapshot())

			result := executor.Execute(
				ToolRequest{
					Actor:       "agent",
					Action:      "execute_shell",
					Resource:    "system",
					Command:     tt.command,
					Destructive: tt.destructive,
				},
				"",
			)

			if result.Allowed || result.Executed {
				t.Fatalf("expected shell execution to be denied, got %+v", result)
			}

			afterEmails, afterFiles := state.snapshot()
			afterOperations := len(state.operationSnapshot())

			if beforeEmails != afterEmails || beforeFiles != afterFiles {
				t.Fatal("denied shell execution mutated mock state")
			}

			if beforeOperations != afterOperations {
				t.Fatal("denied shell execution was recorded as executed")
			}
		})
	}
}
func TestPolicyDoesNotAuthorizeCrossUserRead(t *testing.T) {
	policy := PolicyEngine{}

	decision := policy.Evaluate(ToolRequest{
		Actor:    "agent-1",
		Action:   "read_file",
		Resource: "private-config",
		Owner:    "user-2",
	})

	if decision.Allowed {
		t.Fatal("expected cross-user read to be denied")
	}
}
func TestPermissionFlagsAreRequiredForSensitiveActions(t *testing.T) {
	policy := PolicyEngine{}

	tests := []struct {
		name string
		req  ToolRequest
	}{
		{
			name: "deletion without permission",
			req: ToolRequest{
				Actor:    "agent-1",
				Action:   "delete_file",
				Resource: "report.txt",
				Owner:    "agent-1",
			},
		},
		{
			name: "deployment without permission",
			req: ToolRequest{
				Actor:       "agent-1",
				Action:      "deploy_cloud",
				Resource:    "agentgate-service",
				Environment: "staging",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := policy.Evaluate(tt.req)
			if decision.Allowed {
				t.Fatalf("expected denial, got %+v", decision)
			}
		})
	}
}

func TestTrustedContextOverridesAgentClaims(t *testing.T) {
	policy := PolicyEngine{}

	auth := AuthorizationContext{
		Actor: "agent-1",
		ResourceOwners: map[string]string{
			"private-config": "user-2",
		},
		CanDelete: map[string]bool{
			"private-config": false,
		},
		CanDeploy: map[string]bool{
			"production-service": false,
		},
	}

	t.Run("spoofed actor cannot read another user's file", func(t *testing.T) {
		decision := policy.EvaluateWithContext(ToolRequest{
			Actor:    "user-2",
			Action:   "read_file",
			Resource: "private-config",
			Owner:    "user-2",
		}, auth)

		if decision.Allowed {
			t.Fatalf("expected trusted actor identity to override spoofed actor: %+v", decision)
		}
	})

	t.Run("spoofed delete permission is ignored", func(t *testing.T) {
		decision := policy.EvaluateWithContext(ToolRequest{
			Actor:     "agent-1",
			Action:    "delete_file",
			Resource:  "private-config",
			Owner:     "agent-1",
			CanDelete: true,
		}, auth)

		if decision.Allowed {
			t.Fatalf("expected deletion to be denied without trusted permission: %+v", decision)
		}
	})

	t.Run("spoofed deploy permission is ignored", func(t *testing.T) {
		decision := policy.EvaluateWithContext(ToolRequest{
			Actor:       "agent-1",
			Action:      "deploy_cloud",
			Resource:    "production-service",
			Environment: "production",
			CanDeploy:   true,
		}, auth)

		if decision.Allowed {
			t.Fatalf("expected deployment to be denied without trusted permission: %+v", decision)
		}
	})
}
