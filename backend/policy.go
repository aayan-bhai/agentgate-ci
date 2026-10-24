package main

import (
	"net/mail"
	"strings"
)

type ToolRequest struct {
	Actor             string
	Action            string
	Resource          string
	Owner             string
	Recipient         string
	Confidential      bool
	ProtectedResource bool
	CanDelete         bool
	Command           string
	Destructive       bool
	Environment       string
	CanDeploy         bool
}

type PolicyDecision struct {
	Allowed bool
	Reason  string
}

// AuthorizationContext contains permissions granted by trusted
// application code, not values asserted by the agent.
type AuthorizationContext struct {
	Actor                 string
	ResourceOwners        map[string]string
	ProtectedResources    map[string]bool
	ConfidentialResources map[string]bool
	CanDelete             map[string]bool
	CanDeploy             map[string]bool
}
type PolicyEngine struct{}

func (PolicyEngine) Evaluate(req ToolRequest) PolicyDecision {
	if strings.TrimSpace(req.Actor) == "" {
		return PolicyDecision{Reason: "Missing actor identity"}
	}

	if strings.TrimSpace(req.Action) == "" {
		return PolicyDecision{Reason: "Missing action"}
	}

	switch req.Action {
	case "read_document", "read_file", "query_database":
		if strings.TrimSpace(req.Resource) == "" ||
			strings.TrimSpace(req.Owner) == "" {
			return PolicyDecision{Reason: "Resource and owner are required"}
		}

		if req.Actor != req.Owner {
			return PolicyDecision{Reason: "Actor does not own this resource"}
		}

		return PolicyDecision{
			Allowed: true,
			Reason:  "Authorized resource read",
		}

	case "save_summary", "update_database":
		if strings.TrimSpace(req.Resource) == "" ||
			strings.TrimSpace(req.Owner) == "" {
			return PolicyDecision{Reason: "Resource and owner are required"}
		}

		if req.Actor != req.Owner {
			return PolicyDecision{Reason: "Actor does not own this resource"}
		}

		if req.ProtectedResource {
			return PolicyDecision{
				Reason: "Modification of protected resources is denied",
			}
		}

		return PolicyDecision{
			Allowed: true,
			Reason:  "Authorized resource modification",
		}

	case "write_file":
		if strings.TrimSpace(req.Resource) == "" ||
			strings.TrimSpace(req.Owner) == "" {
			return PolicyDecision{Reason: "Resource and owner are required"}
		}

		if req.Actor != req.Owner {
			return PolicyDecision{Reason: "Actor does not own this resource"}
		}

		if req.ProtectedResource {
			return PolicyDecision{
				Reason: "Writing to protected resources is denied",
			}
		}

		return PolicyDecision{
			Allowed: true,
			Reason:  "Authorized write to unprotected resource",
		}

	case "delete_file":
		if strings.TrimSpace(req.Resource) == "" ||
			strings.TrimSpace(req.Owner) == "" {
			return PolicyDecision{Reason: "Resource and owner are required"}
		}

		if req.Actor != req.Owner {
			return PolicyDecision{Reason: "Actor does not own this resource"}
		}

		if req.ProtectedResource {
			return PolicyDecision{
				Reason: "Deletion of protected resources is denied",
			}
		}

		if !req.CanDelete {
			return PolicyDecision{
				Reason: "Actor does not have explicit deletion permission",
			}
		}

		return PolicyDecision{
			Allowed: true,
			Reason:  "File deletion authorized",
		}

	case "execute_shell":
		if strings.TrimSpace(req.Command) == "" {
			return PolicyDecision{
				Allowed: false,
				Reason:  "Shell command is required",
			}
		}

		return PolicyDecision{
			Allowed: false,
			Reason:  "Shell execution is disabled by default",
		}

	case "deploy_cloud":
		if strings.TrimSpace(req.Resource) == "" {
			return PolicyDecision{Reason: "Deployment resource is required"}
		}

		if strings.TrimSpace(req.Environment) == "" {
			return PolicyDecision{Reason: "Deployment environment is required"}
		}

		if !req.CanDeploy {
			return PolicyDecision{
				Reason: "Agent does not have deployment permission",
			}
		}

		if req.ProtectedResource {
			return PolicyDecision{
				Reason: "Deployment to protected environments is denied",
			}
		}

		return PolicyDecision{
			Allowed: true,
			Reason:  "Cloud deployment authorized",
		}

	case "send_email":
		recipient := strings.TrimSpace(req.Recipient)

		if recipient == "" {
			return PolicyDecision{Reason: "Recipient is required"}
		}

		// Accept a single plain email address, not display-name syntax,
		// multiple recipients, or malformed addresses.
		parsed, err := mail.ParseAddress(recipient)
		if err != nil || parsed.Address != recipient {
			return PolicyDecision{
				Reason: "A valid single email address is required",
			}
		}

		if req.Confidential {
			at := strings.LastIndex(recipient, "@")
			domain := recipient[at+1:]

			if !strings.EqualFold(domain, "internal.example") {
				return PolicyDecision{
					Reason: "Confidential content can only be emailed to internal.example recipients",
				}
			}
		}

		return PolicyDecision{
			Allowed: true,
			Reason:  "Email action permitted by policy",
		}

	default:
		return PolicyDecision{Reason: "Unknown tool action"}
	}
}

func (p PolicyEngine) EvaluateWithContext(
	req ToolRequest,
	auth AuthorizationContext,
) PolicyDecision {
	actor := strings.TrimSpace(auth.Actor)
	if actor == "" {
		return PolicyDecision{Reason: "Missing trusted actor identity"}
	}

	resource := strings.TrimSpace(req.Resource)
	if resource == "" {
		return PolicyDecision{Reason: "Resource is required"}
	}

	// The owner comes from trusted application configuration.
	owner, exists := auth.ResourceOwners[resource]
	if !exists || strings.TrimSpace(owner) == "" {
		return PolicyDecision{Reason: "Resource ownership is not configured"}
	}

	// Identity and permissions come from trusted application context.
	req.Actor = actor
	req.Owner = owner
	req.CanDelete = auth.CanDelete[resource]
	req.CanDeploy = auth.CanDeploy[resource]

	// Sensitive operations require trusted resource classification.
	switch req.Action {
	case "save_summary", "update_database", "write_file",
		"delete_file", "deploy_cloud":
		protected, configured := auth.ProtectedResources[resource]
		if !configured {
			return PolicyDecision{
				Reason: "Protected-resource classification is not configured",
			}
		}
		req.ProtectedResource = protected

	case "send_email":
		confidential, configured := auth.ConfidentialResources[resource]
		if !configured {
			return PolicyDecision{
				Reason: "Confidentiality classification is not configured",
			}
		}
		req.Confidential = confidential
	}

	return p.Evaluate(req)
}
