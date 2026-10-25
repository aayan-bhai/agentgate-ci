# AgentGate CI

**Runtime authorization and security testing for AI agents.**

AgentGate CI evaluates proposed AI-agent tool actions against predefined policies before execution. It helps identify unauthorized behavior, block unsafe actions, and inspect security decisions through a CLI and web dashboard.

## Key Features

- **Policy enforcement:** Evaluate actions before they reach the tool executor.
- **Prompt-injection testing:** Test whether malicious instructions lead to unauthorized actions.
- **Workflow auditing:** Inspect workflows and identify policy violations.
- **Security logs:** Review action decisions and execution outcomes.
- **CLI and dashboard:** Run repeatable security tests and inspect results.

## How It Works

1. An agent or workflow proposes an action.
2. The policy engine evaluates the proposed action.
3. The executor runs permitted actions and rejects blocked actions.
4. Security decisions and outcomes are recorded.

The authorization layer operates separately from the agent's decision-making process.

## CLI Commands

Run these commands from the repository root in Windows PowerShell.

**Run all security scenarios:**

```powershell
.\agentgate.exe test --all
```

**Test prompt injection:**

```powershell
.\agentgate.exe test prompt-injection
```

**Demonstrate expected security failures in vulnerable mode:**

```powershell
.\agentgate.exe test prompt-injection --vulnerable
```

**Run a natural-language task:**

```powershell
.\agentgate.exe run "Read vendor-invoice.txt and summarize"
```

**Audit a workflow:**

```powershell
.\agentgate.exe check workflows/prompt-injection-workflow.json
```

**Get JSON test results:**

```powershell
.\agentgate.exe test --all --json
```

## Installation and Local Setup

### Prerequisites

- Git
- Go installed
- Node.js and npm if running the frontend locally

Clone the repository:

```powershell
git clone https://github.com/aayan-bhai/agentgate-ci.git
cd agentgate-ci
```

### Build and test the backend

```powershell
cd backend
go test ./...
go build -o agentgate-test.exe .
```

### Run the backend

```powershell
go run . serve
```

The server uses port `8080` by default and supports the `PORT` environment variable.

## Demo and API

The backend exposes the following endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Check backend health |
| `GET` | `/api/scenarios` | List available scenarios |
| `POST` | `/api/run` | Run a security scenario |
| `POST` | `/api/agent/run` | Submit an agent-run request |

For a local backend, check health at:

`http://localhost:8080/api/health`

The health endpoint should return a JSON response indicating that the service is healthy.

A public dashboard or backend demo URL can be added here once the deployment URL has been verified.

## Scope and Limitations

AgentGate CI is a prototype for demonstrating runtime authorization and security testing.

- Tool execution in the current demo uses a **mock/simulated environment**; successful actions do not imply real external effects.
- Results demonstrate the implemented scenarios and policies, not comprehensive protection against every attack.
- Production use would require further validation, integrations, and deployment hardening.

## Roadmap

- Integrate with additional AI-agent frameworks.
- Expand adversarial and prompt-injection test coverage.
- Support CI pipeline integrations.
- Extend policy configuration and audit capabilities.

## Contributing

Contributions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make your changes and run the relevant tests.
4. Open a pull request describing the change and its testing.

Please keep security claims evidence-based and include reproducible tests for new policy behavior.
