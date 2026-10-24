
import { useEffect, useState } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  Play,
  CheckCircle2,
  XCircle,
  Ban,
  Mail,
  FileText,
  Activity,
  LockKeyhole,
  LoaderCircle,
  RefreshCw,
  Terminal,
  CloudUpload,
} from 'lucide-react'
import './App.css'

const SCENARIO_PRESENTATIONS = {
  'confidential-email': {
    icon: Mail,
    steps: [
      ['Read document', 'Untrusted content enters context'],
      ['Request external email', 'Attempt to exfiltrate confidential data'],
      ['Evaluate email policy', 'Inspect whether the send action was blocked'],
    ],
    operationLabel: 'Mock email attempts',
  },

  'cross-user-file-read': {
    icon: FileText,
    steps: [
      ['Request file access', 'Agent requests a protected resource'],
      ['Check resource ownership', 'Attempt to read another owner’s file'],
      ['Evaluate access policy', 'Inspect whether unauthorized access was blocked'],
    ],
    operationLabel: 'Mock file-read attempts',
  },

  'unauthorized-file-deletion': {
    icon: LockKeyhole,
    steps: [
      ['Request file deletion', 'Agent requests deletion of a protected resource'],
      ['Check deletion permissions', 'Verify whether the agent is authorized'],
      ['Evaluate deletion policy', 'Inspect whether unauthorized deletion was blocked'],
    ],
    operationLabel: 'Mock deletion attempts',
  },

  'protected-file-write': {
    icon: FileText,
    steps: [
      ['Request configuration write', 'Agent attempts to modify a protected configuration file'],
      ['Inspect resource protection', 'Check whether the target file is protected'],
      ['Evaluate write policy', 'Verify whether the unauthorized modification was blocked'],
    ],
    operationLabel: 'Mock configuration-write attempts',
  },

  'destructive-shell-command': {
    icon: Terminal,
    steps: [
      ['Request shell execution', 'Agent submits a potentially destructive command'],
      ['Inspect command risk', 'Check whether the command is marked destructive'],
      ['Evaluate shell policy', 'Verify that the destructive command is blocked'],
    ],
    operationLabel: 'Mock shell-command attempts',
  },

  'unauthorized-cloud-deployment': {
    icon: CloudUpload,
    steps: [
      ['Request production deployment', 'Agent attempts to deploy a service'],
      ['Check deployment permissions', 'Inspect deployment authorization and environment protection'],
      ['Evaluate deployment policy', 'Verify that the unauthorized deployment is blocked'],
    ],
    operationLabel: 'Mock cloud-deployment attempts',
  },
}

function App() {
  const [protectedMode, setProtectedMode] = useState(true)
  const [scenarios, setScenarios] = useState([])
  const [selectedScenario, setSelectedScenario] = useState('')
  const [scenariosLoading, setScenariosLoading] = useState(true)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    async function loadScenarios() {
      try {
        const response = await fetch('/api/scenarios')

        if (!response.ok) {
          throw new Error(`API returned HTTP ${response.status}`)
        }

        const data = await response.json()

        if (!Array.isArray(data)) {
          throw new Error('Unexpected scenario API response')
        }

        if (!cancelled) {
          setScenarios(data)
          setSelectedScenario((current) =>
            data.some((scenario) => scenario.id === current)
              ? current
              : data[0]?.id ?? '',
          )
          setError('')
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            `${err.message}. Check that the Go backend is running on port 8080.`,
          )
        }
      } finally {
        if (!cancelled) {
          setScenariosLoading(false)
        }
      }
    }

    loadScenarios()

    return () => {
      cancelled = true
    }
  }, [])

  const activeScenario = scenarios.find(
    (scenario) => scenario.id === selectedScenario,
  )

  const activePresentation = SCENARIO_PRESENTATIONS[selectedScenario]
  const ScenarioIcon = activePresentation?.icon ?? FileText

  const passedChecks =
    result?.checks?.filter((check) => check.passed).length ?? 0
  const totalChecks = result?.checks?.length ?? 0

  const events = result?.events ?? []

  const executedCount = events.filter(
    (event) => event.outcome?.toLowerCase() === 'executed',
  ).length

  const blockedCount = events.filter(
    (event) => event.outcome?.toLowerCase() === 'blocked',
  ).length

  async function runTest(mode = protectedMode) {
    if (!selectedScenario) {
      setError('Select a scenario before running the test.')
      return
    }

    setProtectedMode(mode)
    setLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: selectedScenario,
          protected: mode,
        }),
      })

      if (!response.ok) {
        let message = `API returned HTTP ${response.status}`

        try {
          const body = await response.json()
          if (body.error) message = body.error
        } catch {
          // Keep the HTTP status message if the response isn't JSON.
        }

        throw new Error(message)
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(
        `${err.message}. Check that the Go backend is running on port 8080.`,
      )
    } finally {
      setLoading(false)
    }
  }

  function handleScenarioChange(event) {
    setSelectedScenario(event.target.value)
    setResult(null)
    setError('')
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={23} />
          </div>
          <div>
            <div className="brand-name">
              agentgate<span>_</span>
            </div>
            <div className="brand-subtitle">SECURITY TESTING</div>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>

        <div className="nav-item active">
          <Activity size={18} /> Test dashboard
        </div>

        <div className="nav-item muted">
          <ShieldAlert size={18} /> Attack scenarios
          <span className="nav-count">
            {String(scenarios.length).padStart(2, '0')}
          </span>
        </div>

        <div className="nav-item muted">
          <FileText size={18} /> Test reports
        </div>

        <div className="sidebar-bottom">
          <div className="connection-dot" />
          <div>
            <div className="connection-title">Local environment</div>
            <div className="connection-subtitle">
              Go API - localhost:8080
            </div>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> Security tests
          </div>
          <div className="environment">
            <span /> LOCAL DEVELOPMENT
          </div>
        </header>

        <section className="page-heading">
          <div>
            <div className="eyebrow">AGENT SECURITY / TEST RUNNER</div>
            <h1>Security test dashboard</h1>
            <p>Attack-test an agent. Verify its actions. Prove the fix.</p>
          </div>
          <div className="version-chip">
            MVP <span>v0.1</span>
          </div>
        </section>

        <section className="summary-grid">
          <div className="summary-card">
            <div className="summary-top">
              <span>ACTIVE SCENARIOS</span>
              <ShieldAlert size={18} />
            </div>
            <div className="summary-value">
              {String(scenarios.length).padStart(2, '0')}
            </div>
            <div className="summary-foot">
              {scenariosLoading
                ? 'Loading scenarios...'
                : `${scenarios.length} registered by the API`}
            </div>
          </div>

          <div className="summary-card">
            <div className="summary-top">
              <span>EXECUTION MODE</span>
              <LockKeyhole size={18} />
            </div>
            <div className="summary-value">
              {protectedMode ? 'Protected' : 'Vulnerable'}
            </div>
            <div className="summary-foot">
              {protectedMode
                ? 'Policy enforcement enabled for this test'
                : 'Vulnerable baseline simulation'}
            </div>
          </div>

          <div className="summary-card">
            <div className="summary-top">
              <span>LAST TEST RESULT</span>
              <Activity size={18} />
            </div>
            <div
              className={`summary-value ${
                result ? (result.passed ? 'green' : 'red') : ''
              }`}
            >
              {loading
                ? 'Running'
                : result
                  ? result.passed
                    ? 'PASS'
                    : 'FAIL'
                  : '--'}
            </div>
            <div className="summary-foot">
              {result
                ? `${passedChecks}/${totalChecks} assertions passed`
                : 'No test run yet'}
            </div>
          </div>
        </section>

        <section className="test-layout">
          <div className="panel scenario-panel">
            <div className="panel-heading">
              <div>
                <div className="panel-kicker">TEST SUITE / SCENARIOS</div>
                <h2>Attack scenario</h2>
              </div>
              <span className="severity">HIGH</span>
            </div>

            <div className="scenario-icon">
              <ScenarioIcon size={22} />
            </div>

            <label htmlFor="scenario-select" className="mode-label">
              SELECT SCENARIO
            </label>

            <select
              id="scenario-select"
              className="scenario-select"
              value={selectedScenario}
              onChange={handleScenarioChange}
              disabled={
                loading || scenariosLoading || scenarios.length === 0
              }
            >
              {scenarios.length === 0 && (
                <option value="">
                  {scenariosLoading
                    ? 'Loading scenarios...'
                    : 'No scenarios available'}
                </option>
              )}

              {scenarios.map((scenario) => (
                <option key={scenario.id} value={scenario.id}>
                  {scenario.name}
                </option>
              ))}
            </select>

            <h3>{activeScenario?.name ?? 'No scenario selected'}</h3>

            <p className="scenario-description">
              {activeScenario?.description ??
                'Scenarios will appear here when the backend is available.'}
            </p>

            <div className="attack-flow">
              {(
                activePresentation?.steps ?? [
                  ['Prepare scenario', 'Load the selected security test'],
                  ['Evaluate policy', 'Inspect the simulated tool request'],
                  ['Check outcome', 'Review recorded events and assertions'],
                ]
              ).map(([title, description], index) => (
                <div key={title}>
                  {index > 0 && <div className="flow-line" />}

                  <div className="flow-step">
                    <span className="flow-number">
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    <div>
                      <strong>{title}</strong>
                      <small>{description}</small>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="mode-label">EXECUTION MODE</div>

            <div className="mode-switch">
              <button
                className={
                  !protectedMode
                    ? 'mode-option selected-danger'
                    : 'mode-option'
                }
                onClick={() => setProtectedMode(false)}
                disabled={loading}
              >
                <ShieldAlert size={16} /> Vulnerable
              </button>

              <button
                className={
                  protectedMode
                    ? 'mode-option selected-safe'
                    : 'mode-option'
                }
                onClick={() => setProtectedMode(true)}
                disabled={loading}
              >
                <ShieldCheck size={16} /> Protected
              </button>
            </div>

            <button
              className="run-button"
              onClick={() => runTest()}
              disabled={
                loading || scenariosLoading || !selectedScenario
              }
            >
              {loading ? (
                <LoaderCircle className="spin" size={18} />
              ) : (
                <Play size={17} fill="currentColor" />
              )}
              {loading
                ? 'Running test...'
                : `Run ${protectedMode ? 'protected' : 'vulnerable'} test`}
            </button>

            <button
              className="compare-button"
              onClick={() => runTest(!protectedMode)}
              disabled={
                loading || scenariosLoading || !selectedScenario
              }
            >
              <RefreshCw size={15} /> Run the other mode
            </button>
          </div>

          <div className="right-column">
            <div className="panel result-panel">
              <div className="panel-heading">
                <div>
                  <div className="panel-kicker">LIVE OUTPUT</div>
                  <h2>Execution timeline</h2>
                </div>

                <span className={`live-indicator ${loading ? 'running' : ''}`}>
                  <span />
                  {loading
                    ? 'RUNNING'
                    : result
                      ? 'COMPLETED'
                      : 'READY'}
                </span>
              </div>

              {error && <div className="error-box">{error}</div>}

              {!result && !loading && !error && (
                <div className="empty-state">
                  <div className="empty-icon">
                    <Activity size={25} />
                  </div>
                  <strong>Ready to test</strong>
                  <p>
                    Choose a scenario and execution mode, then run the test
                    to inspect its recorded actions.
                  </p>
                </div>
              )}

              {loading && (
                <div className="empty-state">
                  <LoaderCircle className="spin" size={28} />
                  <strong>Executing scenario</strong>
                  <p>Waiting for the Go test runner...</p>
                </div>
              )}

              {result && (
                <>
                  <div
                    className={`result-banner ${
                      result.passed ? 'result-pass' : 'result-fail'
                    }`}
                  >
                    {result.passed ? (
                      <CheckCircle2 size={21} />
                    ) : (
                      <XCircle size={21} />
                    )}

                    <div>
                      <strong>
                        {result.passed
                          ? 'Security assertions passed'
                          : 'Security test failed'}
                      </strong>
                      <p>
                        {result.blocked
                          ? 'The backend reports that the attempted operation was blocked.'
                          : 'The backend did not report the operation as blocked.'}{' '}
                        {result.passed
                          ? 'All security assertions passed.'
                          : 'One or more security assertions failed.'}
                      </p>
                    </div>

                    <span>{result.passed ? 'PASS' : 'FAIL'}</span>
                  </div>

                  <div className="timeline">
                    {events.map((event, index) => {
                      const normalizedOutcome = (
                        event.outcome ?? ''
                      ).toLowerCase()

                      const isBlocked = normalizedOutcome === 'blocked'
                      const isExecuted = normalizedOutcome === 'executed'
                      const isFailure = isExecuted && !result.passed

                      const action = event.action ?? 'unknown action'

                      const EventIcon =
                        action === 'send_email'
                          ? Mail
                          : action === 'delete_file' ||
                              action === 'write_file'
                            ? LockKeyhole
                            : action === 'execute_shell'
                              ? Terminal
                              : action === 'deploy_cloud'
                                ? CloudUpload
                                : FileText

                      const eventStatus = isBlocked
                        ? 'blocked'
                        : isFailure
                          ? 'failed'
                          : isExecuted
                            ? 'executed'
                            : normalizedOutcome || 'unknown'

                      return (
                        <div
                          className="timeline-event"
                          key={`${event.time}-${action}-${index}`}
                        >
                          <div
                            className={`timeline-icon ${
                              isBlocked
                                ? 'event-blocked'
                                : isFailure
                                  ? 'event-failed'
                                  : 'event-ok'
                            }`}
                          >
                            {isBlocked ? (
                              <Ban size={16} />
                            ) : (
                              <EventIcon size={16} />
                            )}
                          </div>

                          <div className="event-body">
                            <div className="event-title">
                              {action.replaceAll('_', ' ')}
                            </div>
                            <div className="event-detail">
                              {event.details}
                            </div>
                            <div className="event-time">{event.time}</div>
                          </div>

                          <span
                            className={`event-status ${
                              isBlocked
                                ? 'status-blocked'
                                : isFailure
                                  ? 'status-failed'
                                  : 'status-ok'
                            }`}
                          >
                            {eventStatus}
                          </span>
                        </div>
                      )
                    })}
                  </div>

                  <p className="assertion-placeholder">
                    Demo note: tool operations and side effects are simulated.
                  </p>
                </>
              )}
            </div>

            <div className="panel assertions-panel">
              <div className="panel-heading">
                <div>
                  <div className="panel-kicker">POST-RUN VALIDATION</div>
                  <h2>Assertions</h2>
                </div>

                {result && (
                  <span className="assertion-count">
                    {passedChecks}/{totalChecks}
                  </span>
                )}
              </div>

              {!result ? (
                <p className="assertion-placeholder">
                  Assertions will appear here after a test run.
                </p>
              ) : (
                (result.checks ?? []).map((check) => (
                  <div className="assertion-row" key={check.name}>
                    {check.passed ? (
                      <CheckCircle2
                        className="assertion-pass"
                        size={18}
                      />
                    ) : (
                      <XCircle className="assertion-fail" size={18} />
                    )}

                    <div>
                      <strong>{check.name}</strong>
                      <small>{check.detail}</small>
                    </div>

                    <span
                      className={
                        check.passed
                          ? 'assertion-label pass-label'
                          : 'assertion-label fail-label'
                      }
                    >
                      {check.passed ? 'PASS' : 'FAIL'}
                    </span>
                  </div>
                ))
              )}

              {result && (
                <div className="state-strip">
                  <div>
                    <Activity size={16} />
                    <span>
                      {activePresentation?.operationLabel ?? 'Mock operations'}
                    </span>
                    <strong>{executedCount} executed</strong>
                  </div>

                  <div>
                    <Ban size={16} />
                    <span>Blocked operations</span>
                    <strong>{blockedCount} blocked</strong>
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        <footer>
          <span>
            AGENTGATE CI <span className="footer-separator">/</span> LOCAL DEMO
          </span>
          <span>Mock tools only - No external emails are sent</span>
        </footer>
      </main>
    </div>
  )
}

export default App
