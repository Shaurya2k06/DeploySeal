import { useEffect, useMemo, useState } from 'react'
import './App.css'

type Gate = {
  id: string
  label: string
  status: 'verified' | 'failed'
}

type TimelineEvent = {
  id: string
  label: string
  status: string
  at: string
}

type Operation = {
  operationId: string
  operationDigest: string
  providerId: string
  policyEpoch: number
  status: string
  gates: Gate[]
  timeline: TimelineEvent[]
  proof: { status: string; kind: string; hash: string }
  provider: {
    operationId: string | null
    requestToken: string
    effectCount: number
  }
  receipt: { hash: string; keyId: string; status: string } | null
}

type Snapshot = {
  mode: string
  warning: string
  policy: { epoch: number; root: string }
  operation: Operation | null
  provider: {
    id: string
    effectCount: number
    executions: { operationId: string; providerOperationId: string; status: string }[]
  }
  lastAttempt: { type: string; status: string; code: string; at: string } | null
  auditCount: number
}

type Disclosure = {
  fields: string[]
  values: Record<string, string | number>
  bundleHash: string
  purpose: string
}

const apiRoot = import.meta.env.VITE_API_URL || ''
const auditOptions = [
  ['policyEpoch', 'Policy epoch'],
  ['operationId', 'Operation ID'],
  ['target', 'Target'],
  ['artifactDigest', 'Artifact digest'],
  ['outcome', 'Outcome'],
] as const

const emptyTimeline = [
  ['proof', 'Private policy proof'],
  ['reserved', 'Midnight authorization'],
  ['submitting', 'Provider request'],
  ['lost', 'Response recovery'],
  ['finalized', 'Signed receipt'],
]

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiRoot}${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', ...init?.headers },
  })
  const body = (await response.json()) as T & { error?: { message?: string } }
  if (!response.ok && !('snapshot' in body)) {
    throw new Error(body.error?.message || 'Request failed')
  }
  return body
}

function short(value: string | null | undefined, edge = 8) {
  if (!value) return '—'
  return value.length > edge * 2 ? `${value.slice(0, edge)}…${value.slice(-edge)}` : value
}

function time(value: string) {
  return new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(
    new Date(value),
  )
}

function Mark({ small = false }: { small?: boolean }) {
  return (
    <span className={`mark ${small ? 'mark-small' : ''}`} aria-hidden="true">
      <span />
    </span>
  )
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [activeView, setActiveView] = useState<'release' | 'receipt' | 'audit'>('release')
  const [selectedFields, setSelectedFields] = useState<string[]>(['policyEpoch', 'outcome'])
  const [disclosure, setDisclosure] = useState<Disclosure | null>(null)
  const [receiptState, setReceiptState] = useState<'idle' | 'checking' | 'valid' | 'invalid'>('idle')

  const operation = snapshot?.operation || null
  const isRecoverable = operation?.status === 'RECOVERY_REQUIRED'
  const isFinal = operation?.status === 'FINALIZED'
  const latestEvent = operation?.timeline.at(-1)
  const progress = useMemo(() => {
    if (!operation) return 0
    return Math.min(operation.timeline.length, emptyTimeline.length)
  }, [operation])

  useEffect(() => {
    request<Snapshot>('/api/release')
      .then(setSnapshot)
      .catch((requestError: Error) => setError(requestError.message))
  }, [])

  async function run(path: string, body?: unknown) {
    setBusy(path)
    setError('')
    try {
      const result = await request<{ snapshot?: Snapshot }>(path, {
        method: 'POST',
        body: JSON.stringify(body || {}),
      })
      if (result.snapshot) setSnapshot(result.snapshot)
      return result
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Request failed')
      return null
    } finally {
      setBusy('')
    }
  }

  async function primaryAction() {
    if (isRecoverable) {
      await run('/api/release/recover')
    } else if (isFinal) {
      await run('/api/reset')
      setDisclosure(null)
      setReceiptState('idle')
    } else {
      await run('/api/release/start', { scenario: 'crash' })
    }
  }

  async function disclose() {
    const result = await run('/api/audit/disclose', { fields: selectedFields })
    if (result && 'disclosure' in result) setDisclosure(result.disclosure as Disclosure)
  }

  async function verifyReceipt() {
    setReceiptState('checking')
    const result = await run('/api/receipt/verify')
    setReceiptState(result && 'valid' in result && result.valid ? 'valid' : 'invalid')
  }

  function toggleField(field: string) {
    setSelectedFields((current) =>
      current.includes(field) ? current.filter((item) => item !== field) : [...current, field],
    )
    setDisclosure(null)
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="DeploySeal home">
          <Mark />
          <span>Deploy<span>Seal</span></span>
        </a>
        <nav className="nav" aria-label="Primary navigation">
          {(['release', 'receipt', 'audit'] as const).map((view) => (
            <button
              className={activeView === view ? 'nav-active' : ''}
              key={view}
              onClick={() => setActiveView(view)}
              type="button"
            >
              {view === 'release' ? 'Release' : view === 'receipt' ? 'Receipt' : 'Audit'}
            </button>
          ))}
        </nav>
        <div className="environment"><i /> LOCAL EMULATOR</div>
      </header>

      <main id="top">
        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow"><span>01</span> Confidential release control</p>
            <h1>Ship the proof.<br /><em>Keep the policy.</em></h1>
            <p className="lede">
              DeploySeal verifies a release against private supply-chain, model, residency, and approval gates—then recovers the same cloud operation when the response disappears.
            </p>
            <div className="hero-actions">
              <button className="button button-primary" disabled={Boolean(busy)} onClick={primaryAction} type="button">
                {busy ? 'Working…' : isRecoverable ? 'Recover operation' : isFinal ? 'Reset demo' : 'Run crash-safe demo'}
                <span aria-hidden="true">↗</span>
              </button>
              <button className="button button-quiet" disabled={Boolean(busy) || Boolean(operation)} onClick={() => run('/api/release/start', { scenario: 'happy' })} type="button">
                Run clean path
              </button>
            </div>
            {error && <p className="error" role="alert">{error}. Start the broker with <code>npm --prefix server run start</code>.</p>}
          </div>
          <div className="hero-stamp" aria-label="One authorization, one effect, one receipt">
            <div className="stamp-ring"><span>ONE USE</span><strong>↗</strong><span>NO LEAK</span></div>
            <p>One authorization<br />One provider effect<br />One receipt</p>
          </div>
        </section>

        <section className="signal-row" aria-label="System status">
          <div><span className="signal-label">Policy epoch</span><strong>{snapshot?.policy.epoch || '—'}</strong></div>
          <div><span className="signal-label">Provider effects</span><strong>{snapshot?.provider.effectCount ?? '—'}</strong></div>
          <div><span className="signal-label">Operation</span><strong>{operation ? short(operation.operationId, 6) : 'Awaiting release'}</strong></div>
          <div><span className="signal-label">Last event</span><strong>{latestEvent ? latestEvent.label : 'Ready'}</strong></div>
        </section>

        <section className={`workspace view-${activeView}`}>
          <div className="main-column">
            <div className="section-heading">
              <div><p className="eyebrow"><span>02</span> {activeView === 'release' ? 'Private release' : activeView === 'receipt' ? 'Verifiable outcome' : 'Scoped disclosure'}</p><h2>{activeView === 'release' ? 'Release intent' : activeView === 'receipt' ? 'Receipt vault' : 'Audit bundle'}</h2></div>
              <span className="tag">{operation ? operation.status.replace('_', ' ') : 'NOT STARTED'}</span>
            </div>

            {activeView === 'release' && (
              <>
                <div className="intent-card">
                  <div className="card-top"><span className="mini-label">Artifact</span><span className="private-chip"><i /> PRIVATE INPUT</span></div>
                  <div className="intent-line"><h3>private artifact</h3><span className="hash">{operation ? 'digest bound / undisclosed' : 'awaiting attestation'}</span></div>
                  <div className="intent-meta">
                    <div><span>Commit</span><strong>{operation ? 'private / attested' : '—'}</strong></div>
                    <div><span>Target</span><strong>{operation ? 'private / policy-bound' : 'AWS / CloudFormation'}</strong></div>
                    <div><span>Provider</span><strong>{operation?.providerId || 'AWS CloudFormation'}</strong></div>
                  </div>
                </div>
                <div className="gates-card">
                  <div className="card-top"><span className="mini-label">Policy gates</span><span className="gate-summary">{operation ? `${operation.gates.filter((gate) => gate.status === 'verified').length} / ${operation.gates.length} verified` : 'Private until proven'}</span></div>
                  <div className="gate-list">
                    {(operation?.gates || [
                      { id: 'provenance', label: 'Artifact provenance', status: 'verified' },
                      { id: 'vulnerabilities', label: 'Vulnerability budget', status: 'verified' },
                      { id: 'evaluation', label: 'Model evaluation', status: 'verified' },
                      { id: 'target', label: 'Target and residency', status: 'verified' },
                      { id: 'approvals', label: 'Required approvals', status: 'verified' },
                    ]).map((gate) => (
                      <div className="gate" key={gate.id}>
                        <span className={`gate-icon ${gate.status}`} aria-hidden="true">{gate.status === 'verified' ? '✓' : '!'}</span>
                        <span>{gate.label}</span>
                        <span className="gate-status">{operation ? gate.status : 'ready'}</span>
                      </div>
                    ))}
                  </div>
                  <p className="privacy-note"><span>◈</span> Policy facts never enter the public release record.</p>
                </div>
              </>
            )}

            {activeView === 'receipt' && (
              <div className="receipt-card">
                {operation?.receipt ? (
                  <>
                    <div className="receipt-seal"><Mark small /><span>VERIFIED RECEIPT</span></div>
                    <div className="receipt-hash"><span>Receipt hash</span><code>{short(operation.receipt.hash, 18)}</code></div>
                    <div className="receipt-grid">
                      <div><span>Operation</span><strong>{short(operation.operationId, 10)}</strong></div>
                      <div><span>Provider operation</span><strong>{operation.provider.operationId}</strong></div>
                      <div><span>Signing key</span><strong>{operation.receipt.keyId}</strong></div>
                      <div><span>Outcome</span><strong className="success-text">{operation.receipt.status}</strong></div>
                    </div>
                    <button className="button button-secondary" disabled={busy === '/api/receipt/verify'} onClick={verifyReceipt} type="button">
                      {receiptState === 'checking' ? 'Checking signature…' : receiptState === 'valid' ? 'Signature verified ✓' : 'Verify signature'}
                    </button>
                    <p className="small-note">The local KMS emulator signs the same canonical receipt bytes that the production KMS path will verify.</p>
                  </>
                ) : <EmptyState title="No receipt yet" body="Run the release path to mint a signed provider receipt." />}
              </div>
            )}

            {activeView === 'audit' && (
              <div className="audit-card">
                <div className="audit-intro"><span className="audit-icon">◫</span><div><h3>Choose what to disclose</h3><p>Only selected fields leave the private evidence bundle.</p></div></div>
                <div className="audit-options">
                  {auditOptions.map(([field, label]) => (
                    <label className="audit-option" key={field}>
                      <input checked={selectedFields.includes(field)} onChange={() => toggleField(field)} type="checkbox" />
                      <span className="fake-checkbox">✓</span><span>{label}</span>
                    </label>
                  ))}
                </div>
                <button className="button button-secondary" disabled={!operation || Boolean(busy)} onClick={disclose} type="button">Create scoped bundle <span>↗</span></button>
                {disclosure && <div className="disclosure-result"><div><span>Bundle hash</span><code>{short(disclosure.bundleHash, 16)}</code></div><div className="disclosed-values">{disclosure.fields.map((field) => <span key={field}><b>{field}</b>{String(disclosure.values[field])}</span>)}</div></div>}
                {!operation && <p className="small-note">A release must be finalized before an audit bundle can be created.</p>}
              </div>
            )}
          </div>

          <aside className="timeline-card">
            <div className="card-top"><span className="mini-label">Operation timeline</span><span className="progress-count">{progress}/{emptyTimeline.length}</span></div>
            <div className="timeline-list">
              {(operation?.timeline || []).length
                ? operation?.timeline.map((event) => (
                    <div className="timeline-event" key={`${event.id}-${event.at}`}><span className="timeline-dot done">✓</span><div><strong>{event.label}</strong><span>{time(event.at)}</span></div></div>
                  ))
                : emptyTimeline.map(([id, label]) => <div className="timeline-event pending" key={id}><span className="timeline-dot">{id === 'proof' ? '○' : '·'}</span><div><strong>{label}</strong><span>waiting</span></div></div>)}
            </div>
            <div className="timeline-footer"><span className="pulse" />{isRecoverable ? 'Recovery required' : isFinal ? 'Operation complete' : 'Awaiting authorization'}<span className="footer-line" /></div>
          </aside>
        </section>

        <section className="attack-panel">
          <div><p className="eyebrow"><span>03</span> Adversarial check</p><h2>Trust, but retry.</h2><p>Test the two failure modes that matter: a policy mismatch stops before the provider, and a replay cannot mint a second effect.</p></div>
          <div className="attack-actions"><button className="button button-outline" disabled={Boolean(busy)} onClick={() => run('/api/release/start', { scenario: 'invalid' })} type="button">Block wrong target <span>↗</span></button><button className="button button-outline" disabled={!operation || Boolean(busy)} onClick={() => run('/api/release/replay')} type="button">Reject replay <span>↗</span></button></div>
          {snapshot?.lastAttempt && <div className="attempt-result"><span>Last attempt</span><strong>{snapshot.lastAttempt.code.replaceAll('_', ' ')}</strong><small>{time(snapshot.lastAttempt.at)}</small></div>}
        </section>
      </main>
      <footer><span>DEPLOYSEAL / PRIVATE RELEASE CONTROL</span><span>Built for a world where the response can disappear.</span></footer>
    </div>
  )
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return <div className="empty-state"><span>◌</span><h3>{title}</h3><p>{body}</p></div>
}

export default App
