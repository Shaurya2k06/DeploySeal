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

type Proof = {
  status: string
  kind: string
  hash: string
  txId?: string | null
  policyRoot?: string
  nullifier?: string
}

type Operation = {
  operationId: string
  operationDigest: string
  providerId: string
  policyEpoch: number
  status: string
  gates: Gate[]
  timeline: TimelineEvent[]
  proof: Proof | null
  finalizationTxId?: string | null
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
  contractAddress?: string | null
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
  operationId: string
  receiptHash: string
  fields: string[]
  values: Record<string, string | number>
  bundleHash: string
  purpose: string
  recipientId: string
  signature: string
  keyId: string
}

const apiRoot = import.meta.env.VITE_API_URL || ''
const repositoryUrl = 'https://github.com/Shaurya2k06/DeploySeal'
const workflowUrl = `${repositoryUrl}/actions/workflows/deployseal-demo.yml`
const midnightExplorerUrl = 'https://preprod.midnightexplorer.com'
const liveContractAddress = '011e650ec7885e33e40bcb9c2393417e0dc7afff61b33ecaffcbebe59a79c6b7'
const azureTargetResourceId = '/subscriptions/9b6559f4-2b0a-4e2a-8f77-b1f72d8310d8/resourceGroups/deployseal-target-rg'
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

const flowSteps = [
  ['01', 'Private policy proof', 'Compact checks the private evidence bundle against the committed policy root.', 'proof'],
  ['02', 'One-use authorization', 'Midnight reserves the operation nullifier before Azure can act.', 'reserved'],
  ['03', 'Azure effect', 'ARM receives the same operation ID as its deployment name and idempotency key.', 'provider-result'],
  ['04', 'Crash-safe recovery', 'A lost response is reconciled by querying the original provider operation.', 'recovered'],
  ['05', 'Public receipt', 'Key Vault signs the outcome and Midnight finalizes the receipt hash.', 'finalized'],
] as const

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

function explorerId(value: string) {
  return value.startsWith('0x') ? value : `0x${value}`
}

function midnightTransactionUrl(txId: string) {
  return `${midnightExplorerUrl}/transactions/${explorerId(txId)}`
}

function midnightContractUrl(address: string) {
  return `${midnightExplorerUrl}/contracts/${explorerId(address)}`
}

function azureResourceUrl(resourceId: string) {
  return `https://resources.azure.com${resourceId}`
}

function providerResourceId(snapshot: Snapshot | null) {
  return snapshot?.operation?.provider.operationId || snapshot?.provider.executions.at(-1)?.providerOperationId || null
}

function stageState(operation: Operation | null, eventId: string) {
  if (!operation) return 'pending'
  const events = new Set(operation.timeline.map((event) => event.id))
  if (eventId === 'recovered') return events.has('recovered') ? 'complete' : operation.status === 'RECOVERY_REQUIRED' ? 'active' : 'pending'
  if (eventId === 'provider-result') return events.has(eventId) || Boolean(operation.provider.operationId) ? 'complete' : 'pending'
  if (eventId === 'finalized') return events.has(eventId) || operation.status === 'FINALIZED' ? 'complete' : 'pending'
  return events.has(eventId) ? 'complete' : 'pending'
}

function FlowSteps({ operation }: { operation: Operation | null }) {
  return (
    <div className="flow-steps">
      {flowSteps.map(([number, title, body, eventId], index) => {
        const state = stageState(operation, eventId)
        return (
          <div className={`flow-step ${state}`} key={eventId}>
            <div className="flow-step-top"><span>{number}</span><i>{state === 'complete' ? '✓' : state === 'active' ? '•' : '·'}</i></div>
            <strong>{title}</strong>
            <p>{body}</p>
            {index < flowSteps.length - 1 && <b className="flow-arrow" aria-hidden="true">→</b>}
          </div>
        )
      })}
    </div>
  )
}

function ExplorerLink({ label, value, href }: { label: string; value: string; href: string }) {
  return (
    <a className="explorer-link" href={href} rel="noreferrer" target="_blank">
      <span className="explorer-link-label">{label}</span>
      <strong>{value}</strong>
      <span aria-hidden="true">↗</span>
    </a>
  )
}

function ExplorerLinks({ snapshot, detailed = false }: { snapshot: Snapshot | null; detailed?: boolean }) {
  const operation = snapshot?.operation
  const contractAddress = snapshot?.contractAddress || (snapshot?.mode === 'azure-arm' ? liveContractAddress : null)
  const providerId = providerResourceId(snapshot)
  const links = [
    {
      label: 'Midnight contract',
      value: contractAddress ? short(contractAddress, 9) : 'Preprod explorer',
      href: contractAddress ? midnightContractUrl(contractAddress) : midnightExplorerUrl,
    },
    {
      label: 'Azure target',
      value: providerId ? short(providerId.split('/').at(-1), 9) : 'deployseal-target-rg',
      href: providerId ? azureResourceUrl(providerId) : azureResourceUrl(azureTargetResourceId),
    },
    { label: 'GitHub workflow', value: 'deployseal-demo.yml', href: workflowUrl },
  ]

  if (detailed && operation?.proof?.txId) {
    links.splice(1, 0, {
      label: 'Midnight reserve tx',
      value: short(operation.proof.txId, 9),
      href: midnightTransactionUrl(operation.proof.txId),
    })
  }
  if (detailed && operation?.finalizationTxId) {
    links.splice(2, 0, {
      label: 'Midnight finalize tx',
      value: short(operation.finalizationTxId, 9),
      href: midnightTransactionUrl(operation.finalizationTxId),
    })
  }

  return (
    <div className="explorer-links">
      {links.map((link) => <ExplorerLink key={link.label} {...link} />)}
      {detailed && !operation?.proof?.txId && <p className="small-note">Run the live path to attach the current reserve and finalize transaction links.</p>}
    </div>
  )
}

function LandingPage() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)

  useEffect(() => {
    request<Snapshot>('/api/release').then(setSnapshot).catch(() => undefined)
  }, [])

  const live = snapshot?.mode === 'azure-arm'
  const operation = snapshot?.operation || null

  return (
    <div className="app-shell landing-shell">
      <header className="topbar landing-topbar">
        <a className="brand" href="/" aria-label="DeploySeal home">
          <Mark />
          <span>Deploy<span>Seal</span></span>
        </a>
        <nav className="landing-nav" aria-label="Primary navigation">
          <a href="#flow">The flow</a>
          <a href="#public-record">Public record</a>
          <a className="landing-nav-cta" href="/demo">Open demo <span aria-hidden="true">↗</span></a>
        </nav>
        <div className="environment"><i /> {live ? 'LIVE · AZURE ARM' : snapshot ? 'LOCAL DEMO READY' : 'CONNECTING'}</div>
      </header>

      <main className="landing-main">
        <section className="landing-hero">
          <div className="landing-hero-copy">
            <p className="eyebrow"><span>00</span> Confidential release control</p>
            <h1>Private policy.<br /><em>Public proof.</em></h1>
            <p className="lede">Deploy regulated software without putting the policy on display. DeploySeal turns private evidence into one authorized cloud effect and one verifiable receipt.</p>
            <div className="hero-actions">
              <a className="button button-primary" href="/demo">Run the live demo <span aria-hidden="true">↗</span></a>
              <a className="button button-quiet" href={`${repositoryUrl}#readme`} rel="noreferrer" target="_blank">Read the protocol</a>
            </div>
            <div className="landing-readout">
              <div><span>Mode</span><strong>{live ? 'AZURE / SEV-SNP' : snapshot ? 'COMPACT SIMULATOR' : '—'}</strong></div>
              <div><span>Provider effects</span><strong>{snapshot?.provider.effectCount ?? '—'}</strong></div>
              <div><span>Receipt</span><strong>{operation?.receipt?.status || 'AWAITING RUN'}</strong></div>
            </div>
          </div>
          <div className="landing-art" aria-label="A release moving from private policy to public receipt">
            <div className="landing-art-top"><span>DEPLOYSEAL / LIVE TRACE</span><span>ONE USE / NO LEAK</span></div>
            <div className="landing-orbit">
              <span className="orbit orbit-one" />
              <span className="orbit orbit-two" />
              <span className="orbit-node node-one" />
              <span className="orbit-node node-two" />
              <div className="landing-core"><Mark small /><span>PRIVATE<br />POLICY</span></div>
              <div className="landing-float float-one"><span>01 / PROOF</span><strong>COMPACT</strong></div>
              <div className="landing-float float-two"><span>02 / EFFECT</span><strong>AZURE ARM</strong></div>
              <div className="landing-float float-three"><span>03 / RECEIPT</span><strong>KEY VAULT</strong></div>
            </div>
            <div className="landing-art-bottom"><span>POLICY → AUTHORIZATION → EFFECT → RECEIPT</span><b>↗</b></div>
          </div>
        </section>

        <section className="signal-row landing-signal-row" aria-label="Live system status">
          <div><span className="signal-label">Policy epoch</span><strong>{snapshot?.policy.epoch || '—'}</strong></div>
          <div><span className="signal-label">Cloud effects</span><strong>{snapshot?.provider.effectCount ?? '—'}</strong></div>
          <div><span className="signal-label">Network</span><strong>{live ? 'MIDNIGHT PREPROD' : 'LOCAL'}</strong></div>
          <div><span className="signal-label">Status</span><strong>{operation?.status || (snapshot ? 'READY' : 'CONNECTING')}</strong></div>
        </section>

        <section className="landing-section" id="flow">
          <div className="landing-section-heading"><div><p className="eyebrow"><span>01</span> The release flow</p><h2>One release.<br /><em>Five proofs.</em></h2></div><p>Every hand-off is bound to the same operation ID. The policy stays private; the outcome stays inspectable.</p></div>
          <FlowSteps operation={operation} />
        </section>

        <section className="landing-split" id="proof">
          <div><p className="eyebrow"><span>02</span> Why it matters</p><h2>Make the right<br /><em>thing visible.</em></h2><p className="landing-copy">Security teams keep the evidence. Operators get a safe retry. Auditors get a receipt they can verify without receiving the entire release dossier.</p><a className="text-link" href="/demo">Inspect the console <span aria-hidden="true">↗</span></a></div>
          <div className="privacy-list">
            <div><span>01</span><div><strong>Private evidence</strong><p>SBOM, evaluation, residency, and approvals remain inside the proof boundary.</p></div></div>
            <div><span>02</span><div><strong>Single-use intent</strong><p>A Midnight nullifier binds authorization to one artifact, target, and policy epoch.</p></div></div>
            <div><span>03</span><div><strong>Durable outcome</strong><p>A lost response recovers the original Azure operation instead of creating a second effect.</p></div></div>
          </div>
        </section>

        <section className="landing-record" id="public-record">
          <div><p className="eyebrow"><span>03</span> Public record</p><h2>Follow the<br /><em>identifiers.</em></h2><p className="landing-copy">The demo gives you the public trail: Midnight Preprod transactions, the Azure resource record, and the GitHub workflow that produced the build.</p></div>
          <ExplorerLinks snapshot={snapshot} />
        </section>
      </main>

      <footer><span>DEPLOYSEAL / PRIVATE RELEASE CONTROL</span><span>Built for a world where the response can disappear.</span></footer>
    </div>
  )
}

function DemoPage() {
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

  useEffect(() => {
    const timer = window.setInterval(() => {
      request<Snapshot>('/api/release').then(setSnapshot).catch(() => undefined)
    }, 3000)
    return () => window.clearInterval(timer)
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
      await run(snapshot?.mode === 'azure-arm' ? '/api/release/start' : '/api/reset', snapshot?.mode === 'azure-arm' ? { scenario: 'crash' } : undefined)
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

  async function exportReceipt() {
    setBusy('/api/receipt/export')
    setError('')
    try {
      const result = await request<{ bundle?: Record<string, unknown> }>('/api/receipt/export', {
        method: 'POST',
        body: '{}',
      })
      if (!result.bundle) throw new Error('No receipt available')
      const url = URL.createObjectURL(new Blob([JSON.stringify(result.bundle, null, 2)], { type: 'application/json' }))
      const link = document.createElement('a')
      link.href = url
      link.download = 'deployseal-receipt.json'
      link.click()
      URL.revokeObjectURL(url)
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Request failed')
    } finally {
      setBusy('')
    }
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
        <a className="brand" href="/" aria-label="DeploySeal home">
          <Mark />
          <span>Deploy<span>Seal</span></span>
        </a>
        <nav className="nav" aria-label="Primary navigation">
          <a className="nav-link" href="/">Home</a>
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
        <div className="environment"><i /> {snapshot?.mode === 'azure-arm' ? 'AZURE ARM · SEV-SNP' : snapshot?.mode === 'aws-cloudformation' ? 'AWS CLOUDFORMATION' : 'LOCAL COMPACT SIMULATOR'}</div>
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
                {busy ? 'Working…' : isRecoverable ? 'Recover operation' : isFinal ? snapshot?.mode === 'azure-arm' ? 'Run next operation' : 'Reset demo' : 'Run crash-safe demo'}
                <span aria-hidden="true">↗</span>
              </button>
              <button className="button button-quiet" disabled={Boolean(busy) || Boolean(operation && !(isFinal && snapshot?.mode === 'azure-arm'))} onClick={() => run('/api/release/start', { scenario: 'happy' })} type="button">
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

        <section className="demo-flow-section">
          <div className="section-heading"><div><p className="eyebrow"><span>02</span> End-to-end trace</p><h2>Follow one operation.</h2></div><span className="tag">PUBLIC IDENTIFIERS</span></div>
          <p className="demo-flow-copy">Start the crash-safe path to watch private policy proof, single-use authorization, Azure effect, recovery, and receipt finalization move together.</p>
          <FlowSteps operation={operation} />
          <ExplorerLinks detailed snapshot={snapshot} />
        </section>

        <section className={`workspace view-${activeView}`}>
          <div className="main-column">
            <div className="section-heading">
              <div><p className="eyebrow"><span>03</span> {activeView === 'release' ? 'Private release' : activeView === 'receipt' ? 'Verifiable outcome' : 'Scoped disclosure'}</p><h2>{activeView === 'release' ? 'Release intent' : activeView === 'receipt' ? 'Receipt vault' : 'Audit bundle'}</h2></div>
              <span className="tag">{operation ? operation.status.replace('_', ' ') : 'NOT STARTED'}</span>
            </div>

            {activeView === 'release' && (
              <>
                <div className="intent-card">
                  <div className="card-top"><span className="mini-label">Artifact</span><span className="private-chip"><i /> PRIVATE INPUT</span></div>
                  <div className="intent-line"><h3>private artifact</h3><span className="hash">{operation ? 'digest bound / undisclosed' : 'awaiting attestation'}</span></div>
                  <div className="intent-meta">
                    <div><span>Commit</span><strong>{operation ? 'private / attested' : '—'}</strong></div>
                    <div><span>Target</span><strong>{operation ? 'private / policy-bound' : snapshot?.mode === 'azure-arm' ? 'Azure / resource group' : 'AWS / CloudFormation'}</strong></div>
                    <div><span>Provider</span><strong>{operation?.providerId || (snapshot?.mode === 'azure-arm' ? 'Azure Resource Manager' : 'AWS CloudFormation')}</strong></div>
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
                    <button className="button button-outline" disabled={Boolean(busy)} onClick={exportReceipt} type="button">Export receipt bundle ↗</button>
                    <p className="small-note">{snapshot?.mode === 'aws-cloudformation' ? 'AWS KMS signs the canonical receipt after provider reconciliation.' : snapshot?.mode === 'azure-arm' ? 'Azure Key Vault signs the canonical receipt after the resource-group effect is reconciled.' : 'The local key emulator signs the same canonical receipt bytes used by the production KMS paths.'}</p>
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
          <div><p className="eyebrow"><span>04</span> Adversarial check</p><h2>Trust, but retry.</h2><p>Test the two failure modes that matter: a policy mismatch stops before the provider, and a replay cannot mint a second effect.</p></div>
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

function App() {
  return window.location.pathname === '/demo' ? <DemoPage /> : <LandingPage />
}

export default App
