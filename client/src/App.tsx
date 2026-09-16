import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import AOS from 'aos'
import 'aos/dist/aos.css'
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import Lenis from 'lenis'
import 'lenis/dist/lenis.css'
import './App.css'
import { DiaTextReveal } from './DiaTextReveal'

type Gate = {
  id: string
  label: string
  status: 'verified' | 'failed' | 'ready'
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
  txHash?: string | null
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
  finalizationTxHash?: string | null
  provider: {
    operationId: string | null
    requestToken: string
    effectCount: number
  }
  receipt: { hash: string; keyId: string; status: string } | null
}

type IssuerProfile = {
  mode: 'production' | 'mixed' | 'operator-demo'
  activeIssuerCount: number
  configuredIssuerCount: number
  issuers: {
    kind: string
    role: string
    keyId: string
    identityName: string
    vaultName: string
    active: boolean
  }[]
}

type Snapshot = {
  mode: string
  contractAddress?: string | null
  policy: { epoch: number; root: string }
  operation: Operation | null
  provider: {
    id: string
    effectCount: number
    executions: { operationId: string; providerOperationId: string; status: string }[]
  }
  evidence: IssuerProfile | null
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
const apiToken = import.meta.env.DEV ? import.meta.env.VITE_API_TOKEN || '' : ''
const repositoryUrl = 'https://github.com/Shaurya2k06/DeploySeal'
const midnightExplorerUrl = 'https://preprod.midnightexplorer.com'
const auditOptions = [
  ['policyEpoch', 'Policy epoch'],
  ['operationId', 'Operation ID'],
  ['target', 'Target'],
  ['artifactDigest', 'Artifact digest'],
  ['outcome', 'Outcome'],
] as const

const flowSteps = [
  ['01', 'Private policy proof', 'Compact checks the private evidence bundle against the committed policy root.', 'proof'],
  ['02', 'Operation reserved', 'Midnight reserves the operation nullifier before Azure can act.', 'reserved'],
  ['03', 'Azure effect', 'ARM receives the same operation ID as its deployment name and idempotency key.', 'provider-result'],
  ['04', 'Crash-safe recovery', 'A lost response is reconciled by querying the original provider operation.', 'recovered'],
  ['05', 'Public receipt', 'Key Vault signs the outcome and Midnight finalizes the receipt hash.', 'finalized'],
] as const

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiRoot}${path}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(apiToken ? { authorization: `Bearer ${apiToken}` } : {}),
      ...init?.headers,
    },
  })
  let body: T & { error?: { message?: string } }
  try {
    body = JSON.parse(await response.text()) as T & { error?: { message?: string } }
  } catch {
    throw new Error(response.ok ? 'Release broker returned an invalid response' : `Release broker unavailable (${response.status})`)
  }
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

type DemoStepState = 'pending' | 'active' | 'complete' | 'failed'

function demoStepState(snapshot: Snapshot | null, operation: Operation | null, step: 'policy' | 'proof' | 'provider' | 'recovery' | 'receipt'): DemoStepState {
  if (step === 'policy') return snapshot ? 'complete' : 'pending'
  if (!operation) return 'pending'

  const events = new Set(operation.timeline.map((event) => event.id))
  if (step === 'proof') {
    if (events.has('reserved')) return 'complete'
    if (operation.status === 'FAILED') return 'failed'
    return operation.status === 'PROOF_SUBMITTING' || operation.status === 'RECOVERY_REQUIRED' ? 'active' : 'pending'
  }
  if (step === 'provider') {
    if (events.has('provider-result') || operation.provider.operationId) return 'complete'
    if (operation.status === 'FAILED') return 'failed'
    return operation.status === 'SUBMITTING' || operation.status === 'RECOVERY_REQUIRED' ? 'active' : 'pending'
  }
  if (step === 'recovery') {
    if (events.has('recovered')) return 'complete'
    if (operation.status === 'FAILED') return 'failed'
    return ['SUBMITTING', 'RECOVERY_REQUIRED', 'RECEIPT_SIGNED'].includes(operation.status) ? 'active' : 'pending'
  }
  if (events.has('finalized') || operation.status === 'FINALIZED') return 'complete'
  if (operation.status === 'FAILED') return 'failed'
  return operation.status === 'RECEIPT_SIGNED' ? 'active' : 'pending'
}

function demoSnapshot(snapshot: Snapshot, operationId: string | null): Snapshot {
  const operation = operationId && snapshot.operation?.operationId === operationId ? snapshot.operation : null
  const hasCurrentAttempt = operation?.timeline.some(({ id }) => ['provider-pending', 'lost', 'recovered'].includes(id))
  return { ...snapshot, operation, lastAttempt: hasCurrentAttempt ? snapshot.lastAttempt : null }
}

function DemoIdentifier({ label, value, href }: { label: string; value: string | number | null | undefined; href?: string }) {
  const display = value === null || value === undefined || value === '' ? '—' : String(value)
  return (
    <div className="demo-identifier">
      <span>{label}</span>
      {href && display !== '—' ? (
        <a href={href} rel="noreferrer" target="_blank"><code>{display}</code><b aria-hidden="true">↗</b></a>
      ) : <code>{display}</code>}
    </div>
  )
}

function DemoStep({ number, title, body, state, children }: { number: string; title: string; body: string; state: DemoStepState; children: ReactNode }) {
  const status = state === 'complete' ? 'COMPLETE' : state === 'active' ? 'IN PROGRESS' : state === 'failed' ? 'FAILED' : 'WAITING'
  return (
    <article className={`demo-step demo-step-${state}`}>
      <div className="demo-step-marker"><span>{number}</span><i aria-hidden="true">{state === 'complete' ? '✓' : state === 'active' ? '•' : state === 'failed' ? '!' : '·'}</i></div>
      <div className="demo-step-body">
        <div className="demo-step-heading">
          <div><h2>{title}</h2><p>{body}</p></div>
          <strong>{status}</strong>
        </div>
        {children}
      </div>
    </article>
  )
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
  const contractAddress = snapshot?.contractAddress
  const providerId = providerResourceId(snapshot)
  const links: { label: string; value: string; href: string }[] = []

  if (contractAddress) links.push({ label: 'Midnight contract', value: short(contractAddress, 9), href: midnightContractUrl(contractAddress) })
  if (snapshot?.mode === 'azure-arm' && providerId) {
    links.push({ label: 'Azure deployment', value: short(providerId.split('/').at(-1), 9), href: azureResourceUrl(providerId) })
  }

  const reserveTransaction = operation?.proof?.txHash || operation?.proof?.txId
  const finalizeTransaction = operation?.finalizationTxHash || operation?.finalizationTxId

  if (detailed && reserveTransaction) {
    links.splice(1, 0, {
      label: 'Midnight reserve tx',
      value: short(reserveTransaction, 9),
      href: midnightTransactionUrl(reserveTransaction),
    })
  }
  if (detailed && finalizeTransaction) {
    links.splice(2, 0, {
      label: 'Midnight finalize tx',
      value: short(finalizeTransaction, 9),
      href: midnightTransactionUrl(finalizeTransaction),
    })
  }

  if (!links.length) return null

  return (
    <div className="explorer-links">
      {links.map((link) => <ExplorerLink key={link.label} {...link} />)}
      {detailed && operation && !reserveTransaction && <p className="small-note">The reserve transaction receipt is not available yet.</p>}
    </div>
  )
}

type ArchitectureNodeData = {
  step: string
  title: string
  detail: string
}

type ArchitectureNode = Node<ArchitectureNodeData, 'architecture'>

const architectureNodes: ArchitectureNode[] = [
  { id: 'evidence', type: 'architecture', position: { x: 0, y: 90 }, data: { step: '01', title: 'Private evidence', detail: 'SBOM · evaluations · approvals' } },
  { id: 'proof', type: 'architecture', position: { x: 225, y: 90 }, data: { step: '02', title: 'Compact proof', detail: 'policy root + release gates' } },
  { id: 'midnight', type: 'architecture', position: { x: 450, y: 90 }, data: { step: '03', title: 'Midnight reserve', detail: 'single-use operation intent' } },
  { id: 'azure', type: 'architecture', position: { x: 675, y: 90 }, data: { step: '04', title: 'Azure ARM effect', detail: 'same operation ID' } },
  { id: 'recovery', type: 'architecture', position: { x: 900, y: 90 }, data: { step: '05', title: 'Reconcile response', detail: 'query, never duplicate' } },
  { id: 'receipt', type: 'architecture', position: { x: 1125, y: 90 }, data: { step: '06', title: 'Signed receipt', detail: 'Key Vault + public hash' } },
]

const architectureEdges: Edge[] = architectureNodes.slice(0, -1).map((node, index) => ({
  id: `${node.id}-${architectureNodes[index + 1].id}`,
  source: node.id,
  target: architectureNodes[index + 1].id,
  type: 'smoothstep',
  markerEnd: { type: MarkerType.ArrowClosed, color: '#2597d0' },
}))

function ArchitectureNode({ data }: NodeProps<ArchitectureNode>) {
  return (
    <div className="architecture-node">
      <Handle className="architecture-handle" type="target" position={Position.Left} />
      <div className="architecture-node-top"><span>{data.step}</span><i>↗</i></div>
      <strong>{data.title}</strong>
      <span>{data.detail}</span>
      <Handle className="architecture-handle" type="source" position={Position.Right} />
    </div>
  )
}

const architectureNodeTypes = { architecture: ArchitectureNode }

function ArchitectureDiagram({ connected }: { connected: boolean }) {
  const [nodes, , onNodesChange] = useNodesState(architectureNodes)
  const [edges, , onEdgesChange] = useEdgesState(architectureEdges)

  return (
    <div className="architecture-shell">
      <div className="architecture-toolbar"><span>DRAG TO INSPECT</span><span>SCROLL TO ZOOM</span><strong><i /> {connected ? 'LIVE TRACE' : 'AWAITING CONNECTION'}</strong></div>
      <div className="architecture-canvas">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={architectureNodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          minZoom={0.45}
          maxZoom={1.4}
          nodesConnectable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#e2e6ea" gap={22} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  )
}

function LandingPage() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)

  useEffect(() => {
    AOS.init({
      disable: () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
      duration: 650,
      easing: 'ease-out-cubic',
      offset: 64,
      once: true,
    })

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return

    const lenis = new Lenis({ lerp: 0.08, smoothWheel: true })
    let frame = 0
    const raf = (time: number) => {
      lenis.raf(time)
      frame = window.requestAnimationFrame(raf)
    }
    frame = window.requestAnimationFrame(raf)

    return () => {
      window.cancelAnimationFrame(frame)
      lenis.destroy()
    }
  }, [])

  useEffect(() => {
    request<Snapshot>('/api/release').then(setSnapshot).catch(() => undefined)
  }, [])

  const connected = Boolean(snapshot)
  const operation = snapshot?.operation || null
  const providerLabel = snapshot?.provider.id?.toUpperCase() || '—'

  return (
    <div className="app-shell landing-shell">
      <header className="topbar landing-topbar">
        <a className="brand" href="/" aria-label="DeploySeal home">
          <Mark />
          <span>Deploy<span>Seal</span></span>
        </a>
        <nav className="landing-nav" aria-label="Primary navigation">
          <a href="#why">Why DeploySeal</a>
          <a href="#issuers">Issuers</a>
          <a href="#architecture">Architecture</a>
          <a href="#flow">The flow</a>
        </nav>
        <div className="nav-actions">
          <a className="button button-quiet nav-github" href={repositoryUrl} rel="noreferrer" target="_blank">GitHub</a>
          <a className="button button-primary nav-demo" href="/demo">Open demo <span aria-hidden="true">↗</span></a>
        </div>
      </header>

      <main className="landing-main">
        <section className="landing-hero" data-aos="fade-up">
          <div className="landing-hero-inner">
            <h1>Private policy.<br /><DiaTextReveal className="landing-reveal" colors={['#2597d0', '#d7e6f5', '#fff']} text="Public proof." textColor="#fff" /></h1>
            <p className="lede">Ship regulated software without putting the policy on display. DeploySeal turns private evidence into one authorized cloud effect and one verifiable receipt.</p>
            <div className="hero-actions">
              <a className="button button-primary" href="/demo">Run the live demo <span aria-hidden="true">↗</span></a>
              <a className="button button-quiet" href="#flow">See how it works</a>
            </div>
            <p className="hero-micro"><span className="status-dot" /> {snapshot ? `Connected to ${snapshot.mode}` : 'Connecting to the release broker'}</p>
          </div>
          <div className="landing-documents" data-aos="fade-up" data-aos-delay="100" aria-label="A release moving from private evidence to a public receipt">
            <article className="document-card document-before">
              <div className="document-top"><span>RELEASE DOSSIER</span><strong>PRIVATE</strong></div>
              <div className="document-title"><span className="document-icon">◌</span><div><strong>private release</strong><span>evidence bundle</span></div></div>
              <div className="document-lines">
                <div><span>SBOM</span><i /><b>PRIVATE</b></div>
                <div><span>EVALUATION</span><i /><b>PRIVATE</b></div>
                <div><span>RESIDENCY</span><i /><b>PRIVATE</b></div>
                <div><span>APPROVALS</span><i /><b>PRIVATE</b></div>
              </div>
              <div className="document-bottom"><span>NOT PUBLISHED</span><span>LOCKED ↗</span></div>
            </article>
            <div className="document-connector" aria-hidden="true"><span>prove + effect</span><strong>→</strong></div>
            <article className="document-card document-after">
              <div className="document-top"><span>DEPLOYSEAL RECEIPT</span><strong className="accent-text">PUBLIC</strong></div>
              <div className="document-title"><span className="document-icon document-icon-check">✓</span><div><strong>{operation ? short(operation.operationId, 9) : 'awaiting operation'}</strong><span>canonical outcome</span></div></div>
              <div className="document-lines">
                <div><span>PROVIDER</span><i /><b>{providerLabel}</b></div>
                <div><span>EFFECTS</span><i /><b>{snapshot?.provider.effectCount ?? '—'} / 1</b></div>
                <div><span>STATUS</span><i /><b>{operation?.receipt?.status || '—'}</b></div>
                <div><span>KEY</span><i /><b>{operation?.receipt?.keyId || '—'}</b></div>
              </div>
              <div className="document-bottom"><span>{snapshot?.contractAddress ? 'MIDNIGHT PREPROD' : '—'}</span><span className="accent-text">{operation?.receipt ? 'SIGNED ✓' : '—'}</span></div>
            </article>
          </div>
        </section>

        <section className="signal-row landing-signal-row" data-aos="fade-up" data-aos-delay="150" aria-label="Live system status">
          <div><span className="signal-label">Policy epoch</span><strong>{snapshot?.policy.epoch || '—'}</strong><small>committed root</small></div>
          <div><span className="signal-label">Cloud effects</span><strong>{snapshot?.provider.effectCount ?? '—'}</strong><small>one-use counter</small></div>
          <div><span className="signal-label">Network</span><strong>{snapshot?.contractAddress ? 'MIDNIGHT PREPROD' : '—'}</strong><small>{snapshot?.contractAddress ? 'explorer links' : 'awaiting broker'}</small></div>
          <div><span className="signal-label">Status</span><strong>{operation?.status || (snapshot ? 'READY' : 'CONNECTING')}</strong><small>release broker</small></div>
        </section>

        <section className="landing-section" id="why">
          <div className="landing-section-heading" data-aos="fade-up"><div><h2>Release with<br /><em>less exposure.</em></h2></div><p>DeploySeal gives security teams a private control plane and gives everyone else the smallest useful public fact: what was authorized, what happened, and whether it can be verified.</p></div>
          <div className="feature-grid" data-aos="fade-up" data-aos-delay="100">
            <article className="feature-card">
              <h3>Keep the dossier inside the boundary.</h3>
              <p>Supply-chain facts, model evaluations, residency checks, and approvals prove the release without becoming the release record.</p>
              <div className="drop-zone">
                <span className="feature-icon">↥</span>
                <strong>Evidence bundle</strong>
                <span>SBOM · evaluations · approvals</span>
                <small>Private input / never published</small>
              </div>
            </article>
            <article className="feature-card">
              <h3>Make retries safe by design.</h3>
              <p>A response can disappear after Azure acts. The operation ID and nullifier make reconciliation boring—and a second effect impossible.</p>
              <div className="wave-card">
                <div className="wave-card-top"><span className="play-button">▶</span><span>Provider effect / reconciled</span><strong>{snapshot?.provider.effectCount ?? '—'}×</strong></div>
                <div className="waveform" aria-hidden="true">{Array.from({ length: 22 }, (_, index) => <i key={index} />)}</div>
                <div className="wave-card-bottom"><span>{providerLabel}</span><span>ONE-USE OPERATION</span></div>
              </div>
            </article>
          </div>
        </section>

        <section className="landing-section issuer-section" id="issuers">
          <div className="landing-section-heading" data-aos="fade-up"><div><h2>Separate<br /><em>the issuers.</em></h2></div><p>Production evidence is signed by role-specific identities. Each issuer keeps its own non-exportable key and publishes only the fact needed for authorization.</p></div>
          <div className="issuer-panel" data-aos="fade-up" data-aos-delay="100">
            <div className="issuer-panel-top"><div><span>Issuer boundary</span><strong>{snapshot?.evidence?.mode === 'production' ? 'PRODUCTION' : snapshot?.evidence?.mode === 'mixed' ? 'MIXED' : 'OPERATOR DEMO'}</strong></div><b>{snapshot?.evidence?.activeIssuerCount || 0} / {snapshot?.evidence?.configuredIssuerCount || '—'} active</b></div>
            <div className="issuer-list">
              {snapshot?.evidence?.issuers.length ? snapshot.evidence.issuers.map((issuer) => (
                <div className="issuer-row" key={issuer.keyId}>
                  <span className={`issuer-marker ${issuer.active ? 'active' : ''}`} aria-hidden="true" />
                  <div><strong>{issuer.role}</strong><span>{issuer.identityName}</span></div>
                  <code>{issuer.keyId}</code>
                  <em>{issuer.active ? 'ACTIVE' : 'READY'}</em>
                </div>
              )) : <p className="issuer-empty">Production issuer registry is not attached to this broker.</p>}
            </div>
            <p className="issuer-note">{snapshot?.evidence?.mode === 'production' ? 'All verified facts come from the registered production issuer identities.' : 'The live demo uses separate, non-exportable Azure operator-demo keys. Production identities are provisioned separately and must supply the release facts before this boundary becomes active.'}</p>
          </div>
        </section>

        <section className="architecture-section" id="architecture">
          <div className="landing-section-heading" data-aos="fade-up"><div><h2>From private<br /><em>proof to effect.</em></h2></div><p>Six bounded steps connect confidential evidence to one cloud effect and one receipt. Move the map, zoom in, and follow the operation ID across each boundary.</p></div>
          <div data-aos="fade-up" data-aos-delay="100"><ArchitectureDiagram connected={connected} /></div>
        </section>

        <section className="landing-section flow-section" id="flow">
          <div className="landing-section-heading" data-aos="fade-up"><div><h2>One release.<br /><em>Five proofs.</em></h2></div><p>Every hand-off is bound to the same operation ID. The policy stays private; the outcome stays inspectable.</p></div>
          <div data-aos="fade-up" data-aos-delay="100"><FlowSteps operation={operation} /></div>
        </section>

        <section className="landing-split" id="proof" data-aos="fade-up">
          <div><h2>Make the right<br /><em>thing visible.</em></h2><p className="landing-copy">Security teams keep the evidence. Operators get a safe retry. Auditors get a receipt they can verify without receiving the entire release dossier.</p><a className="text-link" href="/demo">Inspect the console <span aria-hidden="true">↗</span></a></div>
          <div className="privacy-list">
            <div><span>01</span><div><strong>Private evidence</strong><p>SBOM, evaluation, residency, and approvals remain inside the proof boundary.</p></div></div>
            <div><span>02</span><div><strong>Single-use intent</strong><p>A Midnight nullifier binds authorization to one artifact, target, and policy epoch.</p></div></div>
            <div><span>03</span><div><strong>Durable outcome</strong><p>A lost response recovers the original Azure operation instead of creating a second effect.</p></div></div>
          </div>
        </section>

        <section className="landing-record" id="public-record" data-aos="fade-up">
          <div><h2>Follow the<br /><em>identifiers.</em></h2><p className="landing-copy">The demo gives you the public trail: Midnight Preprod transactions, the Azure resource record, and the GitHub workflow that produced the build. Private inputs stay private; durable identifiers stay useful.</p></div>
          <ExplorerLinks snapshot={snapshot} />
        </section>
      </main>

      <footer><span>DEPLOYSEAL / PRIVATE RELEASE CONTROL</span><span>Built for a world where the response can disappear.</span></footer>
    </div>
  )
}

type ActionResult = {
  accepted?: boolean
  bundle?: Record<string, unknown>
  code?: string
  disclosure?: Disclosure
  snapshot?: Snapshot
  valid?: boolean
}

function DemoPage() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [runState, setRunState] = useState<'idle' | 'running'>('idle')
  const [selectedFields, setSelectedFields] = useState<string[]>(['policyEpoch', 'outcome'])
  const [disclosure, setDisclosure] = useState<Disclosure | null>(null)
  const [receiptState, setReceiptState] = useState<'idle' | 'checking' | 'valid' | 'invalid'>('idle')
  const previousOperationId = useRef<string | null>(null)
  const runOperationId = useRef<string | null>(null)
  const recoveryRequested = useRef(false)
  const visibleOperationId = useRef<string | null>(null)

  const operation = snapshot?.operation || null
  const operationStatus = operation?.status
  const operationTimelineLength = operation?.timeline.length
  const isDone = operation?.status === 'FINALIZED' || operation?.status === 'FAILED'
  const isRecoverable = ['PROOF_SUBMITTING', 'RECOVERY_REQUIRED', 'SUBMITTING', 'RECEIPT_SIGNED'].includes(operation?.status || '')
  const recoveredEvent = operation?.timeline.find(({ id }) => id === 'recovered')

  const run = useCallback(async (path: string, body: unknown = {}, options: { suppressError?: boolean } = {}) => {
    setBusy(path)
    setError('')
    try {
      const result = await request<ActionResult>(path, {
        method: 'POST',
        body: JSON.stringify(body),
      })
      if (result.snapshot) {
        if (path === '/api/release/start' && result.accepted && result.snapshot.operation) visibleOperationId.current = result.snapshot.operation.operationId
        setSnapshot(demoSnapshot(result.snapshot, visibleOperationId.current))
      }
      return result
    } catch (requestError) {
      if (!options.suppressError) setError(requestError instanceof Error ? requestError.message : 'Request failed')
      return null
    } finally {
      setBusy('')
    }
  }, [])

  useEffect(() => {
    request<Snapshot>('/api/release')
      .then((next) => setSnapshot(demoSnapshot(next, visibleOperationId.current)))
      .catch((requestError: Error) => setError(requestError.message))
  }, [])

  useEffect(() => {
    const timer = window.setInterval(() => {
      request<Snapshot>('/api/release').then((next) => {
        if (runState === 'running' && next.operation && next.operation.operationId !== previousOperationId.current) {
          runOperationId.current = next.operation.operationId
          visibleOperationId.current = next.operation.operationId
        }
        setSnapshot(demoSnapshot(next, visibleOperationId.current))
      }).catch(() => undefined)
    }, 3000)
    return () => window.clearInterval(timer)
  }, [runState])

  useEffect(() => {
    if (runState !== 'running' || !operation || operation.operationId !== runOperationId.current || recoveryRequested.current) return
    const needsRecovery = ['SUBMITTING', 'RECOVERY_REQUIRED', 'RECEIPT_SIGNED'].includes(operation.status) && !operation.timeline.some(({ id }) => id === 'recovered')
    if (!needsRecovery) return
    const recoveryTimer = window.setTimeout(() => {
      if (recoveryRequested.current) return
      recoveryRequested.current = true
      void run('/api/release/recover').then((result) => {
        if (!result) {
          recoveryRequested.current = false
          setRunState('idle')
        }
      })
    }, 0)
    return () => window.clearTimeout(recoveryTimer)
  }, [operation, run, runState])

  useEffect(() => {
    if (runState !== 'running' || !operationStatus) return
    document.querySelector<HTMLElement>('.demo-step-active')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [operationStatus, operationTimelineLength, runState])

  useEffect(() => {
    if (runState === 'running' && operation && operation.operationId === runOperationId.current && ['FINALIZED', 'FAILED'].includes(operation.status)) {
      setRunState('idle')
    }
  }, [operation, runState])

  async function primaryAction() {
    if (runState === 'running') return
    setError('')
    recoveryRequested.current = false

    if (isRecoverable && operation) {
      previousOperationId.current = operation.operationId
      runOperationId.current = operation.operationId
      setRunState('running')
      const result = await run('/api/release/recover')
      if (!result) setRunState('idle')
      return
    }

    previousOperationId.current = operation?.operationId || null
    runOperationId.current = null
    visibleOperationId.current = null
    setDisclosure(null)
    setReceiptState('idle')
    setRunState('running')
    const result = await run('/api/release/start', { scenario: 'crash' }, { suppressError: true })
    if (result?.snapshot?.operation && result.snapshot.operation.operationId !== previousOperationId.current) {
      runOperationId.current = result.snapshot.operation.operationId
    }
    if (result?.code === 'OPERATION_EXISTS') {
      setError('The broker already has an active operation.')
      setRunState('idle')
    } else if (result && !result.snapshot && result.code) {
      setError(result.code.replaceAll('_', ' '))
      setRunState('idle')
    }
  }

  async function disclose() {
    const result = await run('/api/audit/disclose', { fields: selectedFields })
    if (result?.disclosure) setDisclosure(result.disclosure)
  }

  async function verifyReceipt() {
    setReceiptState('checking')
    const result = await run('/api/receipt/verify')
    setReceiptState(result?.valid ? 'valid' : result ? 'invalid' : 'idle')
  }

  async function exportReceipt() {
    const result = await run('/api/receipt/export')
    if (!result?.bundle) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(result.bundle, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url
    link.download = 'deployseal-receipt.json'
    link.click()
    URL.revokeObjectURL(url)
  }

  function toggleField(field: string) {
    setSelectedFields((current) => current.includes(field) ? current.filter((item) => item !== field) : [...current, field])
    setDisclosure(null)
  }

  const runLabel = runState === 'running' ? (isRecoverable ? 'Recovering…' : 'Running…') : isRecoverable ? 'Resume recovery' : isDone ? 'Run again' : 'Run end-to-end demo'
  const runStatus = runState === 'running' ? (isRecoverable ? 'Recovering the same provider operation' : 'Waiting for the live release trace') : isDone ? `Last release ${operation?.status.toLowerCase()}` : isRecoverable ? 'Recovery is waiting' : snapshot ? 'Ready to run' : 'Connecting to broker'
  const evidenceMode = snapshot?.evidence?.mode?.replace('-', ' ').toUpperCase() || '—'

  return (
    <div className="app-shell demo-shell">
      <header className="topbar demo-topbar">
        <a className="brand" href="/" aria-label="DeploySeal home"><Mark /><span>Deploy<span>Seal</span></span></a>
        <span className="demo-topbar-label">LIVE END-TO-END DEMO</span>
        <a className="button button-quiet demo-back" href="/">Landing <span aria-hidden="true">↗</span></a>
      </header>

      <main className="demo-main">
        <section className="demo-header">
          <div>
            <p className="demo-kicker"><span>LIVE TRACE</span> {snapshot?.mode?.toUpperCase() || 'CONNECTING'}</p>
            <h1>One release.<br /><em>One receipt.</em></h1>
            <p className="demo-lede">Click once. DeploySeal proves the private policy, reserves the operation, reconciles Azure after a lost response, and returns the identifiers you can verify.</p>
          </div>
          <div className="demo-run-control">
            <button className="button button-primary" disabled={Boolean(busy) || runState === 'running'} onClick={primaryAction} type="button">{runLabel}<span aria-hidden="true">↗</span></button>
            <span className="demo-run-status"><i className={runState === 'running' ? 'is-running' : ''} />{runStatus}</span>
          </div>
        </section>

        {error && <p className="error demo-error" role="alert">{error}</p>}

        <section className="demo-context" aria-label="Live release context">
          <DemoIdentifier label="Provider" value={snapshot?.provider.id} />
          <DemoIdentifier label="Policy epoch" value={snapshot?.policy.epoch} />
          <DemoIdentifier label="Policy root" value={snapshot?.policy.root} />
          <DemoIdentifier label="Issuer boundary" value={snapshot?.evidence ? `${evidenceMode} · ${snapshot.evidence.activeIssuerCount}/${snapshot.evidence.configuredIssuerCount}` : '—'} />
        </section>

        <section className="demo-steps" aria-label="End-to-end release steps">
          <DemoStep number="01" title="Policy boundary" body="The broker loads the committed policy and verifies the registered evidence issuers." state={demoStepState(snapshot, operation, 'policy')}>
            <div className="demo-id-grid">
              <DemoIdentifier label="Policy root" value={snapshot?.policy.root} />
              <DemoIdentifier label="Policy epoch" value={snapshot?.policy.epoch} />
              <DemoIdentifier label="Evidence mode" value={evidenceMode} />
              <DemoIdentifier label="Active issuers" value={snapshot?.evidence ? `${snapshot.evidence.activeIssuerCount} / ${snapshot.evidence.configuredIssuerCount}` : '—'} />
            </div>
            <div className="demo-gate-row">
              {operation?.gates.map((gate) => <span className={`demo-gate ${gate.status}`} key={gate.id}><i aria-hidden="true">{gate.status === 'verified' ? '✓' : '!'}</i>{gate.label}</span>)}
              {!operation && <span className="demo-placeholder">Run the trace to evaluate the release gates.</span>}
            </div>
            {snapshot?.evidence?.issuers.length ? <div className="demo-issuer-grid">
              {snapshot.evidence.issuers.map((issuer) => <div className="demo-issuer" key={issuer.keyId}>
                <i className={issuer.active ? 'active' : ''} aria-hidden="true" />
                <div><span>{issuer.role}</span><strong>{issuer.identityName}</strong><code>{issuer.keyId}</code><small>{issuer.vaultName}</small></div>
              </div>)}
            </div> : null}
          </DemoStep>

          <DemoStep number="02" title="Midnight reserve" body="The private proof binds this release to one operation nullifier before Azure can act." state={demoStepState(snapshot, operation, 'proof')}>
            <div className="demo-id-grid">
              <DemoIdentifier label="Operation ID" value={operation?.operationId} />
              <DemoIdentifier label="Operation digest" value={operation?.operationDigest} />
              <DemoIdentifier label="Policy root" value={operation?.proof?.policyRoot || snapshot?.policy.root} />
              <DemoIdentifier label="Nullifier" value={operation?.proof?.nullifier} />
              <DemoIdentifier label="Reserve tx ID" value={operation?.proof?.txId} href={operation?.proof?.txId ? midnightTransactionUrl(operation.proof.txId) : undefined} />
              <DemoIdentifier label="Reserve tx hash" value={operation?.proof?.txHash} href={operation?.proof?.txHash ? midnightTransactionUrl(operation.proof.txHash) : undefined} />
            </div>
          </DemoStep>

          <DemoStep number="03" title="Azure effect" body="Azure receives the same operation ID as its deployment name and idempotency token." state={demoStepState(snapshot, operation, 'provider')}>
            <div className="demo-id-grid">
              <DemoIdentifier label="Azure deployment resource ID" value={operation?.provider.operationId} href={operation?.provider.operationId ? azureResourceUrl(operation.provider.operationId) : undefined} />
              <DemoIdentifier label="Request token" value={operation?.provider.requestToken} />
              <DemoIdentifier label="Provider" value={operation?.providerId} />
              <DemoIdentifier label="Effects recorded" value={operation?.provider.operationId ? snapshot?.provider.effectCount : undefined} />
            </div>
          </DemoStep>

          <DemoStep number="04" title="Crash-safe recovery" body="The demo drops the first response on purpose; the browser automatically queries the original provider operation." state={demoStepState(snapshot, operation, 'recovery')}>
            <div className="demo-id-grid">
              <DemoIdentifier label="Recovery result" value={snapshot?.lastAttempt?.code || (recoveredEvent ? 'RECOVERED' : undefined)} />
              <DemoIdentifier label="Token binding" value={operation ? operation.provider.requestToken === operation.operationId ? 'MATCH · no duplicate' : 'MISMATCH' : undefined} />
              <DemoIdentifier label="Recovered at" value={recoveredEvent ? time(recoveredEvent.at) : undefined} />
              <DemoIdentifier label="Effect count after recovery" value={operation?.provider.operationId ? snapshot?.provider.effectCount : undefined} />
            </div>
          </DemoStep>

          <DemoStep number="05" title="Signed receipts" body="Key Vault signs the Azure outcome and Midnight finalizes the receipt hash on-chain." state={demoStepState(snapshot, operation, 'receipt')}>
            {operation?.receipt ? <>
              <div className="demo-id-grid">
                <DemoIdentifier label="Receipt hash" value={operation.receipt.hash} />
                <DemoIdentifier label="Receipt signing key" value={operation.receipt.keyId} />
                <DemoIdentifier label="Receipt status" value={operation.receipt.status} />
                <DemoIdentifier label="Finalize tx ID" value={operation.finalizationTxId} href={operation.finalizationTxId ? midnightTransactionUrl(operation.finalizationTxId) : undefined} />
                <DemoIdentifier label="Finalize tx hash" value={operation.finalizationTxHash} href={operation.finalizationTxHash ? midnightTransactionUrl(operation.finalizationTxHash) : undefined} />
                <DemoIdentifier label="Contract address" value={snapshot?.contractAddress} href={snapshot?.contractAddress ? midnightContractUrl(snapshot.contractAddress) : undefined} />
              </div>
              <div className="demo-receipt-actions">
                <button className="button button-secondary" disabled={busy === '/api/receipt/verify'} onClick={verifyReceipt} type="button">{receiptState === 'checking' ? 'Checking…' : receiptState === 'valid' ? 'Signature verified ✓' : 'Verify signature'}</button>
                <button className="button button-outline" disabled={Boolean(busy)} onClick={exportReceipt} type="button">Export receipt bundle ↗</button>
              </div>
              <details className="demo-disclosure">
                <summary>Generate scoped audit disclosure</summary>
                <div className="demo-disclosure-body">
                  <div className="demo-field-options">{auditOptions.map(([field, label]) => <label key={field}><input checked={selectedFields.includes(field)} onChange={() => toggleField(field)} type="checkbox" /><span>{label}</span></label>)}</div>
                  <button className="button button-outline" disabled={Boolean(busy)} onClick={disclose} type="button">Create scoped bundle <span aria-hidden="true">↗</span></button>
                  {disclosure && <div className="demo-disclosure-result"><DemoIdentifier label="Bundle hash" value={disclosure.bundleHash} /><code>{disclosure.fields.map((field) => `${field}=${String(disclosure.values[field])}`).join(' · ')}</code></div>}
                </div>
              </details>
            </> : <p className="demo-placeholder">The receipt identifiers will appear here after the live operation finalizes.</p>}
          </DemoStep>
        </section>

        <section className="demo-safety" aria-label="Optional safety checks">
          <div><span>Optional checks</span><p>Exercise the rejection paths after the main trace.</p></div>
          <div className="demo-safety-actions"><button className="button button-outline" disabled={Boolean(busy)} onClick={() => run('/api/release/start', { scenario: 'invalid' })} type="button">Block wrong target</button><button className="button button-outline" disabled={!operation || Boolean(busy)} onClick={() => run('/api/release/replay')} type="button">Reject replay</button></div>
          {operation && snapshot?.lastAttempt && <code>{snapshot.lastAttempt.code} · {time(snapshot.lastAttempt.at)}</code>}
        </section>
      </main>
    </div>
  )
}

function App() {
  return window.location.pathname === '/demo' ? <DemoPage /> : <LandingPage />
}

export default App
