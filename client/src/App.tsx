import { useEffect, useState } from 'react'
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
const apiToken = import.meta.env.VITE_API_TOKEN || ''
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

function TransactionReceipts({ operation }: { operation: Operation | null }) {
  const reserveReceipt = operation?.proof?.txHash
  const finalizeReceipt = operation?.finalizationTxHash
  const receipts = [
    reserveReceipt ? ['Reserve transaction', reserveReceipt] : null,
    finalizeReceipt ? ['Finalize transaction', finalizeReceipt] : null,
  ].filter((receipt): receipt is [string, string] => Boolean(receipt))

  if (!receipts.length) return null

  return (
    <div className="tx-receipts">
      <div className="card-top"><span className="mini-label">Transaction receipts</span><span className="gate-summary">{receipts.length} on-chain</span></div>
      {receipts.map(([label, hash]) => <ExplorerLink key={label} label={label} value={short(hash, 14)} href={midnightTransactionUrl(hash)} />)}
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

function DemoPage() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [activeView, setActiveView] = useState<'release' | 'receipt' | 'audit'>('release')
  const [selectedFields, setSelectedFields] = useState<string[]>(['policyEpoch', 'outcome'])
  const [disclosure, setDisclosure] = useState<Disclosure | null>(null)
  const [receiptState, setReceiptState] = useState<'idle' | 'checking' | 'valid' | 'invalid'>('idle')

  const operation = snapshot?.operation || null
  const isFinal = operation?.status === 'FINALIZED'
  const isDone = operation?.status === 'FINALIZED' || operation?.status === 'FAILED'
  const isRecoverable = ['PROOF_SUBMITTING', 'RECOVERY_REQUIRED', 'SUBMITTING', 'RECEIPT_SIGNED'].includes(operation?.status || '')
  const latestEvent = operation?.timeline.at(-1)
  const progress = operation?.timeline.length || 0

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
    } else if (isDone) {
      await run('/api/release/start', { scenario: 'happy' })
      setDisclosure(null)
      setReceiptState('idle')
    } else {
      await run('/api/release/start', { scenario: 'happy' })
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
      </header>

      <main id="top">
        <section className="signal-row" aria-label="System status">
          <div><span className="signal-label">Policy epoch</span><strong>{snapshot?.policy.epoch || '—'}</strong></div>
          <div><span className="signal-label">Provider effects</span><strong>{snapshot?.provider.effectCount ?? '—'}</strong></div>
          <div><span className="signal-label">Operation</span><strong>{operation ? short(operation.operationId, 6) : 'Awaiting release'}</strong></div>
          <div><span className="signal-label">Last event</span><strong>{latestEvent ? latestEvent.label : 'Ready'}</strong></div>
        </section>

        <section className="demo-flow-section">
          <div className="section-heading"><div><p className="eyebrow"><span>02</span> End-to-end trace</p><h2>Follow one operation.</h2></div><span className="tag">PUBLIC IDENTIFIERS</span></div>
          <p className="demo-flow-copy">Run once to watch private policy proof, authorization, provider effect, recovery, and the signed receipt complete as one real operation.</p>
          <div className="hero-actions demo-controls">
            <button className="button button-primary" disabled={Boolean(busy)} onClick={primaryAction} type="button">
              {busy ? 'Running…' : isRecoverable ? 'Finish demo' : isDone ? 'Run again' : 'Run end-to-end demo'}
              <span aria-hidden="true">↗</span>
            </button>
          </div>
          {error && <p className="error" role="alert">{error}</p>}
          <FlowSteps operation={operation} />
          <ExplorerLinks detailed snapshot={snapshot} />
          <TransactionReceipts operation={operation} />
        </section>

        <section className={`workspace view-${activeView}`}>
          <div className="main-column">
            <div className="section-heading">
              <div><p className="eyebrow"><span>03</span> {activeView === 'release' ? 'Private release' : activeView === 'receipt' ? 'Verifiable outcome' : 'Scoped disclosure'}</p><h2>{activeView === 'release' ? 'Release intent' : activeView === 'receipt' ? 'Receipt vault' : 'Audit bundle'}</h2></div>
              <span className="tag">{operation ? operation.status.replace('_', ' ') : 'NOT STARTED'}</span>
            </div>

            {activeView === 'release' && (
              operation ? (
                <>
                  <div className="intent-card">
                    <div className="card-top"><span className="mini-label">Operation</span><span className="private-chip"><i /> PRIVATE INPUT</span></div>
                    <div className="intent-line"><h3>{short(operation.operationId, 10)}</h3><span className="hash">{short(operation.operationDigest, 16)}</span></div>
                    <div className="intent-meta">
                      <div><span>Policy epoch</span><strong>{operation.policyEpoch}</strong></div>
                      <div><span>Provider</span><strong>{operation.providerId}</strong></div>
                      <div><span>Provider operation</span><strong>{operation.provider.operationId || 'pending'}</strong></div>
                    </div>
                  </div>
                  <div className="gates-card">
                    <div className="card-top"><span className="mini-label">Policy gates</span><span className="gate-summary">{operation.gates.filter((gate) => gate.status === 'verified').length} / {operation.gates.length} passed</span></div>
                    <div className="gate-list">
                      {operation.gates.map((gate) => (
                        <div className="gate" key={gate.id}>
                          <span className={`gate-icon ${gate.status}`} aria-hidden="true">{gate.status === 'verified' ? '✓' : '·'}</span>
                          <span>{gate.label}</span>
                          <span className="gate-status">{gate.status === 'verified' ? 'passed' : gate.status}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              ) : <div className="intent-card"><EmptyState title="Ready to run" body="Run the demo to create a real operation and stream its receipts." /></div>
            )}

            {activeView === 'receipt' && (
              <div className="receipt-card">
                {operation?.receipt ? (
                  <>
                    <div className="receipt-seal"><Mark small /><span>SIGNED RECEIPT</span></div>
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
                    <p className="small-note">{snapshot?.mode === 'aws-cloudformation' ? 'AWS KMS signs the canonical receipt after provider reconciliation.' : snapshot?.mode === 'azure-arm' ? 'Azure Key Vault signs the canonical receipt after the resource-group effect is reconciled.' : 'The configured receipt signer signs the canonical provider outcome.'}</p>
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
                      <span className="checkbox-mark">✓</span><span>{label}</span>
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
            <div className="card-top"><span className="mini-label">Operation timeline</span><span className="progress-count">{progress} events</span></div>
            <div className="timeline-list">
              {operation?.timeline.length ? operation.timeline.map((event) => (
                <div className="timeline-event" key={`${event.id}-${event.at}`}><span className="timeline-dot done">✓</span><div><strong>{event.label}</strong><span>{time(event.at)}</span></div></div>
              )) : <p className="timeline-empty">Run the demo to stream the real operation timeline.</p>}
            </div>
            <div className="timeline-footer"><span className="pulse" />{isRecoverable ? 'Recovery required' : isFinal ? 'Operation complete' : isDone ? 'Operation failed' : 'Ready to run'}<span className="footer-line" /></div>
          </aside>
        </section>

        <section className="attack-panel">
          <div><p className="eyebrow"><span>04</span> Adversarial check</p><h2>Trust, but retry.</h2><p>Test the two failure modes that matter: a policy mismatch stops before the provider, and a replay cannot mint a second effect.</p></div>
          <div className="attack-actions"><button className="button button-outline" disabled={Boolean(busy)} onClick={() => run('/api/release/start', { scenario: 'invalid' })} type="button">Block wrong target <span>↗</span></button><button className="button button-outline" disabled={!operation || Boolean(busy)} onClick={() => run('/api/release/replay')} type="button">Reject replay <span>↗</span></button></div>
          {snapshot?.lastAttempt && <div className="attempt-result"><span>Last attempt</span><strong>{snapshot.lastAttempt.code.replaceAll('_', ' ')}</strong><small>{time(snapshot.lastAttempt.at)}</small></div>}
        </section>
      </main>
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
