import { useState } from "react";
import type { FormEvent, ReactNode } from "react";
import "./index.css";
import "./navigation.css";

type PageId = "command-center" | "assessments" | "evidence-vault" | "control-coverage" | "threat-register";
type Finding = { rule_id: string; severity: string; title: string; line: number; recommendation: string };
type Gap = { control_id: string; framework: string; title: string; rationale: string };
type ThreatSignal = { category: string; title: string; likelihood: string; impact: string; evidence: string };
type Source = { source_id: string; title: string; framework: string; excerpt: string; version?: string; control_id?: string; source_url?: string };
type Assessment = {
  assessment_id: string;
  project_name: string;
  phase: string;
  risk_level: string;
  analyst_brief: string;
  findings: Finding[];
  compliance_gaps: Gap[];
  threat_signals: ThreatSignal[];
  next_actions: string[];
  evidence_coverage: number;
  retrieved_context: Source[];
  agent_trace: string[];
  ai_review: { status: string; model: string; insight: string };
};

const navItems: { id: PageId; label: string }[] = [
  { id: "command-center", label: "Command center" },
  { id: "assessments", label: "Assessments" },
  { id: "evidence-vault", label: "Evidence vault" },
  { id: "control-coverage", label: "Control coverage" },
  { id: "threat-register", label: "Threat register" },
];
const pageInfo: Record<PageId, { title: string; description: string }> = {
  "command-center": { title: "Assessment workbench", description: "Evidence-led review for software delivery decisions." },
  assessments: { title: "Assessments", description: "Review the assessment created in this session." },
  "evidence-vault": { title: "Evidence vault", description: "Inspect the evidence currently staged for review." },
  "control-coverage": { title: "Control coverage", description: "Review control mappings from the latest assessment." },
  "threat-register": { title: "Threat register", description: "Review threat signals identified from submitted evidence." },
};
const phases = ["requirements", "design", "development", "testing", "deployment", "operations"];
const scope: Record<string, [string, string, string]> = {
  requirements: ["Security requirements review", "Missing security and privacy acceptance criteria.", "PRDs, user stories, questionnaires"],
  design: ["Architecture threat model", "Trust boundaries, attack paths, and design-control gaps.", "Diagrams, API specifications, data flows"],
  development: ["Secure implementation review", "Secrets, insecure defaults, and coding/configuration risks.", "Code, environment files, PR evidence"],
  testing: ["Security test triage", "Vulnerability evidence and remediation priority.", "SAST, DAST, and pen-test reports"],
  deployment: ["Release security gate", "Release hardening, TLS, secrets, and configuration readiness.", "Manifests, release checklists, infrastructure config"],
  operations: ["Operational resilience review", "Monitoring, incident response, and vulnerability ownership.", "Runbooks, logs, alerts, incident reports"],
};
const sample = "System design: public admin portal.\nAPI_KEY = \"demo-only-key\"\nservice_url = \"http://example.com\"\nverify=False";
const api = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8010/api";

export default function App() {
  const [page, setPage] = useState<PageId>("command-center");
  const [project, setProject] = useState("Payments modernization");
  const [phase, setPhase] = useState("design");
  const [content, setContent] = useState(sample);
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<Assessment | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [title, focus, evidence] = scope[phase];

  async function assess(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);
    try {
      let endpoint = "/assessments";
      let body: BodyInit = JSON.stringify({ content, project_name: project, phase, frameworks: ["OWASP ASVS", "NIST SSDF"] });
      let headers: HeadersInit | undefined = { "Content-Type": "application/json" };
      if (file) {
        const form = new FormData();
        form.append("file", file);
        form.append("project_name", project);
        form.append("phase", phase);
        form.append("frameworks", "OWASP ASVS,NIST SSDF");
        endpoint = "/assessments/upload";
        body = form;
        headers = undefined;
      }
      const response = await fetch(`${api}${endpoint}`, { method: "POST", headers, body });
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.detail ?? "Assessment failed.");
      }
      setResult(await response.json() as Assessment);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not run assessment.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span>S</span>SecureLens</div>
        <nav aria-label="Main navigation">
          {navItems.map((item) => (
            <button
              key={item.id}
              type="button"
              className={page === item.id ? "active" : ""}
              aria-current={page === item.id ? "page" : undefined}
              onClick={() => setPage(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="side-note"><small>ASSESSMENT MODE</small><b>Human review required</b><p>AI drafts never approve a security gate.</p></div>
      </aside>

      <main>
        <header>
          <div><small>SSDLC SECURITY INTELLIGENCE</small><h1>{pageInfo[page].title}</h1><p>{pageInfo[page].description}</p></div>
          <span className="online">Platform online</span>
        </header>

        {page === "command-center" && (
          <>
            <div className="stages">{phases.map((item, index) => <button key={item} type="button" className={phase === item ? "selected" : ""} onClick={() => setPhase(item)}><b>0{index + 1}</b>{item}</button>)}</div>
            <section className="grid">
              <form className="panel intake" onSubmit={assess}>
                <div className="title"><div><small>NEW ASSESSMENT</small><h2>{title}</h2></div><i>{phase.toUpperCase()}</i></div>
                <article className="brief"><small>PHASE SCOPE</small><p>{focus}</p><p>Best evidence: {evidence}</p></article>
                <label>Project<input value={project} onChange={(event) => setProject(event.target.value)} /></label>
                <label>Paste source evidence<textarea value={content} placeholder={evidence} onChange={(event) => { setContent(event.target.value); setFile(null); }} /></label>
                <label>Or upload evidence (TXT, MD, CSV, JSON, PDF, DOCX, XLSX; 10 MB max)<input type="file" accept=".pdf,.docx,.xlsx,.txt,.md,.csv,.json" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label>
                <div className="overlays">Policy overlays <b>OWASP ASVS</b><b>NIST SSDF</b>{file && <b>{file.name}</b>}</div>
                <button className="primary" disabled={loading}>{loading ? "Analyzing evidence..." : `Run ${phase} assessment →`}</button>
                {error && <p className="error" role="alert">{error}</p>}
              </form>
              <AssessmentOutput result={result} title={title} focus={focus} />
            </section>
            {result && <AssessmentDetails result={result} />}
          </>
        )}

        {page === "assessments" && <AssessmentsPage result={result} onNew={() => setPage("command-center")} />}
        {page === "evidence-vault" && <EvidencePage project={project} content={content} file={file} onEdit={() => setPage("command-center")} />}
        {page === "control-coverage" && <ControlCoveragePage result={result} onNew={() => setPage("command-center")} />}
        {page === "threat-register" && <ThreatRegisterPage result={result} onNew={() => setPage("command-center")} />}
      </main>
    </div>
  );
}

function AssessmentOutput({ result, title, focus }: { result: Assessment | null; title: string; focus: string }) {
  return (
    <section className="panel output">
      <div className="title"><div><small>ASSESSMENT OUTPUT {result ? `| ${result.phase.toUpperCase()}` : ""}</small><h2>{result?.project_name ?? title}</h2></div>{result && <i className={`risk ${result.risk_level}`}>{result.risk_level} risk</i>}</div>
      {!result ? <div className="empty"><strong>+</strong><h3>{title}</h3><p>{focus}</p></div> : <>
        <div className="metrics"><Metric value={result.findings.filter((item) => item.severity === "high").length} label="High findings" /><Metric value={result.compliance_gaps.length} label="Control gaps" /><Metric value={`${result.evidence_coverage}%`} label="Evidence mapped" /></div>
        <article className="brief"><small>ANALYST BRIEF</small><p>{result.analyst_brief}</p></article>
        <article className="brief ai-brief"><small>LOCAL AI REVIEW | {result.ai_review.model} | {result.ai_review.status}</small><p>{result.ai_review.insight}</p></article>
        <h3>Priority findings <span>{result.findings.length} signals</span></h3>
        {result.findings.slice(0, 3).map((item) => <article className="finding" key={`${item.rule_id}-${item.line}`}><b className={item.severity}>{item.severity}</b><strong>{item.title}</strong><p>Line {item.line} | {item.recommendation}</p></article>)}
      </>}
    </section>
  );
}

function AssessmentDetails({ result }: { result: Assessment }) {
  return <section className="lower">
    <Card title="Control gaps" subtitle="Mapped to policy">{result.compliance_gaps.map((item) => <article className="row" key={item.control_id}><b>{item.control_id}</b><div><strong>{item.title}</strong><p>{item.framework} | {item.rationale}</p></div></article>)}</Card>
    <Card title="Reviewer queue" subtitle="Human decision">{result.next_actions.map((item, index) => <article className="row" key={item}><b>0{index + 1}</b><p>{item}</p></article>)}</Card>
    <Card title="RAG policy context" subtitle={`${result.retrieved_context.length} sources`}>{result.retrieved_context.map((item) => <article className="row" key={item.source_id}><b>{item.framework}{item.version ? ` ${item.version}` : ""}{item.control_id ? ` · ${item.control_id}` : ""}</b><div><strong>{item.title}</strong><p>{item.excerpt}</p>{item.source_url && <a href={item.source_url} target="_blank" rel="noreferrer">Open official source</a>}</div></article>)}</Card>
    <Card title="Agent audit trail" subtitle="Draft only">{result.agent_trace.map((item, index) => <article className="row" key={item}><b>0{index + 1}</b><p>{item}</p></article>)}</Card>
  </section>;
}

function AssessmentsPage({ result, onNew }: { result: Assessment | null; onNew: () => void }) {
  return <section className="page-content">
    <div className="page-toolbar"><div><h2>Session assessments</h2><p>This view shows assessments created in the current browser session.</p></div><button type="button" className="primary small-button" onClick={onNew}>New assessment</button></div>
    {result ? <article className="panel data-card"><div className="title"><div><small>{result.phase.toUpperCase()} PHASE</small><h2>{result.project_name}</h2></div><i className={`risk ${result.risk_level}`}>{result.risk_level} risk</i></div><div className="metrics"><Metric value={result.findings.length} label="Findings" /><Metric value={result.compliance_gaps.length} label="Control gaps" /><Metric value={`${result.evidence_coverage}%`} label="Evidence mapped" /></div><p className="muted">{result.analyst_brief}</p><h3>Findings</h3>{result.findings.length ? result.findings.map((finding) => <article className="finding" key={`${finding.rule_id}-${finding.line}`}><b className={finding.severity}>{finding.severity}</b><strong>{finding.title}</strong><p>Line {finding.line} | {finding.recommendation}</p></article>) : <p className="muted">No configured rules were triggered for this assessment.</p>}</article> : <EmptyPage title="No assessment yet" detail="Run an assessment from the Command center. Its results will appear here for this session." onAction={onNew} action="Go to command center" />}
  </section>;
}

function EvidencePage({ project, content, file, onEdit }: { project: string; content: string; file: File | null; onEdit: () => void }) {
  return <section className="page-content">
    <div className="page-toolbar"><div><h2>Current session evidence</h2><p>Evidence is submitted to the configured API when you run an assessment.</p></div><button type="button" className="primary small-button" onClick={onEdit}>Edit evidence</button></div>
    <article className="panel data-card"><div className="evidence-meta"><div><small>PROJECT</small><strong>{project || "Untitled review"}</strong></div><div><small>INPUT TYPE</small><strong>{file ? "Uploaded file" : "Pasted text"}</strong></div>{file && <div><small>FILE</small><strong>{file.name}</strong></div>}</div><h3>Evidence preview</h3><pre className="evidence-preview">{file ? `Selected file: ${file.name}\n\nThe file will be parsed when you run the assessment.` : (content || "No evidence entered yet.")}</pre><p className="muted">This is the evidence staged in the current browser session, not a persistent document library.</p></article>
  </section>;
}

function ControlCoveragePage({ result, onNew }: { result: Assessment | null; onNew: () => void }) {
  return <section className="page-content">
    {!result ? <EmptyPage title="No control mappings yet" detail="Run an assessment to see the control gaps mapped from its evidence." onAction={onNew} action="Start an assessment" /> : <>
      <div className="page-toolbar"><div><h2>{result.project_name}</h2><p>Assessment phase: {result.phase} · {result.compliance_gaps.length} mapped control gap(s)</p></div><span className="coverage-score">{result.evidence_coverage}%<small>evidence mapped</small></span></div>
      <article className="panel data-card"><h3>Mapped control gaps</h3>{result.compliance_gaps.length ? result.compliance_gaps.map((gap) => <article className="row" key={`${gap.framework}-${gap.control_id}`}><b>{gap.control_id}</b><div><strong>{gap.title}</strong><p>{gap.framework} | {gap.rationale}</p></div></article>) : <p className="muted">No configured control mappings were triggered by this assessment. This does not establish full framework coverage.</p>}<p className="muted coverage-note">Mappings are limited to the rules and references built into SecureLens; they are not a full compliance evaluation.</p></article>
    </>}
  </section>;
}

function ThreatRegisterPage({ result, onNew }: { result: Assessment | null; onNew: () => void }) {
  return <section className="page-content">
    {!result ? <EmptyPage title="No threat signals yet" detail="Run an assessment to see draft threat signals associated with its evidence." onAction={onNew} action="Start an assessment" /> : <>
      <div className="page-toolbar"><div><h2>{result.project_name}</h2><p>Draft signals from the {result.phase} phase assessment. Validate each signal with a human reviewer.</p></div><span className="coverage-score">{result.threat_signals.length}<small>signals</small></span></div>
      <article className="panel data-card"><h3>Threat signals</h3>{result.threat_signals.length ? result.threat_signals.map((signal, index) => <article className="threat-card" key={`${signal.category}-${signal.title}-${index}`}><div><b>{signal.category}</b><span>Likelihood: {signal.likelihood} · Impact: {signal.impact}</span></div><strong>{signal.title}</strong><p>{signal.evidence}</p></article>) : <p className="muted">No configured threat signals were triggered. This is not a guarantee that the evidence is free of threats.</p>}</article>
    </>}
  </section>;
}

function EmptyPage({ title, detail, onAction, action }: { title: string; detail: string; onAction: () => void; action: string }) {
  return <section className="panel page-empty"><strong>+</strong><h2>{title}</h2><p>{detail}</p><button type="button" className="primary small-button" onClick={onAction}>{action}</button></section>;
}

function Metric({ value, label }: { value: string | number; label: string }) { return <div className="metric"><strong>{value}</strong><span>{label}</span></div>; }
function Card({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) { return <section className="panel compact"><h3>{title}<span>{subtitle}</span></h3>{children}</section>; }
