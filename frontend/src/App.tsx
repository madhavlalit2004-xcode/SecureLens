import { useState } from "react";
import type React from "react";
import "./index.css";

type Finding = {
  rule_id: string;
  severity: string;
  title: string;
  line: number;
  evidence: string;
  recommendation: string;
};

type ScanResponse = {
  finding_count: number;
  findings: Finding[];
};

const SAMPLE_TEXT = `API_KEY = "demo-only-key"
service_url = "http://example.com"
verify=False`;

const API_URL = "http://127.0.0.1:8010/api/scan";

export default function App() {
  const [content, setContent] = useState(SAMPLE_TEXT);
  const [fileName, setFileName] = useState("");
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [isReadingFile, setIsReadingFile] = useState(false);

  async function handleFileChange(
    event: React.ChangeEvent<HTMLInputElement>,
  ) {
    const file = event.target.files?.[0];
    setError("");
    setResult(null);

    if (!file) {
      return;
    }

    if (!file.name.toLowerCase().endsWith(".txt")) {
      setError("SecureLens currently supports plain-text (.txt) files only.");
      event.target.value = "";
      return;
    }

    setIsReadingFile(true);

    try {
      const fileContent = await file.text();
      setContent(fileContent);
      setFileName(file.name);
    } catch {
      setError("SecureLens could not read this file.");
    } finally {
      setIsReadingFile(false);
    }
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setResult(null);

    if (!content.trim()) {
      setError("Paste some text or select a text file before starting a scan.");
      return;
    }

    setIsScanning(true);

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content }),
      });

      if (!response.ok) {
        throw new Error("SecureLens could not complete the scan.");
      }

      setResult((await response.json()) as ScanResponse);
    } catch (scanError) {
      setError(
        scanError instanceof Error
          ? scanError.message
          : "An unexpected error occurred.",
      );
    } finally {
      setIsScanning(false);
    }
  }
  const highCount =
    result?.findings.filter((finding) => finding.severity === "high").length ?? 0;

  const mediumCount =
    result?.findings.filter((finding) => finding.severity === "medium").length ?? 0;
  
    return (
    <main className="page-shell">
      <section className="hero">
        <p className="eyebrow">SECURITY REVIEW WORKSPACE</p>
        <h1>SecureLens</h1>
        <p className="subtitle">
          Quickly inspect document and configuration text for common security
          red flags.
        </p>
      </section>

      <section className="workspace">
        <form className="scan-form" onSubmit={handleSubmit}>
          <label htmlFor="document-file">Upload a text file</label>
          <input
            id="document-file"
            type="file"
            accept=".txt,text/plain"
            onChange={handleFileChange}
          />

          {fileName && (
            <p className="selected-file">
              Selected file: <strong>{fileName}</strong>
            </p>
          )}

          <label htmlFor="document-content">Content to review</label>
          <textarea
            id="document-content"
            value={content}
            onChange={(event) => {
              setContent(event.target.value);
              setFileName("");
            }}
            placeholder="Paste a document, environment configuration, or code snippet..."
          />
          <button type="submit" disabled={isScanning || isReadingFile}>
            {isReadingFile
              ? "Reading file…"
              : isScanning
                ? "Scanning…"
                : "Run security scan"}
          </button>
        </form>

        <section className="results-panel" aria-live="polite">
          <div className="results-heading">
            <div>
              <p className="eyebrow">SCAN RESULTS</p>
              <h2>Findings</h2>
            </div>
            {result && <span className="count">{result.finding_count}</span>}
          </div>

            {result && (
            <div className="severity-summary">
              <div className="summary-card high-summary">
                <span>High</span>
                <strong>{highCount}</strong>
              </div>
              <div className="summary-card medium-summary">
                <span>Medium</span>
                <strong>{mediumCount}</strong>
              </div>
              <div className="summary-card total-summary">
                <span>Total</span>
                <strong>{result.finding_count}</strong>
              </div>
            </div>
          )}
          
          {error && <p className="message error">{error}</p>}

          {!result && !error && (
            <p className="message">
              Upload a text file or paste content, then run a scan.
            </p>
          )}

          {result?.finding_count === 0 && (
            <p className="message success">
              No rules were triggered by this content.
            </p>
          )}

          {result?.findings.map((finding) => (
            <article className="finding" key={`${finding.rule_id}-${finding.line}`}>
              <div className="finding-topline">
                <span className={`severity ${finding.severity}`}>
                  {finding.severity}
                </span>
                <span>Line {finding.line}</span>
              </div>
              <h3>{finding.title}</h3>
              <code>{finding.evidence}</code>
              <p>{finding.recommendation}</p>
            </article>
          ))}
        </section>
      </section>
    </main>
  );
}