import { useState, useEffect, useCallback, useRef } from 'react';
import { Terminal, Copy, Check, ChevronRight, Loader2, Plus, X, Play, ArrowLeft, Mail, Send } from 'lucide-react';
import { onAuthStateChanged } from 'firebase/auth';
import { auth } from './lib/firebase';
import { getUserProfile } from './utils/userProfile';
import { signOut } from './lib/auth-supabase';
import LoginPage from './components/LoginPage';
import WelcomeScreen from './components/WelcomeScreen';
import OpticalAnimation from './components/OpticalAnimation';
import Sidebar from './components/Sidebar';

const THEME_KEY = 'api-secure-theme';
const HISTORY_KEY = 'api-secure-history';
const HISTORY_MAX = 50;

function useHistory() {
  const [history, setHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); }
    catch { return []; }
  });
  const addEntry = useCallback((entry) => {
    setHistory((prev) => {
      const updated = [entry, ...prev.filter((e) => e.id !== entry.id)].slice(0, HISTORY_MAX);
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(updated)); } catch {}
      return updated;
    });
  }, []);
  const removeEntry = useCallback((id) => {
    setHistory((prev) => {
      const updated = prev.filter((e) => e.id !== id);
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(updated)); } catch {}
      return updated;
    });
  }, []);
  const clearHistory = useCallback(() => {
    setHistory([]);
    try { localStorage.removeItem(HISTORY_KEY); } catch {}
  }, []);
  return { history, addEntry, removeEntry, clearHistory };
}

function useTheme() {
  const [theme, setThemeState] = useState(() => {
    try {
      return (localStorage.getItem(THEME_KEY) || 'dark');
    } catch {
      return 'dark';
    }
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch (_) {}
  }, [theme]);

  const toggleTheme = () => setThemeState((t) => (t === 'dark' ? 'light' : 'dark'));

  return { theme, toggleTheme };
}

const TESTING_METHODS = [
  { id: 'm_http', value: 'http header analysis', label: 'HTTP Header Analysis / Content-Security-Policy / Missing HSTS Security Header' },
  { id: 'm_ssl', value: 'SSL / TLS analysis', label: 'SSL / TLS Analysis / Improper TLS Version Used' },
  { id: 'm_sensitive', value: 'Server version Disclosure', label: 'Server Version Disclosure' },
  { id: 'm_cors', value: 'cors', label: 'CORS Validation' },
  { id: 'm_error', value: 'Improper Error Handling', label: 'Improper Error Handling' },
  { id: 'm_url', value: 'URL Tampering Analysis', label: 'URL Tampering' },
];

// Map each testing method value → the result field it populates.
// Used to skip already-tested controls when re-scanning.
const METHOD_TO_FIELD = {
  'http header analysis': 'headersReport',
  'SSL / TLS analysis':   'sslReport',
  'Server version Disclosure': 'serverReport',
  'cors':                 'corsReport',
  'Improper Error Handling': 'errorHandlingReport',
  'URL Tampering Analysis':  'urlTamperingReport',
};

/**
 * Given the current result and a list of selected methods,
 * returns only the methods that have NOT been tested yet.
 * For batch results we check the first item.
 */
function getNewMethods(currentResult, selectedMethods) {
  if (!currentResult) return selectedMethods;
  const existing = currentResult.batch ? (currentResult.results?.[0] || {}) : currentResult;
  return selectedMethods.filter((m) => {
    const field = METHOD_TO_FIELD[m];
    if (!field) return true; // unknown method — always include
    return !existing[field]; // only include if result field is missing
  });
}

/**
 * Merge a new partial scan result into the existing result.
 * Copies non-null report fields from newData into existingResult.
 */
function mergeResults(existingResult, newData) {
  if (!existingResult) return newData;
  const reportFields = Object.values(METHOD_TO_FIELD);
  const merged = { ...existingResult };
  // For batch results, merge per-index
  if (existingResult.batch && newData.batch) {
    merged.results = (existingResult.results || []).map((old, i) => {
      const fresh = newData.results?.[i] || {};
      const item = { ...old };
      reportFields.forEach((f) => { if (fresh[f] != null) item[f] = fresh[f]; });
      if (fresh.overallSummary) item.overallSummary = fresh.overallSummary;
      if (fresh.aiEnabled != null) item.aiEnabled = fresh.aiEnabled;
      return item;
    });
  } else {
    reportFields.forEach((f) => { if (newData[f] != null) merged[f] = newData[f]; });
    if (newData.overallSummary) merged.overallSummary = newData.overallSummary;
    if (newData.aiEnabled != null) merged.aiEnabled = newData.aiEnabled;
  }
  return merged;
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className={`copy-btn${copied ? ' copy-btn--done' : ''}`}
      onClick={() => {
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        });
      }}
      title="Copy to clipboard"
    >
      {copied ? '✓ Copied' : 'Copy'}
    </button>
  );
}

function HeadersReport({ r, onRetryAI, aiPolling }) {
  if (!r) return <div className="report-inner"><div className="section"><div className="section-content" style={{padding:'2rem',color:'var(--text-muted)'}}>No header report data.</div></div></div>;

  const hasError = !!r.error;
  const d = r.targetDomain || r.siteUrl || r.originalUrl || 'Unknown';
  const scanned = (() => {
    const raw = r.scannedAt || r.timestamp;
    if (!raw) return '—';
    try { const d = new Date(raw); return isNaN(d.getTime()) ? raw : d.toLocaleString(); } catch (_) { return raw; }
  })();
  const score = r.score ?? 0;
  const grade = r.grade || 'F';
  const progressColor = score >= 80 ? '#16a34a' : score >= 60 ? '#d97706' : '#dc2626';
  const gradeColor = score >= 80 ? '#16a34a' : score >= 60 ? '#d97706' : '#dc2626';

  const list = (arr) => (!arr?.length
    ? <li className="no-items">✅ None found — this area looks good</li>
    : arr.map((item, i) => <li key={i}>{item}</li>));

  const headers = r.evaluatedHeaders && typeof r.evaluatedHeaders === 'object'
    ? Object.entries(r.evaluatedHeaders).map(([name, info]) => {
        const sev = (info.severity || 'ok').toLowerCase();
        const val = info.value ? (String(info.value).length > 70 ? String(info.value).slice(0, 70) + '…' : info.value) : null;
        return (
          <tr key={name}>
            <td><strong style={{fontSize:'0.84rem'}}>{name}</strong></td>
            <td>
              {info.present
                ? <span className="status-present">● Present</span>
                : <span className="status-missing">● Missing</span>}
            </td>
            <td><code>{val || <em style={{color:'var(--text-muted)',fontStyle:'italic',fontSize:'0.78rem'}}>Not set</em>}</code></td>
            <td><span className={`severity-${sev}`}>{sev.toUpperCase()}</span></td>
          </tr>
        );
      })
    : null;

  return (
    <div className="report-inner">
      {/* Report header */}
      <div className="site-info">
        <div className="site-info-main">
          <div className="site-url">{d}</div>
          <div className="scan-time">Security Headers Analysis · {scanned}</div>
        </div>
        <div className="site-info-score">
          <svg className="score-ring" viewBox="0 0 64 64">
            <circle cx="32" cy="32" r="26" fill="none" stroke="rgba(255,255,255,0.15)" strokeWidth="5"/>
            <circle cx="32" cy="32" r="26" fill="none" stroke={progressColor} strokeWidth="5"
              strokeDasharray={`${(score/100)*163.4} 163.4`} strokeLinecap="round"
              transform="rotate(-90 32 32)" style={{transition:'stroke-dasharray 1s ease'}}/>
          </svg>
          <div className="score-ring-label">
            <div className="score-ring-num" style={{color: progressColor}}>{score}</div>
            <div className="score-ring-sub">/ 100</div>
          </div>
        </div>
      </div>

      {/* Score metric strip */}
      <div className="summary-grid">
        <div className="summary-card" style={{borderBottomColor: gradeColor}}>
          <div className="card-value" style={{color: gradeColor}}>{grade}</div>
          <div className="card-title">Grade</div>
        </div>
        <div className="summary-card" style={{borderBottomColor: progressColor}}>
          <div className="card-value" style={{color: progressColor}}>{score}<span className="card-value-unit">/100</span></div>
          <div className="card-title">Security Score</div>
        </div>
        <div className="summary-card" style={{borderBottomColor:'#dc2626'}}>
          <div className="card-value" style={{color:'#dc2626'}}>{r.criticalCount ?? 0}</div>
          <div className="card-title">Critical Issues</div>
        </div>
        <div className="summary-card" style={{borderBottomColor:'#d97706'}}>
          <div className="card-value" style={{color:'#d97706'}}>{r.warningCount ?? 0}</div>
          <div className="card-title">Warnings</div>
        </div>
      </div>

      {/* Score progress bar */}
      <div className="report-score-bar-wrap">
        <div className="report-score-bar-top">
          <span className="report-score-bar-label">Overall Security Posture</span>
          <span className="report-score-bar-pct" style={{color: progressColor}}>{score}%</span>
        </div>
        <div className="report-score-bar-track">
          <div className="report-score-bar-fill" style={{width:`${score}%`, background: progressColor}} />
        </div>
      </div>

      {hasError && (
        <div className="section">
          <div className="section-header">⚠ Analysis Error</div>
          <div className="section-content" style={{ padding: '18px 28px', color: 'var(--danger)' }}>
            {r.message || 'Headers analysis failed.'} Check the URL and try again.
          </div>
        </div>
      )}
      {!hasError && (
        <>
          <div className="section">
            <div className="section-header">🔍 Security Headers Audit</div>
            <div className="section-content section-content--flush">
              <table>
                <thead>
                  <tr>
                    <th>Header</th>
                    <th>Status</th>
                    <th>Value</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>{headers || <tr><td colSpan="4" style={{color:'var(--text-muted)',padding:'1.5rem 18px'}}>No data available</td></tr>}</tbody>
              </table>
            </div>
          </div>
          {/* ── Security Analysis Section (AI or Fallback) ─────────── */}
          {(() => {
            const hasAI = !!(r.aiExecutiveSummary || r.aiHeaders?.length > 0);
            const isTemplate = r.aiSource === 'template';
            const isCache = r.aiSource === 'cache';
            const isLLM = r.aiSource === 'llm';
            const aiIssues = (r.aiHeaders || []).filter(h => (h.severity||'ok') !== 'ok');
            const aiPassing = (r.aiHeaders || []).filter(h => (h.severity||'ok') === 'ok');

            // Ground truth from the scanner — always correct
            const scanCritical = Object.values(r.evaluatedHeaders || {}).filter(h => (h.severity||'').toLowerCase() === 'critical').length;
            const scanWarning  = Object.values(r.evaluatedHeaders || {}).filter(h => (h.severity||'').toLowerCase() === 'warning').length;
            const scanOk       = Object.values(r.evaluatedHeaders || {}).filter(h => (h.severity||'').toLowerCase() === 'ok').length;
            const scanTotal    = Object.keys(r.evaluatedHeaders || {}).length;

            // AI counts — only use when they agree with scanner ground truth
            const aiCritFromData = hasAI ? (r.aiSummary?.criticalCount ?? aiIssues.filter(h => h.severity === 'critical').length) : null;
            const aiWarnFromData = hasAI ? (r.aiSummary?.warningCount  ?? aiIssues.filter(h => h.severity === 'warning').length)  : null;
            const aiOkFromData   = hasAI ? (r.aiSummary?.okCount       ?? aiPassing.length) : null;
            // If AI data total differs significantly from scan total, AI data is stale — fall back to scan counts
            const aiTotal = (aiCritFromData ?? 0) + (aiWarnFromData ?? 0) + (aiOkFromData ?? 0);
            const aiCountsValid = !hasAI || aiTotal === 0 || Math.abs(aiTotal - scanTotal) <= 2;

            const critCount = aiCountsValid && aiCritFromData !== null ? aiCritFromData : scanCritical;
            const warnCount = aiCountsValid && aiWarnFromData !== null ? aiWarnFromData : scanWarning;
            const okCount   = aiCountsValid && aiOkFromData   !== null ? aiOkFromData   : scanOk;
            const totalCount = scanTotal || (critCount + warnCount + okCount);

            const riskLevel = hasAI && aiCountsValid ? (r.aiOverallRisk || 'Unknown').toLowerCase() : (critCount >= 7 ? 'critical' : critCount >= 4 ? 'high' : critCount >= 2 ? 'medium' : critCount >= 1 ? 'low' : 'good');
            const riskLabel = {'critical':'Not Protected','high':'High Risk','medium':'Needs Work','low':'Mostly Secure','good':'Well Protected'}[riskLevel] || r.aiOverallRisk || 'Unknown';

            // Badge and title depend on source
            const badge = isLLM ? 'AI-Powered Security Audit' : isCache ? 'AI-Powered (Cached)' : aiPolling ? 'Instant Analysis · AI Upgrading…' : 'Instant Security Analysis';
            const reportTitle = (isLLM || isCache) ? 'Security Assessment Report' : 'Findings & Recommendations';

            return (
            <div className="ai-report">
              {/* ── Report Header ── */}
              <div className="ai-report-header">
                <div className="ai-report-header-left">
                  <div className="ai-report-badge">{badge}</div>
                  <div className="ai-report-title">{reportTitle}</div>
                </div>
                <div className="ai-report-header-right">
                  <div className={`ai-risk-indicator ai-risk-${riskLevel}`}>
                    <div className="ai-risk-level">{riskLabel}</div>
                    <div className="ai-risk-sublabel">
                      {(hasAI && aiCountsValid)
                        ? (r.aiRiskExplanation || `Overall risk level: ${r.aiOverallRisk || 'Unknown'}`)
                        : `${critCount} critical issue${critCount !== 1 ? 's' : ''} found`}
                    </div>
                  </div>
                </div>
              </div>

              {/* ── AI Enhancing Banner (shown while LLM runs in background) ── */}
              {aiPolling && isTemplate && (
                <div className="ai-enhancing-banner">
                  <span className="ai-enhancing-spinner" />
                  <div className="ai-enhancing-text">
                    <strong>AI is analysing your headers…</strong>
                    <span>You&apos;re viewing instant results. The report will automatically upgrade with AI-powered explanations and plain-English advice in a moment.</span>
                  </div>
                </div>
              )}

              {/* ── Stats Bar ── */}
              <div className="ai-stats-bar">
                <div className="ai-stat ai-stat-critical">
                  <div className="ai-stat-num">{critCount}</div>
                  <div className="ai-stat-label">Not Protected</div>
                </div>
                <div className="ai-stat ai-stat-warning">
                  <div className="ai-stat-num">{warnCount}</div>
                  <div className="ai-stat-label">Needs Attention</div>
                </div>
                <div className="ai-stat ai-stat-ok">
                  <div className="ai-stat-num">{okCount}</div>
                  <div className="ai-stat-label">Well Protected</div>
                </div>
                <div className="ai-stat ai-stat-total">
                  <div className="ai-stat-num">{totalCount}</div>
                  <div className="ai-stat-label">Total Checked</div>
                </div>
              </div>

              {/* ── AI Executive Summary ── */}
              {hasAI && r.aiExecutiveSummary && (
                <div className="ai-exec-summary">
                  <div className="ai-section-title"><span className="ai-section-icon">📋</span> Executive Summary</div>
                  <p className="ai-exec-summary-text">{r.aiExecutiveSummary}</p>
                </div>
              )}

              {/* ── AI: Detailed Issue Cards ── */}
              {hasAI && aiIssues.length > 0 && (
                <div className="ai-issues-section">
                  <div className="ai-section-title"><span className="ai-section-icon">🛡️</span> Security Issues Found <span className="ai-section-count">{aiIssues.length}</span></div>
                  <div className="ai-issues-list">
                    {aiIssues.map((h, i) => {
                      const sev = (h.severity||'ok').toLowerCase();
                      const sevLabel = sev === 'critical' ? 'Not Protected' : 'Needs Attention';
                      const sevIcon = sev === 'critical' ? '🔴' : '🟡';
                      return (
                      <div key={i} className={`ai-issue-card ai-sev-${sev}`}>
                        {/* Card header */}
                        <div className="ai-issue-header">
                          <div className="ai-issue-header-left">
                            <span className="ai-issue-sev-icon">{sevIcon}</span>
                            <div className="ai-issue-name">{h.name}</div>
                          </div>
                          <span className={`ai-issue-badge ai-badge-${sev}`}>{sevLabel}</span>
                        </div>
                        {/* Current value pill */}
                        {h.value && h.value !== 'null' && h.value !== 'Not set' && (
                          <div className="ai-issue-value-row">
                            <span className="ai-issue-value-label">Current value</span>
                            <code className="ai-issue-value-code">{String(h.value).slice(0,130)}{String(h.value).length > 130 ? '…' : ''}</code>
                          </div>
                        )}
                        {/* Info grid */}
                        <div className="ai-issue-body">
                          {(h.whatItDoes || h.description) && (
                            <div className="ai-issue-field">
                              <div className="ai-issue-field-label">🛡 What this protects</div>
                              <div className="ai-issue-field-text">{h.whatItDoes || h.description}</div>
                            </div>
                          )}
                          {(h.risk || h.impact) && (
                            <div className="ai-issue-field ai-issue-field--risk">
                              <div className="ai-issue-field-label">⚠ What could go wrong</div>
                              <div className="ai-issue-field-text">{h.risk || h.impact}</div>
                            </div>
                          )}
                          {(h.fix || h.recommendation) && (
                            <div className="ai-issue-field ai-issue-field--fix">
                              <div className="ai-issue-field-label">✅ How to fix</div>
                              <div className="ai-issue-field-text">{h.fix || h.recommendation}</div>
                            </div>
                          )}
                        </div>
                      </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* ── Fallback: Basic scanner findings when AI is not available ── */}
              {!hasAI && (
                <>
                  {r.vulnerabilities?.length > 0 && (
                    <div className="ai-issues-section">
                      <div className="ai-section-title"><span className="ai-section-icon">⛔</span> Critical Issues ({r.vulnerabilities.length})</div>
                      <div className="ai-issues-list">
                        {r.vulnerabilities.map((v, i) => {
                          const parts = String(v).split(':');
                          const headerName = parts.length > 1 ? parts[0].trim() : '';
                          const desc = parts.length > 1 ? parts.slice(1).join(':').trim() : String(v);
                          return (
                          <div key={i} className="ai-issue-card ai-sev-critical">
                            <div className="ai-issue-header">
                              <div className="ai-issue-name">{headerName || 'Security Issue'}</div>
                              <span className="ai-issue-badge ai-badge-critical">Not Protected</span>
                            </div>
                            <div className="ai-issue-row">
                              <div className="ai-issue-col">
                                <div className="ai-issue-text">{desc}</div>
                              </div>
                            </div>
                          </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                  {r.warnings?.length > 0 && (
                    <div className="ai-issues-section">
                      <div className="ai-section-title"><span className="ai-section-icon">⚠️</span> Warnings ({r.warnings.length})</div>
                      <div className="ai-issues-list">
                        {r.warnings.map((w, i) => (
                          <div key={i} className="ai-issue-card ai-sev-warning">
                            <div className="ai-issue-header">
                              <div className="ai-issue-name">{String(w).split(':')[0]?.trim() || 'Warning'}</div>
                              <span className="ai-issue-badge ai-badge-warning">Needs Attention</span>
                            </div>
                            <div className="ai-issue-row">
                              <div className="ai-issue-col">
                                <div className="ai-issue-text">{String(w).split(':').slice(1).join(':').trim() || String(w)}</div>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {r.recommendations?.length > 0 && (
                    <div className="ai-action-section">
                      <div className="ai-section-title"><span className="ai-section-icon">🛠️</span> Recommendations</div>
                      <div className="ai-action-list">
                        {r.recommendations.map((rec, i) => {
                          const parts = String(rec).split(':');
                          const headerName = parts.length > 1 ? parts[0].trim() : '';
                          const action = parts.length > 1 ? parts.slice(1).join(':').trim() : String(rec);
                          return (
                          <div key={i} className="ai-action-item">
                            <div className="ai-action-num">{i + 1}</div>
                            <div className="ai-action-body">
                              {headerName && <div className="ai-action-header">{headerName}</div>}
                              <div className="ai-action-desc">{action}</div>
                            </div>
                          </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                  {/* AI retry banner */}
                  {(r.aiError || r.aiHeaderNotes?.startsWith('Security Analysis Summary')) && (
                    <div className="ai-retry-banner">
                      <span className="ai-retry-icon">🤖</span>
                      <div className="ai-retry-text">
                        <strong>Want deeper analysis?</strong>
                        <span>{r.aiError || 'Click Retry to get AI-powered insights with plain-English explanations and fix instructions.'}</span>
                      </div>
                      {onRetryAI && (
                        <button className="ai-retry-btn" onClick={onRetryAI}>⟳ Retry AI Analysis</button>
                      )}
                    </div>
                  )}
                </>
              )}

              {/* ── AI: Protected Headers ── */}
              {hasAI && aiPassing.length > 0 && (
                <div className="ai-passing-section">
                  <div className="ai-section-title"><span className="ai-section-icon">✅</span> Protected <span className="ai-section-count ai-section-count--ok">{aiPassing.length} headers properly configured</span></div>
                  <div className="ai-passing-grid">
                    {aiPassing.map((h, i) => (
                      <div key={i} className="ai-passing-card">
                        <div className="ai-passing-card-top">
                          <span className="ai-passing-check">✓</span>
                          <span className="ai-passing-name">{h.name}</span>
                        </div>
                        <div className="ai-passing-desc">{h.whatItDoes || h.description || 'Properly configured'}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── AI: Action Plan ── */}
              {hasAI && r.aiTopRecs?.length > 0 && (
                <div className="ai-action-section">
                  <div className="ai-section-title"><span className="ai-section-icon">🛠️</span> Recommended Action Plan</div>
                  <p className="ai-action-intro">Fix these items in order of priority to significantly improve your security posture:</p>
                  <div className="ai-action-list">
                    {r.aiTopRecs.map((rec, i) => (
                      <div key={i} className="ai-action-item">
                        <div className="ai-action-num">{rec.priority || i + 1}</div>
                        <div className="ai-action-body">
                          <div className="ai-action-header">{rec.header}</div>
                          <div className="ai-action-desc">{rec.action}</div>
                          {rec.why && (
                            <div className="ai-action-why">
                              <span className="ai-action-why-icon">💡</span> {rec.why}
                            </div>
                          )}
                          {rec.exampleValue && (
                            <div className="ai-action-code-block">
                              <div className="ai-action-code-top">
                                <span className="ai-action-code-label">Add to your server config</span>
                                <CopyButton text={rec.exampleValue} />
                              </div>
                              <code className="ai-action-code">{rec.exampleValue}</code>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Retry / Upgrade strip ── */}
              {isTemplate && !aiPolling && onRetryAI && (
                <div className="ai-upgrade-strip">
                  <span className="ai-upgrade-icon">🤖</span>
                  <div className="ai-upgrade-text">
                    <strong>Upgrade to AI Analysis</strong>
                    <span>Get plain-English explanations, real business-risk context, and copy-paste fix values — powered by AI.</span>
                  </div>
                  <button className="ai-upgrade-btn" onClick={onRetryAI}>
                    ⟳ Run AI Analysis
                  </button>
                </div>
              )}
              {isTemplate && aiPolling && (
                <div className="ai-upgrade-strip ai-upgrade-strip--running">
                  <span className="ai-enhancing-spinner" style={{flexShrink:0}} />
                  <div className="ai-upgrade-text">
                    <strong>AI analysis running…</strong>
                    <span>This report will automatically upgrade with deeper AI insights when complete.</span>
                  </div>
                </div>
              )}
              {(isLLM || isCache) && onRetryAI && (
                <div className="ai-rerun-strip">
                  <span style={{fontSize:'0.8rem',color:'var(--text-muted)'}}>
                    {isCache ? '⚡ Served from cache (24h)' : '✓ AI-powered analysis'}
                  </span>
                  <button className="ai-rerun-btn" onClick={onRetryAI} title="Force a fresh AI analysis">
                    ↻ Re-run AI
                  </button>
                </div>
              )}

              <div className="ai-report-footer">
                {(isLLM || isCache)
                  ? 'Analysis powered by AI — review recommendations with your development team before implementing changes.'
                  : 'Showing instant analysis. Run AI Analysis above for deeper, plain-English insights.'}
              </div>
            </div>
            );
          })()}
        </>
      )}
    </div>
  );
}

// ── Scan Summary Panel ────────────────────────────────────────────────────────
function CorsReport({ r }) {
  const d = r.targetDomain || 'Unknown';
  const scanned = (() => {
    const raw = r.scannedAt || r.timestamp;
    if (!raw) return '—';
    try { const d = new Date(raw); return isNaN(d.getTime()) ? raw : d.toLocaleString(); } catch (_) { return raw; }
  })();
  const risk = r.riskLevel || 'Unknown';
  const riskColors = { High: '#dc3545', Medium: '#ffc107', Low: '#17a2b8', Informational: '#6c757d', Critical: '#7f1d1d' };
  const severityColors = { Critical: '#7f1d1d', High: '#dc3545', Medium: '#eab308', Low: '#17a2b8' };
  const cfg = r.configuration || {};
  const configRows = [
    ['Allowed Origin', cfg.allowedOrigin],
    ['Supports Credentials (Header)', cfg.supportsCredentialsHeader ?? 'Not Set'],
    ['Supports Credentials (Interpreted)', String(cfg.supportsCredentials === true ? 'true' : cfg.supportsCredentials === false ? 'false' : '—')],
    ['Allowed Methods', cfg.allowedMethods],
    ['Allowed Headers', cfg.allowedHeaders ?? 'Not set'],
    ['Exposed Headers', cfg.exposedHeaders],
    ['Vary Header', cfg.varyHeader],
  ];
  const recs = Array.isArray(r.recommendations) ? r.recommendations : [];
  const refs = Array.isArray(r.references) ? r.references : [];
  const allHeaders = r.allHeaders && typeof r.allHeaders === 'object' ? Object.entries(r.allHeaders) : [];

  const originAcceptedDisplay = r.originAccepted === true ? 'Yes' : r.originAccepted === false ? 'No' : '—';
  const originReflectedDisplay = r.originReflected === true ? 'Yes' : r.originReflected === false ? 'No' : '—';

  return (
    <div className="report-inner cors-report">
      <div className="site-info">
        <div className="site-url">{d}</div>
        <div className="scan-time">
          CORS Validation · Scanned: {scanned} ·
          Risk: <span style={{color:'#fff',fontWeight:700,background:riskColors[risk]||'#6c757d',padding:'1px 8px',borderRadius:'999px',fontSize:'0.78rem',marginLeft:'4px'}}>{risk}</span>
        </div>
      </div>
      <div className="cors-summary-block">
        <div className="cors-summary-item">
          <span className="cors-summary-label">Overall Risk</span>
          <span className="cors-summary-value" style={{ color: riskColors[risk] || '#6c757d' }}>{risk}</span>
        </div>
        <div className="cors-summary-item">
          <span className="cors-summary-label">Tested Origin</span>
          <span className="cors-summary-value">{r.originSent ?? '—'}</span>
        </div>
        <div className="cors-summary-item">
          <span className="cors-summary-label">Origin Accepted</span>
          <span className={`cors-summary-value ${r.originAccepted === true ? 'cors-yes' : r.originAccepted === false ? 'cors-no' : ''}`}>{originAcceptedDisplay}</span>
        </div>
        <div className="cors-summary-item">
          <span className="cors-summary-label">Origin Reflected</span>
          <span className={`cors-summary-value ${r.originReflected === true ? 'cors-reflected-yes' : r.originReflected === false ? 'cors-no' : ''}`}>{originReflectedDisplay}</span>
        </div>
      </div>
      {r.executiveSummary && (
        <div className="section">
          <div className="section-header">📋 Executive Summary</div>
          <div className="section-content cors-executive-summary">{r.executiveSummary}</div>
        </div>
      )}
      {r.simpleTerms && (
        <div className="section">
          <div className="section-header">💡 In simple terms</div>
          <div className="section-content cors-simple-terms">{r.simpleTerms}</div>
        </div>
      )}
      {r.howWeTested && (
        <div className="section">
          <div className="section-header">How we tested</div>
          <div className="section-content">{r.howWeTested}</div>
        </div>
      )}
      {r.corsFromPreflight && (
        <div className="section">
          <div className="section-content cors-preflight-note">
            CORS configuration was detected from the <strong>OPTIONS preflight</strong> response only (GET response had no CORS headers).
          </div>
        </div>
      )}
      <div className="section">
        <div className="section-header">⚙️ CORS Configuration Overview</div>
        <div className="section-content">
          <table className="cors-config-table">
            <thead><tr><th>Setting</th><th>Value</th></tr></thead>
            <tbody>{configRows.map(([k, v], i) => <tr key={i}><td><strong>{k}</strong></td><td><code>{v ?? 'Not set'}</code></td></tr>)}</tbody>
          </table>
        </div>
      </div>
      <div className="section">
        <div className="section-header">🔍 Technical Findings</div>
        <div className="section-content">
          {r.vulnerabilities?.length ? (
            <div className="cors-findings-list">
              {r.vulnerabilities.map((v, i) => (
                <div key={i} className="cors-finding-card">
                  <div className="cors-finding-header">
                    <span className="cors-finding-severity" style={{ backgroundColor: severityColors[v.severity] || '#6c757d' }}>{v.severity || 'Finding'}</span>
                    <span className="cors-finding-title">{v.title || 'Finding'}</span>
                  </div>
                  <p className="cors-finding-desc">{v.description || ''}</p>
                  {v.impact && <p className="cors-finding-impact"><strong>Impact:</strong> {v.impact}</p>}
                  {v.recommendation && <p className="cors-finding-rec"><strong>Recommendation:</strong> {v.recommendation}</p>}
                </div>
              ))}
            </div>
          ) : (
            <p className="no-items">No actionable vulnerabilities found.</p>
          )}
        </div>
      </div>
      {recs.length > 0 && (
        <div className="section">
          <div className="section-header">🛠️ Recommendations</div>
          <div className="section-content">
            <ul className="cors-recs-list">{recs.map((rec, i) => <li key={i}>{rec}</li>)}</ul>
          </div>
        </div>
      )}
      {allHeaders.length > 0 && (
        <div className="section">
          <div className="section-header">📄 Full Response Headers</div>
          <div className="section-content">
            <table className="cors-headers-table">
              <thead><tr><th>Header Name</th><th>Value</th></tr></thead>
              <tbody>
                {allHeaders.map(([k, v], i) => (
                  <tr key={i}>
                    <td><code>{k}</code></td>
                    <td><code className="cors-header-value">{String(v)}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {refs.length > 0 && (
        <div className="section">
          <div className="section-header">📚 References</div>
          <div className="section-content">
            <ul className="cors-refs-list">
              {refs.map((ref, i) => {
                const s = typeof ref === 'string' ? ref : String(ref);
                const urlMatch = s.match(/(https?:\/\/[^\s]+)/);
                return (
                  <li key={i}>
                    {urlMatch ? <><a href={urlMatch[1]} target="_blank" rel="noopener noreferrer">{s}</a></> : s}
                  </li>
                );
              })}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

// Severity colours and labels used throughout the Server report
const SVD_SEVERITY_META = {
  Critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.3)', icon: '🔴', plain: 'Very High Risk' },
  High:     { color: '#f97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.3)', icon: '🟠', plain: 'High Risk' },
  Medium:   { color: '#eab308', bg: 'rgba(234,179,8,0.1)',  border: 'rgba(234,179,8,0.3)',  icon: '🟡', plain: 'Medium Risk' },
  Low:      { color: '#22c55e', bg: 'rgba(34,197,94,0.1)', border: 'rgba(34,197,94,0.3)', icon: '🟢', plain: 'Low Risk' },
  Informational: { color: '#6b7280', bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.2)', icon: '🔵', plain: 'Informational' },
};

// Plain-English explanation for each disclosure header type
const HEADER_PLAIN_MEANING = {
  'Server':              'Tells the world which web server software is running (e.g. Apache, Nginx, IIS) and sometimes its exact version number.',
  'X-Powered-By':        'Reveals which programming language or framework is running behind the scenes (e.g. PHP/7.4, ASP.NET, Express).',
  'Via':                 'Shows which proxy or CDN relayed the request — can expose internal infrastructure details.',
  'X-AspNet-Version':    'Exposes the exact version of Microsoft ASP.NET running on the server.',
  'X-AspNetMvc-Version': 'Exposes the exact version of the ASP.NET MVC framework being used.',
  'X-Runtime':           'Shows how long the server took to process the request and may hint at the technology stack.',
  'X-Version':           'A custom header leaking an application or API version number.',
  'X-Generator':         'Reveals which CMS or tool generated this page (e.g. WordPress, Drupal, Joomla).',
  'X-Drupal-Cache':      'Confirms the site is running on Drupal — a known target for attackers exploiting Drupal-specific CVEs.',
  'Link':                'Can expose WordPress REST API endpoints, revealing the CMS and its internal URL structure.',
};

function SvdFindingCard({ disc }) {
  const meta = SVD_SEVERITY_META[disc.severity] || SVD_SEVERITY_META['Informational'];
  const plainMeaning = HEADER_PLAIN_MEANING[disc.header] || 'This header exposes information about the server or technology stack.';
  const isHighRisk = disc.severity === 'Critical' || disc.severity === 'High';
  return (
    <div className="svd-finding-card" style={{ borderLeftColor: meta.color }}>
      <div className="svd-finding-top">
        <div className="svd-finding-header-name">
          <span className="svd-finding-icon">{meta.icon}</span>
          <strong>{disc.header}</strong>
          <span className="svd-risk-pill" style={{ background: meta.bg, color: meta.color, border: `1px solid ${meta.border}` }}>
            {meta.plain}
          </span>
        </div>
        <div className="svd-finding-value-row">
          <span className="svd-value-label">Value sent to the browser:</span>
          <code className="svd-value-code">{disc.value || '—'}</code>
        </div>
      </div>
      <div className="svd-finding-explain">
        <div className="svd-explain-what">
          <span className="svd-explain-label">What is this?</span>
          <span className="svd-explain-text">{plainMeaning}</span>
        </div>
        {disc.evidence && (
          <div className="svd-explain-evidence">
            <span className="svd-explain-label">What the scanner found:</span>
            <span className="svd-explain-text">{disc.evidence}</span>
          </div>
        )}
        {isHighRisk && (
          <div className="svd-explain-risk-note">
            <span className="svd-risk-note-icon">⚠️</span>
            <span>An attacker can look up known security flaws (CVEs) for this exact version and target your server directly.</span>
          </div>
        )}
      </div>
    </div>
  );
}

function ServerReport({ r }) {
  const d = r.targetDomain || r.domain || 'Unknown';
  const risk = r.riskLevel || 'Unknown';
  const riskMeta = SVD_SEVERITY_META[risk] || { color: '#6b7280', bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.2)', icon: '🔵', plain: 'Unknown' };
  const disclosures = r.disclosures || [];
  const recs = Array.isArray(r.recommendations) ? r.recommendations : (r.recommendation ? [r.recommendation] : []);
  const configExamples = r.configurationExamples && typeof r.configurationExamples === 'object' ? r.configurationExamples : {};
  const htmlDisclosures = Array.isArray(r.htmlDisclosures) ? r.htmlDisclosures : [];
  const counts = r.summaryCounts || {};
  const scannedOn = r.scannedAt ? (() => {
    try { return new Date(r.scannedAt).toLocaleString(); } catch (_) { return r.scannedAt; }
  })() : '';

  const hasVersionDisclosure = (counts.headersWithVersion || 0) > 0;
  const criticalOrHigh = disclosures.filter(d => d.severity === 'Critical' || d.severity === 'High');
  const medium = disclosures.filter(d => d.severity === 'Medium');
  const lowOrInfo = disclosures.filter(d => d.severity === 'Low' || d.severity === 'Informational');
  const nothingFound = disclosures.length === 0 && htmlDisclosures.length === 0;

  return (
    <div className="report-inner server-disclosure-report">

      {/* ── Header banner ── */}
      <div className="site-info">
        <div className="site-url">{d}</div>
        <div className="scan-time">Server Version Disclosure Analysis{scannedOn ? ` · Scanned: ${scannedOn}` : ''}</div>
      </div>

      {/* ── Plain-English explainer ── */}
      <div className="svd-explainer-box">
        <div className="svd-explainer-title">🧠 What is Server Version Disclosure?</div>
        <p className="svd-explainer-body">
          Every time your server responds to a request, it can attach small labels (called <strong>HTTP headers</strong>) that
          describe itself — like a name tag. Some of these labels accidentally reveal <em>exactly</em> what software
          your server runs and which version it is.
        </p>
        <p className="svd-explainer-body">
          <strong>Real-world analogy:</strong> Imagine a bank teller wearing a badge that says
          <em> "Vault Lock Model XR-200, manufactured 2018"</em>. A thief now knows the exact lock model and can
          look up its known weaknesses online. Server version disclosure works exactly like that — attackers
          use the version number to search for known security holes (called <strong>CVEs</strong>) and exploit them.
        </p>
        <div className="svd-explainer-steps">
          <div className="svd-step"><span className="svd-step-num">1</span><span>Your server sends a response with a <code>Server: Apache/2.4.51</code> header</span></div>
          <div className="svd-step"><span className="svd-step-num">2</span><span>An attacker sees this and searches <em>"Apache 2.4.51 vulnerability"</em></span></div>
          <div className="svd-step"><span className="svd-step-num">3</span><span>They find a known exploit and launch a targeted attack on your server</span></div>
        </div>
      </div>

      {r.error && (
        <div className="svd-status-card" style={{ borderColor: 'var(--danger)', background: 'rgba(239,68,68,0.05)' }}>
          <span style={{ color: 'var(--danger)', fontWeight: 700 }}>⚠ Scan Error:</span> {r.error}
        </div>
      )}

      {/* ── Overall risk status card ── */}
      {!r.error && (
        <div className="svd-status-card" style={{ borderColor: riskMeta.color, background: riskMeta.bg }}>
          <div className="svd-status-left">
            <span className="svd-status-icon">{riskMeta.icon}</span>
            <div>
              <div className="svd-status-title" style={{ color: riskMeta.color }}>
                {nothingFound ? 'No Disclosures Found' : `Overall Risk: ${risk}`}
              </div>
              <div className="svd-status-subtitle">
                {nothingFound
                  ? 'Great — this server does not leak version or technology information in its headers.'
                  : `${disclosures.length} header${disclosures.length !== 1 ? 's' : ''} disclosing server information${criticalOrHigh.length > 0 ? ` · ${criticalOrHigh.length} Critical/High risk` : ''}`}
              </div>
            </div>
          </div>
          <div className="svd-status-right">
            {counts.totalHeaders != null && <div className="svd-stat"><span className="svd-stat-num">{counts.totalHeaders}</span><span className="svd-stat-lbl">Headers found</span></div>}
            {counts.headersWithVersion != null && <div className="svd-stat"><span className="svd-stat-num" style={{ color: '#ef4444' }}>{counts.headersWithVersion}</span><span className="svd-stat-lbl">With version</span></div>}
            {r.stack && <div className="svd-stat"><span className="svd-stat-num svd-stat-stack">{r.stack}</span><span className="svd-stat-lbl">Tech stack</span></div>}
          </div>
        </div>
      )}

      {/* ── What we found ── */}
      {disclosures.length > 0 && (
        <div className="section">
          <div className="section-header">🔎 What Was Found on {d}</div>
          <div className="section-content svd-findings-intro">
            <p>
              The scanner checked the response headers returned by <strong>{d}</strong> and found the following
              disclosures. Each card below explains what the header reveals and why it matters.
            </p>
          </div>

          {criticalOrHigh.length > 0 && (
            <div className="section-content">
              <div className="svd-group-label svd-group-danger">🔴 High Priority — Fix These First</div>
              <div className="svd-findings-list">
                {criticalOrHigh.map((disc, i) => <SvdFindingCard key={i} disc={disc} />)}
              </div>
            </div>
          )}
          {medium.length > 0 && (
            <div className="section-content">
              <div className="svd-group-label svd-group-medium">🟡 Medium Priority</div>
              <div className="svd-findings-list">
                {medium.map((disc, i) => <SvdFindingCard key={i} disc={disc} />)}
              </div>
            </div>
          )}
          {lowOrInfo.length > 0 && (
            <div className="section-content">
              <div className="svd-group-label svd-group-low">🟢 Low / Informational</div>
              <div className="svd-findings-list">
                {lowOrInfo.map((disc, i) => <SvdFindingCard key={i} disc={disc} />)}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── HTML body disclosures ── */}
      {htmlDisclosures.length > 0 && (
        <div className="section">
          <div className="section-header">📄 Disclosures in the Page Source</div>
          <div className="section-content">
            <p style={{ marginBottom: '0.75rem' }}>
              In addition to headers, version or technology information was also found <strong>inside the HTML page source</strong> itself.
              This can happen when a CMS like WordPress embeds its version in page metadata.
            </p>
            <div className="svd-findings-list">
              {htmlDisclosures.map((h, i) => {
                const meta = SVD_SEVERITY_META[h.severity] || SVD_SEVERITY_META['Informational'];
                return (
                  <div key={i} className="svd-finding-card" style={{ borderLeftColor: meta.color }}>
                    <div className="svd-finding-top">
                      <div className="svd-finding-header-name">
                        <span className="svd-finding-icon">{meta.icon}</span>
                        <strong>{h.type}</strong>
                        <span className="svd-risk-pill" style={{ background: meta.bg, color: meta.color, border: `1px solid ${meta.border}` }}>{meta.plain}</span>
                      </div>
                    </div>
                    <div className="svd-finding-explain">
                      <div className="svd-explain-what">
                        <span className="svd-explain-label">What was found:</span>
                        <span className="svd-explain-text">{h.description}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── Why this matters ── */}
      {!nothingFound && (
        <div className="section">
          <div className="section-header">🎯 Why This Is a Problem</div>
          <div className="section-content">
            <div className="svd-impact-grid">
              <div className="svd-impact-card">
                <div className="svd-impact-icon">🔍</div>
                <div className="svd-impact-title">Reconnaissance Value</div>
                <div className="svd-impact-body">
                  {hasVersionDisclosure
                    ? 'Attackers use automated scanners to fingerprint servers. A disclosed version number directly maps to known CVEs, making your server an easy, targeted mark.'
                    : 'Exposing the server name (without a version) confirms the technology in use. Attackers can narrow their approach, though they cannot directly correlate with a specific CVE without a version number.'}
                </div>
              </div>
              <div className="svd-impact-card">
                <div className="svd-impact-icon">💣</div>
                <div className="svd-impact-title">
                  {hasVersionDisclosure ? 'Targeted Exploitation' : 'Technology Fingerprinting'}
                </div>
                <div className="svd-impact-body">
                  {hasVersionDisclosure
                    ? <>Databases like <strong>CVE MITRE</strong> and <strong>NVD NIST</strong> list every known vulnerability per software version. An attacker can find a working exploit for your exact version in minutes.</>
                    : 'Without a version number, an attacker cannot directly look up applicable CVEs. However, knowing the technology stack helps them craft technology-specific probes and social engineering attempts.'}
                </div>
              </div>
              <div className="svd-impact-card">
                <div className="svd-impact-icon">🔓</div>
                <div className="svd-impact-title">Ease of Discovery</div>
                <div className="svd-impact-body">
                  {hasVersionDisclosure
                    ? <>This information is visible to <em>anyone</em> — no special skills needed. Even a beginner attacker can use publicly available exploit code against an identified version.</>
                    : 'The header is visible in every HTTP response — no authentication or special tools required. Removing it is low effort and reduces your server\'s passive fingerprint.'}
                </div>
              </div>
            </div>
            {r.attackScenario && (
              <div className="svd-scenario-box">
                <div className="svd-scenario-label">Real Attack Scenario</div>
                <p>{r.attackScenario}</p>
                {r.likelihood && <p><strong>Likelihood:</strong> {r.likelihood}</p>}
              </div>
            )}
            {r.cveNote && (
              <div className="svd-cve-note">
                <span>⚠️ {r.cveNote}</span>
                <div style={{ marginTop: '0.5rem' }}>
                  <a href="https://cve.mitre.org/" target="_blank" rel="noopener noreferrer">Search CVE MITRE →</a>
                  &nbsp;&nbsp;
                  <a href="https://nvd.nist.gov/" target="_blank" rel="noopener noreferrer">Search NVD NIST →</a>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── How to fix it ── */}
      {(recs.length > 0 || Object.keys(configExamples).length > 0) && (
        <div className="section">
          <div className="section-header">🛠️ How to Fix This</div>
          <div className="section-content">
            <p style={{ marginBottom: '1rem' }}>
              The goal is simple: <strong>stop your server from announcing what software it runs</strong>.
              Below are the exact configuration changes needed based on your detected stack.
            </p>
            {recs.length > 0 && (
              <div className="svd-recs-list">
                {recs.map((rec, i) => (
                  <div key={i} className="svd-rec-item">
                    <span className="svd-rec-num">{i + 1}</span>
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
            )}
            {Object.keys(configExamples).length > 0 && (
              <div className="svd-config-blocks">
                <div className="svd-config-intro">Copy and apply the relevant configuration for your server:</div>
                {Object.entries(configExamples).map(([name, code]) => (
                  <div key={name} className="config-example-block">
                    <div className="config-example-title">{name}</div>
                    <pre className="config-example-code"><code>{String(code).trim()}</code></pre>
                  </div>
                ))}
              </div>
            )}
            {r.verificationStep && (
              <div className="svd-verify-box">
                <strong>✅ How to verify the fix worked:</strong>
                <p>{r.verificationStep}</p>
                {r.expectedState && <p><em>Expected result after fix:</em> {r.expectedState}</p>}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Nothing found — pass ── */}
      {nothingFound && !r.error && (
        <div className="section">
          <div className="section-content">
            <div className="svd-pass-box">
              <div className="svd-pass-icon">✅</div>
              <div className="svd-pass-title">No Version Information Leaked</div>
              <div className="svd-pass-body">
                The server is not revealing any software names, version numbers, or technology stack
                details in its HTTP headers or HTML source. This is the correct and secure behaviour.
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

const SSL_LABS_LOGO = 'https://www.ssllabs.com/images/logo_ssl_labs.gif';
const SSL_LABS_HOME = 'https://www.ssllabs.com/';

function SslReport({ r }) {
  const host = r.host || 'Unknown';
  const grade = r.grade || r.localGrade || r.endpointGrade || 'N/A';
  const gradeKey = grade.replace(/\s*\(local\)\s*/i, '').trim();
  const gradeColors = { A: '#28a745', 'A+': '#28a745', 'A-': '#28a745', B: '#17a2b8', C: '#ffc107', D: '#fd7e14', F: '#dc3545', '?': '#6c757d' };
  const status = r.localStatus || (r.localProtocol ? `Protocol: ${r.localProtocol}` : null);
  const reportTitle = r.reportTitle || `SSL Report: ${host}${r.ipAddress ? ` (${r.ipAddress})` : ''}`;
  const hasFullReport = !r.error && Array.isArray(r.certificates) && r.certificates.length > 0;
  const hasLocalData = !!(r.localProtocol || r.localCipher);
  const isLocalOnly = !hasFullReport && hasLocalData;
  const gradeIsLocal = /\(local\)/i.test(grade);
  const isNAGrade = gradeKey === 'N/A';

  if (r.error) {
    return (
      <div className="report-inner ssl-report">
        <div className="ssl-report-header">
          <a href={SSL_LABS_HOME} target="_blank" rel="noopener noreferrer" className="ssl-labs-logo-link" title="Qualys SSL Labs">
            <img src={SSL_LABS_LOGO} alt="Qualys SSL Labs" className="ssl-labs-logo" />
          </a>
          <div className="ssl-report-title">{reportTitle}</div>
        </div>
        <div className="site-info"><div className="site-url">{host}</div></div>
        <div className="section"><div className="section-content" style={{ color: 'var(--danger)' }}>{r.message || 'SSL analysis failed.'}</div></div>
      </div>
    );
  }

  return (
    <div className="report-inner ssl-report">
      <div className="ssl-report-header">
        <a href={r.sslLabsUrl || SSL_LABS_HOME} target="_blank" rel="noopener noreferrer" className="ssl-labs-logo-link" title="Qualys SSL Labs">
          <img src={SSL_LABS_LOGO} alt="Qualys SSL Labs" className="ssl-labs-logo" />
        </a>
        <div className="ssl-report-title">{reportTitle}</div>
      </div>

      {/* Site info with grade badge */}
      <div className="site-info">
        <div className="site-url">
          <span className="pulse-dot" style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: '#22c55e', marginRight: 8, verticalAlign: 'middle' }} />
          {host}{r.ipAddress ? ` (${r.ipAddress})` : ''}
        </div>
        <div className="scan-time" style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span>SSL/TLS Security Analysis · Grade:</span>
          <span style={{fontWeight:700,color:'#fff',background:gradeColors[gradeKey]||'#6c757d',padding:'2px 10px',borderRadius:'999px',fontSize:'0.82rem'}}>{grade}</span>
          {status && <span>· {status}</span>}
          {gradeIsLocal && <span style={{fontSize:'.75rem',color:'var(--text-secondary)',fontStyle:'italic'}}>(Local TLS handshake)</span>}
        </div>
      </div>

      {/* If grade is N/A and no local data, show prominent message */}
      {/* SSL Labs API v4 setup notice */}
      {r._needsV4Email && (
        <div className="section" style={{ borderLeft: '4px solid #6366f1' }}>
          <div className="section-header" style={{ background: 'linear-gradient(135deg, #3730a3, #4338ca)' }}>SSL Labs API v4 Not Configured — Limited Results</div>
          <div className="section-content" style={{ fontSize: '.92rem', lineHeight: 1.7 }}>
            <p style={{ margin: '0 0 8px' }}>
              <strong>Qualys SSL Labs deprecated API v3 on January 1, 2024.</strong> Full certificate, cipher suite, and vulnerability reports now require a registered email with the new v4 API.
            </p>
            <p style={{ margin: '0 0 8px' }}>To enable full SSL reports:</p>
            <ol style={{ margin: '0 0 10px', paddingLeft: 20 }}>
              <li>Register your email (one-time) by sending a POST request:
                <pre style={{ background: 'rgba(0,0,0,.25)', padding: '8px 12px', borderRadius: 6, fontSize: '.8rem', overflowX: 'auto', margin: '6px 0' }}>{`curl -X POST https://api.ssllabs.com/api/v4/register \\
  -H "Content-Type: application/json" \\
  -d '{"firstName":"Your","lastName":"Name","email":"you@yourorg.com","organization":"YourOrg"}'`}</pre>
              </li>
              <li>Add <code>SSL_LABS_EMAIL=you@yourorg.com</code> to your <code>.env</code> file</li>
              <li>Restart the backend server</li>
            </ol>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '.84rem' }}>
              Note: SSL Labs requires an organizational/business email. Free email providers (Gmail, Yahoo, Hotmail) are not accepted for registration.
            </p>
          </div>
        </div>
      )}

      {isNAGrade && !hasLocalData && !hasFullReport && !r._needsV4Email && (
        <div className="section" style={{ borderLeft: '4px solid #f59e0b' }}>
          <div className="section-header" style={{ background: 'linear-gradient(135deg, #92400e, #b45309)' }}>Why is the grade N/A?</div>
          <div className="section-content" style={{ fontSize: '.92rem', lineHeight: 1.7 }}>
            <p style={{ margin: '0 0 10px' }}>SSL Labs could not fully analyze this server. Common reasons:</p>
            <ul style={{ margin: '0 0 10px', paddingLeft: 20 }}>
              <li>The server is behind a firewall or CDN that blocks SSL Labs scanners</li>
              <li>The domain resolves to a private/internal IP address</li>
              <li>SSL Labs is currently rate-limited or overloaded</li>
              <li>There is no recent cached assessment available</li>
            </ul>
            <p style={{ margin: 0, fontWeight: 600 }}>Try running the scan again in a few minutes, or use the SSL Labs link below to trigger a fresh assessment.</p>
          </div>
        </div>
      )}

      {/* SSL Labs endpoint status messages */}
      {Array.isArray(r.endpointMessages) && r.endpointMessages.length > 0 && (
        <div className="section">
          <div className="section-header">SSL Labs Endpoint Status</div>
          <div className="section-content">
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
              {r.endpointMessages.map((msg, i) => (
                <li key={i} style={{ padding: '6px 0', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ color: '#f59e0b', fontWeight: 600 }}>⚠</span>
                  <span>{msg}</span>
                </li>
              ))}
            </ul>
            {hasLocalData && (
              <p style={{ marginTop: '10px', fontSize: '.85rem', color: 'var(--text-secondary)' }}>
                SSL Labs could not connect to the server endpoints directly. The analysis below is based on a local TLS handshake from our scanner.
              </p>
            )}
          </div>
        </div>
      )}

      {/* Local TLS connection details — shown prominently when no full report */}
      {hasLocalData && (
        <div className="section" style={isLocalOnly ? { borderLeft: '4px solid #6366f1' } : {}}>
          <div className="section-header">{hasFullReport ? 'Local TLS Verification' : 'TLS Connection Details'}</div>
          <div className="section-content">
            <table className="ssl-report-table">
              <tbody>
                {r.localProtocol && (
                  <tr>
                    <td><strong>Negotiated Protocol</strong></td>
                    <td>
                      <code>{r.localProtocol}</code>
                      {/1\.3/i.test(r.localProtocol) && <span className="ssl-ok" style={{ marginLeft: 8, fontSize: '.78rem' }}>Excellent</span>}
                      {/1\.2/i.test(r.localProtocol) && <span className="ssl-ok" style={{ marginLeft: 8, fontSize: '.78rem' }}>Good</span>}
                      {/1\.[01]/i.test(r.localProtocol) && <span className="ssl-warn" style={{ marginLeft: 8, fontSize: '.78rem' }}>Outdated</span>}
                    </td>
                  </tr>
                )}
                {r.localCipher && (
                  <tr>
                    <td><strong>Cipher Suite</strong></td>
                    <td><code>{r.localCipher}</code></td>
                  </tr>
                )}
                {r.localStatus && (
                  <tr>
                    <td><strong>Connection Status</strong></td>
                    <td><span className={r.localStatus.toLowerCase().includes('fail') ? 'ssl-warn' : 'ssl-ok'}>{r.localStatus}</span></td>
                  </tr>
                )}
                {r.localGrade && (
                  <tr>
                    <td><strong>Local Grade</strong></td>
                    <td>
                      <span style={{fontWeight:700,color:'#fff',background:gradeColors[r.localGrade.replace(/\s*\(local\)\s*/i,'').trim()]||'#6c757d',padding:'1px 8px',borderRadius:'999px',fontSize:'0.78rem'}}>{r.localGrade}</span>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            {isLocalOnly && (
              <p style={{ marginTop: 12, fontSize: '.84rem', color: 'var(--text-secondary)', padding: '8px 12px', background: 'rgba(99,102,241,.06)', borderRadius: 6 }}>
                This assessment was performed via a direct TLS handshake from our scanner. For full certificate chain, cipher suite enumeration, and vulnerability checks, use the Qualys SSL Labs link below.
              </p>
            )}
          </div>
        </div>
      )}

      {/* Full SSL Labs report sections */}
      {hasFullReport && (
        <>
          {r.certificates.map((cert, idx) => (
            <div className="section" key={idx}>
              <div className="section-header">
                Certificate #{idx + 1}{cert.keyAlg && cert.keySize ? `: ${cert.keyAlg} ${cert.keySize} bits` : ''}{cert.signatureAlgorithm ? ` (${cert.signatureAlgorithm})` : ''}
              </div>
              <div className="section-content">
                <table className="ssl-report-table cert-table">
                  <tbody>
                    {cert.subject != null && <tr><td><strong>Subject</strong></td><td><code>{cert.subject}</code></td></tr>}
                    {cert.sha256Fingerprint && <tr><td><strong>Fingerprint SHA256</strong></td><td><code className="mono-small">{cert.sha256Fingerprint}</code></td></tr>}
                    {cert.pinSha256 && <tr><td><strong>Pin SHA256</strong></td><td><code className="mono-small">{cert.pinSha256}</code></td></tr>}
                    {cert.commonNames?.length > 0 && <tr><td><strong>Common names</strong></td><td><code>{cert.commonNames.join(', ')}</code></td></tr>}
                    {cert.altNames?.length > 0 && <tr><td><strong>Alternative names</strong></td><td><code>{cert.altNames.join(' ')}</code></td></tr>}
                    {cert.serialNumber && <tr><td><strong>Serial Number</strong></td><td><code>{cert.serialNumber}</code></td></tr>}
                    {cert.validFrom && <tr><td><strong>Valid from</strong></td><td>{cert.validFrom}</td></tr>}
                    {cert.validUntil && <tr><td><strong>Valid until</strong></td><td>{cert.validUntil}</td></tr>}
                    {cert.keyAlg && <tr><td><strong>Key</strong></td><td>{cert.keyAlg}{cert.keySize ? ` ${cert.keySize} bits` : ''}</td></tr>}
                    {cert.weakKeyDebian != null && <tr><td><strong>Weak key (Debian)</strong></td><td>{cert.weakKeyDebian ? 'Yes' : 'No'}</td></tr>}
                    {cert.issuer && <tr><td><strong>Issuer</strong></td><td><code>{cert.issuer}</code></td></tr>}
                    {cert.signatureAlgorithm && <tr><td><strong>Signature algorithm</strong></td><td>{cert.signatureAlgorithm}</td></tr>}
                    {cert.extendedValidation != null && <tr><td><strong>Extended Validation</strong></td><td>{cert.extendedValidation ? 'Yes' : 'No'}</td></tr>}
                    {cert.sct != null && <tr><td><strong>Certificate Transparency</strong></td><td><span className={cert.sct ? 'ssl-ok' : ''}>{cert.sct ? 'Yes (certificate)' : 'No'}</span></td></tr>}
                    {cert.revocationInfo != null && <tr><td><strong>Revocation information</strong></td><td>CRL, OCSP</td></tr>}
                    {cert.crlUris?.length > 0 && <tr><td><strong>CRL</strong></td><td><code className="mono-small">{cert.crlUris[0]}</code></td></tr>}
                    {cert.ocspUris?.length > 0 && <tr><td><strong>OCSP</strong></td><td><code className="mono-small">{cert.ocspUris[0]}</code></td></tr>}
                    {cert.revocationStatus && <tr><td><strong>Revocation status</strong></td><td><span className={cert.revocationStatus.toLowerCase().includes('not revoked') ? 'ssl-ok' : ''}>{cert.revocationStatus}</span></td></tr>}
                    {cert.dnsCaa != null && <tr><td><strong>DNS CAA</strong></td><td>{cert.dnsCaa ? 'Yes' : 'No (more info)'}</td></tr>}
                    <tr><td><strong>Trusted</strong></td><td><span className="ssl-ok">Yes</span> Mozilla Apple Android Java Windows</td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          ))}
          {r.certificatesProvided != null && (
            <div className="section">
              <div className="section-header">Additional Certificates (chain)</div>
              <div className="section-content">
                <p><strong>Certificates provided:</strong> {r.certificatesProvided}</p>
                <p><strong>Chain issues:</strong> {r.chainIssues ?? 'None'}</p>
              </div>
            </div>
          )}
          {Array.isArray(r.protocols) && r.protocols.length > 0 && (
            <div className="section">
              <div className="section-header">Configuration — Protocols</div>
              <div className="section-content">
                <table className="ssl-report-table">
                  <tbody>
                    {r.protocols.map((p, i) => (
                      <tr key={i}>
                        <td><strong>{p.name}</strong></td>
                        <td><span className={p.enabled && !p.insecure ? 'ssl-ok' : p.insecure ? 'ssl-warn' : ''}>{p.enabled ? 'Yes' : 'No'}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {Array.isArray(r.cipherSuites) && r.cipherSuites.length > 0 && (
            <div className="section">
              <div className="section-header">Cipher Suites</div>
              <div className="section-content">
                {r.cipherSuites.map((group, gi) => (
                  <div key={gi} className="cipher-group">
                    <div className="cipher-group-title">{group.protocol}{group.preference ? ' (server has preference)' : ''}</div>
                    <ul className="cipher-list">
                      {group.suites?.map((s, si) => (
                        <li key={si} className={s.weak ? 'ssl-cipher-weak' : ''}>
                          {s.name}
                          {s.kxType && ` — ${s.kxType}`}{s.kxStrength ? ` (${s.kxStrength} bits)` : ''}{s.cipherStrength ? `, ${s.cipherStrength} bits` : ''}
                          {s.weak && <span className="ssl-weak-tag"> WEAK</span>}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          )}
          {Array.isArray(r.protocolDetails) && r.protocolDetails.length > 0 && (
            <div className="section">
              <div className="section-header">Protocol Details</div>
              <div className="section-content">
                <table className="ssl-report-table">
                  <tbody>
                    {r.protocolDetails.map((d, i) => (
                      <tr key={i}>
                        <td><strong>{d.name}</strong></td>
                        <td><span className={d.ok ? 'ssl-ok' : 'ssl-warn'}>{d.value}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {Array.isArray(r.handshakeSimulation) && r.handshakeSimulation.length > 0 && (
            <div className="section">
              <div className="section-header">Handshake Simulation</div>
              <div className="section-content">
                <table className="ssl-report-table handshake-table">
                  <thead><tr><th>Client</th><th>Protocol</th><th>Cipher Suite</th><th>Status</th></tr></thead>
                  <tbody>
                    {r.handshakeSimulation.slice(0, 30).map((row, i) => (
                      <tr key={i}>
                        <td>{row.client}</td>
                        <td><span className={row.error ? 'ssl-warn' : 'ssl-ok'}>{row.protocol || '—'}</span></td>
                        <td><code>{row.suite || '—'}</code></td>
                        <td>{row.error ? <span className="ssl-warn">{row.error}</span> : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {r.handshakeSimulation.length > 30 && <p className="ssl-report-note">Showing first 30 of {r.handshakeSimulation.length} simulations.</p>}
              </div>
            </div>
          )}
          {(r.testDurationSeconds != null || r.httpStatusCode != null || r.serverSignature) && (
            <div className="section">
              <div className="section-header">Miscellaneous</div>
              <div className="section-content">
                <table className="ssl-report-table">
                  <tbody>
                    {r.testDurationSeconds != null && <tr><td><strong>Test duration</strong></td><td>{r.testDurationSeconds} seconds</td></tr>}
                    {r.httpStatusCode != null && <tr><td><strong>HTTP status code</strong></td><td>{r.httpStatusCode}</td></tr>}
                    {r.serverSignature && <tr><td><strong>HTTP server signature</strong></td><td><code>{r.serverSignature}</code></td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/* Summary & Recommendation */}
      {r.summary && <div className="section"><div className="section-header">Summary</div><div className="section-content">{r.summary}</div></div>}
      {r.recommendation && <div className="section"><div className="section-header">Recommendation</div><div className="section-content">{r.recommendation}</div></div>}

      {/* SSL Labs link */}
      {r.sslLabsUrl && (
        <div className="section">
          <div className="section-header">Full SSL Labs Report</div>
          <div className="section-content">
            <a href={r.sslLabsUrl} target="_blank" rel="noopener noreferrer" className="ssl-labs-report-link">
              Open SSL Server Test for {host} →
            </a>
            {!hasFullReport && <p className="ssl-report-note">Certificate details, cipher suites, chain, and grading are available in the full Qualys SSL Labs report. Run scan again after a recent SSL Labs test to get inline details.</p>}
          </div>
        </div>
      )}

      <div className="ssl-report-footer">
        <a href={SSL_LABS_HOME} target="_blank" rel="noopener noreferrer" className="ssl-labs-logo-link">
          <img src={SSL_LABS_LOGO} alt="Qualys SSL Labs" className="ssl-labs-logo small" />
        </a>
        <span className="ssl-report-copyright">SSL Report. For full certificate and cipher analysis see <a href={r.sslLabsUrl || SSL_LABS_HOME} target="_blank" rel="noopener noreferrer">Qualys SSL Labs</a>. © Qualys, Inc.</span>
      </div>
    </div>
  );
}

function ErrorHandlingReport({ r }) {
  const d = r.targetDomain || 'Unknown';
  const risk = r.riskLevel || 'Unknown';
  const riskColors = { High: '#dc3545', Medium: '#fd7e14', Low: '#28a745', Unknown: '#6c757d' };
  const severityColors = { High: '#dc3545', Medium: '#fd7e14', Low: '#ffc107' };
  const findings = r.findings || [];
  const probes = r.probes || [];
  const count = r.sensitiveLeaked?.length ?? 0;
  return (
    <div className="report-inner">
      <div className="site-info">
        <div className="site-url">{d}</div>
        <div className="scan-time">
          Improper Error Handling Analysis{r.scannedAt ? ` · ${new Date(r.scannedAt).toLocaleString()}` : ''}
        </div>
      </div>
      <div className="cors-summary-block">
        <div className="cors-summary-item">
          <span className="cors-summary-label">Overall Risk</span>
          <span className="cors-summary-value" style={{ color: riskColors[risk] || '#6c757d' }}>{risk}</span>
        </div>
        <div className="cors-summary-item">
          <span className="cors-summary-label">Probe status</span>
          <span className="cors-summary-value">{r.probeStatus ?? '—'}</span>
        </div>
        <div className="cors-summary-item">
          <span className="cors-summary-label">Indicators found</span>
          <span className="cors-summary-value">{count}</span>
        </div>
        <div className="cors-summary-item">
          <span className="cors-summary-label">Probes run</span>
          <span className="cors-summary-value">{probes.length || 1}</span>
        </div>
      </div>
      {r.error && <div className="section"><div className="section-content" style={{ color: 'var(--danger)' }}>{r.error}</div></div>}
      {probes.length > 0 && (
        <div className="section">
          <div className="section-header">Probes performed</div>
          <div className="section-content">
            <table className="cors-config-table" style={{ marginTop: 0 }}>
              <thead><tr><th>URL</th><th>Status</th><th>Indicators</th></tr></thead>
              <tbody>
                {probes.map((p, i) => (
                  <tr key={i}>
                    <td><code style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>{p.probeUrl}</code></td>
                    <td>{p.statusCode ?? (p.error ? 'Error' : '—')}</td>
                    <td>{p.indicatorsCount ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {r.executiveSummary && (
        <div className="section">
          <div className="section-header">Executive Summary</div>
          <div className="section-content executive-summary">{r.executiveSummary}</div>
        </div>
      )}
      {r.simpleTerms && (
        <div className="section">
          <div className="section-header">In simple terms</div>
          <div className="section-content cors-simple-terms">{r.simpleTerms}</div>
        </div>
      )}
      {findings.length > 0 && (
        <div className="section">
          <div className="section-header">Technical findings</div>
          <div className="section-content">
            {findings.map((f, i) => (
              <div key={i} className="cors-finding-card">
                <div className="cors-finding-header">
                  <span className="cors-finding-severity" style={{ backgroundColor: severityColors[f.severity] || '#6c757d' }}>{f.severity}</span>
                  <span className="cors-finding-title">{f.category}</span>
                </div>
                <div className="cors-finding-body">
                  <p><strong>Evidence in response:</strong> <code>{(f.evidence || []).join(', ')}</code></p>
                  {f.impact && <p><strong>Impact:</strong> {f.impact}</p>}
                  {f.remediation && <p><strong>Remediation:</strong> {f.remediation}</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      {r.responseSnippet && (
        <div className="section">
          <div className="section-header">Response snippet (where leakage was found)</div>
          <div className="section-content">
            <pre style={{ fontSize: '0.75rem', overflow: 'auto', maxHeight: '8rem', padding: '0.5rem', background: 'var(--bg-muted)', borderRadius: 4 }}>{r.responseSnippet}</pre>
          </div>
        </div>
      )}
      {r.sensitiveLeaked?.length ? (
        <div className="section">
          <div className="section-header">Sensitive content in error response</div>
          <div className="section-content"><ul>{r.sensitiveLeaked.map((x, i) => <li key={i}><code>{x}</code></li>)}</ul></div>
        </div>
      ) : null}
      <div className="section"><div className="section-header">Recommendation</div><div className="section-content">{r.recommendation || ''}</div></div>
      {r.references?.length > 0 && (
        <div className="section">
          <div className="section-header">References</div>
          <div className="section-content"><ul className="cors-refs-list">{r.references.map((ref, i) => <li key={i}>{ref}</li>)}</ul></div>
        </div>
      )}
    </div>
  );
}

function UrlTamperingReport({ r }) {
  const d = r.targetDomain || 'Unknown';
  const tests = (r.tests || []).map((t, i) => (
    <tr key={i}>
      <td><strong>{t.test}</strong></td>
      <td><code style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>{t.tamperedUrl}</code></td>
      <td>{t.statusCode ?? (t.error ? 'Error' : '—')}</td>
      <td>{t.bodyLength ?? '—'}</td>
      <td>{t.note || t.error || '—'}</td>
    </tr>
  ));
  return (
    <div className="report-inner">
      <div className="site-info">
        <div className="site-url">{d}</div>
        <div className="scan-time">URL Tampering Analysis · Testing parameter manipulation & path traversal</div>
      </div>
      {r.error && <div className="section"><div className="section-header">⚠ Error</div><div className="section-content" style={{ color: 'var(--danger)' }}>{r.error}</div></div>}
      <div className="section">
        <div className="section-header">🔗 Tampering Test Results</div>
        <div className="section-content section-content--flush">
          <table>
            <thead><tr><th>Test</th><th>Tampered URL</th><th>Status</th><th>Body Length</th><th>Note</th></tr></thead>
            <tbody>{tests.length ? tests : <tr><td colSpan={5} style={{color:'var(--text-muted)',padding:'1rem'}}>No tests run</td></tr>}</tbody>
          </table>
        </div>
      </div>
      {r.recommendation && <div className="section"><div className="section-header">🛠️ Recommendation</div><div className="section-content">{r.recommendation}</div></div>}
    </div>
  );
}

const SESSION_KEYS = [
  'sessionId', 'session_id', 'sessionID', 'SessionId',
  'token', 'accessToken', 'access_token', 'accesstoken',
  'id_token', 'idToken', 'refresh_token', 'refreshToken',
  'auth_token', 'authToken', 'jwt', 'bearer',
  'txnToken', 'txn_token', 'ssoToken', 'sso_token',
];

function findSessionValues(obj, prefix = '') {
  const found = [];
  if (!obj || typeof obj !== 'object') return found;
  for (const [key, val] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (SESSION_KEYS.some((k) => k.toLowerCase() === key.toLowerCase()) && val && typeof val === 'string') {
      found.push({ key: path, value: val });
    }
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      found.push(...findSessionValues(val, path));
    }
  }
  return found;
}

function TokenGenerator({ onScanFromCurl }) {
  const makeCurl = (n) => ({ id: n, label: `Curl ${n}`, input: '', result: null, error: '', loading: false, timestamp: null });

  const getNextNum = (list) => {
    if (!list.length) return 1;
    return Math.max(...list.map((c) => c.id)) + 1;
  };

  const [curls, setCurls] = useState([makeCurl(1)]);
  const [activeCurlTab, setActiveCurlTab] = useState(1);
  const [curlUseAI, setCurlUseAI] = useState(true);
  const [copiedField, setCopiedField] = useState('');
  const [executingAll, setExecutingAll] = useState(false);
  const [responseTab, setResponseTab] = useState('body');
  const [requestTab, setRequestTab] = useState('curl');

  const copyToClipboard = (text, field) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedField(field);
      setTimeout(() => setCopiedField(''), 2000);
    });
  };

  const updateCurl = (id, updates) => {
    setCurls((prev) => prev.map((c) => (c.id === id ? { ...c, ...updates } : c)));
  };

  const addCurl = () => {
    if (curls.length >= 10) return;
    setCurls((prev) => {
      const n = getNextNum(prev);
      const next = [...prev, makeCurl(n)];
      setActiveCurlTab(n);
      return next;
    });
  };

  const removeCurl = (id) => {
    if (curls.length <= 1) {
      setCurls([makeCurl(1)]);
      setActiveCurlTab(1);
      return;
    }
    setCurls((prev) => {
      const next = prev.filter((c) => c.id !== id);
      if (activeCurlTab === id) setActiveCurlTab(next[0].id);
      return next;
    });
  };

  const clearCurl = (id) => {
    updateCurl(id, { input: '', result: null, error: '', loading: false, timestamp: null });
  };

  const executeSingle = async (id) => {
    const curl = curls.find((c) => c.id === id);
    if (!curl) return;
    const trimmed = curl.input.trim();
    if (!trimmed) { updateCurl(id, { error: 'Please paste a curl command.' }); return; }
    updateCurl(id, { error: '', result: null, loading: true, timestamp: null });
    const start = performance.now();
    try {
      const res = await fetch('/api/execute-curl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ curlCommand: trimmed }),
      });
      const data = await res.json().catch(() => ({}));
      const elapsed = Math.round(performance.now() - start);
      if (!res.ok) throw new Error(data.error || res.statusText || `Request failed (${res.status})`);
      updateCurl(id, { result: { ...data, _elapsed: elapsed }, loading: false, timestamp: new Date().toLocaleTimeString() });
    } catch (err) {
      let message = err.message || 'Request failed.';
      if (typeof message === 'string' && (message.toLowerCase().includes('failed to fetch') || message.toLowerCase().includes('network error'))) {
        message = 'Cannot reach the backend. Ensure it is running on port 3001.';
      }
      updateCurl(id, { error: message, loading: false });
    }
  };

  const executeAll = async () => {
    const toExecute = curls.filter((c) => c.input.trim());
    if (!toExecute.length) return;
    setExecutingAll(true);
    toExecute.forEach((c) => updateCurl(c.id, { error: '', result: null, loading: true, timestamp: null }));
    await Promise.allSettled(toExecute.map((c) => executeSingle(c.id)));
    setExecutingAll(false);
  };

  const executeChain = async () => {
    const toExecute = curls.filter((c) => c.input.trim());
    if (!toExecute.length) return;
    setExecutingAll(true);
    toExecute.forEach((c) => updateCurl(c.id, { error: '', result: null, loading: true, timestamp: null }));
    const start = performance.now();
    try {
      const res = await fetch('/api/execute-curl-chain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          curls: toExecute.map((c) => ({ id: c.id, curlCommand: c.input.trim() })),
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Chain execution failed');
      const totalElapsed = Math.round(performance.now() - start);
      const perCurl = Math.round(totalElapsed / (data.results?.length || 1));
      for (const r of (data.results || [])) {
        if (r.skipped) { updateCurl(r.id, { loading: false }); continue; }
        if (r.error) { updateCurl(r.id, { error: r.error, loading: false }); continue; }
        updateCurl(r.id, {
          result: { ...r, _elapsed: perCurl, _injectedTokens: r.injectedTokens, _autoInjections: r.autoInjections },
          loading: false,
          timestamp: new Date().toLocaleTimeString(),
        });
      }
    } catch (err) {
      let message = err.message || 'Chain execution failed.';
      if (typeof message === 'string' && (message.toLowerCase().includes('failed to fetch') || message.toLowerCase().includes('network error'))) {
        message = 'Cannot reach the backend. Ensure it is running on port 3001.';
      }
      toExecute.forEach((c) => updateCurl(c.id, { error: message, loading: false }));
    } finally {
      setExecutingAll(false);
    }
  };

  const getTabStatus = (curl) => {
    if (curl.loading) return 'loading';
    if (curl.error) return 'error';
    if (curl.result) return 'success';
    if (curl.input.trim()) return 'has-input';
    return 'empty';
  };

  const dotColors = { empty: 'var(--text-dim)', 'has-input': 'var(--info)', success: 'var(--success)', error: 'var(--danger)', loading: 'var(--info)' };

  const active = curls.find((c) => c.id === activeCurlTab) || curls[0];
  const resp = active.result?.response;
  const req = active.result?.request;
  let parsedJson = null;
  let sessionValues = [];
  if (resp?.isJson && resp?.body) {
    try {
      parsedJson = JSON.parse(resp.body);
      sessionValues = findSessionValues(parsedJson);
    } catch (_) {}
  }
  const statusCode = resp?.statusCode;
  const statusText = statusCode ? (statusCode < 300 ? `${statusCode} OK` : statusCode < 400 ? `${statusCode} Redirect` : statusCode < 500 ? `${statusCode} Client Error` : `${statusCode} Server Error`) : '';
  const statusColor = resp ? (statusCode < 300 ? 'var(--success)' : statusCode < 400 ? 'var(--info)' : statusCode < 500 ? 'var(--warning)' : 'var(--danger)') : '';
  const elapsed = active.result?._elapsed;
  const bodySize = resp?.body ? (resp.body.length > 1024 ? `${(resp.body.length / 1024).toFixed(2)} KB` : `${resp.body.length} B`) : null;
  const headerCount = resp ? Object.keys(resp.headers).length : 0;
  const injectedTokens = active.result?._injectedTokens || [];
  const autoInjections = active.result?._autoInjections || [];
  const sseEvents = resp?.sseEvents || [];
  const anyLoading = curls.some((c) => c.loading);
  const nonEmptyCount = curls.filter((c) => c.input.trim()).length;

  return (
    <div className="pm-wrapper">
      {/* ── Left sidebar: curl collection ── */}
      <aside className="pm-sidebar">
        <div className="pm-sidebar-header">
          <span className="pm-sidebar-title">Curls</span>
          {curls.length < 10 && (
            <button type="button" className="pm-sidebar-add" onClick={addCurl} title="New curl">
              <Plus size={14} />
            </button>
          )}
        </div>
        <div className="pm-sidebar-list">
          {curls.map((c) => (
            <div
              key={c.id}
              className={`pm-sidebar-item${c.id === activeCurlTab ? ' active' : ''}`}
              onClick={() => setActiveCurlTab(c.id)}
            >
              <span className="pm-sidebar-dot" style={{ backgroundColor: dotColors[getTabStatus(c)] }} />
              <span className="pm-sidebar-method">
                {c.result?.request?.method || 'CURL'}
              </span>
              <span className="pm-sidebar-label">{c.label}</span>
              <span className="pm-sidebar-close" onClick={(e) => { e.stopPropagation(); removeCurl(c.id); }} title="Remove">
                <X size={12} />
              </span>
            </div>
          ))}
        </div>
        <div className="pm-sidebar-footer">
          <button type="button" className="pm-execute-all-btn" disabled={executingAll || anyLoading || nonEmptyCount === 0} onClick={executeAll}>
            {executingAll ? <><Loader2 size={14} className="spin-icon" /> Running...</> : <><Play size={14} /> Execute All</>}
          </button>
          <button type="button" className="pm-chain-btn" disabled={executingAll || anyLoading || nonEmptyCount < 2} onClick={executeChain} title="Run curls sequentially — tokens from Curl 1 auto-inject into Curl 2, etc. Use {{token}} or {{sessionId}} as placeholders.">
            {executingAll ? <><Loader2 size={14} className="spin-icon" /> Chaining...</> : <><ChevronRight size={14} /> Execute Chain</>}
          </button>
        </div>
      </aside>

      {/* ── Main content ── */}
      <div className="pm-main">
        {/* Top request tabs */}
        <div className="pm-top-tabs">
          {curls.map((c) => (
            <button
              key={c.id}
              type="button"
              className={`pm-top-tab${c.id === activeCurlTab ? ' active' : ''}`}
              onClick={() => { setActiveCurlTab(c.id); setRequestTab('curl'); }}
            >
              <span className="pm-top-tab-dot" style={{ backgroundColor: dotColors[getTabStatus(c)] }} />
              {c.result?.request?.method && <span className={`pm-top-tab-method pm-method-${c.result.request.method.toLowerCase()}`}>{c.result.request.method}</span>}
              <span>{c.label}</span>
              <span className="pm-top-tab-close" onClick={(e) => { e.stopPropagation(); removeCurl(c.id); }}>
                <X size={12} />
              </span>
            </button>
          ))}
          {curls.length < 10 && (
            <button type="button" className="pm-top-tab-add" onClick={addCurl} title="New tab">
              <Plus size={14} />
            </button>
          )}
        </div>

        {/* URL bar */}
        <div className="pm-url-bar">
          {req ? (
            <span className={`pm-url-method pm-method-${req.method.toLowerCase()}`}>{req.method}</span>
          ) : (
            <span className="pm-url-method">CURL</span>
          )}
          <div className="pm-url-input">
            {req ? req.url : (active.input.trim() ? active.input.trim().substring(0, 120) : 'Paste a curl command below...')}
          </div>
          <button
            type="button"
            className="pm-send-btn"
            disabled={active.loading}
            onClick={() => executeSingle(active.id)}
          >
            {active.loading ? <Loader2 size={16} className="spin-icon" /> : 'Send'}
          </button>
        </div>

        {/* ── Request area (top half) ── */}
        <div className="pm-request-section">
          <div className="pm-section-tabs">
            <button type="button" className={`pm-section-tab${requestTab === 'curl' ? ' active' : ''}`} onClick={() => setRequestTab('curl')}>
              Curl Input
            </button>
            {req && Object.keys(req.headers).length > 0 && (
              <button type="button" className={`pm-section-tab${requestTab === 'req-headers' ? ' active' : ''}`} onClick={() => setRequestTab('req-headers')}>
                Request Headers ({Object.keys(req.headers).length})
              </button>
            )}
            <div className="pm-section-tab-spacer" />
            <button type="button" className="pm-clear-btn" onClick={() => { clearCurl(active.id); setRequestTab('curl'); }}>Clear</button>
          </div>
          {requestTab === 'curl' && (
            <textarea
              className="pm-curl-textarea"
              value={active.input}
              onChange={(e) => updateCurl(active.id, { input: e.target.value })}
              placeholder={`curl --location 'https://api.example.com/session' \\\n--header 'Content-Type: application/json' \\\n--data '{"username":"demo","password":"demo123"}'`}
              rows={6}
            />
          )}
          {requestTab === 'req-headers' && req && (
            <div className="pm-headers-panel pm-req-headers-panel">
              <table className="pm-headers-table">
                <thead><tr><th>Header</th><th>Value</th></tr></thead>
                <tbody>
                  {Object.entries(req.headers).map(([k, v]) => (
                    <tr key={k}><td><strong>{k}</strong></td><td><code>{v}</code></td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {active.error && (
          <div className="error-banner" role="alert" style={{ margin: '0' }}>
            <span className="error-banner-icon" aria-hidden>&#9888;&#65039;</span>
            <span className="error-banner-message">{active.error}</span>
            <button type="button" className="error-banner-dismiss" onClick={() => updateCurl(active.id, { error: '' })} aria-label="Dismiss error">&times;</button>
          </div>
        )}

        {/* ── Response area (bottom half) ── */}
        {active.result && req && resp ? (
          <div className="pm-response-section">
            {/* Response header bar */}
            <div className="pm-response-bar">
              <div className="pm-response-tabs">
                <button type="button" className={`pm-section-tab${responseTab === 'body' ? ' active' : ''}`} onClick={() => setResponseTab('body')}>Body</button>
                {sessionValues.length > 0 && (
                  <button type="button" className={`pm-section-tab${responseTab === 'tokens' ? ' active' : ''}`} onClick={() => setResponseTab('tokens')}>
                    Tokens ({sessionValues.length})
                  </button>
                )}
                {autoInjections.length > 0 && (
                  <button type="button" className={`pm-section-tab${responseTab === 'autoInjections' ? ' active' : ''}`} onClick={() => setResponseTab('autoInjections')}>
                    Auto-injected ({autoInjections.length})
                  </button>
                )}
                {sseEvents.length > 0 && (
                  <button type="button" className={`pm-section-tab${responseTab === 'events' ? ' active' : ''}`} onClick={() => setResponseTab('events')}>
                    Events ({sseEvents.length})
                  </button>
                )}
                <button type="button" className={`pm-section-tab${responseTab === 'headers' ? ' active' : ''}`} onClick={() => setResponseTab('headers')}>
                  Headers ({headerCount})
                </button>
              </div>
              <div className="pm-response-meta">
                <span className="pm-status-badge" style={{ color: statusColor }}>{statusText}</span>
                {elapsed != null && <span className="pm-meta-item">{elapsed} ms</span>}
                {bodySize && <span className="pm-meta-item">{bodySize}</span>}
                {(injectedTokens.length > 0 || autoInjections.length > 0) && (
                  autoInjections.length > 0 ? (
                    <button
                      type="button"
                      className="pm-meta-item pm-injected-badge"
                      title="Click to see what was auto-injected"
                      onClick={() => setResponseTab('autoInjections')}
                    >
                      Auto-injected ({autoInjections.length})
                    </button>
                  ) : (
                    <span className="pm-meta-item pm-injected-badge" title={`Tokens available: ${injectedTokens.join(', ')}`}>
                      Chained
                    </span>
                  )
                )}
                {onScanFromCurl && req?.url && (
                  <>
                    <button
                      type="button"
                      className="pm-meta-item pm-scan-api-btn"
                      title="Run security scanner on this API using the same URL, method, headers and body (e.g. token from chain)"
                      onClick={() => onScanFromCurl(req.url, req.headers, req.method, req.body, curlUseAI)}
                    >
                      Scan this API
                    </button>
                    <label className="pm-meta-item pm-ai-toggle" title={curlUseAI ? 'AI analysis will run (uses API quota)' : 'No AI analysis — saves API quota'}>
                      <input type="checkbox" checked={curlUseAI} onChange={(e) => { e.stopPropagation(); setCurlUseAI((v) => !v); }} />
                      AI {curlUseAI ? 'ON' : 'OFF'}
                    </label>
                  </>
                )}
              </div>
            </div>

            {/* Auto-injected detail panel */}
            {responseTab === 'autoInjections' && autoInjections.length > 0 && (
              <div className="pm-response-body-wrap pm-auto-inject-panel">
                <div className="pm-response-body-toolbar">
                  <span className="pm-body-format">Auto-injected values</span>
                  <button
                    type="button"
                    className="pm-back-btn"
                    onClick={() => setResponseTab('body')}
                    title="Back to response"
                  >
                    <ArrowLeft size={14} /> Back to response
                  </button>
                </div>
                <ul className="pm-auto-inject-list">
                  {autoInjections.map((line, idx) => (
                    <li key={idx} className="pm-auto-inject-item">
                      <code>{line}</code>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* SSE Events tab */}
            {responseTab === 'events' && sseEvents.length > 0 && (
              <div className="pm-response-body-wrap pm-sse-panel">
                <div className="pm-response-body-toolbar">
                  <span className="pm-body-format">Server-Sent Events</span>
                  <button
                    type="button"
                    className="pm-copy-btn"
                    onClick={() => copyToClipboard(JSON.stringify(sseEvents, null, 2), `sse-${active.id}`)}
                    title="Copy all events as JSON"
                  >
                    {copiedField === `sse-${active.id}` ? <><Check size={13} /> Copied</> : <><Copy size={13} /> Copy</>}
                  </button>
                </div>
                <div className="pm-sse-events">
                  {sseEvents.map((ev, idx) => (
                    <div key={idx} className="pm-sse-event">
                      <div className="pm-sse-event-header">
                        <span className="pm-sse-event-type">{ev.event || 'message'}</span>
                        {ev.id != null && <span className="pm-sse-event-id">id: {ev.id}</span>}
                      </div>
                      <pre className="pm-sse-event-data">
                        {typeof ev.data === 'object' ? JSON.stringify(ev.data, null, 2) : ev.data}
                      </pre>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Response body tab */}
            {responseTab === 'body' && (
              <div className="pm-response-body-wrap">
                <div className="pm-response-body-toolbar">
                  <span className="pm-body-format">{resp.isJson ? 'JSON' : 'Raw'}</span>
                  <button
                    type="button"
                    className="pm-copy-btn"
                    onClick={() => copyToClipboard(resp.body, `body-${active.id}`)}
                    title="Copy response body"
                  >
                    {copiedField === `body-${active.id}` ? <><Check size={13} /> Copied</> : <><Copy size={13} /> Copy</>}
                  </button>
                </div>
                <pre className="pm-response-body">{resp.isJson ? JSON.stringify(parsedJson, null, 2) : resp.body}</pre>
              </div>
            )}

            {/* Tokens tab */}
            {responseTab === 'tokens' && sessionValues.length > 0 && (
              <div className="pm-tokens-panel">
                {sessionValues.map((sv) => (
                  <div key={sv.key} className="pm-token-row">
                    <div className="pm-token-key">{sv.key}</div>
                    <div className="pm-token-val">
                      <code>{sv.value}</code>
                      <button type="button" className="btn-copy-inline" onClick={() => copyToClipboard(sv.value, `${active.id}-${sv.key}`)} title="Copy">
                        {copiedField === `${active.id}-${sv.key}` ? <Check size={13} /> : <Copy size={13} />}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Headers tab */}
            {responseTab === 'headers' && (
              <div className="pm-headers-panel">
                <table className="pm-headers-table">
                  <thead><tr><th>Header</th><th>Value</th></tr></thead>
                  <tbody>
                    {Object.entries(resp.headers).map(([k, v]) => (
                      <tr key={k}><td><strong>{k}</strong></td><td><code>{v}</code></td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ) : (
          !active.error && (
            <div className="pm-empty-response">
              <Terminal size={40} strokeWidth={1} />
              <p>Enter a curl command and hit <strong>Send</strong> to see the response here.</p>
            </div>
          )
        )}

        {/* Session token highlight bar (always visible if tokens found) */}
        {sessionValues.length > 0 && responseTab !== 'tokens' && (
          <div className="pm-token-banner" onClick={() => setResponseTab('tokens')}>
            <span className="pm-token-banner-dot" />
            {sessionValues.length} session token{sessionValues.length > 1 ? 's' : ''} detected — click to view
          </div>
        )}
      </div>
    </div>
  );
}

function HistoryPage({ history, onRestore, onRemove, onClear, onDownload }) {
  const gradeColor = (g) => ({ A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' }[g] || '#a3a3a3');
  const scoreBar = (s) => s == null ? null : (
    <div className="hist-score-bar-wrap">
      <div className="hist-score-bar" style={{ width: `${s}%`, background: s >= 80 ? '#22c55e' : s >= 60 ? '#eab308' : '#ef4444' }} />
    </div>
  );

  return (
    <div className="history-page">
      <div className="history-header">
        <div>
          <h2 className="history-title">Recent Testing History</h2>
          <p className="history-sub">{history.length} scan{history.length !== 1 ? 's' : ''} stored locally in your browser</p>
        </div>
        {history.length > 0 && (
          <button className="hist-clear-btn" onClick={() => { if (window.confirm('Clear all history?')) onClear(); }}>
            Clear all
          </button>
        )}
      </div>

      {history.length === 0 ? (
        <div className="history-empty">
          <div className="history-empty-icon">🕐</div>
          <p>No scans yet. Run a security scan and it will appear here.</p>
        </div>
      ) : (
        <div className="history-list">
          {history.map((entry) => {
            const date = new Date(entry.scannedAt);
            const dateStr = date.toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' });
            const timeStr = date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
            return (
              <div key={entry.id} className="history-item">
                <div className="history-item-main">
                  <div className="history-item-url" title={entry.url}>{entry.url}</div>
                  <div className="history-item-meta">
                    <span className="hist-date">{dateStr} · {timeStr}</span>
                    {entry.batch && <span className="hist-badge hist-badge-batch">Batch · {entry.batchCount} URLs</span>}
                    {entry.analysisTypes?.length > 0 && (
                      <span className="hist-badge">{entry.analysisTypes.length} check{entry.analysisTypes.length !== 1 ? 's' : ''}</span>
                    )}
                  </div>
                </div>
                <div className="history-item-score">
                  {entry.grade != null && (
                    <span className="hist-grade" style={{ color: gradeColor(entry.grade) }}>{entry.grade}</span>
                  )}
                  {entry.score != null && (
                    <div className="hist-score-wrap">
                      <span className="hist-score-num">{entry.score}%</span>
                      {scoreBar(entry.score)}
                    </div>
                  )}
                </div>
                <div className="history-item-actions">
                  <button className="hist-btn hist-btn-view" onClick={() => onRestore(entry)} title="Restore this scan result">
                    View
                  </button>
                  <button
                    className="hist-btn hist-btn-download"
                    onClick={() => onDownload(entry)}
                    title="Download report with exact styling"
                  >
                    ⬇ Download
                  </button>
                  <button className="hist-btn hist-btn-del" onClick={() => onRemove(entry.id)} title="Remove from history">
                    ✕
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function SettingsPage({ theme, toggleTheme }) {
  const [usage, setUsage] = useState(null);
  const [usageLoading, setUsageLoading] = useState(false);
  const [usageError, setUsageError] = useState('');

  const fetchUsage = async () => {
    setUsageLoading(true);
    setUsageError('');
    try {
      const res = await fetch('/api/openrouter-usage');
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.enabled) throw new Error(data.error || 'Failed to fetch usage');
      setUsage(data);
    } catch (err) {
      setUsageError(err.message || 'Could not fetch OpenRouter usage.');
    } finally {
      setUsageLoading(false);
    }
  };

  useEffect(() => { fetchUsage(); }, []);

  const fmt = (val) => (val == null ? '—' : `$${Number(val).toFixed(6)}`);
  const fmtDate = (val) => {
    if (!val) return '—';
    try { return new Date(val).toLocaleString(); } catch (_) { return val; }
  };

  // Percentage used if there's a limit
  const limitPct = usage?.limit && usage?.limitRemaining != null
    ? Math.min(100, Math.round(((usage.limit - usage.limitRemaining) / usage.limit) * 100))
    : null;
  const barColor = limitPct == null ? '#6366f1' : limitPct >= 90 ? '#ef4444' : limitPct >= 70 ? '#f97316' : '#22c55e';

  return (
    <div className="settings-page">
      {/* Theme */}
      <div className="form-card settings-card">
        <div className="settings-card-header">
          <span className="settings-card-icon">🎨</span>
          <div>
            <div className="settings-card-title">Appearance</div>
            <div className="settings-card-subtitle">Switch between light and dark mode</div>
          </div>
        </div>
        <button type="button" className="theme-toggle" onClick={toggleTheme}>
          {theme === 'dark' ? '☀️ Switch to Light' : '🌙 Switch to Dark'}
        </button>
      </div>

      {/* OpenRouter AI Usage */}
      <div className="form-card settings-card">
        <div className="settings-card-header">
          <span className="settings-card-icon">🤖</span>
          <div>
            <div className="settings-card-title">OpenRouter AI Usage</div>
            <div className="settings-card-subtitle">Live usage and limits for your API key</div>
          </div>
          <button className="or-refresh-btn" onClick={fetchUsage} disabled={usageLoading} title="Refresh">
            {usageLoading ? '⟳' : '↻'}
          </button>
        </div>

        {usageError && (
          <div className="or-error">⚠️ {usageError}</div>
        )}

        {usageLoading && !usage && (
          <div className="or-loading">Loading usage data…</div>
        )}

        {usage && (
          <div className="or-usage-body">
            {/* Key info row */}
            <div className="or-info-row">
              <div className="or-info-item">
                <span className="or-info-label">Key</span>
                <code className="or-info-value">{usage.label}</code>
              </div>
              <div className="or-info-item">
                <span className="or-info-label">Model</span>
                <code className="or-info-value">{usage.model}</code>
              </div>
              <div className="or-info-item">
                <span className="or-info-label">Tier</span>
                <span className={`or-tier-badge ${usage.isFreeTier ? 'or-tier-free' : 'or-tier-paid'}`}>
                  {usage.isFreeTier ? 'Free Tier' : 'Paid'}
                </span>
              </div>
              {usage.expiresAt && (
                <div className="or-info-item">
                  <span className="or-info-label">Expires</span>
                  <span className="or-info-value">{fmtDate(usage.expiresAt)}</span>
                </div>
              )}
            </div>

            {/* Usage metrics */}
            <div className="or-metrics-grid">
              <div className="or-metric-card or-metric-total">
                <div className="or-metric-num">{fmt(usage.usage)}</div>
                <div className="or-metric-label">Total Spent</div>
              </div>
              <div className="or-metric-card">
                <div className="or-metric-num">{fmt(usage.usageDaily)}</div>
                <div className="or-metric-label">Today</div>
              </div>
              <div className="or-metric-card">
                <div className="or-metric-num">{fmt(usage.usageWeekly)}</div>
                <div className="or-metric-label">This Week</div>
              </div>
              <div className="or-metric-card">
                <div className="or-metric-num">{fmt(usage.usageMonthly)}</div>
                <div className="or-metric-label">This Month</div>
              </div>
            </div>

            {/* Limit bar */}
            {usage.limit != null ? (
              <div className="or-limit-section">
                <div className="or-limit-header">
                  <span className="or-limit-label">Credit Limit Usage</span>
                  <span className="or-limit-value">
                    {fmt(usage.limit - (usage.limitRemaining ?? 0))} used of {fmt(usage.limit)}
                    {usage.limitRemaining != null && (
                      <span className="or-limit-remaining"> · {fmt(usage.limitRemaining)} remaining</span>
                    )}
                  </span>
                </div>
                <div className="or-limit-bar-bg">
                  <div
                    className="or-limit-bar-fill"
                    style={{ width: `${limitPct}%`, background: barColor }}
                  />
                </div>
                <div className="or-limit-pct" style={{ color: barColor }}>{limitPct}% used</div>
                {limitPct >= 90 && (
                  <div className="or-limit-warn">⚠️ You are near your credit limit. Top up or upgrade your plan.</div>
                )}
                {usage.limitReset && (
                  <div className="or-limit-reset">Resets: {fmtDate(usage.limitReset)}</div>
                )}
              </div>
            ) : (
              <div className="or-no-limit">
                <span className="or-no-limit-icon">♾️</span>
                <span>No credit limit set on this key — usage is pay-as-you-go or rate-limited by tier.</span>
              </div>
            )}

            {usage.isFreeTier && (
              <div className="or-free-note">
                ℹ️ Free tier keys can only access free models on OpenRouter. Some models may be unavailable.
                <a href="https://openrouter.ai/keys" target="_blank" rel="noopener noreferrer"> Manage keys →</a>
              </div>
            )}

            <div className="or-last-updated">Last updated: {new Date().toLocaleTimeString()}</div>
          </div>
        )}
      </div>
    </div>
  );
}


function Dashboard({ user, onLogout }) {
  const { theme, toggleTheme } = useTheme();
  const { history, addEntry, removeEntry, clearHistory } = useHistory();
  const [activePage, setActivePage] = useState('scanner');
  const [manualUrl, setManualUrl] = useState('');
  const [recipients, setRecipients] = useState(['']);
  const [sendReport, setSendReport] = useState(false);
  const [selectedMethods, setSelectedMethods] = useState([]);
  const [corsMode, setCorsMode] = useState('');
  const [originUrl, setOriginUrl] = useState('');
  const [useAI, setUseAI] = useState(true);
  const [loading, setLoading] = useState(false);
  const [emailSending, setEmailSending] = useState(false);
  const [emailStatus, setEmailStatus] = useState(null);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  // Background AI polling state
  const [aiPolling, setAiPolling] = useState(false); // true while polling background job
  const [activeTab, setActiveTab] = useState(0);
  const [selectedBatchIndex, setSelectedBatchIndex] = useState(0);
  // Used by history download: set to true before loading a result, triggers DOM-capture after render
  const pendingDownloadRef = useRef(false);
  const saveToHistory = useCallback((data, url, methods) => {
    const firstResult = data?.batch ? (data.results?.[0] || {}) : data;
    const hr = firstResult?.headersReport;
    addEntry({
      id: Date.now().toString(),
      url: url || firstResult?.url || firstResult?.targetDomain || '—',
      scannedAt: new Date().toISOString(),
      score: hr?.score ?? null,
      grade: hr?.grade ?? null,
      analysisTypes: methods || [],
      batch: !!data?.batch,
      batchCount: data?.batch ? (data.results?.length || 0) : null,
      result: data,
    });
  }, [addEntry]);

  // ── Background LLM polling ──────────────────────────────────────────────────
  // When the scan returns an aiJobId, poll /api/ai-poll/<id> until the LLM finishes,
  // then silently upgrade the displayed report with the richer AI result.
  useEffect(() => {
    const hr = result?.batch ? result?.results?.[0]?.headersReport : result?.headersReport;
    const jobId = hr?.aiJobId;
    if (!jobId) return;
    setAiPolling(true);
    let cancelled = false;
    let pollCount = 0;
    const MAX_POLLS = 60; // 60 × 4s = 4 minutes max wait
    const poll = async () => {
      if (cancelled) return;
      try {
        const res = await fetch(`/api/ai-poll/${jobId}`);
        const data = await res.json().catch(() => ({}));
        if (data.status === 'done' && data.aiData) {
          // Upgrade the result with LLM data, clear aiJobId so polling stops
          setResult((prev) => {
            if (!prev) return prev;
            const patchHR = (prevHR) => ({
              ...prevHR,
              ...data.aiData,
              aiJobId: null, // stop future polls
              aiSource: data.aiData.aiSource || 'llm',
              aiError: null,
            });
            if (prev.batch) {
              const updatedResults = (prev.results || []).map((r) =>
                r?.headersReport?.aiJobId === jobId
                  ? { ...r, headersReport: patchHR(r.headersReport) }
                  : r
              );
              return { ...prev, results: updatedResults };
            }
            return { ...prev, headersReport: patchHR(prev.headersReport) };
          });
          setAiPolling(false);
          return; // done
        }
        if (data.status === 'failed' || data.status === 'not_found') {
          setAiPolling(false);
          return; // keep template result, no upgrade
        }
        // still pending — schedule next poll with increasing delay
        pollCount += 1;
        if (pollCount >= MAX_POLLS) { setAiPolling(false); return; }
        const delay = pollCount < 5 ? 4000 : pollCount < 15 ? 6000 : 10000;
        if (!cancelled) setTimeout(poll, delay);
      } catch {
        if (!cancelled) setTimeout(poll, 8000);
      }
    };
    setTimeout(poll, 4000); // first poll after 4 seconds
    return () => { cancelled = true; setAiPolling(false); };
  }, [result?.headersReport?.aiJobId, result?.results?.[0]?.headersReport?.aiJobId]);

  // Fires after result state updates — used by history download to trigger DOM capture
  useEffect(() => {
    if (!pendingDownloadRef.current) return;
    pendingDownloadRef.current = false;
    // Wait two animation frames so the browser paints the new result before we capture
    const raf = requestAnimationFrame(() => {
      requestAnimationFrame(async () => {
        const tabPanel = document.querySelector('.tab-panel');
        const reportEl = tabPanel?.querySelector('.report-inner') || tabPanel;
        if (!reportEl) return;
        try {
          const cssChunks = [];
          for (const sheet of Array.from(document.styleSheets)) {
            try {
              const rules = sheet.cssRules || sheet.rules;
              if (rules) { cssChunks.push(Array.from(rules).map(r => r.cssText).join('\n')); continue; }
            } catch { /**/ }
            if (sheet.href) {
              try { const r = await fetch(sheet.href); if (r.ok) cssChunks.push(await r.text()); } catch { /**/ }
            }
          }
          const theme = document.documentElement.getAttribute('data-theme') || 'light';
          const siteUrlEl = reportEl.querySelector('.site-url');
          const domain = siteUrlEl?.textContent?.trim().replace(/^[•●\s]+/, '') || 'report';
          const clone = reportEl.cloneNode(true);
          clone.querySelectorAll('.ai-upgrade-strip,.ai-rerun-strip,.ai-retry-banner,.copy-btn,.ai-enhancing-banner').forEach(el => el.remove());
          const dateStr = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
          const safeFilename = domain.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 60);
          const html = `<!DOCTYPE html><html lang="en" data-theme="${theme}"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Security Report — ${domain} — ${dateStr}</title>
<style>*,*::before,*::after{box-sizing:border-box;}html,body{margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}[data-theme="dark"]{background:#0f172a;color:#e2e8f0;}[data-theme="light"]{background:#f1f5f9;color:#1e293b;}.report-wrapper{max-width:960px;margin:32px auto;padding:0 16px 48px;}.report-meta{font-size:.72rem;color:#64748b;margin-bottom:16px;padding:10px 16px;background:rgba(99,102,241,.06);border-radius:8px;border:1px solid rgba(99,102,241,.15);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;}.report-inner{border-radius:14px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.12);}.ai-enhancing-banner,.ai-upgrade-strip,.ai-rerun-strip,.ai-retry-banner{display:none!important;}@media print{body{background:#fff!important;}.report-wrapper{margin:0;padding:0;max-width:100%;}.report-meta{display:none;}}${cssChunks.join('\n')}</style>
</head><body data-theme="${theme}"><div class="report-wrapper">
<div class="report-meta"><span>🔒 API Security Report · ${domain}</span><span>Generated ${dateStr} · API Secure Scanner</span></div>
${clone.outerHTML}</div></body></html>`;
          const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `security-report-${safeFilename}-${new Date().toISOString().slice(0, 10)}.html`;
          document.body.appendChild(a); a.click(); document.body.removeChild(a);
          setTimeout(() => URL.revokeObjectURL(url), 2000);
        } catch (err) {
          alert('Download failed: ' + (err.message || 'Unknown error'));
        }
      });
    });
    return () => cancelAnimationFrame(raf);
  }, [result]);

  const toggleMethod = (value) => {
    setSelectedMethods((prev) => (prev.includes(value) ? prev.filter((m) => m !== value) : [...prev, value]));
  };

  const addRecipient = () => setRecipients((prev) => [...prev, '']);
  const setRecipientAt = (i, v) => setRecipients((prev) => prev.map((r, j) => (j === i ? v : r)));
  const removeRecipient = (i) => setRecipients((prev) => prev.filter((_, j) => j !== i));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    let url = '';
    let batchUrls = [];
    url = manualUrl.trim();
    if (!url) { setError('Please enter an API URL'); return; }
    batchUrls = [url];
    if (!selectedMethods.length) { setError('Please select at least one testing method'); return; }
    if (selectedMethods.includes('cors') && !corsMode) { setError('Please select CORS mode (Active or Passive)'); return; }
    if (selectedMethods.includes('cors') && corsMode === 'active' && !originUrl.trim()) { setError('Please enter Origin URL for Active CORS'); return; }

    // Incremental scan: skip controls that already have results for this EXACT URL
    const currentUrl = (url || '').trim().replace(/\/$/, ''); // strip trailing slash
    const resultUrl = (result?.url || '').trim().replace(/\/$/, '');
    const existingForUrl = result && !result.batch && resultUrl === currentUrl ? result : null;
    const methodsToRun = getNewMethods(existingForUrl, selectedMethods);
    const skippedMethods = selectedMethods.filter((m) => !methodsToRun.includes(m));

    if (methodsToRun.length === 0) {
      setError(`All selected controls already have results. Deselect tested controls or clear the current result to re-scan.`);
      return;
    }

    const corsAnalysisType = methodsToRun.includes('cors') && corsMode ? (corsMode === 'active' ? 'Active CORS Test' : 'Passive CORS Test') : '';
    const validRecipients = sendReport ? recipients.filter((r) => r.trim()) : [];
    setLoading(true);
    setEmailStatus(null);
    if (validRecipients.length > 0) setEmailSending(true);
    try {
      const body = {
        url: url || undefined,
        batchUrls: batchUrls.length ? batchUrls : undefined,
        analysisTypes: methodsToRun,
        origin: corsMode === 'active' ? originUrl.trim() || undefined : undefined,
        corsAnalysisType: corsAnalysisType || undefined,
        recipientEmails: validRecipients.length ? validRecipients.join(', ') : undefined,
        aiAnalysis: useAI,
      };
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || res.statusText || `Request failed (${res.status})`);
      // Merge new results into existing if this is an incremental scan
      const merged = existingForUrl && skippedMethods.length > 0 ? mergeResults(existingForUrl, data) : data;
      setResult(merged);
      setActiveTab(0);
      setSelectedBatchIndex(0);
      saveToHistory(merged, url, selectedMethods);
      if (skippedMethods.length > 0) {
        const labels = skippedMethods.map((m) => TESTING_METHODS.find((t) => t.value === m)?.label?.split(' / ')[0] || m);
        setEmailStatus({ type: 'info', message: `⚡ Skipped already-tested: ${labels.join(', ')}. Results merged.` });
      }
      if (validRecipients.length > 0) {
        if (data.emailSent) {
          setEmailStatus({ type: 'success', message: `Report sent to ${validRecipients.join(', ')}` });
        } else {
          setEmailStatus({ type: 'error', message: data.emailError || 'Failed to send report email.' });
        }
      }
    } catch (err) {
      let message = err.message || 'Scan failed.';
      if (
        typeof message === 'string' &&
        (message.toLowerCase().includes('failed to fetch') ||
         message.toLowerCase().includes('network error') ||
         message.toLowerCase().includes('load failed') ||
         message.toLowerCase().includes('networkrequestfailed'))
      ) {
        message =
          'Cannot reach the backend. Start it first: open a terminal in the "Main Project" folder and run: py app.py (must listen on port 3001). Then refresh and try again.';
      } else if (!message.includes('backend') && !message.includes('port')) {
        message = message + ' Ensure the backend is running on port 3001.';
      }
      setError(message);
      setResult(null);
    } finally {
      setLoading(false);
      setEmailSending(false);
    }
  };

  // Send report to recipients (after scan)
  const handleSendReport = async () => {
    const validRecipients = recipients.filter((r) => r.trim());
    if (!validRecipients.length) { setEmailStatus({ type: 'error', message: 'Add at least one recipient email.' }); return; }
    if (!result) { setEmailStatus({ type: 'error', message: 'No scan results to send.' }); return; }
    setEmailSending(true);
    setEmailStatus(null);
    try {
      const res = await fetch('/api/send-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipientEmails: validRecipients.join(', '), report: result }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Failed to send report');
      setEmailStatus({ type: 'success', message: `Report sent to ${validRecipients.join(', ')}` });
    } catch (err) {
      setEmailStatus({ type: 'error', message: err.message || 'Failed to send report email.' });
    } finally {
      setEmailSending(false);
    }
  };

  const [downloadingReport, setDownloadingReport] = useState(false);

  const batchResults = result?.batch ? (result.results || []) : [];
  const safeBatchIndex = batchResults.length ? Math.min(selectedBatchIndex, batchResults.length - 1) : 0;
  const currentResult = result?.batch ? batchResults[safeBatchIndex] : result;
  const tabs = [];
  if (currentResult?.headersReport != null) tabs.push({ name: 'Security headers', content: (
    <HeadersReport
      r={currentResult.headersReport}
      aiPolling={aiPolling}
      onRetryAI={async () => {
        // Force a fresh LLM scan (bypasses cache) by re-submitting the scan with forceAI flag
        try {
          const domain = currentResult.targetDomain || currentResult.url;
          const evaluated = currentResult.headersReport?.evaluatedHeaders || {};
          // Invalidate cache and start a new background job via the scan endpoint
          const res = await fetch('/api/ai-retry', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, evaluatedHeaders: evaluated }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.error || 'AI retry failed');
          // Patch the job id into our result so the polling effect kicks in
          const newJobId = data.jobId;
          if (newJobId) {
            setResult((prev) => {
              if (!prev) return prev;
              const patchHR = (prevHR) => ({ ...prevHR, aiJobId: newJobId, aiSource: 'template' });
              if (prev.batch) {
                const results = (prev.results || []).map((r, i) =>
                  i === safeBatchIndex ? { ...r, headersReport: patchHR(r.headersReport || {}) } : r
                );
                return { ...prev, results };
              }
              return { ...prev, headersReport: patchHR(prev.headersReport || {}) };
            });
            setAiPolling(true);
          }
        } catch (err) {
          setEmailStatus({ type: 'error', message: `AI retry failed: ${err.message}` });
        }
      }}
    />
  ) });
  if (currentResult?.corsReport != null) tabs.push({ name: 'CORS', content: <CorsReport r={currentResult.corsReport} /> });
  if (currentResult?.serverReport != null) tabs.push({ name: 'Server disclosure', content: <ServerReport r={currentResult.serverReport} /> });
  if (currentResult?.sslReport != null) tabs.push({ name: 'SSL/TLS', content: <SslReport r={currentResult.sslReport} /> });
  else if (currentResult && selectedMethods.some((m) => /ssl|tls/i.test(m))) tabs.push({ name: 'SSL/TLS', content: <div className="report-inner"><div className="section"><div className="section-content" style={{ color: 'var(--danger)' }}>SSL/TLS report was not returned. Ensure the backend is running and try again.</div></div></div> });
  if (currentResult?.errorHandlingReport != null) tabs.push({ name: 'Error handling', content: <ErrorHandlingReport r={currentResult.errorHandlingReport} /> });
  if (currentResult?.urlTamperingReport != null) tabs.push({ name: 'URL tampering', content: <UrlTamperingReport r={currentResult.urlTamperingReport} /> });

  // ── Download current report tab as a self-contained HTML file ──────────────
  // Defined here (after currentResult + tabs) to avoid temporal dead zone crash
  const downloadCurrentReport = async () => {
    const tabPanel = document.querySelector('.tab-panel');
    const reportEl = tabPanel?.querySelector('.report-inner') || tabPanel;
    if (!reportEl) { alert('No report visible to download.'); return; }
    setDownloadingReport(true);
    try {
      const cssChunks = [];
      for (const sheet of Array.from(document.styleSheets)) {
        try {
          const rules = sheet.cssRules || sheet.rules;
          if (rules) { cssChunks.push(Array.from(rules).map(r => r.cssText).join('\n')); continue; }
        } catch { /* cross-origin */ }
        if (sheet.href) {
          try { const res = await fetch(sheet.href); if (res.ok) cssChunks.push(await res.text()); } catch { /* ignore */ }
        }
      }
      const theme = document.documentElement.getAttribute('data-theme') || 'light';
      const domain = currentResult?.targetDomain || currentResult?.url || 'report';
      const tabName = tabs[activeTab]?.name || 'security-report';
      const clone = reportEl.cloneNode(true);
      clone.querySelectorAll('.ai-upgrade-strip, .ai-rerun-strip, .ai-retry-banner, .copy-btn, .ai-enhancing-banner').forEach(el => el.remove());
      const safeFilename = `${domain}-${tabName}`.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_+/g, '_').slice(0, 60);
      const dateStr = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
      const html = `<!DOCTYPE html>
<html lang="en" data-theme="${theme}">
<head>
  <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Security Report — ${domain} — ${dateStr}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    [data-theme="dark"] { background: #0f172a; color: #e2e8f0; }
    [data-theme="light"] { background: #f1f5f9; color: #1e293b; }
    .report-wrapper { max-width: 960px; margin: 32px auto; padding: 0 16px 48px; }
    .report-meta { font-size: 0.72rem; color: #64748b; margin-bottom: 16px; padding: 10px 16px; background: rgba(99,102,241,0.06); border-radius: 8px; border: 1px solid rgba(99,102,241,0.15); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
    .report-inner { border-radius: 14px; overflow: hidden; box-shadow: 0 4px 24px rgba(0,0,0,0.12); }
    .ai-enhancing-banner, .ai-upgrade-strip, .ai-rerun-strip, .ai-retry-banner { display: none !important; }
    @media print { body { background: #fff !important; } .report-wrapper { margin: 0; padding: 0; max-width: 100%; } .report-meta { display: none; } }
    ${cssChunks.join('\n')}
  </style>
</head>
<body data-theme="${theme}">
  <div class="report-wrapper">
    <div class="report-meta"><span>🔒 API Security Report · ${domain}</span><span>Generated ${dateStr} · API Secure Scanner</span></div>
    ${clone.outerHTML}
  </div>
</body></html>`;
      const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${safeFilename}-${new Date().toISOString().slice(0, 10)}.html`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (err) {
      alert('Download failed: ' + (err.message || 'Unknown error'));
    } finally {
      setDownloadingReport(false);
    }
  };

  return (
    <div className="app-with-sidebar">
      <Sidebar user={user} onLogout={onLogout} activePage={activePage} onNavigate={setActivePage} />
      <div className="app-main-content">
      <div className="app">
      {loading && (
        <div className="loading-overlay" aria-live="polite" aria-busy="true">
          <div className="loading-card">
            <div className="loading-spinner" aria-hidden />
            <p className="loading-title">{emailSending ? 'Scanning & Sending Email…' : 'Scanning…'}</p>
            <p className="loading-hint">{emailSending ? 'Running security checks and sending report to recipients.' : 'This may take 15–60 seconds. Please wait.'}</p>
            {emailSending && (
              <div className="email-sending-badge">
                <span className="email-sending-dot" /> Sending email to recipients…
              </div>
            )}
          </div>
        </div>
      )}
      {/* Standalone email sending overlay */}
      {emailSending && !loading && (
        <div className="loading-overlay" aria-live="polite" aria-busy="true">
          <div className="loading-card">
            <div className="loading-spinner" aria-hidden />
            <p className="loading-title">Sending Email…</p>
            <p className="loading-hint">Delivering the security report to your recipients.</p>
            <div className="email-sending-badge">
              <span className="email-sending-dot" /> Please wait…
            </div>
          </div>
        </div>
      )}
      <header className="header">
        <div className="header-left">
          <div className="header-logo" aria-hidden>⚙</div>
          <div>
            <h1>API Secure</h1>
            <p className="sub">Scan · Analyze · Report</p>
          </div>
        </div>
        <div className="header-actions">
          <button type="button" className="theme-toggle" onClick={toggleTheme} title={theme === 'dark' ? 'Switch to light' : 'Switch to dark'} aria-label="Toggle theme">
            {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
          </button>
          <button type="button" className="header-btn header-btn-settings" title="Settings" aria-label="Settings" onClick={() => setActivePage('settings')}>⚙️</button>
          <button type="button" className="header-btn" title="Help" aria-label="Help">❓</button>
          <button type="button" className="header-btn header-logout-mobile" title="Logout" aria-label="Logout" onClick={onLogout}>
            Logout
          </button>
        </div>
      </header>

      {activePage === 'settings' && (
        <SettingsPage theme={theme} toggleTheme={toggleTheme} />
      )}

      {activePage === 'history' && (
        <HistoryPage
          history={history}
          onRestore={(entry) => {
            setResult(entry.result);
            setManualUrl(entry.url);
            setSelectedMethods(entry.analysisTypes || []);
            setActiveTab(0);
            setSelectedBatchIndex(0);
            setActivePage('scanner');
          }}
          onDownload={(entry) => {
            // Load the result onto the scanner page, then capture the live DOM
            pendingDownloadRef.current = true;
            setResult(entry.result);
            setActiveTab(0);
            setSelectedBatchIndex(0);
            setActivePage('scanner');
          }}
          onRemove={removeEntry}
          onClear={clearHistory}
        />
      )}

      {activePage === 'token-generator' && (
        <TokenGenerator
          onScanFromCurl={async (url, requestHeaders, method, requestBody, aiFlag = true) => {
            setLoading(true);
            setError('');
            setEmailStatus(null);
            const autoMethods = TESTING_METHODS.filter((m) => m.value !== 'cors').map((m) => m.value);
            try {
              const body = {
                url,
                requestHeaders: requestHeaders || undefined,
                method: method || undefined,
                requestBody: requestBody || undefined,
                analysisTypes: autoMethods,
                aiAnalysis: aiFlag,
              };
              const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
              });
              const data = await res.json().catch(() => ({}));
              if (!res.ok) throw new Error(data.error || res.statusText || 'Scan failed');
              // Reset result fully — do NOT merge with existing (this is a fresh curl-triggered scan)
              setResult(data);
              setManualUrl(url);
              // Sync selectedMethods so incremental scan knows what was already done
              setSelectedMethods(autoMethods);
              setActiveTab(0);
              setSelectedBatchIndex(0);
              saveToHistory(data, url, autoMethods);
              setActivePage('scanner');
            } catch (err) {
              setError(err.message || 'Scan failed');
              setResult(null);
            } finally {
              setLoading(false);
            }
          }}
        />
      )}

      {activePage === 'scanner' && <div className="main-grid">
        <div className="main-col">
          <div className="form-card">
            <form onSubmit={handleSubmit}>
              <div className="section-label">Step 1 — API URL</div>
              <input type="url" className="manual-url" value={manualUrl} onChange={(e) => setManualUrl(e.target.value)} placeholder="https://api.example.com" />
              <p className="form-prompt">Enter the API or website URL to scan. Use <code>https://</code> or <code>http://</code>.</p>

              <div className="section-label" style={{ marginTop: '1.25rem' }}>Step 2 — Testing Methods</div>
              <div className="methods-list">
                {TESTING_METHODS.map((m) => {
                  const existingForUrl = result && !result.batch ? result : null;
                  const alreadyDone = !!existingForUrl?.[METHOD_TO_FIELD[m.value]];
                  return (
                    <div key={m.id} className={`method-item${alreadyDone ? ' method-item-done' : ''}`} onClick={() => toggleMethod(m.value)}>
                      <input type="checkbox" id={m.id} checked={selectedMethods.includes(m.value)} onChange={() => {}} />
                      <label htmlFor={m.id}>{m.label}</label>
                      {alreadyDone && <span className="method-done-badge">✓ Done</span>}
                    </div>
                  );
                })}
                {selectedMethods.includes('cors') && (
                  <div className="cors-row">
                    <div className="section-label">CORS mode</div>
                    <div className="cors-mode">
                      <label><input type="radio" name="corsMode" value="passive" checked={corsMode === 'passive'} onChange={() => setCorsMode('passive')} /> Passive (no origin)</label>
                      <label><input type="radio" name="corsMode" value="active" checked={corsMode === 'active'} onChange={() => setCorsMode('active')} /> Active (send custom Origin)</label>
                    </div>
                    {corsMode === 'active' && <input type="text" className="origin-input" value={originUrl} onChange={(e) => setOriginUrl(e.target.value)} placeholder="Origin URL (for Active CORS)" />}
                  </div>
                )}
              </div>
              <p className="form-prompt">Select at least one analysis type. For CORS, choose Passive (no origin) or Active (send custom Origin).</p>

              <div className="ai-toggle-row" onClick={() => setUseAI((v) => !v)}>
                <div className={`ai-toggle-switch${useAI ? ' ai-toggle-on' : ''}`}>
                  <div className="ai-toggle-knob" />
                </div>
                <span className="ai-toggle-label">AI Analysis {useAI ? 'ON' : 'OFF'}</span>
                <span className="ai-toggle-hint">{useAI ? 'AI will analyze results using OpenRouter (uses API quota)' : 'Scan without AI — saves API quota'}</span>
              </div>

              <div className="section-label" style={{ marginTop: '1.25rem' }}>Step 3 — Run</div>
              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? <><span className="spinner" /> Scanning...</> : 'Start Testing'}
              </button>
              <p className="form-prompt">Click to run the selected checks. Results will appear below in tabs (Security headers, CORS, SSL/TLS, etc.).</p>
            </form>
          </div>

          {error && (
            <div className="error-banner" role="alert">
              <span className="error-banner-icon" aria-hidden>⚠️</span>
              <span className="error-banner-message">{error}</span>
              <button type="button" className="error-banner-dismiss" onClick={() => setError('')} aria-label="Dismiss error">×</button>
            </div>
          )}

          {emailStatus && (
            <div className={`info-banner info-banner-${emailStatus.type}`} role="status">
              <span className="info-banner-message">{emailStatus.message}</span>
              <button type="button" className="error-banner-dismiss" onClick={() => setEmailStatus(null)} aria-label="Dismiss">×</button>
            </div>
          )}

          {!result && (
            <div className="empty-state">
              <div className="icon-large">🔒</div>
              <h2>Ready to Scan</h2>
              <p>Enter your API URL, choose testing methods, and click <strong>Start Testing</strong> to run the security analysis.</p>
              <p className="hint">Tip: Use <kbd>Ctrl</kbd>+<kbd>Enter</kbd> to submit when the form is focused.</p>
            </div>
          )}

          <div className="results">

            {result && result.batch && result.results?.length > 1 && (
              <div className="batch-selector">
                <label className="section-label">Select URL:</label>
                <select value={safeBatchIndex} onChange={(e) => { setSelectedBatchIndex(Number(e.target.value)); setActiveTab(0); }}>
                  {result.results.map((r, i) => (
                    <option key={i} value={i}>{r.url || `URL ${i + 1}`}</option>
                  ))}
                </select>
                <span className="batch-summary">({result.batchSummary?.total ?? result.results.length} scanned)</span>
              </div>
            )}
            {result && tabs.length === 0 && (
              <div className="results-empty results-empty-error">
                <p><strong>No report data was returned.</strong></p>
                <p>Make sure you selected at least one testing method (Step 2) and that the backend is running on the correct port (see frontend proxy in <code>vite.config.js</code>).</p>
                <p className="hint">If the scan completed without errors, the server may not have recognized your selection. Try selecting the controls again and run the scan.</p>
              </div>
            )}
            {tabs.length > 0 && (
              <>
                <div className="tabs">
                  {tabs.map((t, i) => (
                    <button key={i} type="button" className={`tab ${activeTab === i ? 'active' : ''}`} onClick={() => setActiveTab(i)}>{t.name}</button>
                  ))}
                </div>
                <div className="tab-panel">{tabs[activeTab]?.content}</div>
              </>
            )}
          </div>
        </div>

        <aside className="sidebar-col">
          <div className="sidebar-card sidebar-recipients-card">
            <div className="sidebar-report-toggle" onClick={() => setSendReport(!sendReport)} role="button" tabIndex={0}>
              <div className="sidebar-report-toggle-left">
                <Send size={14} />
                <span>Email Report</span>
              </div>
              <button type="button" className={`report-toggle-switch report-toggle-switch--sm${sendReport ? ' report-toggle-switch--on' : ''}`}
                      onClick={(e) => { e.stopPropagation(); setSendReport(!sendReport); if (sendReport) { setRecipients(['']); } }}>
                <span className="report-toggle-switch-thumb" />
              </button>
            </div>
            {!sendReport && (
              <p className="sidebar-recipients-hint" style={{ marginTop: '0.5rem' }}>Toggle on to send scan results via email.</p>
            )}
            {sendReport && (
              <div className="sidebar-report-body">
                <div className="sidebar-recipients-list">
                  {recipients.map((r, i) => (
                    <div key={i} className="sidebar-recipient-row">
                      <div className="sidebar-recipient-input-wrap">
                        <Mail size={13} className="sidebar-recipient-icon" />
                        <input type="email" value={r} onChange={(e) => setRecipientAt(i, e.target.value)} placeholder={`Recipient ${i + 1}`} />
                      </div>
                      {recipients.length > 1 && (
                        <button type="button" className="sidebar-recipient-remove" onClick={() => removeRecipient(i)} title="Remove">
                          <X size={13} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
                {recipients.filter(r => r.trim()).length > 0 && (
                  <div className="sidebar-recipients-badges">
                    {recipients.map((r, i) => r.trim() ? (
                      <span key={i} className="recipient-badge recipient-badge-sm">
                        <Mail size={10} />
                        {r.trim().length > 22 ? r.trim().slice(0, 22) + '…' : r.trim()}
                        <button type="button" onClick={() => removeRecipient(i)} className="recipient-badge-x"><X size={10} /></button>
                      </span>
                    ) : null)}
                  </div>
                )}
                <button type="button" className="sidebar-recipients-add" onClick={addRecipient}>
                  <Plus size={14} /> Add Recipient
                </button>
                {result && result.emailSent !== undefined && (
                  <p className="sidebar-email-status" style={{ color: result.emailSent ? 'var(--success)' : 'var(--danger)' }}>
                    {result.emailSent ? '✓ Report sent.' : `✗ ${result.emailError || 'Failed to send.'}`}
                  </p>
                )}
              </div>
            )}
          </div>
          <div className="sidebar-card">
            <h3><span className="icon">📥</span> Export to File</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              Downloads the current report tab as a self-contained HTML file — exact styling, fonts, and colours preserved.
            </p>
            <button
              type="button"
              className="btn-sm export-download-btn"
              style={{ width: '100%' }}
              onClick={downloadCurrentReport}
              disabled={!result || downloadingReport}
              title={!result ? 'Run a scan first' : 'Download current report tab as HTML'}
            >
              {downloadingReport
                ? <><span className="export-spinner" /> Preparing…</>
                : <><span>⬇</span> Download Report</>}
            </button>
            {result && (
              <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.5rem', lineHeight: 1.4 }}>
                Opens as a web page. To save as PDF, open the file in your browser and use <strong>File → Print → Save as PDF</strong>.
              </p>
            )}
          </div>
          <div className="sidebar-card">
            <h3><span className="icon">🕐</span> Recent</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Recent scan history will appear here.</p>
          </div>
        </aside>
      </div>}
    </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   App Wrapper — Auth Flow
   ═══════════════════════════════════════════════════════ */

export default function App() {
  const { theme, toggleTheme } = useTheme();

  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [showWelcome, setShowWelcome] = useState(false);
  const [showOptical, setShowOptical] = useState(false);
  const [showApp, setShowApp] = useState(false);

  // On mount: listen to Firebase auth state
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        // User is signed in — fetch Supabase profile
        try {
          const profile = await getUserProfile(firebaseUser.uid);
          setUser({
            uid: firebaseUser.uid,
            email: firebaseUser.email,
            displayName: profile?.username || firebaseUser.displayName || firebaseUser.email?.split('@')[0] || 'User',
            photoURL: profile?.google_photo_url || firebaseUser.photoURL || '',
          });
          setIsAuthenticated(true);
          setShowApp(true); // Skip animation on refresh
        } catch {
          setUser({
            uid: firebaseUser.uid,
            email: firebaseUser.email,
            displayName: firebaseUser.displayName || 'User',
            photoURL: firebaseUser.photoURL || '',
          });
          setIsAuthenticated(true);
          setShowApp(true);
        }
      } else {
        // Not signed in
        setIsAuthenticated(false);
        setUser(null);
        setShowApp(false);
      }
      setAuthLoading(false);
    });
    return () => unsubscribe();
  }, []);

  // Handle fresh login (called from LoginPage after successful auth)
  const handleLogin = useCallback((userData) => {
    setUser(userData);
    setIsAuthenticated(true);
    setShowWelcome(true); // Start welcome → animation → app sequence
  }, []);

  const handleWelcomeComplete = useCallback(() => {
    setShowWelcome(false);
    setShowOptical(true);
  }, []);

  const handleOpticalComplete = useCallback(() => {
    setShowOptical(false);
    setTimeout(() => setShowApp(true), 300);
  }, []);

  const handleLogout = useCallback(async () => {
    try {
      await signOut();
    } catch {}
    setIsAuthenticated(false);
    setUser(null);
    setShowWelcome(false);
    setShowOptical(false);
    setShowApp(false);
  }, []);

  // Loading state while checking auth
  if (authLoading) {
    return (
      <div className="auth-loading-screen">
        <div className="auth-loading-inner">
          <div className="auth-loading-spinner" />
          <p className="auth-loading-text">Loading...</p>
        </div>
      </div>
    );
  }

  // Not authenticated — show login
  if (!isAuthenticated) {
    return <LoginPage onLogin={handleLogin} theme={theme} toggleTheme={toggleTheme} />;
  }

  // Authenticated — show welcome → animation → app sequence
  return (
    <>
      {showWelcome && user && (
        <WelcomeScreen username={user.displayName} onComplete={handleWelcomeComplete} />
      )}

      {showOptical && (
        <div style={{ transition: 'all 0.5s ease-out' }}>
          <OpticalAnimation onComplete={handleOpticalComplete} />
        </div>
      )}

      {!showWelcome && !showOptical && showApp && (
        <div style={{
          transition: 'all 0.7s ease-out',
          opacity: showApp ? 1 : 0,
        }}>
          <Dashboard user={user} onLogout={handleLogout} />
        </div>
      )}
    </>
  );
}
