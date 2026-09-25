import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate, useLocation } from 'react-router-dom';
import { Terminal, Copy, Check, ChevronRight, Loader2, Plus, X, Play, ArrowLeft, Send, Shield, Sun, Moon, Settings, HelpCircle, LogOut, ScanSearch, Workflow, MailCheck, FileSearch, CheckCircle2, ShieldCheck, Lock, Globe, Server, AlertTriangle, Link2, EyeOff, Zap, ListChecks, Clock, Target, SlidersHorizontal, Info } from 'lucide-react';
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

const PAGE_TO_PATH = {
  'scanner':         '/scanner',
  'token-generator': '/testcurl',
  'history':         '/history',
  'settings':        '/settings',
};
const PATH_TO_PAGE = {
  '/scanner':  'scanner',
  '/testcurl': 'token-generator',
  '/history':  'history',
  '/settings': 'settings',
  '/':         'scanner',
};

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
      return (localStorage.getItem(THEME_KEY) || 'light');
    } catch {
      return 'light';
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
  { id: 'm_pii', value: 'Sensitive Data Exposure', label: 'Sensitive Data Exposure / PII Clear Text' },
];

/* Presentation only — short name, description and icon for each check in
   TESTING_METHODS. Keyed by the same `value` that is sent to the API, so the
   payload is unaffected. The long `label` above is still the accessible title. */
const CHECK_META = {
  'http header analysis':      { short: 'Security Headers',       desc: 'CSP, HSTS, X-Frame-Options and more',    Icon: ShieldCheck,    tone: 'blue' },
  'SSL / TLS analysis':        { short: 'SSL / TLS',              desc: 'Certificate, encryption and protocols',  Icon: Lock,           tone: 'green' },
  'cors':                      { short: 'CORS',                   desc: 'Cross-origin policy validation',         Icon: Globe,          tone: 'violet' },
  'Server version Disclosure': { short: 'Server Information',     desc: 'Version and service disclosure',         Icon: Server,         tone: 'amber' },
  'Improper Error Handling':   { short: 'Error Handling',          desc: 'Verbose errors and information leakage', Icon: AlertTriangle,  tone: 'red' },
  'URL Tampering Analysis':    { short: 'URL Tampering',          desc: 'Parameter and URL manipulation',         Icon: Link2,          tone: 'cyan' },
  'Sensitive Data Exposure':   { short: 'Sensitive Data Exposure', desc: 'PII and plaintext data exposure',       Icon: EyeOff,         tone: 'slate' },
};

/* Presentation only — scan profiles are presets that tick the existing
   checkboxes. They do not alter how a scan runs; the request still sends
   whatever is selected in `selectedMethods`. */
const QUICK_SCAN_METHODS = ['http header analysis', 'SSL / TLS analysis', 'Server version Disclosure'];

const SCAN_PROFILES = [
  { id: 'quick',    label: 'Quick Scan',    hint: 'Essential checks · ~2 min', Icon: Zap },
  { id: 'standard', label: 'Standard Scan', hint: 'All checks · ~5 min',       Icon: ShieldCheck },
  { id: 'custom',   label: 'Custom Scan',   hint: 'Choose your own checks',    Icon: SlidersHorizontal },
];

/* Presentation only — short relative time for the Recent Scans panel. */
function AnalysisInfoButton({ variant = 'pill' }) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef(null);
  const panelId = `analysis-info-panel-${variant}`;

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => { if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false); };
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div className="analysis-info" ref={wrapRef}>
      {variant === 'icon' ? (
        <button
          type="button"
          className="header-icon-btn"
          title="Help"
          aria-label="Help"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => setOpen((v) => !v)}
        >
          <HelpCircle size={16} />
        </button>
      ) : (
        <button
          type="button"
          className="analysis-info-btn"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => setOpen((v) => !v)}
        >
          <Info size={14} aria-hidden />
          About analysis
        </button>
      )}
      {open && (
        <div id={panelId} className="analysis-info-panel" role="dialog" aria-label="About the analysis engine">
          <div className="analysis-info-head">
            <strong>Rule-based analysis · no LLM</strong>
            <button type="button" className="analysis-info-close" aria-label="Close" onClick={() => setOpen(false)}>
              <X size={14} />
            </button>
          </div>
          <p>
            A local LLM such as BART can be integrated into this project for AI-based analysis in the future.
            However, the backend is currently deployed on Render&rsquo;s free tier, which has resource limitations
            and does not support hosting an LLM model of 3&nbsp;GB or larger.
          </p>
          <p>
            Using external LLM APIs would also introduce additional usage costs. Therefore, the current
            implementation has been intentionally rebuilt using lightweight, rule-based scripting and basic
            analysis, without relying on an external or locally hosted LLM.
          </p>
          <p>
            The existing architecture can be further extended in the future to support AI-powered analysis,
            intelligent vulnerability interpretation, automated recommendations, and more advanced security
            insights once suitable infrastructure or an appropriate LLM service is available.
          </p>
        </div>
      )}
    </div>
  );
}

function formatRelativeTime(iso) {
  if (!iso) return '';
  const then = new Date(iso).getTime();
  if (isNaN(then)) return '';
  const mins = Math.round((Date.now() - then) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs} hr ago`;
  const days = Math.round(hrs / 24);
  return days === 1 ? '1 day ago' : `${days} days ago`;
}

// Map each testing method value → the result field it populates.
// Used to skip already-tested controls when re-scanning.
const METHOD_TO_FIELD = {
  'http header analysis': 'headersReport',
  'SSL / TLS analysis':   'sslReport',
  'Server version Disclosure': 'serverReport',
  'cors':                 'corsReport',
  'Improper Error Handling': 'errorHandlingReport',
  'URL Tampering Analysis':  'urlTamperingReport',
  'Sensitive Data Exposure':  'sensitiveDataReport',
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

function capturePageCSS() {
  let css = '';
  for (const sheet of document.styleSheets) {
    try { for (const rule of sheet.cssRules) css += rule.cssText + '\n'; } catch (_) {}
  }
  return css;
}

function buildDownloadHTML(innerHtml, title) {
  const theme = document.documentElement.getAttribute('data-theme') || 'dark';
  const css = capturePageCSS();
  return `<!DOCTYPE html>
<html lang="en" data-theme="${theme}">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${title}</title>
<style>
${css}
:root{--bg:#0f172a;--bg-card:#1e293b;--bg-input:#334155;--text:#f1f5f9;--text-muted:#94a3b8;--border:#334155;--primary:#6366f1;--primary-light:#818cf8;--danger:#ef4444;--success:#22c55e;--warning:#f59e0b}
[data-theme="light"]{--bg:#f8fafc;--bg-card:#fff;--bg-input:#f1f5f9;--text:#1e293b;--text-muted:#64748b;--border:#e2e8f0}
body{margin:0;padding:24px;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
@media print{body{padding:8px}}
</style>
</head>
<body>
${innerHtml}
</body>
</html>`;
}

function downloadHTMLFile(html, filename) {
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Validate that aiHeaders in a headersReport are consistent with evaluatedHeaders.
 * If any header's present/absent state disagrees, strip the stale AI fields and
 * rebuild minimal consistent ones from evaluatedHeaders so the report never lies.
 */
function sanitizeHeadersReport(hr) {
  if (!hr || !hr.evaluatedHeaders) return hr;
  const evaluated = hr.evaluatedHeaders;
  const aiHeaders = hr.aiHeaders;
  if (!aiHeaders || !aiHeaders.length) return hr;

  const aiMap = {};
  for (const h of aiHeaders) { if (h.name) aiMap[h.name] = h; }

  let stale = false;
  for (const [name, info] of Object.entries(evaluated)) {
    const scanPresent = !!info.present;
    const aiEntry = aiMap[name];
    if (aiEntry && !!aiEntry.present !== scanPresent) { stale = true; break; }
  }
  if (!stale) return hr;

  const HEADER_FIX_MAP = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'X-XSS-Protection': '1; mode=block',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'X-Permitted-Cross-Domain-Policies': 'none',
  };

  const rebuilt = [];
  let crit = 0, warn = 0, ok = 0;
  for (const [name, info] of Object.entries(evaluated)) {
    const sev = info.present ? ((info.severity || 'ok').toLowerCase() === 'warning' ? 'warning' : 'ok') : 'critical';
    if (sev === 'critical') crit++;
    else if (sev === 'warning') warn++;
    else ok++;
    rebuilt.push({
      name,
      present: !!info.present,
      value: info.value || null,
      severity: sev,
      whatItDoes: aiMap[name]?.whatItDoes || `Security header: ${name}`,
      status: info.present ? 'Properly configured.' : 'Not configured — missing from response.',
      risk: info.present ? 'No immediate risk.' : `Missing ${name} header leaves your site exposed.`,
      fix: info.present ? 'No action needed.' : `Add: ${HEADER_FIX_MAP[name] || name}`,
      description: aiMap[name]?.description || `Security header: ${name}`,
      issue: info.present ? 'Configured' : `Missing ${name} header`,
      impact: info.present ? 'Low risk' : 'High security risk',
      recommendation: info.present ? 'Review configuration' : `Add ${name} header`,
    });
  }
  const riskLevel = crit >= 6 ? 'Critical' : crit >= 4 ? 'High' : crit >= 2 ? 'Medium' : crit >= 1 ? 'Low' : 'Good';
  return {
    ...hr,
    aiHeaders: rebuilt,
    aiSummary: { criticalCount: crit, warningCount: warn, okCount: ok, totalHeaders: rebuilt.length },
    aiOverallRisk: riskLevel,
    aiRiskExplanation: `${crit} critical issue${crit !== 1 ? 's' : ''} found — data refreshed from scan results.`,
    aiExecutiveSummary: hr.aiExecutiveSummary || null,
    aiTopRecs: (hr.aiTopRecs || []).filter(r => {
      const entry = evaluated[r.header];
      return entry && !entry.present;
    }),
    aiSource: 'sanitized',
  };
}

function sanitizeResult(result) {
  if (!result) return result;
  if (result.batch && result.results) {
    return { ...result, results: result.results.map(r => {
      if (!r?.headersReport) return r;
      return { ...r, headersReport: sanitizeHeadersReport(r.headersReport) };
    })};
  }
  if (result.headersReport) {
    return { ...result, headersReport: sanitizeHeadersReport(result.headersReport) };
  }
  return result;
}

/**
 * Merge a new partial scan result into the existing result.
 * Copies non-null report fields from newData into existingResult.
 */
function mergeResults(existingResult, newData) {
  if (!existingResult) return newData;
  const reportFields = Object.values(METHOD_TO_FIELD);
  const merged = { ...existingResult };
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
  return sanitizeResult(merged);
}

function HeadersReport({ r }) {
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
        <div className="site-url">{d}</div>
        <div className="scan-time">Security Headers Analysis · {scanned}</div>
      </div>

      {/* Score metric strip */}
      <div className="summary-grid">
        <div className="summary-card" style={{borderBottomColor:'#dc2626'}}>
          <div className="card-value" style={{color:'#dc2626'}}>{r.criticalCount ?? 0}</div>
          <div className="card-title">Critical Issues</div>
        </div>
        <div className="summary-card" style={{borderBottomColor:'#d97706'}}>
          <div className="card-value" style={{color:'#d97706'}}>{r.warningCount ?? 0}</div>
          <div className="card-title">Warnings</div>
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
          {/* ── Security Assessment Section ─────────── */}
          {(() => {
            const aiIssues = (r.aiHeaders || []).filter(h => (h.severity||'ok') !== 'ok');
            const aiPassing = (r.aiHeaders || []).filter(h => (h.severity||'ok') === 'ok');
            const critCount = r.aiSummary?.criticalCount ?? aiIssues.filter(h => h.severity === 'critical').length;
            const warnCount = r.aiSummary?.warningCount ?? aiIssues.filter(h => h.severity === 'warning').length;
            const okCount = r.aiSummary?.okCount ?? aiPassing.length;
            const riskLevel = (r.aiOverallRisk || 'Unknown').toLowerCase();
            const riskLabel = {'critical':'Not Protected','high':'High Risk','medium':'Needs Work','low':'Mostly Secure','good':'Well Protected'}[riskLevel] || r.aiOverallRisk || 'Unknown';

            return (
            <div className="ai-report">
              {/* ── Report Header ── */}
              <div className="ai-report-header">
                <div className="ai-report-header-left">
                  <div className="ai-report-badge">Security Audit</div>
                  <div className="ai-report-title">Security Assessment Report</div>
                </div>
                <div className="ai-report-header-right">
                  <div className={`ai-risk-indicator ai-risk-${riskLevel}`}>
                    <div className="ai-risk-level">{riskLabel}</div>
                    <div className="ai-risk-sublabel">
                      {r.aiRiskExplanation || `${critCount} critical issue${critCount !== 1 ? 's' : ''} found`}
                    </div>
                  </div>
                </div>
              </div>

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
                  <div className="ai-stat-num">{(r.aiHeaders || []).length}</div>
                  <div className="ai-stat-label">Total Checked</div>
                </div>
              </div>

              {/* ── Executive Summary ── */}
              {r.aiExecutiveSummary && (
                <div className="ai-exec-summary">
                  <div className="ai-section-title"><span className="ai-section-icon">📋</span> Executive Summary</div>
                  <p className="ai-exec-summary-text">{r.aiExecutiveSummary}</p>
                </div>
              )}

              {/* ── Detailed Issue Cards ── */}
              {aiIssues.length > 0 && (
                <div className="ai-issues-section">
                  <div className="ai-section-title"><span className="ai-section-icon">🛡️</span> Security Issues Found ({aiIssues.length})</div>
                  <div className="ai-issues-list">
                    {aiIssues.map((h, i) => {
                      const sev = (h.severity||'ok').toLowerCase();
                      const sevLabel = sev === 'critical' ? 'Not Protected' : 'Needs Attention';
                      return (
                      <div key={i} className={`ai-issue-card ai-sev-${sev}`}>
                        <div className="ai-issue-header">
                          <div className="ai-issue-name">{h.name}</div>
                          <span className={`ai-issue-badge ai-badge-${sev}`}>{sevLabel}</span>
                        </div>
                        {h.value && h.value !== 'null' && h.value !== 'Not set' && (
                          <div className="ai-issue-value-row">
                            <span className="ai-issue-value-label">Value</span>
                            <code className="ai-issue-value-code">{String(h.value).slice(0,120)}{String(h.value).length > 120 ? '…' : ''}</code>
                          </div>
                        )}
                        <div className="ai-issue-body">
                          <div className="ai-issue-field">
                            <div className="ai-issue-field-label">What this protects</div>
                            <div className="ai-issue-field-text">{h.whatItDoes || h.description || ''}</div>
                          </div>
                          {sev !== 'critical' && (
                          <div className="ai-issue-field">
                            <div className="ai-issue-field-label">Current status</div>
                            <div className="ai-issue-field-text">{h.status || h.issue || ''}</div>
                          </div>
                          )}
                          <div className="ai-issue-field ai-issue-field--risk">
                            <div className="ai-issue-field-label">What could go wrong</div>
                            <div className="ai-issue-field-text">{h.risk || h.impact || ''}</div>
                          </div>
                          <div className="ai-issue-field ai-issue-field--fix">
                            <div className="ai-issue-field-label">How to fix</div>
                            <div className="ai-issue-field-text">{h.fix || h.recommendation || ''}</div>
                          </div>
                          {(() => {
                            const important = (h.findings || []).filter(f => f.severity === 'high' || f.severity === 'medium');
                            if (!important.length) return null;
                            return (
                            <div className="ai-issue-field ai-issue-field--findings">
                              <div className="ai-issue-field-label">Detailed findings ({important.length})</div>
                              <ul className="ai-findings-list">
                                {important.map((f, fi) => (
                                  <li key={fi} className={`ai-finding-item ai-finding-${f.severity}`}>
                                    <span className="ai-finding-sev">{f.severity === 'high' ? '🔴' : '🟠'}</span>
                                    <strong>{f.title}</strong> — {f.detail}
                                  </li>
                                ))}
                              </ul>
                            </div>
                            );
                          })()}
                        </div>
                      </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* ── Extra Findings (Cookies, Server, Info Leakage, Deprecated, Duplicates) ── */}
              {r.extraFindings && r.extraFindings.length > 0 && (() => {
                const cookieFindings = r.extraFindings.filter(f => (f.id || '').startsWith('cookie-'));
                const securityFindings = r.extraFindings.filter(f => !(f.id || '').startsWith('cookie-') && (f.severity === 'high' || f.severity === 'medium'));
                const infoFindings = r.extraFindings.filter(f => !(f.id || '').startsWith('cookie-') && f.severity !== 'high' && f.severity !== 'medium');
                const sevBadge = (sev) => sev === 'high' ? 'critical' : sev === 'medium' ? 'warning' : 'ok';
                const sevLabel = (sev) => sev === 'high' ? 'High' : sev === 'medium' ? 'Warning' : 'Info';
                const sevIcon = (sev) => sev === 'high' ? '🔴' : sev === 'medium' ? '🟠' : sev === 'low' ? '🟡' : 'ℹ️';
                return (
                <div className="ai-issues-section ai-extra-findings-section">
                  <div className="ai-section-title"><span className="ai-section-icon">📋</span> Additional Security Observations ({r.extraFindings.length})</div>

                  {cookieFindings.length > 0 && (
                    <div className="ai-extra-group">
                      <div className="ai-extra-group-title">🍪 Cookie Security ({cookieFindings.length} issue{cookieFindings.length !== 1 ? 's' : ''})</div>
                      <div className="ai-issues-list">
                        {cookieFindings.map((f, i) => (
                          <div key={`c${i}`} className={`ai-issue-card ai-sev-${sevBadge(f.severity)}`}>
                            <div className="ai-issue-header">
                              <div className="ai-issue-name">{f.title}</div>
                              <span className={`ai-issue-badge ai-badge-${sevBadge(f.severity)}`}>{sevLabel(f.severity)}</span>
                            </div>
                            <div className="ai-issue-body"><div className="ai-issue-field"><div className="ai-issue-field-text">{f.detail}</div></div></div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {securityFindings.length > 0 && (
                    <div className="ai-extra-group">
                      <div className="ai-extra-group-title">⚠️ Security Warnings ({securityFindings.length})</div>
                      <div className="ai-issues-list">
                        {securityFindings.map((f, i) => (
                          <div key={`s${i}`} className={`ai-issue-card ai-sev-${sevBadge(f.severity)}`}>
                            <div className="ai-issue-header">
                              <div className="ai-issue-name">{f.title}</div>
                              <span className={`ai-issue-badge ai-badge-${sevBadge(f.severity)}`}>{sevLabel(f.severity)}</span>
                            </div>
                            <div className="ai-issue-body"><div className="ai-issue-field"><div className="ai-issue-field-text">{f.detail}</div></div></div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {infoFindings.length > 0 && (
                    <div className="ai-extra-group">
                      <div className="ai-extra-group-title">ℹ️ Informational ({infoFindings.length})</div>
                      <div className="ai-issues-list">
                        {infoFindings.map((f, i) => (
                          <div key={`i${i}`} className={`ai-issue-card ai-sev-ok`}>
                            <div className="ai-issue-header">
                              <div className="ai-issue-name">{sevIcon(f.severity)} {f.title}</div>
                              <span className="ai-issue-badge ai-badge-ok">{sevLabel(f.severity)}</span>
                            </div>
                            <div className="ai-issue-body"><div className="ai-issue-field"><div className="ai-issue-field-text">{f.detail}</div></div></div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                );
              })()}

              {/* ── Protected Headers ── */}
              {aiPassing.length > 0 && (
                <div className="ai-passing-section">
                  <div className="ai-section-title"><span className="ai-section-icon">✅</span> Protected <span className="ai-section-count ai-section-count--ok">{aiPassing.length} headers properly configured</span></div>
                  <div className="ai-passing-grid">
                    {aiPassing.map((h, i) => (
                      <div key={i} className="ai-passing-card">
                        <div className="ai-passing-card-top">
                          <span className="ai-passing-check">✓</span>
                          <span className="ai-passing-name">{h.name}</span>
                        </div>
                        <div className="ai-passing-desc">{h.whatItDoes || h.status || h.description || 'Properly configured'}</div>
                        {h.findings && h.findings.length > 0 && (
                          <div className="ai-passing-notes">
                            {h.findings.map((f, fi) => (
                              <div key={fi} className="ai-passing-note">
                                <span className="ai-passing-note-icon">{f.severity === 'low' ? '💡' : 'ℹ️'}</span>
                                <span>{f.title}{f.detail ? ` — ${f.detail}` : ''}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Action Plan ── */}
              {r.aiTopRecs?.length > 0 && (
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
                          {rec.why && <div className="ai-action-why"><span className="ai-action-why-icon">💡</span> <strong>Why:</strong> {rec.why}</div>}
                          {rec.exampleValue && (
                            <div className="ai-action-code-block">
                              <div className="ai-action-code-top">
                                <div className="ai-action-code-label">Add this to your server configuration:</div>
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

              <div className="ai-report-footer">
                Review recommendations with your development team before implementing changes.
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

const SVD_SEVERITY_META = {
  Critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.3)', label: 'Critical' },
  High:     { color: '#f97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.3)', label: 'High' },
  Medium:   { color: '#eab308', bg: 'rgba(234,179,8,0.1)',  border: 'rgba(234,179,8,0.3)',  label: 'Medium' },
  Low:      { color: '#22c55e', bg: 'rgba(34,197,94,0.1)', border: 'rgba(34,197,94,0.3)', label: 'Low' },
  Informational: { color: '#6b7280', bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.2)', label: 'Info' },
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
          <span className="svd-severity-dot" style={{ background: meta.color }}></span>
          <strong>{disc.header}</strong>
          <span className="svd-risk-pill" style={{ background: meta.bg, color: meta.color, border: `1px solid ${meta.border}` }}>{meta.label}</span>
        </div>
        <div className="svd-finding-value-row">
          <span className="svd-value-label">Value:</span>
          <code className="svd-value-code">{disc.value || '—'}</code>
        </div>
      </div>
      <table className="svd-finding-detail-table">
        <tbody>
          <tr><td className="svd-detail-label">Description</td><td>{plainMeaning}</td></tr>
          {disc.evidence && <tr><td className="svd-detail-label">Evidence</td><td>{disc.evidence}</td></tr>}
          {isHighRisk && <tr className="svd-detail-risk"><td className="svd-detail-label">Risk</td><td>An attacker can look up known security flaws (CVEs) for this exact version and target your server directly.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function ServerReport({ r }) {
  const d = r.targetDomain || r.domain || 'Unknown';
  const risk = r.riskLevel || 'Unknown';
  const riskMeta = SVD_SEVERITY_META[risk] || { color: '#6b7280', bg: 'rgba(107,114,128,0.08)', border: 'rgba(107,114,128,0.2)', label: 'Unknown' };
  const disclosures = r.disclosures || [];
  const recs = Array.isArray(r.recommendations) ? r.recommendations : (r.recommendation ? [r.recommendation] : []);
  const configExamples = r.configurationExamples && typeof r.configurationExamples === 'object' ? r.configurationExamples : {};
  const htmlDisclosures = Array.isArray(r.htmlDisclosures) ? r.htmlDisclosures : [];
  const counts = r.summaryCounts || {};
  const scannedOn = r.scannedAt ? (() => { try { return new Date(r.scannedAt).toLocaleString(); } catch (_) { return r.scannedAt; } })() : '';

  const criticalOrHigh = disclosures.filter(d => d.severity === 'Critical' || d.severity === 'High');
  const medium = disclosures.filter(d => d.severity === 'Medium');
  const lowOrInfo = disclosures.filter(d => d.severity === 'Low' || d.severity === 'Informational');
  const nothingFound = disclosures.length === 0 && htmlDisclosures.length === 0;

  return (
    <div className="report-inner server-disclosure-report">

      {/* ── Header ── */}
      <div className="site-info">
        <div className="site-url">{d}</div>
        <div className="scan-time">Server Version Disclosure Analysis{scannedOn ? ` · Scanned: ${scannedOn}` : ''}</div>
      </div>

      {r.error && (
        <div className="svd-error-bar"><span className="svd-error-icon">!</span> {r.error}</div>
      )}

      {/* ── Risk Banner ── */}
      {!r.error && (
        <div className="svd-risk-banner" style={{ borderLeft: `4px solid ${riskMeta.color}`, background: riskMeta.bg }}>
          <div className="svd-risk-badge" style={{ background: riskMeta.color }}>{risk.charAt(0)}</div>
          <div className="svd-risk-text">
            <div className="svd-risk-title">{nothingFound ? 'No Disclosures Found' : `Overall Risk: ${risk}`}</div>
            <div className="svd-risk-subtitle">
              {nothingFound
                ? 'This server does not leak version or technology information in its response headers.'
                : `${disclosures.length} header${disclosures.length !== 1 ? 's' : ''} disclosing server information${criticalOrHigh.length > 0 ? ` — ${criticalOrHigh.length} critical/high risk` : ''}`}
            </div>
          </div>
          <div className="svd-risk-stats">
            {counts.totalHeaders != null && <div className="svd-rstat"><span className="svd-rstat-num">{counts.totalHeaders}</span><span className="svd-rstat-lbl">Headers</span></div>}
            {counts.headersWithVersion != null && <div className="svd-rstat"><span className="svd-rstat-num" style={{ color: counts.headersWithVersion > 0 ? '#ef4444' : '#22c55e' }}>{counts.headersWithVersion}</span><span className="svd-rstat-lbl">With version</span></div>}
            {r.stack && <div className="svd-rstat"><span className="svd-rstat-stack">{r.stack}</span><span className="svd-rstat-lbl">Stack</span></div>}
          </div>
        </div>
      )}

      {/* ── Findings ── */}
      {disclosures.length > 0 && (
        <div className="section">
          <div className="section-header">Disclosure Findings ({disclosures.length})</div>
          <div className="section-content svd-findings-intro">
            <p>The following response headers expose server software or technology stack information to any client.</p>
          </div>
          {criticalOrHigh.length > 0 && (
            <div className="section-content">
              <div className="svd-group-label svd-group-danger"><span className="svd-group-dot" style={{background:'#ef4444'}}></span> Critical / High</div>
              <div className="svd-findings-list">{criticalOrHigh.map((disc, i) => <SvdFindingCard key={i} disc={disc} />)}</div>
            </div>
          )}
          {medium.length > 0 && (
            <div className="section-content">
              <div className="svd-group-label svd-group-medium"><span className="svd-group-dot" style={{background:'#eab308'}}></span> Medium</div>
              <div className="svd-findings-list">{medium.map((disc, i) => <SvdFindingCard key={i} disc={disc} />)}</div>
            </div>
          )}
          {lowOrInfo.length > 0 && (
            <div className="section-content">
              <div className="svd-group-label svd-group-low"><span className="svd-group-dot" style={{background:'#22c55e'}}></span> Low / Informational</div>
              <div className="svd-findings-list">{lowOrInfo.map((disc, i) => <SvdFindingCard key={i} disc={disc} />)}</div>
            </div>
          )}
        </div>
      )}

      {/* ── HTML body disclosures ── */}
      {htmlDisclosures.length > 0 && (
        <div className="section">
          <div className="section-header">Page Source Disclosures</div>
          <div className="section-content">
            <p style={{ marginBottom: '0.75rem', fontSize: '0.88rem', color: 'var(--text-muted)' }}>
              Version or technology information found in the HTML page source (e.g. CMS version in metadata).
            </p>
            <div className="svd-findings-list">
              {htmlDisclosures.map((h, i) => {
                const meta = SVD_SEVERITY_META[h.severity] || SVD_SEVERITY_META['Informational'];
                return (
                  <div key={i} className="svd-finding-card" style={{ borderLeftColor: meta.color }}>
                    <div className="svd-finding-top">
                      <div className="svd-finding-header-name">
                        <span className="svd-severity-dot" style={{ background: meta.color }}></span>
                        <strong>{h.type}</strong>
                        <span className="svd-risk-pill" style={{ background: meta.bg, color: meta.color, border: `1px solid ${meta.border}` }}>{meta.label}</span>
                      </div>
                    </div>
                    <table className="svd-finding-detail-table"><tbody>
                      <tr><td className="svd-detail-label">Details</td><td>{h.description}</td></tr>
                    </tbody></table>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── Impact Assessment ── */}
      {!nothingFound && r.attackScenario && (
        <div className="section">
          <div className="section-header">Impact Assessment</div>
          <div className="section-content">
            <div className="svd-scenario-box">
              <div className="svd-scenario-label">Attack Scenario</div>
              <p>{r.attackScenario}</p>
              {r.likelihood && <p className="svd-scenario-likelihood"><strong>Likelihood:</strong> {r.likelihood}</p>}
            </div>
            {r.cveNote && (
              <div className="svd-cve-note">
                <strong>CVE Reference:</strong> {r.cveNote}
                <div className="svd-cve-links">
                  <a href="https://cve.mitre.org/" target="_blank" rel="noopener noreferrer">CVE MITRE</a>
                  <a href="https://nvd.nist.gov/" target="_blank" rel="noopener noreferrer">NVD NIST</a>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Remediation ── */}
      {(recs.length > 0 || Object.keys(configExamples).length > 0) && (
        <div className="section">
          <div className="section-header">Remediation</div>
          <div className="section-content">
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
                <div className="svd-config-intro">Apply the configuration for your detected stack:</div>
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
                <div className="svd-verify-title">Verification</div>
                <p>{r.verificationStep}</p>
                {r.expectedState && <p className="svd-verify-expected"><strong>Expected result:</strong> {r.expectedState}</p>}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Pass state ── */}
      {nothingFound && !r.error && (
        <div className="section">
          <div className="section-content">
            <div className="svd-pass-box">
              <div className="svd-pass-check">&#10003;</div>
              <div className="svd-pass-title">No Version Information Leaked</div>
              <div className="svd-pass-body">
                The server is not revealing any software names, version numbers, or technology stack
                details in its HTTP headers or HTML source.
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
  const gradeColors = { 'A+':'#22c55e', A:'#22c55e', B:'#3b82f6', C:'#eab308', D:'#f97316', F:'#ef4444', '?':'#6b7280', 'N/A':'#6b7280' };
  const gradeBg = { 'A+':'rgba(34,197,94,0.12)', A:'rgba(34,197,94,0.12)', B:'rgba(59,130,246,0.12)', C:'rgba(234,179,8,0.12)', D:'rgba(249,115,22,0.12)', F:'rgba(239,68,68,0.12)' };
  const status = r.localStatus || (r.localProtocol ? `Protocol: ${r.localProtocol}` : null);
  const reportTitle = r.reportTitle || `SSL Report: ${host}`;
  const isLocal = !!(r.localProtocol || r.localGrade);

  if (r.error) {
    return (
      <div className="report-inner ssl-report">
        <div className="ssl-report-header">
          <a href={SSL_LABS_HOME} target="_blank" rel="noopener noreferrer" className="ssl-labs-logo-link" title="Qualys SSL Labs"><img src={SSL_LABS_LOGO} alt="Qualys SSL Labs" className="ssl-labs-logo" /></a>
          <div className="ssl-report-title">{reportTitle}</div>
        </div>
        <div className="site-info"><div className="site-url">{host}</div></div>
        <div className="section"><div className="section-content" style={{ color: 'var(--danger)' }}>{r.message || 'SSL analysis failed.'}</div></div>
      </div>
    );
  }

  const hasFullReport = Array.isArray(r.certificates) && r.certificates.length > 0;
  const cd = r.cipherDetails || {};
  const ci = r.certInfo || null;
  const assessment = r.assessment || [];

  return (
    <div className="report-inner ssl-report">
      {/* ── Header ── */}
      <div className="ssl-report-header">
        <a href={r.sslLabsUrl || SSL_LABS_HOME} target="_blank" rel="noopener noreferrer" className="ssl-labs-logo-link" title="Qualys SSL Labs"><img src={SSL_LABS_LOGO} alt="Qualys SSL Labs" className="ssl-labs-logo" /></a>
        <div>
          <div className="ssl-report-title">{reportTitle}</div>
          <div className="ssl-report-host">{host}{r.ipAddress ? ` (${r.ipAddress})` : ''}</div>
        </div>
      </div>

      {/* ── Grade Banner ── */}
      <div className="ssl-grade-banner" style={{background: gradeBg[gradeKey] || 'rgba(107,114,128,0.1)', borderLeft: `4px solid ${gradeColors[gradeKey] || '#6b7280'}`}}>
        <div className="ssl-grade-circle" style={{background: gradeColors[gradeKey] || '#6b7280'}}>{gradeKey}</div>
        <div className="ssl-grade-text">
          <div className="ssl-grade-label">Overall Rating{isLocal && !hasFullReport ? ' (Local Analysis)' : ''}</div>
          <div className="ssl-grade-status">{status || `Grade ${gradeKey}`}</div>
          {isLocal && !hasFullReport && <div className="ssl-grade-note">Based on direct TLS handshake — SSL Labs could not reach this server</div>}
        </div>
      </div>

      {/* ═══════════════════════════════════════════════════ */}
      {/* ██  SECTION 1 — SUMMARY & ANALYSIS                ██ */}
      {/* ═══════════════════════════════════════════════════ */}

      {/* ── Security Observation ── */}
      {r.observation && (
        <div className="section">
          <div className="section-header">Security Observation</div>
          <div className="section-content">
            <div className="ssl-observation-text">{r.observation}</div>
            {r.observationFindings?.length > 0 && (
              <div className="ssl-obs-findings">
                {r.observationFindings.map((f, i) => (
                  <div key={i} className={`ssl-obs-finding ssl-obs-${f.severity?.toLowerCase() || 'info'}`}>
                    <div className="ssl-obs-finding-head">
                      <span className="ssl-obs-sev-dot"></span>
                      <strong>{f.title}</strong>
                      <span className="ssl-obs-sev-tag">{f.severity}</span>
                    </div>
                    <p className="ssl-obs-finding-detail">{f.detail}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Security Assessment (local) ── */}
      {assessment.length > 0 && !hasFullReport && (
        <div className="section">
          <div className="section-header">Security Assessment</div>
          <div className="section-content">
            <table className="ssl-report-table ssl-assessment-table">
              <thead><tr><th style={{width:'28px'}}></th><th>Check</th><th>Result</th><th>Details</th></tr></thead>
              <tbody>
                {assessment.map((a, i) => (
                  <tr key={i} className={`ssl-assess-${a.status}`}>
                    <td className="ssl-assess-icon">{a.status === 'good' ? '✓' : a.status === 'warn' ? '⚠' : a.status === 'bad' ? '✗' : '—'}</td>
                    <td><strong>{a.name}</strong></td>
                    <td><code className="ssl-val">{a.value}</code></td>
                    <td className="ssl-assess-detail">{a.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Summary ── */}
      <div className="section"><div className="section-header">Summary</div><div className="section-content ssl-summary-text">{r.summary || ''}</div></div>

      {/* ── Recommendation ── */}
      <div className="section"><div className="section-header">Recommendation</div><div className="section-content ssl-summary-text">{r.recommendation || ''}</div></div>

      {/* ═══════════════════════════════════════════════════ */}
      {/* ██  SECTION 2 — TECHNICAL DETAILS                 ██ */}
      {/* ═══════════════════════════════════════════════════ */}
      <div className="ssl-section-divider">
        <span className="ssl-section-divider-label">Technical Details</span>
      </div>

      {/* ── Server / TLS Details (local check) ── */}
      {(r.localProtocol || r.localCipher) && !hasFullReport && (
        <div className="section">
          <div className="section-header">Server / TLS Configuration</div>
          <div className="section-content">
            <table className="ssl-report-table">
              <tbody>
                {r.localProtocol && <tr><td><strong>Negotiated protocol</strong></td><td><code className="ssl-val">{r.localProtocol}</code></td></tr>}
                {r.localCipher && <tr><td><strong>Negotiated cipher suite</strong></td><td><code className="ssl-val">{r.localCipher}</code></td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Cipher Suite Analysis (local) ── */}
      {cd.name && !hasFullReport && (
        <div className="section">
          <div className="section-header">Cipher Suite Analysis</div>
          <div className="section-content">
            <table className="ssl-report-table">
              <tbody>
                <tr><td><strong>Key exchange</strong></td><td><code className="ssl-val">{cd.keyExchange}</code>{cd.forwardSecrecy && <span className="ssl-badge-good">Forward Secrecy</span>}</td></tr>
                <tr><td><strong>Authentication</strong></td><td><code className="ssl-val">{cd.authentication}</code></td></tr>
                <tr><td><strong>Encryption</strong></td><td><code className="ssl-val">{cd.encryption}{cd.bits ? ` (${cd.bits} bits)` : ''}</code></td></tr>
                <tr><td><strong>Mode</strong></td><td><code className="ssl-val">{cd.mode}</code>{cd.aead && <span className="ssl-badge-good">AEAD</span>}</td></tr>
                <tr><td><strong>MAC / Integrity</strong></td><td><code className="ssl-val">{cd.mac}</code></td></tr>
                <tr><td><strong>Overall strength</strong></td><td><span className={`ssl-strength ssl-strength-${cd.strength}`}>{cd.strength === 'strong' ? 'Strong' : cd.strength === 'acceptable' ? 'Acceptable' : cd.strength === 'weak' ? 'Weak' : 'Unknown'}</span></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Certificate (local) ── */}
      {ci && !hasFullReport && (
        <div className="section">
          <div className="section-header">Certificate{r.certTrusted === true ? '' : r.certTrusted === false ? ' — Validation Failed' : ''}</div>
          <div className="section-content">
            <table className="ssl-report-table cert-table">
              <tbody>
                {ci.commonName && <tr><td><strong>Common name</strong></td><td><code>{ci.commonName}</code></td></tr>}
                {ci.altNames?.length > 0 && <tr><td><strong>Alternative names</strong></td><td><code className="mono-small">{ci.altNames.join('  ')}</code></td></tr>}
                {ci.serialNumber && <tr><td><strong>Serial number</strong></td><td><code className="mono-small">{ci.serialNumber}</code></td></tr>}
                {ci.validFrom && <tr><td><strong>Valid from</strong></td><td>{ci.validFrom}</td></tr>}
                {ci.validUntil && <tr><td><strong>Valid until</strong></td><td>{ci.validUntil}</td></tr>}
                {ci.issuerCN && <tr><td><strong>Issuer</strong></td><td>{ci.issuerCN}{ci.issuerOrg ? ` (${ci.issuerOrg})` : ''}</td></tr>}
                {ci.ocsp?.length > 0 && <tr><td><strong>OCSP</strong></td><td><code className="mono-small">{ci.ocsp[0]}</code></td></tr>}
                <tr><td><strong>Trusted</strong></td><td>{r.certTrusted === true ? <span className="ssl-ok">Yes — validated by OS certificate store</span> : r.certTrusted === false ? <span className="ssl-warn">No — certificate validation failed</span> : <span style={{color:'var(--text-muted)'}}>Unknown</span>}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Protocols (local enumeration) ── */}
      {!hasFullReport && Array.isArray(r.protocols) && r.protocols.length > 0 && (
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

      {/* ── Cipher Suites (local enumeration) ── */}
      {!hasFullReport && Array.isArray(r.cipherSuites) && r.cipherSuites.length > 0 && (
        <div className="section">
          <div className="section-header">Cipher Suites</div>
          <div className="section-content">
            {r.cipherSuites.map((group, gi) => (
              <div key={gi} className="cipher-group">
                <div className="cipher-group-title">{group.protocol}{group.preference ? ' (server chooses the cipher)' : ''}</div>
                <ul className="cipher-list">
                  {group.suites?.map((s, si) => (
                    <li key={si} className={s.weak ? 'ssl-cipher-weak' : ''}>
                      {s.name}
                      {s.kxType && ` — ${s.kxType}`}{s.cipherStrength ? `, ${s.cipherStrength} bits` : ''}
                      {s.weak && <span className="ssl-weak-tag"> WEAK</span>}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Full SSL Labs Report Sections ── */}
      {hasFullReport && (
        <>
          {r.certificates.map((cert, idx) => (
            <div className="section" key={idx}>
              <div className="section-header">Certificate #{idx + 1}{cert.keyAlg && cert.keySize ? `: ${cert.keyAlg} ${cert.keySize} bits` : ''}{cert.signatureAlgorithm ? ` (${cert.signatureAlgorithm})` : ''}</div>
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
                    <div className="cipher-group-title">{group.protocol}{group.preference ? ' (server chooses the cipher)' : ''}</div>
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

      {/* ── Full SSL Labs Link ── */}
      {r.sslLabsUrl && (
        <div className="section">
          <div className="section-header">Full SSL Labs Report</div>
          <div className="section-content">
            <a href={r.sslLabsUrl} target="_blank" rel="noopener noreferrer" className="ssl-labs-report-link">Open SSL Server Test for {host} →</a>
            {!hasFullReport && <p className="ssl-report-note">Certificate details, cipher suites, chain, and full grading are available in the Qualys SSL Labs report. Run a scan on the SSL Labs website first, then re-scan here to pull cached results inline.</p>}
          </div>
        </div>
      )}

      {/* ── Footer ── */}
      <div className="ssl-report-footer">
        <a href={SSL_LABS_HOME} target="_blank" rel="noopener noreferrer" className="ssl-labs-logo-link"><img src={SSL_LABS_LOGO} alt="Qualys SSL Labs" className="ssl-labs-logo small" /></a>
        <span className="ssl-report-copyright">SSL Server Rating Guide based on <a href="https://www.ssllabs.com/projects/rating-guide/" target="_blank" rel="noopener noreferrer">Qualys SSL Labs</a> methodology. © Qualys, Inc.</span>
      </div>
    </div>
  );
}

function ErrorHandlingReport({ r }) {
  const d = r.targetDomain || 'Unknown';
  const risk = r.riskLevel || 'Unknown';
  const riskMeta = { High: {color:'#ef4444',bg:'rgba(239,68,68,0.1)'}, Medium: {color:'#f97316',bg:'rgba(249,115,22,0.1)'}, Low: {color:'#22c55e',bg:'rgba(34,197,94,0.1)'}, Unknown: {color:'#6b7280',bg:'rgba(107,114,128,0.08)'} }[risk] || {color:'#6b7280',bg:'rgba(107,114,128,0.08)'};
  const sevColors = { High: '#ef4444', Medium: '#f97316', Low: '#eab308' };
  const findings = r.findings || [];
  const probes = r.probes || [];
  const count = r.sensitiveLeaked?.length ?? 0;
  const successProbes = probes.filter(p => !p.error);
  const hitProbes = probes.filter(p => (p.indicatorsCount || 0) > 0);

  return (
    <div className="report-inner err-report">
      {/* ── Header ── */}
      <div className="site-info">
        <div className="site-url">{d}</div>
        <div className="scan-time">Improper Error Handling Analysis{r.scannedAt ? ` · ${new Date(r.scannedAt).toLocaleString()}` : ''}</div>
      </div>

      {r.error && <div className="err-error-bar"><span className="err-error-icon">!</span> {r.error}</div>}

      {/* ── Risk Banner ── */}
      {!r.error && (
        <div className="err-risk-banner" style={{borderLeft:`4px solid ${riskMeta.color}`, background: riskMeta.bg}}>
          <div className="err-risk-badge" style={{background: riskMeta.color}}>{risk.charAt(0)}</div>
          <div className="err-risk-text">
            <div className="err-risk-title">Risk Level: {risk}</div>
            <div className="err-risk-subtitle">{count > 0 ? `${count} disclosure indicator${count !== 1 ? 's' : ''} detected across ${hitProbes.length} probe${hitProbes.length !== 1 ? 's' : ''}` : 'No information disclosure indicators detected'}</div>
          </div>
          <div className="err-risk-stats">
            <div className="err-rstat"><span className="err-rstat-num">{successProbes.length}</span><span className="err-rstat-lbl">Probes</span></div>
            <div className="err-rstat"><span className="err-rstat-num" style={{color: hitProbes.length > 0 ? '#ef4444' : '#22c55e'}}>{hitProbes.length}</span><span className="err-rstat-lbl">With findings</span></div>
            <div className="err-rstat"><span className="err-rstat-num" style={{color: count > 0 ? '#ef4444' : '#22c55e'}}>{count}</span><span className="err-rstat-lbl">Indicators</span></div>
            {r.probeStatus && <div className="err-rstat"><span className="err-rstat-num">{r.probeStatus}</span><span className="err-rstat-lbl">HTTP status</span></div>}
          </div>
        </div>
      )}

      {/* ── Executive Summary ── */}
      {r.executiveSummary && (
        <div className="section"><div className="section-header">Executive Summary</div>
          <div className="section-content err-summary-text">{r.executiveSummary}</div>
        </div>
      )}

      {/* ── Findings ── */}
      {findings.length > 0 && (
        <div className="section">
          <div className="section-header">Disclosure Findings ({findings.length})</div>
          <div className="section-content">
            {findings.map((f, i) => (
              <div key={i} className="err-finding-card" style={{borderLeftColor: sevColors[f.severity] || '#6b7280'}}>
                <div className="err-finding-top">
                  <span className="err-sev-dot" style={{background: sevColors[f.severity] || '#6b7280'}}></span>
                  <strong className="err-finding-cat">{f.category}</strong>
                  <span className="err-sev-pill" style={{background: (sevColors[f.severity] || '#6b7280') + '22', color: sevColors[f.severity] || '#6b7280', border: `1px solid ${sevColors[f.severity] || '#6b7280'}44`}}>{f.severity}</span>
                </div>
                <table className="err-finding-table"><tbody>
                  <tr><td className="err-td-label">Evidence</td><td>{(f.evidence || []).map((e, j) => <div key={j}><code className="err-evidence-code">{e}</code></div>)}</td></tr>
                  {f.probes?.length > 0 && <tr><td className="err-td-label">Triggered by</td><td className="err-triggered">{f.probes.join('; ')}</td></tr>}
                  {f.impact && <tr><td className="err-td-label">Impact</td><td>{f.impact}</td></tr>}
                  {f.remediation && <tr><td className="err-td-label">Remediation</td><td>{f.remediation}</td></tr>}
                </tbody></table>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Response Snippet ── */}
      {r.responseSnippet && (
        <div className="section"><div className="section-header">Response Snippet</div>
          <div className="section-content"><pre className="err-snippet">{r.responseSnippet}</pre></div>
        </div>
      )}

      {/* ── Probes Table ── */}
      {probes.length > 0 && (
        <div className="section">
          <div className="section-header">Probes Performed ({probes.length})</div>
          <div className="section-content">
            <table className="err-probes-table">
              <thead><tr><th>Probe</th><th>Method</th><th>Status</th><th>Findings</th></tr></thead>
              <tbody>
                {probes.map((p, i) => (
                  <tr key={i} className={(p.indicatorsCount || 0) > 0 ? 'err-probe-hit' : ''}>
                    <td><div className="err-probe-label">{p.probeLabel || 'Probe'}</div><code className="err-probe-url">{p.probeUrl}</code></td>
                    <td><code className="err-probe-method">{p.method || 'GET'}</code></td>
                    <td className={`err-probe-status ${p.error ? 'err-s-error' : (p.statusCode || 0) >= 500 ? 'err-s-5xx' : (p.statusCode || 0) >= 400 ? 'err-s-4xx' : ''}`}>{p.statusCode ?? (p.error ? 'Err' : '—')}</td>
                    <td className={`err-probe-count ${(p.indicatorsCount || 0) > 0 ? 'err-c-hit' : 'err-c-clean'}`}>{p.indicatorsCount ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Recommendation ── */}
      <div className="section"><div className="section-header">Recommendation</div>
        <div className="section-content err-summary-text">{r.recommendation || ''}</div>
      </div>

      {/* ── References ── */}
      {r.references?.length > 0 && (
        <div className="section"><div className="section-header">References</div>
          <div className="section-content"><ul className="err-refs-list">{r.references.map((ref, i) => <li key={i}>{ref}</li>)}</ul></div>
        </div>
      )}
    </div>
  );
}

function SensitiveDataReport({ r }) {
  const d = r.targetDomain || 'Unknown';
  const risk = r.riskLevel || 'Unknown';
  const riskMeta = { High: {color:'#ef4444',bg:'rgba(239,68,68,0.1)',label:'Critical Exposure'}, Medium: {color:'#f97316',bg:'rgba(249,115,22,0.1)',label:'Moderate Exposure'}, Low: {color:'#eab308',bg:'rgba(234,179,8,0.1)',label:'Minor Exposure'}, None: {color:'#22c55e',bg:'rgba(34,197,94,0.1)',label:'No Exposure Detected'}, Unknown: {color:'#6b7280',bg:'rgba(107,114,128,0.08)',label:'Scan Incomplete'} }[risk] || {color:'#6b7280',bg:'rgba(107,114,128,0.08)',label:risk};
  const sevColors = { High: '#ef4444', Medium: '#f97316', Low: '#eab308' };
  const findings = r.findings || [];
  const headerIssues = r.headerIssues || [];
  const stats = r.piiStats || {};
  const totalPii = r.totalPiiInstances || 0;
  const totalCats = r.totalCategories || 0;
  const compliance = r.compliance || [];

  return (
    <div className="report-inner pii-report">
      <div className="site-info">
        <div className="site-url">{d}</div>
        <div className="scan-time">Sensitive Data Exposure Analysis{r.scannedAt ? ` · ${new Date(r.scannedAt).toLocaleString()}` : ''}</div>
      </div>

      {r.error && <div className="pii-error-bar"><span className="pii-error-icon">!</span> {r.error}</div>}

      {!r.error && (
        <div className="pii-risk-banner" style={{borderLeft:`4px solid ${riskMeta.color}`, background: riskMeta.bg}}>
          <div className="pii-risk-badge" style={{background: riskMeta.color}}>{risk === 'None' ? '✓' : risk.charAt(0)}</div>
          <div className="pii-risk-text">
            <div className="pii-risk-title">{riskMeta.label}</div>
            <div className="pii-risk-subtitle">{totalPii > 0 ? `${totalPii} PII instance${totalPii !== 1 ? 's' : ''} across ${totalCats} categor${totalCats !== 1 ? 'ies' : 'y'}` : 'No cleartext PII detected in the API response'}</div>
          </div>
          <div className="pii-risk-stats">
            <div className="pii-rstat"><span className="pii-rstat-num" style={{color: totalPii > 0 ? '#ef4444' : '#22c55e'}}>{totalPii}</span><span className="pii-rstat-lbl">PII found</span></div>
            <div className="pii-rstat"><span className="pii-rstat-num">{totalCats}</span><span className="pii-rstat-lbl">Categories</span></div>
            <div className="pii-rstat"><span className="pii-rstat-num" style={{color: headerIssues.length > 0 ? '#f97316' : '#22c55e'}}>{headerIssues.length}</span><span className="pii-rstat-lbl">Header issues</span></div>
            {r.httpStatus && <div className="pii-rstat"><span className="pii-rstat-num">{r.httpStatus}</span><span className="pii-rstat-lbl">HTTP status</span></div>}
          </div>
        </div>
      )}

      {r.executiveSummary && (
        <div className="section"><div className="section-header">Executive Summary</div>
          <div className="section-content pii-summary-text">{r.executiveSummary}</div>
        </div>
      )}

      {findings.length > 0 && (
        <div className="section">
          <div className="section-header">PII / Sensitive Data Findings ({findings.length})</div>
          <div className="section-content">
            {findings.map((f, i) => (
              <div key={i} className="pii-finding-card" style={{borderLeftColor: sevColors[f.severity] || '#6b7280'}}>
                <div className="pii-finding-top">
                  <span className="pii-sev-dot" style={{background: sevColors[f.severity] || '#6b7280'}}></span>
                  <strong className="pii-finding-cat">{f.category}</strong>
                  <span className="pii-sev-pill" style={{background: (sevColors[f.severity] || '#6b7280') + '22', color: sevColors[f.severity] || '#6b7280', border: `1px solid ${sevColors[f.severity] || '#6b7280'}44`}}>{f.severity}</span>
                </div>
                <table className="pii-finding-table"><tbody>
                  <tr><td className="pii-td-label">Exposed Data</td><td>{(f.evidence || []).map((e, j) => (
                    <div key={j} className="pii-evidence-row">
                      <code className="pii-evidence-value">{e.value}</code>
                    </div>
                  ))}</td></tr>
                  <tr><td className="pii-td-label">Location</td><td>{(f.evidence || []).map((e, j) => (
                    <div key={j} className="pii-evidence-row">
                      {e.field && <span className="pii-evidence-field">Field: <code>{e.field}</code></span>}
                      {e.path && <span className="pii-evidence-path">Path: <code>{e.path}</code></span>}
                    </div>
                  ))}</td></tr>
                  <tr><td className="pii-td-label">Detection</td><td>{(f.evidence || []).slice(0, 1).map((e, j) => (
                    <span key={j} className="pii-detection-text">{e.detectionMethod || (e.source === 'json_field' ? 'Sensitive field name match' : 'Regex pattern match')}</span>
                  ))}</td></tr>
                  <tr><td className="pii-td-label">Impact</td><td className="pii-impact-text">{f.impact}</td></tr>
                  <tr><td className="pii-td-label">Remediation</td><td className="pii-remediation-text">{f.remediation}</td></tr>
                </tbody></table>
              </div>
            ))}
          </div>
        </div>
      )}

      {headerIssues.length > 0 && (
        <div className="section">
          <div className="section-header">Response Header Issues ({headerIssues.length})</div>
          <div className="section-content">
            {headerIssues.map((h, i) => (
              <div key={i} className="pii-finding-card" style={{borderLeftColor: sevColors[h.severity] || '#6b7280'}}>
                <div className="pii-finding-top">
                  <span className="pii-sev-dot" style={{background: sevColors[h.severity] || '#6b7280'}}></span>
                  <strong className="pii-finding-cat">{h.header}: {h.issue}</strong>
                  <span className="pii-sev-pill" style={{background: (sevColors[h.severity] || '#6b7280') + '22', color: sevColors[h.severity] || '#6b7280', border: `1px solid ${sevColors[h.severity] || '#6b7280'}44`}}>{h.severity}</span>
                </div>
                <table className="pii-finding-table"><tbody>
                  <tr><td className="pii-td-label">Detail</td><td>{h.detail}</td></tr>
                  <tr><td className="pii-td-label">Fix</td><td className="pii-remediation-text">{h.fix}</td></tr>
                </tbody></table>
              </div>
            ))}
          </div>
        </div>
      )}

      {compliance.length > 0 && (
        <div className="section">
          <div className="section-header">Compliance Violations</div>
          <div className="section-content">
            {compliance.map((c, i) => (
              <div key={i} className="pii-compliance-card">
                <strong className="pii-compliance-std">{c.standard}</strong>
                <p className="pii-compliance-detail">{c.detail}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {Object.keys(stats).length > 0 && (
        <div className="section">
          <div className="section-header">PII Breakdown</div>
          <div className="section-content">
            <table className="pii-stats-table">
              <thead><tr><th>Category</th><th>Instances</th><th>Severity</th></tr></thead>
              <tbody>
                {Object.entries(stats).map(([cat, cnt], i) => {
                  const f = findings.find(x => x.category === cat);
                  return (
                    <tr key={i}>
                      <td>{cat}</td>
                      <td><strong>{cnt}</strong></td>
                      <td><span className="pii-sev-pill" style={{background: (sevColors[f?.severity] || '#6b7280') + '22', color: sevColors[f?.severity] || '#6b7280', border: `1px solid ${sevColors[f?.severity] || '#6b7280'}44`}}>{f?.severity || 'Unknown'}</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {r.recommendation && (
        <div className="section"><div className="section-header">Recommendation</div>
          <div className="section-content pii-summary-text">{r.recommendation}</div>
        </div>
      )}

      {!r.error && (
        <div className="section">
          <div className="section-header">Scan Metadata</div>
          <div className="section-content">
            <table className="pii-stats-table">
              <tbody>
                <tr><td><strong>Endpoint</strong></td><td><code className="pii-evidence-path">{r.originalUrl || d}</code></td></tr>
                <tr><td><strong>HTTP Status</strong></td><td>{r.httpStatus}</td></tr>
                <tr><td><strong>Content-Type</strong></td><td><code>{r.contentType || 'unknown'}</code></td></tr>
                <tr><td><strong>Response Size</strong></td><td>{r.responseSize != null ? `${(r.responseSize / 1024).toFixed(1)} KB` : '—'}</td></tr>
                <tr><td><strong>Analysis Method</strong></td><td>{r.isJson ? 'JSON tree walk + regex pattern matching' : 'Response body text regex scanning'}</td></tr>
                <tr><td><strong>Scanned At</strong></td><td>{r.scannedAt ? new Date(r.scannedAt).toLocaleString() : '—'}</td></tr>
              </tbody>
            </table>
          </div>
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

const DEFAULT_SELECTED_TESTS = TESTING_METHODS.filter((m) => m.value !== 'cors').map((m) => m.value);

function ScanDropdownPortal({ anchorRef, children }) {
  const [pos, setPos] = useState({ top: 0, left: 0 });

  useEffect(() => {
    const update = () => {
      if (!anchorRef.current) return;
      const rect = anchorRef.current.getBoundingClientRect();
      const dropW = 330;
      let left = rect.right - dropW;
      if (left < 8) left = 8;
      if (left + dropW > window.innerWidth - 8) left = window.innerWidth - dropW - 8;
      let top = rect.bottom + 6;
      const maxH = window.innerHeight * 0.7;
      if (top + maxH > window.innerHeight - 12) {
        top = rect.top - maxH - 6;
        if (top < 8) top = 8;
      }
      setPos({ top, left });
    };
    update();
    window.addEventListener('scroll', update, true);
    window.addEventListener('resize', update);
    return () => {
      window.removeEventListener('scroll', update, true);
      window.removeEventListener('resize', update);
    };
  }, [anchorRef]);

  return createPortal(
    <div className="pm-scan-dropdown" style={{ top: pos.top, left: pos.left }}>
      {children}
    </div>,
    document.body,
  );
}

/* Splits a curl command into highlighted tokens. Every value a user may want
   to change (URL, header name/value, body, flag argument) carries `edit`:
   its exact character range in `normalized` plus the quote wrapping it, so
   an inline edit can replace just those characters and leave the rest of
   the command byte-for-byte intact. */
function tokenizeCurlLines(normalized) {
  const rawLines = [];
  let cur = '', curStart = 0, inSingle = false, inDouble = false;
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    if (ch === '\n' && !inSingle && !inDouble) {
      rawLines.push({ text: cur, start: curStart });
      cur = ''; curStart = i + 1;
      continue;
    }
    cur += ch;
  }
  if (cur) rawLines.push({ text: cur, start: curStart });

  const quoted = (s) => s.match(/^'((?:[^'\\]|\\.)*)'/) || s.match(/^"((?:[^"\\]|\\.)*)"/);

  return rawLines.map(({ text, start }) => {
    const trailingBs = text.endsWith('\\') && !text.endsWith('\\\\');
    const body = trailingBs ? text.slice(0, -1).trimEnd() : text;
    const lead = body.length - body.trimStart().length;
    let rest = body.slice(lead);
    let pos = start + lead;
    const tokens = [];
    // `quote` undefined = not editable; null = editable, unquoted.
    const take = (cls, len, quote) => {
      const t = rest.slice(0, len);
      tokens.push(quote === undefined ? { cls, text: t } : { cls, text: t, edit: { start: pos, end: pos + len, quote } });
      rest = rest.slice(len);
      pos += len;
    };

    if (/^curl\b/.test(rest)) take('ch-kw', 4);
    while (rest.length > 0) {
      const sp = rest.match(/^\s+/);
      if (sp) { take('', sp[0].length); continue; }
      const flagMatch = rest.match(/^(--[\w-]+|-[a-zA-Z])(\s*)/);
      if (flagMatch) {
        const flag = flagMatch[1];
        const isHeader = flag === '-H' || flag === '--header';
        const isData   = flag === '-d' || flag === '--data' || flag === '--data-raw' || flag === '--data-binary';
        take(isHeader ? 'ch-flag-h' : isData ? 'ch-flag-d' : 'ch-flag', flag.length);
        if (flagMatch[2]) take('', flagMatch[2].length);
        const m = quoted(rest);
        if (m) {
          const q = m[0][0];
          const inner = m[1];
          const ci = inner.indexOf(':');
          if (isHeader && ci > 0) {
            take('ch-quote', 1);
            take('ch-hdr-key', ci, q);
            take('ch-hdr-colon', 1);
            const val = inner.slice(ci + 1);
            const vLead = val.length - val.trimStart().length;
            if (vLead) take('', vLead);
            take('ch-hdr-val', val.length - vLead, q);
            take('ch-quote', 1);
          } else {
            const cls = isData ? 'ch-body' : 'ch-str';
            take(cls, 1);
            take(cls, inner.length, q);
            take(cls, 1);
          }
        }
        continue;
      }
      const url = rest.match(/^https?:\/\/\S+/);
      if (url) { take('ch-url', url[0].length, null); continue; }
      const m2 = quoted(rest);
      if (m2) {
        take('ch-str', 1);
        take('ch-str', m2[1].length, m2[0][0]);
        take('ch-str', 1);
        continue;
      }
      const word = rest.match(/^\S+/);
      if (word) { take('ch-plain', word[0].length, null); continue; }
      break;
    }
    return { tokens, trailingBs };
  });
}

/* Read-only highlighter; pass `onChange(nextRaw)` to make values editable in
   place. `onChange` returns an error message to reject the edit, or null. */
function CurlHighlight({ raw, onChange }) {
  const [editing, setEditing] = useState(null);
  const [error, setError] = useState('');
  const settledRef = useRef(true);

  if (!raw) return null;
  const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const lines = tokenizeCurlLines(normalized);
  const editable = typeof onChange === 'function';

  const begin = (tok) => {
    settledRef.current = false;
    setError('');
    setEditing({ ...tok.edit, value: tok.text, multiline: tok.text.includes('\n') || tok.text.length > 60 });
  };

  const cancel = () => {
    settledRef.current = true;
    setEditing(null);
    setError('');
  };

  const commit = () => {
    if (!editing) return;
    const { start, end, quote, value } = editing;
    if (value === normalized.slice(start, end)) { cancel(); return; }
    if (quote === "'" && value.includes("'")) {
      setError("This value is wrapped in single quotes ('), so it can't contain a ' character.");
      return;
    }
    if (quote === '"' && /(^|[^\\])"/.test(value)) {
      setError('This value is wrapped in double quotes ("), so a " inside it must be written as \\".');
      return;
    }
    if (quote === null && !value.trim()) { setError("This value can't be empty."); return; }
    if (quote === null && /\s/.test(value)) {
      setError("This value isn't quoted, so it can't contain spaces.");
      return;
    }
    const rejection = onChange(normalized.slice(0, start) + value + normalized.slice(end));
    if (rejection) { setError(rejection); return; }
    cancel();
  };

  const onKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); cancel(); return; }
    if (e.key === 'Enter' && (!editing?.multiline || e.metaKey || e.ctrlKey)) { e.preventDefault(); commit(); }
  };

  const renderToken = (tok, key) => {
    if (editable && tok.edit) {
      if (editing && editing.start === tok.edit.start) {
        const common = {
          key,
          className: `ch-inline-input ${tok.cls}`,
          value: editing.value,
          autoFocus: true,
          spellCheck: false,
          onFocus: (e) => e.target.select(),
          onChange: (e) => { setError(''); setEditing((prev) => ({ ...prev, value: e.target.value })); },
          onKeyDown: onKey,
          onBlur: () => { if (!settledRef.current) commit(); },
          'aria-label': 'Edit value',
        };
        return editing.multiline
          ? <textarea {...common} rows={Math.min(12, editing.value.split('\n').length + 1)} />
          : <input {...common} size={Math.max(editing.value.length + 1, 6)} />;
      }
      return (
        <span
          key={key}
          className={`${tok.cls} ch-editable`}
          role="button"
          tabIndex={0}
          title="Click to edit"
          onClick={() => begin(tok)}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); begin(tok); } }}
        >
          {tok.text}
        </span>
      );
    }
    return <span key={key} className={tok.cls || undefined}>{tok.text}</span>;
  };

  return (
    <div className="pm-curl-highlight-wrap">
      <div className={`pm-curl-highlight${editable ? ' pm-curl-highlight--editable' : ''}`}>
        {lines.map((line, i) => (
          <div key={i} className="pm-curl-highlight-line">
            <span className="pm-curl-ln">{i + 1}</span>
            <span className="pm-curl-lc">
              {line.tokens.map(renderToken)}
              {line.trailingBs && <span className="ch-bs"> \</span>}
            </span>
          </div>
        ))}
      </div>
      {editable && (
        <div className={`ch-inline-bar${error ? ' ch-inline-bar--error' : ''}`} role={error ? 'alert' : undefined}>
          {error
            ? <>⚠ {error}</>
            : editing
              ? (editing.multiline ? '⌘/Ctrl + Enter to save · Esc to cancel' : 'Enter to save · Esc to cancel')
              : 'Click any highlighted value to edit it in place'}
        </div>
      )}
    </div>
  );
}

function collapseLineContinuations(s) {
  let out = '';
  let inSingle = false, inDouble = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "'" && !inDouble) { inSingle = !inSingle; out += ch; }
    else if (ch === '"' && !inSingle) { inDouble = !inDouble; out += ch; }
    else if (ch === '\\' && !inSingle && !inDouble && (s[i + 1] === '\n' || s[i + 1] === '\r')) {
      i++; if (s[i + 1] === '\n') i++;
    } else { out += ch; }
  }
  return out;
}

const parseCurlCommand = (str) => {
  try {
    let s = str.trim().replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    s = collapseLineContinuations(s);
    if (s.startsWith('curl ') || s === 'curl') s = s.slice(5);
    else if (s.startsWith('curl')) s = s.slice(4);
    let url = '';
    const urlMatch = s.match(/(?:--url\s+|(?<=^|\s))(['"])(https?:\/\/[^\1]+?)\1(?=\s|$)/) ||
                     s.match(/(?:--url\s+)(https?:\/\/\S+)/) ||
                     s.match(/(https?:\/\/[^\s'"]+)/);
    if (urlMatch) url = urlMatch[2] || urlMatch[1];
    const hdrReSingle = /(?:-H|--header)\s+'([^']+)'/gi;
    const hdrReDouble = /(?:-H|--header)\s+"((?:[^"\\]|\\.)*)"/gi;
    const reqHeaders = []; let hm; let hid = Date.now();
    for (const re of [hdrReSingle, hdrReDouble]) {
      re.lastIndex = 0;
      while ((hm = re.exec(s)) !== null) {
        const raw = hm[1].replace(/\\"/g, '"').replace(/\\'/g, "'");
        const ci = raw.indexOf(':');
        if (ci > 0) reqHeaders.push({ id: ++hid, key: raw.slice(0, ci).trim(), value: raw.slice(ci + 1).trim(), enabled: true });
      }
    }
    const bodyMatch = s.match(/(?:--data-binary|--data-raw|--data|-d)\s+'((?:[^'\\]|\\.)*)'/i) ||
                      s.match(/(?:--data-binary|--data-raw|--data|-d)\s+"((?:[^"\\]|\\.)*)"/i) ||
                      s.match(/(?:--data-binary|--data-raw|--data|-d)\s+(\S+)/i);
    const bodyContent = bodyMatch ? bodyMatch[1].replace(/\\'/g, "'").replace(/\\"/g, '"') : '';
    const methodMatch = s.match(/(?:-X|--request)\s+([A-Z]+)/i);
    let method = methodMatch ? methodMatch[1].toUpperCase() : (bodyContent ? 'POST' : 'GET');
    let bodyType = 'none';
    if (bodyContent) {
      try { JSON.parse(bodyContent); bodyType = 'json'; } catch { bodyType = 'raw'; }
    }
    return { method, url, reqHeaders, bodyType, bodyContent, error: null };
  } catch (e) { return { error: `Parse error: ${e.message}` }; }
};

const buildCurlCommand = (curl) => {
  const parts = [`curl --location '${curl.url}'`];
  if (curl.method && curl.method !== 'GET') parts.push(`  --request ${curl.method}`);
  for (const h of (curl.reqHeaders || [])) {
    if (h.enabled && h.key.trim()) parts.push(`  --header '${h.key}: ${h.value}'`);
  }
  if (curl.bodyContent) {
    const escaped = curl.bodyContent.replace(/'/g, "'\\''");
    parts.push(`  --data-raw '${escaped}'`);
  }
  return parts.join(' \\\n');
};

function TokenGenerator({ onScanFromCurl }) {
  const makeHeader = () => ({ id: Date.now() + Math.random(), key: '', value: '', enabled: true });
  const makeCurl = (n) => ({
    id: n, label: `Req ${n}`,
    method: 'GET', url: '',
    reqHeaders: [makeHeader()], bodyType: 'none', bodyContent: '',
    rawCurl: '', importedFromCurl: false, liveParseResult: null, importName: '', parseError: '',
    result: null, error: '', loading: false, timestamp: null,
  });

  const getNextNum = (list) => {
    if (!list.length) return 1;
    return Math.max(...list.map((c) => c.id)) + 1;
  };

  const [curls, setCurls] = useState([makeCurl(1)]);
  const [activeCurlTab, setActiveCurlTab] = useState(1);
  const [copiedField, setCopiedField] = useState('');
  const [executingAll, setExecutingAll] = useState(false);
  const [responseTab, setResponseTab] = useState('body');
  const [requestTab, setRequestTab] = useState('curl');
  const [selectedTests, setSelectedTests] = useState(DEFAULT_SELECTED_TESTS);
  const [testCorsMode, setTestCorsMode] = useState('');
  const [testOriginUrl, setTestOriginUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [showScanDropdown, setShowScanDropdown] = useState(false);
  const scanDropdownRef = useRef(null);

  useEffect(() => {
    const handler = (e) => {
      if (scanDropdownRef.current && !scanDropdownRef.current.contains(e.target)) {
        const portalEl = document.querySelector('.pm-scan-dropdown');
        if (portalEl && portalEl.contains(e.target)) return;
        setShowScanDropdown(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const toggleTest = (val) => setSelectedTests((prev) => prev.includes(val) ? prev.filter((v) => v !== val) : [...prev, val]);

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
    updateCurl(id, {
      method: 'GET', url: '', reqHeaders: [makeHeader()], bodyType: 'none', bodyContent: '',
      rawCurl: '', importedFromCurl: false, liveParseResult: null, importName: '', parseError: '',
      result: null, error: '', loading: false, timestamp: null,
    });
  };

  const getCurlToSend = (curl) => {
    if (curl.importedFromCurl && curl.rawCurl.trim()) return curl.rawCurl.trim();
    if (curl.url.trim()) return buildCurlCommand(curl);
    return curl.rawCurl.trim();
  };

  const handleImportCurl = (id) => {
    const curl = curls.find((c) => c.id === id);
    if (!curl?.liveParseResult?.method) return;
    const p = curl.liveParseResult;
    updateCurl(id, {
      method: p.method, url: p.url,
      reqHeaders: p.reqHeaders.length ? p.reqHeaders : [makeHeader()],
      bodyType: p.bodyType, bodyContent: p.bodyContent,
      importedFromCurl: true, liveParseResult: null, importName: '',
    });
    setRequestTab('headers');
  };

  const detachFromRawCurl = (id) => {
    updateCurl(id, { rawCurl: '', importedFromCurl: false, liveParseResult: null });
  };

  // Inline edits keep the curl text as the verbatim command that gets sent;
  // the parsed fields are refreshed so the Headers/Body tabs stay in sync.
  const applyInlineCurlEdit = (id, raw) => {
    const curl = curls.find((c) => c.id === id);
    if (!curl) return 'Request not found.';
    const p = parseCurlCommand(raw);
    if (p.error) return p.error;
    if (!p.url) return 'Could not find a URL in this curl command.';
    if (curl.importedFromCurl) {
      updateCurl(id, {
        rawCurl: raw,
        method: p.method, url: p.url,
        reqHeaders: p.reqHeaders.length ? p.reqHeaders : [makeHeader()],
        bodyType: p.bodyType, bodyContent: p.bodyContent,
        parseError: '',
      });
    } else {
      updateCurl(id, { rawCurl: raw, liveParseResult: p, parseError: '' });
    }
    return null;
  };

  const executeSingle = async (id) => {
    const curl = curls.find((c) => c.id === id);
    if (!curl) return;
    const trimmed = getCurlToSend(curl);
    if (!trimmed) { updateCurl(id, { error: 'Enter a URL or import a curl command first.' }); return; }
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
    const toExecute = curls.filter((c) => getCurlToSend(c));
    if (!toExecute.length) return;
    setExecutingAll(true);
    toExecute.forEach((c) => updateCurl(c.id, { error: '', result: null, loading: true, timestamp: null }));
    await Promise.allSettled(toExecute.map((c) => executeSingle(c.id)));
    setExecutingAll(false);
  };

  const executeChain = async () => {
    const toExecute = curls.filter((c) => getCurlToSend(c));
    if (!toExecute.length) return;
    setExecutingAll(true);
    toExecute.forEach((c) => updateCurl(c.id, { error: '', result: null, loading: true, timestamp: null }));
    const start = performance.now();
    try {
      const res = await fetch('/api/execute-curl-chain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          curls: toExecute.map((c) => ({ id: c.id, curlCommand: getCurlToSend(c) })),
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
    if (getCurlToSend(curl)) return 'has-input';
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
  const nonEmptyCount = curls.filter((c) => getCurlToSend(c)).length;

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

        {/* URL bar — Postman-like method selector + editable URL */}
        <div className="pm-url-bar">
          <select
            className={`pm-method-select pm-method-${active.method.toLowerCase()}`}
            value={active.method}
            onChange={(e) => updateCurl(active.id, { method: e.target.value, importedFromCurl: false })}
          >
            {['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <input
            type="text"
            className="pm-url-input-field"
            value={active.url}
            onChange={(e) => updateCurl(active.id, { url: e.target.value, importedFromCurl: false })}
            placeholder="https://api.example.com/endpoint"
          />
          <button
            type="button"
            className="pm-send-btn"
            disabled={active.loading}
            onClick={() => executeSingle(active.id)}
          >
            {active.loading ? <Loader2 size={16} className="spin-icon" /> : 'Send'}
          </button>
        </div>

        {/* ── Request area ── */}
        <div className="pm-request-section">
          <div className="pm-section-tabs">
            <button type="button" className={`pm-section-tab${requestTab === 'curl' ? ' active' : ''}`} onClick={() => setRequestTab('curl')}>
              Import cURL
            </button>
            <button type="button" className={`pm-section-tab${requestTab === 'headers' ? ' active' : ''}`} onClick={() => setRequestTab('headers')}>
              Headers {active.reqHeaders.filter((h) => h.enabled && h.key.trim()).length > 0 && `(${active.reqHeaders.filter((h) => h.enabled && h.key.trim()).length})`}
            </button>
            <button type="button" className={`pm-section-tab${requestTab === 'body' ? ' active' : ''}`} onClick={() => setRequestTab('body')}>
              Body {active.bodyContent && active.bodyType !== 'none' ? `· ${active.bodyType}` : ''}
            </button>
            <button type="button" className={`pm-section-tab${requestTab === 'tests' ? ' active' : ''}`} onClick={() => setRequestTab('tests')}>
              Security Tests
            </button>
            {req && Object.keys(req.headers).length > 0 && (
              <button type="button" className={`pm-section-tab${requestTab === 'req-headers' ? ' active' : ''}`} onClick={() => setRequestTab('req-headers')}>
                Sent Headers ({Object.keys(req.headers).length})
              </button>
            )}
            <div className="pm-section-tab-spacer" />
            <button type="button" className="pm-clear-btn" onClick={() => { clearCurl(active.id); setRequestTab('curl'); }}>Clear</button>
          </div>

          {/* Import cURL tab */}
          {requestTab === 'curl' && !active.importedFromCurl && (
            <div className="pm-import-area">
              {active.liveParseResult?.method ? (
                <div className="pm-import-card">
                  <div className="pm-import-name-row">
                    <label>Request name</label>
                    <input
                      className="pm-import-name-input"
                      value={active.importName || active.liveParseResult.url}
                      onChange={(e) => updateCurl(active.id, { importName: e.target.value })}
                      placeholder="Request name"
                    />
                  </div>
                  <CurlHighlight raw={active.rawCurl} onChange={(next) => applyInlineCurlEdit(active.id, next)} />
                  <div className="pm-import-summary">
                    <span className={`pm-import-method-pill pm-method-${active.liveParseResult.method.toLowerCase()}`}>{active.liveParseResult.method}</span>
                    {active.liveParseResult.reqHeaders.length > 0 && <span className="pm-import-pill">{active.liveParseResult.reqHeaders.length} header{active.liveParseResult.reqHeaders.length !== 1 ? 's' : ''}</span>}
                    {active.liveParseResult.bodyType !== 'none' && <span className="pm-import-pill">Body · {active.liveParseResult.bodyType}</span>}
                  </div>
                  <div className="pm-import-card-footer">
                    <button type="button" className="pm-send-btn" onClick={() => handleImportCurl(active.id)}>Import into request →</button>
                    <button type="button" className="pm-clear-btn" onClick={() => updateCurl(active.id, { rawCurl: '', liveParseResult: null, parseError: '' })}>Cancel</button>
                  </div>
                </div>
              ) : (
                <>
                  {active.parseError && (
                    <div className="pm-import-error-banner">
                      <span className="pm-import-error-icon">⚠</span>
                      <span className="pm-import-error-msg">{active.parseError}</span>
                    </div>
                  )}
                  <textarea
                    className={`pm-curl-textarea${active.parseError ? ' pm-curl-textarea--error' : ''}`}
                    value={active.rawCurl}
                    onChange={(e) => {
                      const raw = e.target.value;
                      if (!raw.trim()) {
                        updateCurl(active.id, { rawCurl: raw, liveParseResult: null, parseError: '' });
                        return;
                      }
                      const parsed = parseCurlCommand(raw);
                      if (parsed.error) {
                        updateCurl(active.id, { rawCurl: raw, liveParseResult: null, parseError: parsed.error });
                      } else {
                        updateCurl(active.id, { rawCurl: raw, liveParseResult: parsed, parseError: '' });
                      }
                    }}
                    placeholder={`curl --location 'https://api.example.com/session' \\\n--header 'Content-Type: application/json' \\\n--data '{"username":"demo","password":"demo123"}'`}
                    rows={7}
                  />
                </>
              )}
            </div>
          )}

          {/* Imported & locked state */}
          {requestTab === 'curl' && active.importedFromCurl && (
            <div className="pm-imported-locked">
              <div className="pm-imported-locked-badge">✓ Original curl imported — sending verbatim</div>
              <CurlHighlight raw={active.rawCurl} onChange={(next) => applyInlineCurlEdit(active.id, next)} />
              <div className="pm-imported-locked-note">
                <button type="button" className="pm-clear-btn" onClick={() => detachFromRawCurl(active.id)}>Detach &amp; use fields</button>
                <span className="pm-imported-locked-hint">Or switch to editing method/URL/headers as separate fields.</span>
              </div>
            </div>
          )}

          {/* Headers editor */}
          {requestTab === 'headers' && (
            <div className="pm-headers-editor">
              <table className="pm-headers-editor-table">
                <thead><tr><th style={{width:'2rem'}} /><th>Key</th><th>Value</th><th style={{width:'2rem'}} /></tr></thead>
                <tbody>
                  {active.reqHeaders.map((h) => (
                    <tr key={h.id} className={h.enabled ? '' : 'pm-hdr-disabled'}>
                      <td><input type="checkbox" checked={h.enabled} onChange={() => updateCurl(active.id, { reqHeaders: active.reqHeaders.map((r) => r.id === h.id ? { ...r, enabled: !r.enabled } : r) })} /></td>
                      <td><input className="pm-hdr-input" value={h.key} onChange={(e) => updateCurl(active.id, { reqHeaders: active.reqHeaders.map((r) => r.id === h.id ? { ...r, key: e.target.value } : r), importedFromCurl: false })} placeholder="Header name" /></td>
                      <td><input className="pm-hdr-input" value={h.value} onChange={(e) => updateCurl(active.id, { reqHeaders: active.reqHeaders.map((r) => r.id === h.id ? { ...r, value: e.target.value } : r), importedFromCurl: false })} placeholder="Value" /></td>
                      <td><button type="button" className="pm-hdr-del" onClick={() => updateCurl(active.id, { reqHeaders: active.reqHeaders.filter((r) => r.id !== h.id) || [makeHeader()] })} title="Remove"><X size={12} /></button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <button type="button" className="pm-add-header-btn" onClick={() => updateCurl(active.id, { reqHeaders: [...active.reqHeaders, makeHeader()] })}><Plus size={13} /> Add Header</button>
            </div>
          )}

          {/* Body editor */}
          {requestTab === 'body' && (
            <div className="pm-body-editor">
              <div className="pm-body-type-bar">
                {['none','json','raw','form'].map((t) => (
                  <button key={t} type="button" className={`pm-body-type-btn${active.bodyType === t ? ' active' : ''}`} onClick={() => updateCurl(active.id, { bodyType: t, importedFromCurl: false })}>{t === 'none' ? 'None' : t === 'json' ? 'JSON' : t === 'raw' ? 'Raw' : 'Form Data'}</button>
                ))}
              </div>
              {active.bodyType !== 'none' && (
                <textarea
                  className="pm-curl-textarea"
                  rows={6}
                  value={active.bodyContent}
                  onChange={(e) => updateCurl(active.id, { bodyContent: e.target.value, importedFromCurl: false })}
                  placeholder={active.bodyType === 'json' ? '{\n  "key": "value"\n}' : active.bodyType === 'form' ? 'key=value&another=value' : 'Raw body content'}
                />
              )}
            </div>
          )}

          {/* Security Tests tab */}
          {requestTab === 'tests' && (
            <div className="pm-tests-panel">
              <div className="pm-tests-header">
                <span className="pm-tests-title">Security Tests</span>
                <div className="pm-tests-quick">
                  <button type="button" className="pm-clear-btn" onClick={() => setSelectedTests(DEFAULT_SELECTED_TESTS)}>All</button>
                  <button type="button" className="pm-clear-btn" onClick={() => setSelectedTests([])}>None</button>
                </div>
              </div>
              <div className="pm-tests-grid">
                {TESTING_METHODS.map((m) => {
                  const icons = { 'http header analysis': '🛡', 'SSL / TLS analysis': '🔒', 'Server version Disclosure': '🖥', 'cors': '🌐', 'Improper Error Handling': '⚠', 'URL Tampering Analysis': '🔗' };
                  return (
                    <div key={m.id} className={`pm-test-card${selectedTests.includes(m.value) ? ' selected' : ''}`} onClick={() => toggleTest(m.value)}>
                      <span className="pm-test-card-icon">{icons[m.value] || '🔍'}</span>
                      <span className="pm-test-card-label">{m.label.split(' / ')[0]}</span>
                      <input type="checkbox" checked={selectedTests.includes(m.value)} onChange={() => {}} />
                    </div>
                  );
                })}
              </div>
              {selectedTests.includes('cors') && (
                <div className="pm-tests-cors">
                  <span className="pm-tests-cors-label">CORS Mode</span>
                  <div className="pm-tests-cors-opts">
                    <label className={`pm-cors-opt${testCorsMode === 'passive' ? ' selected' : ''}`}>
                      <input type="radio" name="testCorsMode-tab" value="passive" checked={testCorsMode === 'passive'} onChange={() => setTestCorsMode('passive')} />
                      Passive <small>(no origin sent)</small>
                    </label>
                    <label className={`pm-cors-opt${testCorsMode === 'active' ? ' selected' : ''}`}>
                      <input type="radio" name="testCorsMode-tab" value="active" checked={testCorsMode === 'active'} onChange={() => setTestCorsMode('active')} />
                      Active <small>(custom origin)</small>
                    </label>
                  </div>
                  {testCorsMode === 'active' && (
                    <input
                      className="pm-hdr-input"
                      style={{width:'100%', marginTop:'0.25rem'}}
                      value={testOriginUrl}
                      onChange={(e) => setTestOriginUrl(e.target.value)}
                      placeholder="https://your-origin.com"
                    />
                  )}
                </div>
              )}
              {active.url && (
                <button
                  type="button"
                  className={`pm-tests-scan-btn${scanning ? ' loading' : ''}`}
                  disabled={scanning || !selectedTests.length || (selectedTests.includes('cors') && !testCorsMode)}
                  onClick={async () => {
                    if (!onScanFromCurl) return;
                    setScanning(true);
                    await onScanFromCurl(
                      active.url, active.result?.request?.headers, active.method, active.bodyContent,
                      true, selectedTests,
                      selectedTests.includes('cors') ? testCorsMode : undefined,
                      testCorsMode === 'active' ? testOriginUrl : undefined,
                    );
                    setScanning(false);
                  }}
                >
                  {scanning ? <><Loader2 size={13} className="spin-icon" /> Scanning…</> : <><Shield size={13} /> Run Security Scan ({selectedTests.length})</>}
                </button>
              )}
            </div>
          )}

          {/* Sent request headers (read-only) */}
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
                    <div className="pm-scan-dropdown-wrap" ref={scanDropdownRef}>
                      <button
                        type="button"
                        className={`pm-meta-item pm-scan-api-btn${showScanDropdown ? ' active' : ''}`}
                        onClick={() => setShowScanDropdown((v) => !v)}
                      >
                        <Shield size={13} /> Scan this API ▾
                      </button>
                      {showScanDropdown && (
                        <ScanDropdownPortal anchorRef={scanDropdownRef}>
                          <div className="pm-scan-dd-header">
                            <span>Choose tests to run</span>
                            <label className="pm-scan-dd-toggle" onClick={(e) => {
                              e.preventDefault();
                              const allValues = TESTING_METHODS.map((m) => m.value);
                              setSelectedTests((prev) => prev.length === allValues.length ? [] : allValues);
                            }}>
                              <input type="checkbox" checked={selectedTests.length === TESTING_METHODS.length} readOnly />
                              {selectedTests.length === TESTING_METHODS.length ? 'Deselect All' : 'Select All'}
                            </label>
                          </div>
                          <div className="pm-scan-dd-list">
                            {TESTING_METHODS.map((m) => (
                              <label key={m.id} className="pm-scan-dd-item">
                                <input type="checkbox" checked={selectedTests.includes(m.value)} onChange={() => toggleTest(m.value)} />
                                {m.label.split(' / ')[0]}
                              </label>
                            ))}
                          </div>
                          {selectedTests.includes('cors') && (
                            <div className="pm-scan-dd-cors">
                              <span className="pm-scan-dd-cors-label">CORS Mode</span>
                              <div className="pm-tests-cors-opts">
                                <label className={`pm-cors-opt${testCorsMode === 'passive' ? ' selected' : ''}`}>
                                  <input type="radio" name="testCorsMode-dd" value="passive" checked={testCorsMode === 'passive'} onChange={() => setTestCorsMode('passive')} />
                                  Passive
                                </label>
                                <label className={`pm-cors-opt${testCorsMode === 'active' ? ' selected' : ''}`}>
                                  <input type="radio" name="testCorsMode-dd" value="active" checked={testCorsMode === 'active'} onChange={() => setTestCorsMode('active')} />
                                  Active
                                </label>
                              </div>
                              {testCorsMode === 'active' && (
                                <input
                                  className="pm-hdr-input"
                                  style={{width:'100%', marginTop:'0.35rem'}}
                                  value={testOriginUrl}
                                  onChange={(e) => setTestOriginUrl(e.target.value)}
                                  placeholder="https://your-origin.com"
                                />
                              )}
                            </div>
                          )}
                          <div className="pm-scan-dd-footer">
                            <button
                              type="button"
                              className={`pm-tests-scan-btn${scanning ? ' loading' : ''}`}
                              disabled={scanning || !selectedTests.length || (selectedTests.includes('cors') && !testCorsMode)}
                              onClick={async () => {
                                setShowScanDropdown(false);
                                setScanning(true);
                                await onScanFromCurl(
                                  req.url, req.headers, req.method, req.body,
                                  true, selectedTests,
                                  selectedTests.includes('cors') ? testCorsMode : undefined,
                                  testCorsMode === 'active' ? testOriginUrl : undefined,
                                );
                                setScanning(false);
                              }}
                            >
                              {scanning ? <><Loader2 size={13} className="spin-icon" /> Scanning…</> : <><Shield size={13} /> Run ({selectedTests.length})</>}
                            </button>
                          </div>
                        </ScanDropdownPortal>
                      )}
                    </div>
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

function HistoryPage({ history, onRestore, onRemove, onClear }) {
  const [downloading, setDownloading] = useState({});

  const gradeColor = (g) => ({ A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' }[g] || '#a3a3a3');
  const scoreBar = (s) => s == null ? null : (
    <div className="hist-score-bar-wrap">
      <div className="hist-score-bar" style={{ width: `${s}%`, background: s >= 80 ? '#22c55e' : s >= 60 ? '#eab308' : '#ef4444' }} />
    </div>
  );

  const handleDownload = async (entry) => {
    setDownloading((prev) => ({ ...prev, [entry.id]: true }));
    try {
      const res = await fetch('/api/download-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report: entry.result }),
      });
      if (!res.ok) throw new Error('Failed to generate report');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const safeDomain = (entry.url || 'report').replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9.-]/g, '_').replace(/_+/g, '_').slice(0, 60);
      const r = entry.result?.batch ? entry.result.results?.[0] : entry.result;
      const parts = [];
      if (r?.headersReport) parts.push('Header Analysis');
      if (r?.sslReport) parts.push('SSL-TLS');
      if (r?.serverReport) parts.push('Server Version Disclosure');
      if (r?.corsReport) parts.push('CORS');
      if (r?.errorHandlingReport) parts.push('Error Handling');
      if (r?.urlTamperingReport) parts.push('URL Tampering');
      const prefix = parts.length ? parts.join(' + ') : 'Security Report';
      a.href = url;
      a.download = `${prefix} - ${safeDomain}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(err.message || 'Download failed. Make sure the backend is running.');
    } finally {
      setDownloading((prev) => ({ ...prev, [entry.id]: false }));
    }
  };

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
                    onClick={() => handleDownload(entry)}
                    disabled={downloading[entry.id]}
                    title="Download HTML security report"
                  >
                    {downloading[entry.id] ? '…' : '⬇ Download'}
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
  return (
    <div className="settings-page">
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
    </div>
  );
}


function ScanProgressCard({ emailSending }) {
  const SCAN_STEPS = [
    { icon: ScanSearch,   label: 'Reaching target',          sub: 'Resolving DNS and connecting…' },
    { icon: Send,         label: 'Sending request',          sub: 'GET / OPTIONS probes in flight…' },
    { icon: Shield,       label: 'Analyzing headers & TLS',  sub: 'Inspecting security headers and certificate…' },
    { icon: FileSearch,   label: 'Evaluating rules',         sub: 'Running 50+ security checks…' },
    { icon: CheckCircle2, label: 'Compiling report',         sub: 'Scoring findings and building output…' },
  ];
  const STEP_DELAYS = [900, 2300, 5500, 10500];
  const STEP_PCTS = [15, 35, 55, 78, 92];

  const [step, setStep] = useState(0);

  useEffect(() => {
    setStep(0);
    const timers = STEP_DELAYS.map((delay, idx) =>
      setTimeout(() => setStep(idx + 1), delay)
    );
    return () => timers.forEach(clearTimeout);
  }, []);

  const pct = STEP_PCTS[step] ?? STEP_PCTS[STEP_PCTS.length - 1];

  return (
    <div className="scan-progress-card">
      <div className="scan-progress-head">
        <Loader2 size={15} className="scan-spin" aria-hidden />
        <span className="scan-progress-title">
          {emailSending ? 'Scanning & sending report…' : 'Running security scan…'}
        </span>
        <span className="scan-progress-pct">{pct}%</span>
      </div>

      <div className="scan-progress-bar">
        <div className="scan-progress-bar-fill" style={{ width: `${pct}%` }} />
      </div>

      <ol className="scan-progress-steps">
        {SCAN_STEPS.map((s, i) => {
          const Icon = s.icon;
          const done = i < step;
          const active = i === step;
          return (
            <li
              key={i}
              className={`scan-step ${done ? 'is-done' : active ? 'is-active' : 'is-pending'}`}
            >
              <div className="scan-step-dot">
                {done
                  ? <CheckCircle2 size={14} aria-hidden />
                  : active
                    ? <Loader2 size={14} className="scan-spin" aria-hidden />
                    : <Icon size={13} aria-hidden />}
              </div>
              <div className="scan-step-text">
                <p className="scan-step-label">{s.label}</p>
                <p className="scan-step-sub">{s.sub}</p>
              </div>
            </li>
          );
        })}
      </ol>

      {emailSending && (
        <div className="email-sending-badge scan-progress-badge">
          <span className="email-sending-dot" /> Sending email to recipients…
        </div>
      )}
    </div>
  );
}

function Dashboard({ user, onLogout }) {
  const { theme, toggleTheme } = useTheme();
  const { history, addEntry, removeEntry, clearHistory } = useHistory();
  const navigate = useNavigate();
  const location = useLocation();
  const activePage = PATH_TO_PAGE[location.pathname] || 'scanner';
  const setActivePage = (pageId) => navigate(PAGE_TO_PATH[pageId] || '/scanner');
  const [manualUrl, setManualUrl] = useState('');
  const [recipients] = useState(['']);
  const [sendReport] = useState(false);
  const [selectedMethods, setSelectedMethods] = useState([]);
  const [scanProfile, setScanProfile] = useState('custom');
  const [corsMode, setCorsMode] = useState('');
  const [originUrl, setOriginUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [emailSending, setEmailSending] = useState(false);
  const [emailStatus, setEmailStatus] = useState(null);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  const [selectedBatchIndex, setSelectedBatchIndex] = useState(0);
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

  const toggleMethod = (value) => {
    setSelectedMethods((prev) => (prev.includes(value) ? prev.filter((m) => m !== value) : [...prev, value]));
  };

  /* Profiles are presets over the same `selectedMethods` checkboxes the user
     can tick by hand — they only change which boxes are ticked, never how the
     scan runs. Ticking a box manually falls back to the "Custom" label. */
  const applyScanProfile = (id) => {
    setScanProfile(id);
    if (id === 'quick') setSelectedMethods(QUICK_SCAN_METHODS);
    else if (id === 'standard') setSelectedMethods(TESTING_METHODS.map((m) => m.value));
  };

  const toggleMethodManual = (value) => {
    setScanProfile('custom');
    toggleMethod(value);
  };

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
      setResult(sanitizeResult(merged));
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

  const batchResults = result?.batch ? (result.results || []) : [];
  const safeBatchIndex = batchResults.length ? Math.min(selectedBatchIndex, batchResults.length - 1) : 0;
  const currentResult = result?.batch ? batchResults[safeBatchIndex] : result;
  const scanUrl = currentResult?.url || currentResult?.targetDomain || manualUrl || '';

  const downloadSingleReport = async (_reportData, prefix) => {
    try {
      const panel = document.querySelector('.tab-panel');
      if (!panel) { alert('No report visible to download.'); return; }
      const clone = panel.cloneNode(true);
      clone.querySelectorAll('button, .copy-btn').forEach(el => el.remove());
      const safeDomain = (scanUrl || 'report').replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9.-]/g, '_').replace(/_+/g, '_').slice(0, 60);
      const html = buildDownloadHTML(clone.innerHTML, `${prefix} - ${safeDomain}`);
      downloadHTMLFile(html, `${prefix} - ${safeDomain}.html`);
    } catch (err) {
      alert(err.message || 'Download failed.');
    }
  };

  const tabs = [];
  if (currentResult?.headersReport != null) tabs.push({ name: 'Security headers', reportKey: 'headersReport', downloadPrefix: 'Header Analysis', content: (
    <HeadersReport r={currentResult.headersReport} />
  ) });
  if (currentResult?.corsReport != null) tabs.push({ name: 'CORS', reportKey: 'corsReport', downloadPrefix: 'CORS Analysis', content: <CorsReport r={currentResult.corsReport} /> });
  if (currentResult?.serverReport != null) tabs.push({ name: 'Server disclosure', reportKey: 'serverReport', downloadPrefix: 'Server Version Disclosure', content: <ServerReport r={currentResult.serverReport} /> });
  if (currentResult?.sslReport != null) tabs.push({ name: 'SSL/TLS', reportKey: 'sslReport', downloadPrefix: 'SSL-TLS Analysis', content: <SslReport r={currentResult.sslReport} /> });
  else if (currentResult && selectedMethods.some((m) => /ssl|tls/i.test(m))) tabs.push({ name: 'SSL/TLS', content: <div className="report-inner"><div className="section"><div className="section-content" style={{ color: 'var(--danger)' }}>SSL/TLS report was not returned. Ensure the backend is running and try again.</div></div></div> });
  if (currentResult?.errorHandlingReport != null) tabs.push({ name: 'Error handling', reportKey: 'errorHandlingReport', downloadPrefix: 'Error Handling Analysis', content: <ErrorHandlingReport r={currentResult.errorHandlingReport} /> });
  if (currentResult?.urlTamperingReport != null) tabs.push({ name: 'URL tampering', reportKey: 'urlTamperingReport', content: <UrlTamperingReport r={currentResult.urlTamperingReport} /> });
  if (currentResult?.sensitiveDataReport != null) tabs.push({ name: 'PII / Sensitive data', reportKey: 'sensitiveDataReport', downloadPrefix: 'Sensitive Data Exposure', content: <SensitiveDataReport r={currentResult.sensitiveDataReport} /> });

  return (
    <div className="app-with-sidebar">
      <Sidebar user={user} onLogout={onLogout} />
      <div className="app-main-content">
      <div className="app">
      {loading && (
        <div className="loading-overlay" aria-live="polite" aria-busy="true">
          <ScanProgressCard emailSending={emailSending} />
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
          <img
            src="/app-logo.svg"
            alt="API Secure"
            className="header-app-logo"
          />
          <div className="header-divider" aria-hidden />
          <div className="header-title-block">
            <h1>API SECURE</h1>
            <p className="header-eyebrow">Security Scanner</p>
          </div>
        </div>
        <div className="header-actions">
          <span className="header-status-pill" title="Backend reachable">
            <span className="header-status-dot" /> backend ok
          </span>
          <button
            type="button"
            className="header-icon-btn"
            onClick={toggleTheme}
            title={theme === 'dark' ? 'Switch to light' : 'Switch to dark'}
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <button
            type="button"
            className="header-icon-btn"
            title="Settings"
            aria-label="Settings"
            onClick={() => setActivePage('settings')}
          >
            <Settings size={16} />
          </button>
          <AnalysisInfoButton variant="icon" />
          <button
            type="button"
            className="header-icon-btn header-logout-mobile"
            title="Logout"
            aria-label="Logout"
            onClick={onLogout}
          >
            <LogOut size={16} />
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
            setResult(sanitizeResult(entry.result));
            setManualUrl(entry.url);
            setSelectedMethods(entry.analysisTypes || []);
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
          onScanFromCurl={async (url, requestHeaders, method, requestBody, _unused, chosenTests, corsMode, originUrl) => {
            setLoading(true);
            setError('');
            setEmailStatus(null);
            const methodsToRun = (chosenTests && chosenTests.length)
              ? chosenTests
              : TESTING_METHODS.filter((m) => m.value !== 'cors').map((m) => m.value);
            try {
              const body = {
                url,
                requestHeaders: requestHeaders || undefined,
                method: method || undefined,
                requestBody: requestBody || undefined,
                analysisTypes: methodsToRun,
                ...(methodsToRun.includes('cors') && corsMode ? { corsAnalysisType: corsMode === 'active' ? 'Active CORS Test' : 'Passive CORS Test' } : {}),
                ...(methodsToRun.includes('cors') && corsMode === 'active' && originUrl ? { origin: originUrl } : {}),
              };
              const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
              });
              const data = await res.json().catch(() => ({}));
              if (!res.ok) throw new Error(data.error || res.statusText || 'Scan failed');
              setResult(sanitizeResult(data));
              setManualUrl(url);
              setSelectedMethods(methodsToRun);
              setActiveTab(0);
              setSelectedBatchIndex(0);
              saveToHistory(data, url, methodsToRun);
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

      {activePage === 'scanner' && <div className="scan-layout">
        <div className="main-col">
          <header className="scan-hero">
            <div className="scan-hero-top">
              <span className="scan-hero-eyebrow">Security Scanner</span>
              <AnalysisInfoButton />
            </div>
            <h2 className="scan-hero-title">Start a Security Scan</h2>
            <p className="scan-hero-sub">Test your API or website for common security vulnerabilities and get a detailed report.</p>
          </header>

          <div className="form-card">
            <form onSubmit={handleSubmit}>
              <div className="field-block">
                <label className="field-label" htmlFor="target-url">Target URL</label>
                <div className="url-field">
                  <Link2 size={15} className="url-field-icon" aria-hidden />
                  <input id="target-url" type="url" className="manual-url" value={manualUrl} onChange={(e) => setManualUrl(e.target.value)} placeholder="https://api.example.com" />
                </div>
                <p className="field-hint">Enter a valid API endpoint or website URL to scan. Use <code>https://</code> or <code>http://</code>.</p>
              </div>

              <div className="field-block">
                <span className="field-label">Select Scan Profile</span>
                <div className="profile-grid">
                  {SCAN_PROFILES.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      className={`profile-card${scanProfile === p.id ? ' is-active' : ''}`}
                      onClick={() => applyScanProfile(p.id)}
                      aria-pressed={scanProfile === p.id}
                    >
                      <span className="profile-card-icon"><p.Icon size={16} /></span>
                      <span className="profile-card-text">
                        <span className="profile-card-title">{p.label}</span>
                        <span className="profile-card-hint">{p.hint}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="field-block">
                <div className="field-label-row">
                  <span className="field-label">Choose Security Checks</span>
                  <span className="field-count">{selectedMethods.length} selected</span>
                </div>
                <p className="field-hint field-hint-lead">Select the checks you want to run. You can choose multiple.</p>
                <div className="checks-grid">
                  {TESTING_METHODS.map((m) => {
                    const existingForUrl = result && !result.batch ? result : null;
                    const alreadyDone = !!existingForUrl?.[METHOD_TO_FIELD[m.value]];
                    const meta = CHECK_META[m.value] || { short: m.label, desc: '', Icon: Shield, tone: 'slate' };
                    const checked = selectedMethods.includes(m.value);
                    return (
                      <label
                        key={m.id}
                        className={`check-card${checked ? ' is-selected' : ''}${alreadyDone ? ' method-item-done' : ''}`}
                        title={m.label}
                      >
                        <input
                          type="checkbox"
                          id={m.id}
                          className="check-card-box"
                          checked={checked}
                          onChange={() => toggleMethodManual(m.value)}
                        />
                        <span className="check-card-icon" data-tone={meta.tone} aria-hidden>
                          <meta.Icon size={16} />
                        </span>
                        <span className="check-card-body">
                          <span className="check-card-title">{meta.short}</span>
                          <span className="check-card-desc">{meta.desc}</span>
                        </span>
                        {alreadyDone && <span className="method-done-badge">Done</span>}
                      </label>
                    );
                  })}
                </div>
                {selectedMethods.includes('cors') && (
                  <div className="cors-row">
                    <span className="field-label field-label-sm">CORS mode</span>
                    <div className="cors-mode">
                      <label><input type="radio" name="corsMode" value="passive" checked={corsMode === 'passive'} onChange={() => setCorsMode('passive')} /> Passive (no origin)</label>
                      <label><input type="radio" name="corsMode" value="active" checked={corsMode === 'active'} onChange={() => setCorsMode('active')} /> Active (send custom Origin)</label>
                    </div>
                    {corsMode === 'active' && <input type="text" className="origin-input" value={originUrl} onChange={(e) => setOriginUrl(e.target.value)} placeholder="Origin URL (for Active CORS)" />}
                  </div>
                )}
              </div>

              <button type="submit" className="btn-primary btn-run" disabled={loading}>
                {loading ? <><span className="spinner" /> Scanning…</> : <>Run Security Scan <ChevronRight size={16} /></>}
              </button>
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
                  {tabs[activeTab]?.downloadPrefix && (
                    <button
                      type="button"
                      className="tab-download-btn"
                      title={`Download ${tabs[activeTab].downloadPrefix} report`}
                      onClick={() => {
                        const t = tabs[activeTab];
                        const reportSlice = { [t.reportKey]: currentResult[t.reportKey], url: scanUrl, targetDomain: currentResult?.targetDomain || scanUrl };
                        downloadSingleReport(reportSlice, t.downloadPrefix);
                      }}
                    >
                      ⬇ Download {tabs[activeTab].downloadPrefix}
                    </button>
                  )}
                </div>
                <div className="tab-panel">{tabs[activeTab]?.content}</div>
              </>
            )}
          </div>
        </div>

        <aside className="scan-aside">
          <div className="aside-card aside-card-accent">
            <span className="aside-card-badge"><ShieldCheck size={18} /></span>
            <h3 className="aside-card-title">Why Scan?</h3>
            <p className="aside-card-text">Find and fix security issues before attackers exploit them. Protect your APIs, data and users.</p>
          </div>

          <div className="aside-card">
            <h3 className="aside-card-title">Quick Info</h3>
            <ul className="aside-facts">
              <li>
                <Clock size={15} aria-hidden />
                <span><span className="aside-fact-label">Scan time</span>~2–5 minutes</span>
              </li>
              <li>
                <ListChecks size={15} aria-hidden />
                <span><span className="aside-fact-label">Checks</span>{selectedMethods.length} selected</span>
              </li>
              <li>
                <Target size={15} aria-hidden />
                <span><span className="aside-fact-label">Supported targets</span>APIs and web applications</span>
              </li>
            </ul>
          </div>

          <div className="aside-card">
            <div className="aside-card-head">
              <h3 className="aside-card-title">Recent Scans</h3>
              {history.length > 0 && (
                <button type="button" className="aside-link" onClick={() => setActivePage('history')}>
                  View all <ChevronRight size={13} />
                </button>
              )}
            </div>
            {history.length === 0 ? (
              <p className="aside-card-text aside-card-empty">No scans yet. Your recent scans will appear here.</p>
            ) : (
              <ul className="recent-list">
                {history.slice(0, 4).map((entry) => (
                  <li key={entry.id} className="recent-item">
                    <Link2 size={13} className="recent-item-icon" aria-hidden />
                    <span className="recent-item-body">
                      <span className="recent-item-url" title={entry.url}>{entry.url}</span>
                      <span className="recent-item-meta">
                        <span className="recent-item-dot" aria-hidden /> Completed · {formatRelativeTime(entry.scannedAt)}
                      </span>
                    </span>
                    {entry.grade && <span className="recent-item-grade" data-grade={String(entry.grade).charAt(0)}>{entry.grade}</span>}
                  </li>
                ))}
              </ul>
            )}
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
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (location.pathname === '/') navigate('/scanner', { replace: true });
  }, [location.pathname, navigate]);

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
