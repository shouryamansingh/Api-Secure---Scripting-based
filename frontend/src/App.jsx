import { useState, useRef, useEffect } from 'react';
import { Info } from 'lucide-react';

const THEME_KEY = 'api-secure-theme';

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

function HeadersReport({ r }) {
  if (!r) return <div className="report-inner"><div className="section"><div className="section-content">No header report data.</div></div></div>;

  const hasError = !!r.error;
  const d = r.targetDomain || r.siteUrl || r.originalUrl || 'Unknown';
  const scanned = r.scannedAt ? new Date(r.scannedAt).toLocaleString() : '—';
  const score = r.score ?? 0;
  const grade = r.grade || 'F';
  const progressColor = score >= 80 ? '#28a745' : score >= 60 ? '#ffc107' : '#dc3545';
  const gradeColors = { A: '#28a745', B: '#17a2b8', C: '#ffc107', D: '#fd7e14', F: '#dc3545' };
  const cards = [
    { title: 'Security Score', value: `${score}%`, color: progressColor },
    { title: 'Grade', value: grade, color: gradeColors[grade] || '#dc3545' },
    { title: 'Critical', value: r.criticalCount ?? 0, color: '#dc3545' },
    { title: 'Warnings', value: r.warningCount ?? 0, color: '#ffc107' },
  ];
  const list = (arr) => (!arr?.length ? <li className="no-items">None</li> : arr.map((item, i) => <li key={i}>{item}</li>));
  const headers = r.evaluatedHeaders && typeof r.evaluatedHeaders === 'object'
    ? Object.entries(r.evaluatedHeaders).map(([name, info]) => {
        const sev = (info.severity || 'ok').toLowerCase();
        const val = info.value ? (String(info.value).length > 60 ? String(info.value).slice(0, 60) + '...' : info.value) : 'Not set';
        return (
          <tr key={name}>
            <td><strong>{name}</strong></td>
            <td>{info.present ? '✓ Present' : '✗ Missing'}</td>
            <td><code>{val}</code></td>
            <td><span className={`severity-${sev}`}>{(info.severity || 'ok').toUpperCase()}</span></td>
          </tr>
        );
      })
    : null;

  return (
    <div className="report-inner">
      <div className="site-info">
        <div className="site-url">{d}</div>
        <div className="scan-time">Scanned: {scanned}</div>
      </div>
      {hasError && (
        <div className="section">
          <div className="section-header">Analysis error</div>
          <div className="section-content" style={{ color: 'var(--danger)' }}>
            {r.message || 'Headers analysis failed.'} Check the URL (use https:// or http://), network, and try again.
          </div>
        </div>
      )}
      {!hasError && (
        <>
          <div className="summary-grid">
            {cards.map((c) => (
              <div key={c.title} className="summary-card" style={{ borderLeftColor: c.color }}>
                <div className="card-value" style={{ color: c.color }}>{c.value}</div>
                <div className="card-title">{c.title}</div>
              </div>
            ))}
          </div>
          <div className="section">
            <div className="section-header">Security headers</div>
            <div className="section-content">
              <table>
                <thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Severity</th></tr></thead>
                <tbody>{headers || <tr><td colSpan="4">No data</td></tr>}</tbody>
              </table>
            </div>
          </div>
          <div className="section"><div className="section-header">Critical issues</div><div className="section-content"><ul>{list(r.vulnerabilities)}</ul></div></div>
          <div className="section"><div className="section-header">Warnings</div><div className="section-content"><ul>{list(r.warnings)}</ul></div></div>
          <div className="section"><div className="section-header">Recommendations</div><div className="section-content"><ul>{list(r.recommendations)}</ul></div></div>
          <div className="section"><div className="section-header">Summary</div><div className="section-content" style={{ whiteSpace: 'pre-wrap' }}>{r.aiHeaderNotes || ''}</div></div>
        </>
      )}
    </div>
  );
}

function CorsReport({ r }) {
  const d = r.targetDomain || 'Unknown';
  const scanned = r.timestamp ? new Date(r.timestamp).toLocaleString() : '—';
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
        <div className="scan-time">Scanned: {scanned} · Risk: <span style={{ color: riskColors[risk] || '#6c757d' }}>{risk}</span></div>
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

function ServerReport({ r }) {
  const d = r.targetDomain || r.domain || 'Unknown';
  const risk = r.riskLevel || 'Unknown';
  const riskColors = { Critical: '#7f1d1d', High: '#dc3545', Medium: '#eab308', Low: '#17a2b8', Informational: '#6c757d', Unknown: '#6c757d' };
  const severityColors = { Critical: '#7f1d1d', High: '#dc3545', Medium: '#eab308', Low: '#17a2b8', Informational: '#6c757d' };
  const disclosures = r.disclosures || [];
  const list = disclosures.map((x, i) => (
    <tr key={i}>
      <td><strong>{x.header}</strong></td>
      <td><span className="severity-badge" style={{ backgroundColor: severityColors[x.severity] || '#6c757d' }}>{x.severity || '—'}</span></td>
      <td><code>{x.value}</code></td>
      <td className="evidence-cell">{x.evidence || '—'}</td>
    </tr>
  ));
  const versions = r.possibleVersions && typeof r.possibleVersions === 'object' ? Object.entries(r.possibleVersions) : [];
  const affectedComponents = Array.isArray(r.affectedComponents) ? r.affectedComponents : [];
  const recs = Array.isArray(r.recommendations) ? r.recommendations : (r.recommendation ? [r.recommendation] : []);
  const configExamples = r.configurationExamples && typeof r.configurationExamples === 'object' ? r.configurationExamples : {};
  const complianceMapping = Array.isArray(r.complianceMapping) ? r.complianceMapping : [];
  const htmlDisclosures = Array.isArray(r.htmlDisclosures) ? r.htmlDisclosures : [];
  const counts = r.summaryCounts || {};
  const scannedOn = r.scannedAt ? (() => {
    try {
      const dt = new Date(r.scannedAt);
      return dt.toLocaleDateString(undefined, { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (_) { return r.scannedAt; }
  })() : '';
  return (
    <div className="report-inner server-disclosure-report">
      <div className="server-report-header">
        {r.findingId && <span className="server-finding-id">{r.findingId}</span>}
        <h2 className="server-report-title">{r.reportTitle || `Server Version Disclosure Audit Report - ${d}`}</h2>
        <p className="server-report-subtitle">Comprehensive System &amp; Stack Analysis</p>
      </div>
      <div className="site-info">
        <div className="site-url">🌐 {d}</div>
        {scannedOn && <div className="scan-time">Scanned On: {scannedOn}</div>}
        <div className="server-report-meta">
          <div className="server-risk-block">
            <span className="server-meta-label">
              Overall Risk
              <span className="server-meta-info" title="Severity of the version disclosure finding. Critical/High = serious exposure; Medium/Low = limited; Informational = minimal." data-tooltip="Severity of the version disclosure finding. Critical/High = serious exposure; Medium/Low = limited; Informational = minimal."><Info size={14} strokeWidth={2} /></span>
            </span>
            <span className="server-risk-badge" style={{ backgroundColor: riskColors[risk] || '#6c757d' }}>{risk}</span>
          </div>
          {r.confidence != null && (
            <div className="server-confidence">
              <span className="server-meta-label">
                Confidence
                <span className="server-meta-info" title="How reliable this assessment is (0–10). Based on the number and type of headers detected." data-tooltip="How reliable this assessment is (0–10). Based on the number and type of headers detected."><Info size={14} strokeWidth={2} /></span>
              </span>
              <span className="server-confidence-value">{r.confidence} / 10</span>
            </div>
          )}
          {r.remediationPriority && (
            <div className="server-priority">
              <span className="server-meta-label">
                Priority
                <span className="server-meta-info" title="Suggested remediation order: P1 = fix first (Critical/High risk), P2 = medium, P3 = lower." data-tooltip="Suggested remediation order: P1 = fix first (Critical/High risk), P2 = medium, P3 = lower."><Info size={14} strokeWidth={2} /></span>
              </span>
              <span className="server-priority-value">{r.remediationPriority}</span>
            </div>
          )}
          {r.disclosureScore != null && (
            <div className="server-score">
              <span className="server-meta-label">
                Disclosure Score
                <span className="server-meta-info" title="Exposure level 0–100. Higher = more version or stack details visible to the public (e.g. attackers can target known CVEs)." data-tooltip="Exposure level 0–100. Higher = more version or stack details visible to the public (e.g. attackers can target known CVEs)."><Info size={14} strokeWidth={2} /></span>
              </span>
              <span className="server-score-value">{r.disclosureScore}/100</span>
            </div>
          )}
          {r.stack && (
            <div className="server-stack-one">
              <span className="server-meta-label">
                Stack
                <span className="server-meta-info" title="Technology stack inferred from response headers (e.g. CDN, web server, runtime, CMS). Helps attackers know what software is in use." data-tooltip="Technology stack inferred from response headers (e.g. CDN, web server, runtime, CMS). Helps attackers know what software is in use."><Info size={14} strokeWidth={2} /></span>
              </span>
              <span className="server-stack-text">{r.stack}</span>
            </div>
          )}
        </div>
      </div>
      {(counts.totalHeaders != null || counts.criticalHighCount != null) && (
        <div className="section server-summary-metrics">
          <div className="section-header">📊 Summary Metrics</div>
          <div className="section-content">
            <div className="metrics-grid">
              {counts.totalHeaders != null && <div className="metric-item"><span className="metric-value">{counts.totalHeaders}</span><span className="metric-label">Headers disclosed</span></div>}
              {counts.headersWithVersion != null && <div className="metric-item"><span className="metric-value">{counts.headersWithVersion}</span><span className="metric-label">With version</span></div>}
              {counts.productOnlyCount != null && <div className="metric-item"><span className="metric-value">{counts.productOnlyCount}</span><span className="metric-label">Product only</span></div>}
              {counts.criticalHighCount != null && <div className="metric-item"><span className="metric-value" style={{ color: 'var(--danger)' }}>{counts.criticalHighCount}</span><span className="metric-label">Critical/High</span></div>}
            </div>
          </div>
        </div>
      )}
      {r.error && <div className="section"><div className="section-content" style={{ color: 'var(--danger)' }}>{r.error}</div></div>}
      {r.executiveSummary && (
        <div className="section">
          <div className="section-header">📋 Executive Summary</div>
          <div className="section-content executive-summary">{r.executiveSummary}</div>
        </div>
      )}
      {r.notes && !r.executiveSummary && <div className="section"><div className="section-header">Summary</div><div className="section-content">{r.notes}</div></div>}
      {versions.length > 0 && (
        <div className="section">
          <div className="section-header">⚙️ Versions &amp; Stack Components</div>
          <div className="section-content">
            <table className="server-versions-table">
              <thead><tr><th>Component</th><th>Version</th></tr></thead>
              <tbody>{versions.map(([k, v], i) => <tr key={i}><td><strong>{k}</strong></td><td><code>{String(v)}</code></td></tr>)}</tbody>
            </table>
          </div>
        </div>
      )}
      {affectedComponents.length > 0 && (
        <div className="section">
          <div className="section-header">🔍 Affected Components</div>
          <div className="section-content">
            <table className="server-versions-table">
              <thead><tr><th>Component</th><th>Version</th><th>Role</th></tr></thead>
              <tbody>{affectedComponents.map((c, i) => <tr key={i}><td><strong>{c.component}</strong></td><td><code>{c.version}</code></td><td>{c.role}</td></tr>)}</tbody>
            </table>
          </div>
        </div>
      )}
      <div className="section">
        <div className="section-header">Disclosed Headers</div>
        <div className="section-content">
          <table className="server-disclosures-table">
            <thead><tr><th>Header</th><th>Severity</th><th>Value</th><th>Evidence</th></tr></thead>
            <tbody>{list.length ? list : <tr><td colSpan={4}>None detected</td></tr>}</tbody>
          </table>
        </div>
      </div>
      {htmlDisclosures.length > 0 && (
        <div className="section">
          <div className="section-header">📄 HTML / Body Disclosure</div>
          <div className="section-content">
            <ul className="html-disclosures-list">
              {htmlDisclosures.map((h, i) => (
                <li key={i}>
                  <span className="severity-badge small" style={{ backgroundColor: severityColors[h.severity] || '#6c757d' }}>{h.severity}</span>
                  <strong>{h.type}</strong>: {h.description}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
      {r.cveNote && (
        <div className="section">
          <div className="section-header">⚠️ CVE &amp; Vendor Advisories</div>
          <div className="section-content">
            <p>{r.cveNote}</p>
            <p><a href="https://cve.mitre.org/" target="_blank" rel="noopener noreferrer">CVE MITRE</a> · <a href="https://nvd.nist.gov/" target="_blank" rel="noopener noreferrer">NVD NIST</a></p>
          </div>
        </div>
      )}
      {(r.attackScenario || r.businessImpact || r.likelihood) && (
        <div className="section">
          <div className="section-header">🎯 Attack Scenario &amp; Impact</div>
          <div className="section-content">
            {r.attackScenario && <p><strong>Scenario:</strong> {r.attackScenario}</p>}
            {r.businessImpact && <p><strong>Business impact:</strong> {r.businessImpact}</p>}
            {r.likelihood && <p><strong>Likelihood:</strong> {r.likelihood}</p>}
          </div>
        </div>
      )}
      {complianceMapping.length > 0 && (
        <div className="section">
          <div className="section-header">📋 Compliance Mapping</div>
          <div className="section-content">
            <table className="server-versions-table compliance-table">
              <thead><tr><th>Framework</th><th>Control ID</th><th>Requirement</th></tr></thead>
              <tbody>{complianceMapping.map((row, i) => <tr key={i}><td>{row.framework}</td><td><code>{row.controlId}</code></td><td>{row.requirement}</td></tr>)}</tbody>
            </table>
          </div>
        </div>
      )}
      {recs.length > 0 && (
        <div className="section">
          <div className="section-header">🛠️ Recommendations</div>
          <div className="section-content"><ul className="server-recs-list">{recs.map((rec, i) => <li key={i}>{rec}</li>)}</ul></div>
        </div>
      )}
      {recs.length === 0 && r.recommendation && <div className="section"><div className="section-header">Recommendation</div><div className="section-content">{r.recommendation}</div></div>}
      {(r.verificationStep || r.expectedState) && (
        <div className="section">
          <div className="section-header">✅ Remediation &amp; Verification</div>
          <div className="section-content">
            {r.verificationStep && <p><strong>Verification step:</strong> {r.verificationStep}</p>}
            {r.expectedState && <p><strong>Expected state:</strong> {r.expectedState}</p>}
          </div>
        </div>
      )}
      {Object.keys(configExamples).length > 0 && (
        <div className="section">
          <div className="section-header">💻 Configuration Examples</div>
          <div className="section-content config-examples">
            {Object.entries(configExamples).map(([name, code]) => (
              <div key={name} className="config-example-block">
                <div className="config-example-title">{name}</div>
                <pre className="config-example-code"><code>{String(code).trim()}</code></pre>
              </div>
            ))}
          </div>
        </div>
      )}
      {r.references && r.references.length > 0 && (
        <div className="section">
          <div className="section-header">📚 References</div>
          <div className="section-content"><ul>{r.references.map((ref, i) => <li key={i}>{ref}</li>)}</ul></div>
        </div>
      )}
      <div className="server-report-footer">Generated by API Secure</div>
    </div>
  );
}

const SSL_LABS_LOGO = 'https://www.ssllabs.com/images/logo_ssl_labs.gif';
const SSL_LABS_HOME = 'https://www.ssllabs.com/';

function SslReport({ r }) {
  const host = r.host || 'Unknown';
  const grade = r.grade || r.localGrade || r.endpointGrade || 'N/A';
  const gradeKey = grade.replace(/\s*\(local\)\s*/i, '').trim();
  const gradeColors = { A: '#28a745', 'A+': '#28a745', B: '#17a2b8', C: '#ffc107', D: '#fd7e14', F: '#dc3545', '?': '#6c757d' };
  const status = r.localStatus || (r.localProtocol ? `Protocol: ${r.localProtocol}` : null);
  const reportTitle = r.reportTitle || `SSL Report: ${host}${r.ipAddress ? ` (${r.ipAddress})` : ''}`;
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
  const hasFullReport = Array.isArray(r.certificates) && r.certificates.length > 0;
  return (
    <div className="report-inner ssl-report">
      <div className="ssl-report-header">
        <a href={r.sslLabsUrl || SSL_LABS_HOME} target="_blank" rel="noopener noreferrer" className="ssl-labs-logo-link" title="Qualys SSL Labs">
          <img src={SSL_LABS_LOGO} alt="Qualys SSL Labs" className="ssl-labs-logo" />
        </a>
        <div className="ssl-report-title">{reportTitle}</div>
      </div>
      <div className="site-info">
        <div className="site-url">{host}{r.ipAddress ? ` (${r.ipAddress})` : ''}</div>
        <div className="scan-time ssl-grade-row">
          {hasFullReport && (
            <span className="ssl-grade-badge" style={{ backgroundColor: gradeColors[gradeKey] || '#6c757d' }}>{gradeKey}</span>
          )}
          Grade: <span style={{ color: gradeColors[gradeKey] || '#6c757d' }}>{grade}</span>
          {status ? ` · ${status}` : ''}
          {r.localProtocol && !status ? ` · ${r.localProtocol}` : ''}
        </div>
      </div>
      {(r.localProtocol || r.localCipher) && !hasFullReport && (
        <div className="section">
          <div className="section-header">Server / TLS (local check)</div>
          <div className="section-content">
            <table className="ssl-report-table">
              <tbody>
                {r.localProtocol && <tr><td><strong>Negotiated protocol</strong></td><td><code>{r.localProtocol}</code></td></tr>}
                {r.localCipher && <tr><td><strong>Cipher</strong></td><td><code>{r.localCipher}</code></td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}
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
      <div className="section"><div className="section-header">Summary</div><div className="section-content">{r.summary || ''}</div></div>
      <div className="section"><div className="section-header">Recommendation</div><div className="section-content">{r.recommendation || ''}</div></div>
      {r.sslLabsUrl && (
        <div className="section">
          <div className="section-header">Full SSL Labs report</div>
          <div className="section-content">
            <a href={r.sslLabsUrl} target="_blank" rel="noopener noreferrer" className="ssl-labs-report-link">
              Open SSL Server Test for {host} →
            </a>
            {!hasFullReport && <p className="ssl-report-note">Certificate details, cipher suites, chain, and grading are available in the full Qualys SSL Labs report. Use cached report (run scan again after a recent SSL Labs test) for inline details.</p>}
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
        <div className="scan-time">{r.scannedAt ? new Date(r.scannedAt).toLocaleString() : ''}</div>
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
      <div className="site-info"><div className="site-url">{d}</div></div>
      {r.error && <div className="section"><div className="section-content" style={{ color: 'var(--danger)' }}>{r.error}</div></div>}
      <div className="section">
        <div className="section-header">Tampering tests</div>
        <div className="section-content">
          <table>
            <thead><tr><th>Test</th><th>Tampered URL</th><th>Status</th><th>Body length</th><th>Note</th></tr></thead>
            <tbody>{tests.length ? tests : <tr><td colSpan={5}>No tests run</td></tr>}</tbody>
          </table>
        </div>
      </div>
      <div className="section"><div className="section-header">Recommendation</div><div className="section-content">{r.recommendation || ''}</div></div>
    </div>
  );
}

export default function App() {
  const { theme, toggleTheme } = useTheme();
  const [inputMode] = useState('manual');
  const [listSource] = useState(null);
  const [manualUrl, setManualUrl] = useState('');
  const [linkUrls, setLinkUrls] = useState(['']);
  const [recipients, setRecipients] = useState(['']);
  const [selectedMethods, setSelectedMethods] = useState([]);
  const [corsMode, setCorsMode] = useState('');
  const [originUrl, setOriginUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  const [selectedBatchIndex, setSelectedBatchIndex] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [fileParseCount, setFileParseCount] = useState(null);
  const fileInputRef = useRef(null);

  const toggleMethod = (value) => {
    setSelectedMethods((prev) => (prev.includes(value) ? prev.filter((m) => m !== value) : [...prev, value]));
  };

  const addLinkUrl = () => setLinkUrls((prev) => [...prev, '']);
  const setLinkUrlAt = (i, v) => setLinkUrls((prev) => prev.map((u, j) => (j === i ? v : u)));
  const removeLinkUrl = (i) => setLinkUrls((prev) => prev.filter((_, j) => j !== i));

  const addRecipient = () => setRecipients((prev) => [...prev, '']);
  const setRecipientAt = (i, v) => setRecipients((prev) => prev.map((r, j) => (j === i ? v : r)));
  const removeRecipient = (i) => setRecipients((prev) => prev.filter((_, j) => j !== i));

  const handleFileUpload = async (e) => {
    const file = e.target?.files?.[0];
    if (!file) return;
    setError('');
    setFileParseCount(null);
    setUploading(true);
    try {
      const form = new FormData();
      form.append('file', file);
      const res = await fetch('/api/parse-urls', { method: 'POST', body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      const urls = data.urls || [];
      if (urls.length) {
        setLinkUrls(urls);
        setListSource('link');
        setFileParseCount(urls.length);
      } else {
        setError('No URLs found in file. Use a column named url/link/uri or put URLs in the first column.');
        setFileParseCount(0);
      }
    } catch (err) {
      setError(err.message || 'Upload failed');
      setFileParseCount(null);
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
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

    const corsAnalysisType = selectedMethods.includes('cors') && corsMode ? (corsMode === 'active' ? 'Active CORS Test' : 'Passive CORS Test') : '';
    setLoading(true);
    try {
      const body = {
        url: url || undefined,
        batchUrls: batchUrls.length ? batchUrls : undefined,
        analysisTypes: Array.isArray(selectedMethods) ? selectedMethods : [selectedMethods].filter(Boolean),
        origin: corsMode === 'active' ? originUrl.trim() || undefined : undefined,
        corsAnalysisType: corsAnalysisType || undefined,
        recipientEmails: recipients.filter((r) => r.trim()).length ? recipients.filter((r) => r.trim()).join(', ') : undefined,
      };
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || res.statusText || `Request failed (${res.status})`);
      setResult(data);
      setActiveTab(0);
      setSelectedBatchIndex(0);
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
    }
  };

  const batchResults = result?.batch ? (result.results || []) : [];
  const safeBatchIndex = batchResults.length ? Math.min(selectedBatchIndex, batchResults.length - 1) : 0;
  const currentResult = result?.batch ? batchResults[safeBatchIndex] : result;
  const tabs = [];
  if (currentResult?.headersReport != null) tabs.push({ name: 'Security headers', content: <HeadersReport r={currentResult.headersReport} /> });
  if (currentResult?.corsReport != null) tabs.push({ name: 'CORS', content: <CorsReport r={currentResult.corsReport} /> });
  if (currentResult?.serverReport != null) tabs.push({ name: 'Server disclosure', content: <ServerReport r={currentResult.serverReport} /> });
  if (currentResult?.sslReport != null) tabs.push({ name: 'SSL/TLS', content: <SslReport r={currentResult.sslReport} /> });
  else if (currentResult && selectedMethods.some((m) => /ssl|tls/i.test(m))) tabs.push({ name: 'SSL/TLS', content: <div className="report-inner"><div className="section"><div className="section-content" style={{ color: 'var(--danger)' }}>SSL/TLS report was not returned. Ensure the backend is running and try again.</div></div></div> });
  if (currentResult?.errorHandlingReport != null) tabs.push({ name: 'Error handling', content: <ErrorHandlingReport r={currentResult.errorHandlingReport} /> });
  if (currentResult?.urlTamperingReport != null) tabs.push({ name: 'URL tampering', content: <UrlTamperingReport r={currentResult.urlTamperingReport} /> });

  return (
    <div className="app">
      {loading && (
        <div className="loading-overlay" aria-live="polite" aria-busy="true">
          <div className="loading-card">
            <div className="loading-spinner" aria-hidden />
            <p className="loading-title">Scanning…</p>
            <p className="loading-hint">This may take 15–60 seconds. Please wait.</p>
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
          <button type="button" className="header-btn" title="Settings" aria-label="Settings">⚙️</button>
          <button type="button" className="header-btn" title="Help" aria-label="Help">❓</button>
        </div>
      </header>

      <div className="main-grid">
        <div className="main-col">
          <div className="form-card">
            <form onSubmit={handleSubmit}>
              <div className="section-label">Step 1 — API URL</div>
              <input type="url" className="manual-url" value={manualUrl} onChange={(e) => setManualUrl(e.target.value)} placeholder="https://api.example.com" />
              <p className="form-prompt">Enter the API or website URL to scan. Use <code>https://</code> or <code>http://</code>.</p>

              <div className="section-label" style={{ marginTop: '1.25rem' }}>Step 2 — Testing Methods</div>
              <div className="methods-list">
                {TESTING_METHODS.map((m) => (
                  <div key={m.id} className="method-item" onClick={() => toggleMethod(m.value)}>
                    <input type="checkbox" id={m.id} checked={selectedMethods.includes(m.value)} onChange={() => {}} />
                    <label htmlFor={m.id}>{m.label}</label>
                  </div>
                ))}
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
          <div className="sidebar-card">
            <h3><span className="icon">✉️</span> Report Recipients</h3>
            <p style={{ fontSize: '0.8rem', marginBottom: '0.75rem', color: 'var(--text-muted)' }}>Email addresses to receive security reports.</p>
            <div className="recipients">
              {recipients.map((r, i) => (
                <div key={i} className="recipient-row">
                  <input type="email" value={r} onChange={(e) => setRecipientAt(i, e.target.value)} placeholder={`Recipient ${i + 1}`} />
                  <button type="button" className="btn-sm" onClick={() => removeRecipient(i)}>Remove</button>
                </div>
              ))}
            </div>
            <button type="button" className="add-link" onClick={addRecipient}>+ Add Another Recipient</button>
          </div>
          <div className="sidebar-card">
            <h3><span className="icon">📥</span> Export to File</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Export results when a scan is complete.</p>
            <select style={{ marginTop: '0.5rem', padding: '0.5rem 0.75rem', width: '100%', fontSize: '0.85rem' }} disabled>
              <option>PDF</option>
              <option>JSON</option>
            </select>
            <button type="button" className="btn-sm" style={{ marginTop: '0.5rem', width: '100%' }} disabled>Download</button>
          </div>
          <div className="sidebar-card">
            <h3><span className="icon">🕐</span> Recent</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Recent scan history will appear here.</p>
          </div>
        </aside>
      </div>
    </div>
  );
}
