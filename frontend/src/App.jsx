import { useCallback, useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  Activity, ArrowDown, ArrowRight, Check, ChevronDown, ChevronRight, Database,
  ExternalLink, Globe, Info, Lightbulb, LockKeyhole, ScanSearch, Shield,
  ShieldAlert, ShieldCheck, Terminal, TriangleAlert, Zap,
} from 'lucide-react'
import HeroScene from './components/HeroScene.jsx'
import { API_CONFIGURED, API_NOT_CONFIGURED_MESSAGE } from './api.js'
import { analyzeUrl, getHealth, getModelInfo, predictUrl } from './agentClient.js'

const FEATURE_GROUPS = {
  'URL Structure': ['URLLength', 'path_length', 'query_length', 'fragment_length', 'NoOfSubDomain'],
  Domain: ['DomainLength', 'TLDLength', 'TLD', 'IsDomainIP', 'has_punycode', 'has_url_shortener'],
  Security: ['IsHTTPS', 'has_port'],
  Obfuscation: ['HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio', 'num_encoded_chars'],
  Characters: ['NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes', 'num_at', 'num_hashes', 'num_percent', 'num_colons', 'num_semicolons'],
  Statistics: ['url_entropy', 'max_repeat_ratio', 'num_suspicious_keywords'],
}

const FEATURE_LABELS = {
  URLLength: 'URL length', DomainLength: 'Domain length', TLDLength: 'TLD length', TLD: 'Top-level domain',
  NoOfSubDomain: 'Subdomains', HasObfuscation: 'Obfuscation present', NoOfObfuscatedChar: 'Obfuscation characters',
  ObfuscationRatio: 'Obfuscation ratio', NoOfLettersInURL: 'Letters', LetterRatioInURL: 'Letter ratio',
  NoOfDegitsInURL: 'Digits', DegitRatioInURL: 'Digit ratio', NoOfEqualsInURL: 'Equals signs',
  NoOfQMarkInURL: 'Question marks', NoOfAmpersandInURL: 'Ampersands',
  NoOfOtherSpecialCharsInURL: 'Other special characters', SpacialCharRatioInURL: 'Special character ratio',
  num_dots: 'Dots', num_hyphens: 'Hyphens', num_underscores: 'Underscores', num_slashes: 'Slashes',
  num_at: 'At signs', num_hashes: 'Hashes', num_percent: 'Percent signs', num_colons: 'Colons',
  num_semicolons: 'Semicolons', url_entropy: 'URL entropy', path_length: 'Path length',
  query_length: 'Query length', fragment_length: 'Fragment length', has_port: 'Custom port',
  has_punycode: 'Punycode', has_url_shortener: 'Known shortener pattern', num_encoded_chars: 'Encoded characters',
  max_repeat_ratio: 'Max repeated character ratio', num_suspicious_keywords: 'Suspicious URL keywords',
}

const STEPS = [
  ['01', 'Enter URL', 'The user pastes a link. Nothing is opened.'],
  ['02', 'Validate', 'Scheme, length and syntax are checked before any scoring.'],
  ['03', 'Agent', 'A deterministic agent orchestrates the local model. No external AI service is used.'],
  ['04', 'Model', '38 URL-derived features are scored by the trained classifier.'],
  ['05', 'Explain', 'Measured signals are turned into a plain-language assessment.'],
  ['06', 'Advise', 'Actionable, safety-first guidance is returned to the user.'],
]

const RISK_TONE = { high: 'ag-chip-risk', elevated: 'ag-chip-risk', moderate: 'ag-chip-warn', low: 'ag-chip-safe', 'low-to-moderate': 'ag-chip-warn', uncertain: 'ag-chip-warn' }

function useApiStatus() {
  const [info, setInfo] = useState(null)
  const [state, setState] = useState(API_CONFIGURED ? 'checking' : 'offline')
  useEffect(() => {
    if (!API_CONFIGURED) { setState('offline'); return undefined }
    let live = true
    const refresh = async () => {
      try {
        const health = await getHealth()
        const data = await getModelInfo()
        if (health.status !== 'healthy') throw new Error('API unavailable')
        if (live) { setInfo(data); setState('online') }
      } catch {
        if (live) setState('offline')
      }
    }
    refresh()
    const timer = setInterval(refresh, 15000)
    return () => { live = false; clearInterval(timer) }
  }, [])
  return [info, state]
}

function App() {
  const reduced = useReducedMotion()
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showFeatures, setShowFeatures] = useState(false)
  const [features, setFeatures] = useState(null)
  const [info, apiState] = useApiStatus()

  const onSubmit = useCallback(async (event) => {
    event.preventDefault()
    setError(''); setResult(null); setFeatures(null); setShowFeatures(false)
    if (!API_CONFIGURED) { setError(API_NOT_CONFIGURED_MESSAGE); return }
    if (!url.trim()) { setError('Enter a URL to analyze.'); return }
    setLoading(true)
    try {
      const assessment = await analyzeUrl(url)
      setResult(assessment)
      try {
        const raw = await predictUrl(url)
        setFeatures(raw.features)
      } catch { setFeatures(null) }
    } catch (err) {
      setError(err.message.includes('Failed to fetch')
        ? 'Cannot reach the configured PhishGuard API. Check that it is running and try again.'
        : err.message)
    } finally { setLoading(false) }
  }, [url])

  const number = (value) => (typeof value === 'number'
    ? (Number.isInteger(value) ? value.toLocaleString() : value.toFixed(3))
    : String(value))

  const isRisk = result?.label === 0

  return (
    <main>
      <header className="topbar">
        <a className="brand" href="#top">
          <span className="brand-mark"><Shield size={19} /></span>
          <span>PHISH<span className="brand-accent">GUARD</span> <span className="muted">AI</span></span>
        </a>
        <nav>
          <a href="#analyzer">Analyzer</a>
          <a href="#agent">Agent</a>
          <a href="#method">How it works</a>
          <a href="#model">Model</a>
        </nav>
        <div className="api-badge">
          <i className={apiState === 'online' ? 'online' : apiState === 'offline' ? 'offline' : ''} />
          {!API_CONFIGURED ? 'API NOT CONFIGURED' : apiState === 'online' ? 'SYSTEM ONLINE' : apiState === 'checking' ? 'CONNECTING' : 'API OFFLINE'}
        </div>
      </header>

      <section className="hero wrap" id="top">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-line" /> AI SECURITY AGENT <span className="eyebrow-dot">•</span> URL INTELLIGENCE</div>
          <h1>See the signal.<br /><span>Stop the threat.</span></h1>
          <p className="hero-sub">Phishing URL Detection Research &amp; Demonstration System</p>
          <p className="hero-desc">
            Paste a link. A deterministic AI agent inspects its structure with a locally trained model,
            then explains what it found and what you should do next. The submitted website is never
            visited, fetched or rendered.
          </p>
          <div className="hero-actions">
            <a className="button primary" href="#analyzer">Analyze a URL <ArrowRight size={16} /></a>
            <a className="text-link" href="#agent">Meet the agent <ArrowDown size={15} /></a>
          </div>
          <div className="hero-proof">
            <span><LockKeyhole size={15} /> No website requests</span>
            <span><Zap size={15} /> On-device inference</span>
            <span><Activity size={15} /> Explainable signals</span>
          </div>
        </div>
        <div className="hero-visual">
          <div className="visual-glow" />
          <HeroScene />
          <div className="scene-label"><span className="pulse-dot" /> STATIC URL ANALYSIS <span className="scene-coords">PG—01</span></div>
          <div className="orbit-tag tag-a">URL PARSED <Check size={12} /></div>
          <div className="orbit-tag tag-b"><span /> THREAT SIGNALS</div>
        </div>
        <div className="hero-bottom">
          <span>RESEARCH / DEMONSTRATION BUILD</span>
          <span>01 / 03 <span className="muted">— INTELLIGENCE OVER ASSUMPTION</span></span>
        </div>
      </section>

      <section className="analyzer-section wrap" id="analyzer">
        <div className="section-kicker">01 <span /> URL ANALYZER</div>
        <div className="analyzer-grid">
          <div>
            <h2>Inspect a link.<br /><span>Understand its signals.</span></h2>
            <p className="section-copy">
              Enter any HTTP or HTTPS URL. The agent validates it, scores it with the trained model,
              and returns a plain-language assessment with actionable guidance.
            </p>
            <div className="privacy-note">
              <LockKeyhole size={16} />
              <span>PRIVATE BY DESIGN <small>Your URL is sent as text to the PhishGuard API. It is never opened.</small></span>
            </div>
            <div className="ag-notice" style={{ marginTop: 18 }}>
              <TriangleAlert size={17} />
              <div>
                <h4>RESEARCH / DEMO NOTICE</h4>
                <p>
                  The model is trained on the UCI PhiUSIIL corpus, whose legitimate class contains only
                  HTTPS, <code>www</code>-prefixed, root-path URLs. Legitimate apex, non-<code>www</code> subdomain,
                  HTTP and query-string URLs are absent from the training data, so verdicts on those shapes are
                  unreliable and tend to over-report phishing.
                </p>
                <p>A prediction is a statistical classification, not a guarantee of safety or maliciousness.</p>
              </div>
            </div>
          </div>

          <div className="analyzer-card">
            <div className="card-head">
              <div><ScanSearch size={17} /><span>URL ANALYSIS</span></div>
              <span className="card-ref">PG / ANALYZE</span>
            </div>
            <form onSubmit={onSubmit} noValidate>
              <label htmlFor="url-entry">Enter a URL to analyze</label>
              <div className={`input-wrap ${error ? 'input-error' : ''}`}>
                <Globe size={18} />
                <input
                  id="url-entry"
                  value={url}
                  onChange={(event) => { setUrl(event.target.value); setResult(null); setError('') }}
                  placeholder="https://example.com/login"
                  maxLength={2048}
                  autoComplete="url"
                  spellCheck={false}
                />
                <span className="input-suffix">HTTPS · HTTP</span>
              </div>
              <button className="button primary submit" type="submit" disabled={loading || !API_CONFIGURED}>
                {!API_CONFIGURED ? 'API not connected' : loading
                  ? <><span className="spinner" /> Agent analyzing…</>
                  : result ? 'Analysis complete' : <>Analyze URL <ArrowRight size={16} /></>}
              </button>
              {error && <div className="error-message" role="alert"><TriangleAlert size={16} />{error}</div>}
              <p className="form-foot"><LockKeyhole size={13} /> Submitted URL is parsed as text. No network request is made to it.</p>
            </form>
          </div>
        </div>

        {!API_CONFIGURED && <div className="offline-note" role="status">{API_NOT_CONFIGURED_MESSAGE}</div>}

        {result && (
          <motion.div
            initial={reduced ? false : { opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className={`result-card ${isRisk ? 'risk' : 'safe'}`}
            role="region"
            aria-live="polite"
            aria-label="PhishGuard agent assessment"
          >
            <div className="result-top">
              <div className="result-icon">{isRisk ? <ShieldAlert /> : <ShieldCheck />}</div>
              <div className="result-title">
                <div className="section-kicker">AGENT ASSESSMENT <span className="result-time">{new Date().toLocaleString()}</span></div>
                <h3>{isRisk ? 'POTENTIAL PHISHING' : 'LEGITIMATE'}</h3>
                <p>Model class: {result.prediction}</p>
              </div>
              <div className="confidence">
                <span>MODEL SCORE</span>
                <strong>{(result.confidence * 100).toFixed(1)}<small>%</small></strong>
              </div>
            </div>

            <div className="ag-verdict">
              <div className={`ag-verdict-main ${isRisk ? 'risk-text' : 'safe-text'}`}>{result.risk_level.toUpperCase()} RISK</div>
              <span className={`ag-chip ${RISK_TONE[result.risk_level] || ''}`}>risk band</span>
              <span className="ag-chip">label {result.label}</span>
              <span className="ag-score">normalized <b>{result.normalized_url.replace(/^https?:\/\//, '').slice(0, 46)}</b></span>
            </div>

            <div className="ag-block">
              <h5><Lightbulb size={12} /> WHY</h5>
              <ol className="ag-list ag-list-num">{result.explanation.map((line, index) => <li key={index}>{line}</li>)}</ol>
            </div>

            {result.signals?.length > 0 && (
              <div className="ag-block">
                <h5><Activity size={12} /> URL SIGNALS DETECTED ({result.signals.length})</h5>
                <div className="ag-signal-grid">
                  {result.signals.map((signal) => (
                    <div className="ag-signal" key={signal.code}>
                      <div className="ag-signal-top"><span>{signal.label}</span><b>{number(signal.value)}</b></div>
                      <p>{signal.observation}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.training_distribution_gaps?.length > 0 && (
              <div className="ag-block">
                <h5><Info size={12} /> OUTSIDE THE VERIFIED TRAINING SHAPE</h5>
                <ul className="ag-list ag-list-warn">
                  {result.training_distribution_gaps.map((gap, index) => <li key={index}>{gap}</li>)}
                </ul>
              </div>
            )}

            <div className="ag-block">
              <h5><ShieldCheck size={12} /> RECOMMENDATION</h5>
              <div className="ag-rec"><p>{result.recommendation}</p></div>
              {result.advisories?.length > 0 && (
                <ul className="ag-list" style={{ marginTop: 12 }}>{result.advisories.map((item, index) => <li key={index}>{item}</li>)}</ul>
              )}
            </div>

            <p className="ag-fine">
              <b>Score meaning:</b> {result.confidence_semantics}<br />
              <b>Scope:</b> {result.disclaimer}
            </p>

            {features && (
              <>
                <button className="ag-toggle" type="button" onClick={() => setShowFeatures((value) => !value)} aria-expanded={showFeatures}>
                  <span>{showFeatures ? 'Hide' : 'Show'} the {Object.keys(features).length} extracted URL features</span>
                  <ChevronDown size={14} style={{ transform: showFeatures ? 'rotate(180deg)' : 'none' }} />
                </button>
                {showFeatures && (
                  <div className="feature-breakdown">
                    <div className="breakdown-head"><h4>Extracted URL features</h4><span>{Object.keys(features).length} SIGNALS</span></div>
                    <div className="feature-groups">
                      {Object.entries(FEATURE_GROUPS).map(([group, keys]) => (
                        <div className="feature-group" key={group}>
                          <h5>{group}</h5>
                          <div className="feature-list">
                            {keys.map((key) => (
                              <div className="feature-row" key={key}>
                                <span>{FEATURE_LABELS[key] || key}</span>
                                <b>{number(features[key])}</b>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </motion.div>
        )}
      </section>

      <section className="workflow-section" id="agent">
        <div className="wrap">
          <div className="section-kicker">02 <span /> THE PHISHGUARD AGENT</div>
          <div className="section-heading">
            <h2>A local agent that<br /><span>explains its reasoning.</span></h2>
            <p>No external LLM, no API key, no cloud AI. Deterministic rules over measured features.</p>
          </div>
          <div className="ag-flow">
            <span>URL</span><i>→</i><span>Validate</span><i>→</i><span>Model</span><i>→</i><span>Explain</span><i>→</i><span>Advise</span>
          </div>
          <p className="ag-fine">
            The agent runs entirely inside the PhishGuard API process. It reads only the URL string and the
            locally trained model, so an explanation can always be traced back to a measured feature.
          </p>
        </div>
      </section>

      <section className="workflow-section" id="method">
        <div className="wrap">
          <div className="section-kicker">03 <span /> UNDER THE HOOD</div>
          <div className="section-heading">
            <h2>One transparent pipeline<br /><span>from URL to verdict.</span></h2>
            <p>Each stage operates on the URL string and its derived features.</p>
          </div>
          <div className="steps">
            {STEPS.map(([number_, title, description], index) => (
              <motion.div
                className="step"
                key={number_}
                initial={reduced ? false : { opacity: 0, y: 12 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: reduced ? 0 : index * 0.06 }}
              >
                <div className="step-top"><span>{number_}</span><ChevronRight size={15} /></div>
                <div className="step-icon">
                  {[<Terminal />, <Globe />, <ScanSearch />, <Activity />, <Zap />, <ShieldCheck />][index]}
                </div>
                <h3>{title}</h3>
                <p>{description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      <section className="model-section wrap" id="model">
        <div className="section-kicker">04 <span /> MODEL SNAPSHOT</div>
        <div className="section-heading">
          <h2>Measured on<br /><span>held-out data.</span></h2>
          <p>Live metadata from the trained model. Performance figures describe a test set and are not a safety guarantee.</p>
        </div>
        {info ? (
          <>
            <div className="metrics-row">
              <Metric label="ACCURACY" value={info.accuracy} />
              <Metric label="PRECISION" value={info.precision} />
              <Metric label="RECALL" value={info.recall} />
              <Metric label="F1 SCORE" value={info.f1} />
            </div>
            <div className="model-details">
              <div className="detail-card">
                <div className="detail-icon"><Database /></div>
                <div>
                  <span>TRAINING DATASET</span>
                  <strong>{info.dataset}</strong>
                  <small>{info.records.toLocaleString()} cleaned records · {info.features} URL features</small>
                </div>
              </div>
              <div className="detail-card">
                <div className="detail-icon"><Shield /></div>
                <div>
                  <span>SELECTED CLASSIFIER</span>
                  <strong>{info.model}</strong>
                  <small>{info.false_positives.toLocaleString()} false positives · {info.false_negatives.toLocaleString()} false negatives</small>
                </div>
              </div>
            </div>
            <div className="domain-note">
              <Activity size={16} />
              <span>
                DOMAIN-AWARE HOLDOUT <b>{(info.domain_aware.accuracy * 100).toFixed(1)}% accuracy</b>
                <small>{info.domain_aware.test_rows.toLocaleString()} held-out URLs from domains absent in training. Registrable-domain overlap: {info.domain_aware.domain_overlap}.</small>
              </span>
            </div>
            <p className="ag-fine">
              These figures come from a random stratified split of the training corpus. They do not measure
              performance on legitimate apex, non-<code>www</code> subdomain, HTTP or query-string URLs, which the
              training data does not contain.
            </p>
          </>
        ) : (
          <div className="offline-note">
            {!API_CONFIGURED ? API_NOT_CONFIGURED_MESSAGE : apiState === 'offline' ? 'Configured PhishGuard API is unavailable.' : 'Loading live model information…'}
          </div>
        )}
      </section>

      <section className="limits-section">
        <div className="wrap limits-inner">
          <div className="limits-icon"><LockKeyhole /></div>
          <div>
            <div className="section-kicker">BUILT WITH CLEAR LIMITS</div>
            <h2>Signals, not certainty.</h2>
            <p>
              PhishGuard analyzes URL-derived features only. It never visits, fetches or renders the submitted
              website, so it cannot see page content, redirects or the party behind a domain. HTTPS and common
              domain extensions are model signals, not guarantees of legitimacy. This is a research and
              demonstration system built on a single public dataset with a documented coverage gap.
            </p>
          </div>
        </div>
      </section>

      <footer className="footer wrap">
        <a className="brand" href="#top"><span className="brand-mark"><Shield size={17} /></span><span>PHISH<span className="brand-accent">GUARD</span> AI</span></a>
        <span>PHISHING URL DETECTION · RESEARCH / DEMONSTRATION SYSTEM</span>
        <a href="#top" className="back-top">BACK TO TOP ↑</a>
      </footer>
    </main>
  )
}

function Metric({ label, value }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{(value * 100).toFixed(1)}<small>%</small></strong>
      <div className="metric-track"><i style={{ width: `${Math.min(100, value * 100)}%` }} /></div>
    </div>
  )
}

export default App
