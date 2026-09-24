import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Unlock,
  ArrowRight,
  Download,
  Copy,
  History,
  Code2,
  FileJson,
  ExternalLink,
  RefreshCw,
  Search,
  Server,
  Info,
  ChevronDown,
  ChevronUp,
  Sliders,
  Check,
  Terminal,
  Cookie
} from 'lucide-react';

interface RedirectHop {
  step: number;
  url: string;
  status_code: number;
  location?: string | null;
}

interface HeaderFinding {
  header: string;
  status: 'PASS' | 'WARN' | 'INFO';
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH';
  value: string | null;
  message: string;
  recommendation: string;
  score_contribution: number;
  max_score_contribution: number;
}

interface CookieFinding {
  name: string;
  secure: boolean;
  httponly: boolean;
  samesite: string;
  path: string;
  domain?: string | null;
  expires_or_max_age?: string | null;
  status: 'PASS' | 'WARN' | 'INFO';
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH';
  notes: string[];
}

interface ScoringRule {
  header: string;
  allocated_points: number;
  description: string;
}

interface ScanResponse {
  id: string;
  target: string;
  final_url: string;
  timestamp: string;
  status_code: number;
  is_https: boolean;
  score: number;
  max_score: number;
  score_percentage: number;
  redirect_count: number;
  redirect_chain: RedirectHop[];
  findings: HeaderFinding[];
  cookies: CookieFinding[];
  raw_headers: Record<string, string>;
  scoring_methodology: ScoringRule[];
  disclaimer: string;
}

interface ScanHistoryItem {
  id: string;
  original_url: string;
  final_url: string;
  timestamp: string;
  status_code: number;
  score: number;
  max_score: number;
  is_https: boolean;
}

export default function App() {
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'ALL' | 'PASS' | 'WARN'>('ALL');
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [activeSnippetTab, setActiveSnippetTab] = useState<'nginx' | 'apache' | 'caddy' | 'cloudflare' | 'express'>('nginx');
  const [copied, setCopied] = useState<string | null>(null);

  const sampleUrls = [
    { label: 'GitHub', url: 'https://github.com' },
    { label: 'Cloudflare', url: 'https://cloudflare.com' },
    { label: 'Google', url: 'https://google.com' },
    { label: 'HTTPBin (Demo)', url: 'http://httpbin.org' },
  ];

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/scans');
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (err) {
      console.error('Failed to load scan history:', err);
    }
  };

  const handleScan = async (urlToScan?: string) => {
    const rawUrl = urlToScan || targetUrl;
    if (!rawUrl.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawUrl.trim() }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Scan failed. Please check the destination URL.');
      }

      setScanResult(data);
      if (urlToScan) setTargetUrl(urlToScan);
      fetchHistory();
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred.');
    } finally {
      setLoading(false);
    }
  };

  const loadPastScan = async (id: string) => {
    try {
      setLoading(true);
      const res = await fetch(`/api/scans/${id}`);
      if (!res.ok) throw new Error('Could not load record.');
      const data = await res.json();
      setScanResult(data);
      setTargetUrl(data.target);
      setShowHistoryModal(false);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve scan history.');
    } finally {
      setLoading(false);
    }
  };

  const exportJSON = () => {
    if (!scanResult) return;
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_scan_${scanResult.id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const filteredFindings = scanResult?.findings.filter((item) => {
    if (filter === 'PASS') return item.status === 'PASS';
    if (filter === 'WARN') return item.status === 'WARN';
    return true;
  });

  const getScoreColor = (percentage: number) => {
    if (percentage >= 80) return 'text-emerald-400 border-emerald-500/50 bg-emerald-950/30';
    if (percentage >= 50) return 'text-amber-400 border-amber-500/50 bg-amber-950/30';
    return 'text-rose-400 border-rose-500/50 bg-rose-950/30';
  };

  const generateHardeningSnippet = (tab: string) => {
    switch (tab) {
      case 'nginx':
        return `# Nginx Security Headers Configuration
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self';" always;`;

      case 'apache':
        return `# Apache .htaccess / httpd.conf
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
</IfModule>`;

      case 'caddy':
        return `# Caddyfile
example.com {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
    }
}`;

      case 'cloudflare':
        return `// Cloudflare Workers / Transform Rules
export default {
  async fetch(request, env, ctx) {
    const response = await fetch(request);
    const newHeaders = new Headers(response.headers);
    newHeaders.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    newHeaders.set("X-Content-Type-Options", "nosniff");
    newHeaders.set("X-Frame-Options", "SAMEORIGIN");
    newHeaders.set("Referrer-Policy", "strict-origin-when-cross-origin");
    newHeaders.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    newHeaders.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';");
    return new Response(response.body, { ...response, headers: newHeaders });
  }
};`;

      case 'express':
        return `// Node.js Express (or use helmet package)
const helmet = require('helmet');
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"]
    }
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));`;

      default:
        return '';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Glow background effects */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-600/10 rounded-full blur-3xl" />
        <div className="absolute top-1/3 right-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl" />
      </div>

      <div className="relative z-10 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Top Navbar */}
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-600/30 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center shadow-lg shadow-cyan-950/50">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                  HTTP SECURITY HEADER SCANNER
                </h1>
                <span className="px-2 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wider rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  SOC Defensive v1.0
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Defensive HTTP response headers, cookie flags & redirect chain audit tool
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={() => setShowHistoryModal(true)}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-700/80 hover:border-cyan-500/50 text-xs font-medium text-slate-200 hover:text-white transition shadow-sm"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              History ({history.length})
            </button>
            <a
              href="/README.md"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700/80 hover:border-slate-600 text-xs font-medium text-slate-300 hover:text-white transition"
            >
              <Info className="w-3.5 h-3.5 text-slate-400" />
              Docs
            </a>
          </div>
        </header>

        {/* URL Input Hero Section */}
        <section className="mt-8 bg-slate-900/90 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500" />

          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleScan();
            }}
            className="flex flex-col sm:flex-row gap-3"
          >
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <Search className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="Enter target domain or URL (e.g. https://example.com or github.com)"
                className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-700/80 rounded-xl text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-sm font-semibold text-white shadow-lg shadow-cyan-950 transition cursor-pointer"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Analyzing Target...
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  Run Security Scan
                </>
              )}
            </button>
          </form>

          {/* Quick preset targets */}
          <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span className="text-slate-500 font-mono text-[11px]">Quick Tests:</span>
            {sampleUrls.map((sample) => (
              <button
                key={sample.url}
                onClick={() => {
                  setTargetUrl(sample.url);
                  handleScan(sample.url);
                }}
                className="px-2.5 py-1 rounded-md bg-slate-950 border border-slate-800 hover:border-cyan-500/50 text-slate-300 hover:text-cyan-300 font-mono transition"
              >
                {sample.label}
              </button>
            ))}
          </div>

          {/* Error Alert */}
          {error && (
            <div className="mt-4 p-3.5 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-rose-200">Scan Error</p>
                <p className="mt-0.5">{error}</p>
              </div>
            </div>
          )}
        </section>

        {/* Scan Dashboard View */}
        {scanResult && (
          <main className="mt-8 space-y-6">
            {/* Top Target Meta Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              <div className="col-span-2 sm:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Target Endpoint</span>
                <p className="text-sm font-mono text-slate-100 font-semibold truncate mt-0.5" title={scanResult.final_url}>
                  {scanResult.final_url}
                </p>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">HTTP Status</span>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  <p className="text-sm font-mono font-bold text-slate-100">{scanResult.status_code}</p>
                </div>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Transport Security</span>
                <div className="flex items-center gap-1.5 mt-0.5">
                  {scanResult.is_https ? (
                    <>
                      <Lock className="w-3.5 h-3.5 text-emerald-400" />
                      <p className="text-xs font-mono font-semibold text-emerald-400">HTTPS (TLS)</p>
                    </>
                  ) : (
                    <>
                      <Unlock className="w-3.5 h-3.5 text-rose-400" />
                      <p className="text-xs font-mono font-semibold text-rose-400">Insecure HTTP</p>
                    </>
                  )}
                </div>
              </div>

              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Redirect Hops</span>
                <p className="text-sm font-mono font-bold text-slate-100 mt-0.5">{scanResult.redirect_count}</p>
              </div>
            </div>

            {/* Score & Health Card */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row items-center gap-6">
              <div className={`w-32 h-32 rounded-full border-4 flex flex-col items-center justify-center shrink-0 shadow-lg ${getScoreColor(scanResult.score_percentage)}`}>
                <span className="text-2xl font-mono font-black">{scanResult.score} / {scanResult.max_score}</span>
                <span className="text-xs font-mono font-bold">{scanResult.score_percentage}% Score</span>
              </div>

              <div className="flex-1 w-full">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <h2 className="text-lg font-bold text-white">Security Configuration Score</h2>
                    <p className="text-xs text-slate-400 mt-0.5">{scanResult.disclaimer}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={exportJSON}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition"
                    >
                      <Download className="w-3.5 h-3.5 text-cyan-400" />
                      Export JSON
                    </button>
                    <button
                      onClick={() => {
                        const summary = `[Security Header Scan]\nTarget: ${scanResult.target}\nScore: ${scanResult.score}/${scanResult.max_score} (${scanResult.score_percentage}%)\nHTTPS: ${scanResult.is_https ? 'Yes' : 'No'}\nScanned: ${scanResult.timestamp}`;
                        copyToClipboard(summary, 'summary');
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition"
                    >
                      {copied === 'summary' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                      {copied === 'summary' ? 'Copied' : 'Copy Summary'}
                    </button>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-slate-800 mt-4">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-700"
                    style={{ width: `${scanResult.score_percentage}%` }}
                  />
                </div>

                {/* Score breakdown metrics */}
                <div className="mt-3 flex flex-wrap gap-4 text-xs font-mono text-slate-400">
                  <span>✓ Passed: <strong className="text-emerald-400">{scanResult.findings.filter(f => f.status === 'PASS').length}</strong></span>
                  <span>⚠ Warnings: <strong className="text-amber-400">{scanResult.findings.filter(f => f.status === 'WARN').length}</strong></span>
                  <span>🍪 Cookies Checked: <strong className="text-cyan-400">{scanResult.cookies.length}</strong></span>
                </div>
              </div>
            </div>

            {/* Redirect Chain Visualizer */}
            {scanResult.redirect_chain && scanResult.redirect_chain.length > 1 && (
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg">
                <div className="flex items-center gap-2 mb-3">
                  <ArrowRight className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">Redirect Chain Trace</h3>
                </div>
                <div className="space-y-2">
                  {scanResult.redirect_chain.map((hop, idx) => (
                    <div key={idx} className="flex items-center gap-3 text-xs font-mono p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold">Hop {hop.step}</span>
                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/50">{hop.status_code}</span>
                      <span className="text-slate-200 truncate flex-1">{hop.url}</span>
                      {hop.location && (
                        <span className="text-slate-500 text-[11px] hidden sm:inline">➔ {hop.location}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Header Findings Grid */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-lg">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-base font-bold text-white">Security Header Findings</h3>
                </div>

                <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-950 border border-slate-800">
                  {(['ALL', 'PASS', 'WARN'] as const).map((f) => (
                    <button
                      key={f}
                      onClick={() => setFilter(f)}
                      className={`px-3 py-1 rounded-md text-xs font-medium transition ${
                        filter === f
                          ? 'bg-cyan-600 text-white shadow-sm'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {f === 'ALL' ? 'All Findings' : f === 'PASS' ? 'Passed' : 'Warnings'}
                    </button>
                  ))}
                </div>
              </div>

              <div className="mt-4 space-y-3">
                {filteredFindings?.map((finding, idx) => {
                  const isPass = finding.status === 'PASS';
                  return (
                    <div
                      key={idx}
                      className={`p-4 rounded-xl border transition ${
                        isPass
                          ? 'bg-slate-950/60 border-slate-800/80 hover:border-emerald-500/40'
                          : 'bg-amber-950/10 border-amber-900/40 hover:border-amber-500/50'
                      }`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          {isPass ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                          ) : (
                            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                          )}
                          <span className="font-mono text-sm font-bold text-slate-100">
                            {finding.header}
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase ${
                              isPass
                                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/50'
                                : 'bg-amber-950 text-amber-400 border border-amber-800/50'
                            }`}
                          >
                            {finding.status} (+{finding.score_contribution}/{finding.max_score_contribution} pts)
                          </span>
                        </div>
                      </div>

                      {finding.value ? (
                        <div className="mt-2.5 p-2 rounded-lg bg-slate-900 border border-slate-800 text-cyan-300 font-mono text-xs break-all">
                          <code>{finding.value}</code>
                        </div>
                      ) : (
                        <div className="mt-2 p-1.5 text-xs text-rose-400/90 font-mono italic">
                          Header omitted in server response
                        </div>
                      )}

                      <p className="mt-2 text-xs text-slate-300 leading-relaxed">
                        {finding.message}
                      </p>

                      {finding.recommendation && (
                        <div className="mt-2.5 pt-2.5 border-t border-slate-800/80 flex items-start gap-2 text-xs text-slate-400">
                          <span className="text-cyan-400 font-semibold font-mono text-[11px] shrink-0">Advice:</span>
                          <span className="leading-relaxed">{finding.recommendation}</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Cookie Security Inspector */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-lg">
              <div className="flex items-center gap-2 mb-1">
                <Cookie className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-bold text-white">Cookie Security Flags</h3>
              </div>
              <p className="text-xs text-slate-400 mb-4">
                Analysis of collected <code>Set-Cookie</code> directives. (Sensitive cookie values are strictly redacted).
              </p>

              {scanResult.cookies.length === 0 ? (
                <div className="text-center py-6 border border-dashed border-slate-800 rounded-xl text-xs text-slate-500">
                  No <code>Set-Cookie</code> headers were issued on the final response.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                        <th className="pb-2.5 pr-4">Cookie Name</th>
                        <th className="pb-2.5 pr-4">Secure</th>
                        <th className="pb-2.5 pr-4">HttpOnly</th>
                        <th className="pb-2.5 pr-4">SameSite</th>
                        <th className="pb-2.5 pr-4">Scope (Path/Domain)</th>
                        <th className="pb-2.5">Analysis Notes</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {scanResult.cookies.map((c, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30">
                          <td className="py-3 pr-4 font-bold text-slate-200">{c.name}</td>
                          <td className="py-3 pr-4">
                            {c.secure ? (
                              <span className="text-emerald-400 font-bold">✓ True</span>
                            ) : (
                              <span className="text-rose-400 font-bold">✕ False</span>
                            )}
                          </td>
                          <td className="py-3 pr-4">
                            {c.httponly ? (
                              <span className="text-emerald-400 font-bold">✓ True</span>
                            ) : (
                              <span className="text-amber-400 font-bold">✕ False</span>
                            )}
                          </td>
                          <td className="py-3 pr-4">
                            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                              {c.samesite || 'None'}
                            </span>
                          </td>
                          <td className="py-3 pr-4 text-slate-400 text-[11px]">
                            {c.path} {c.domain ? `(${c.domain})` : ''}
                          </td>
                          <td className="py-3 text-slate-300 font-sans text-[11px]">
                            {c.notes.map((n, i) => (
                              <div key={i} className="mb-0.5">• {n}</div>
                            ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Quick Hardening Remediation Snippets */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-lg">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-cyan-400" />
                  <div>
                    <h3 className="text-base font-bold text-white">Recommended Server Configuration</h3>
                    <p className="text-xs text-slate-400">Drop-in configuration snippets to apply recommended security headers</p>
                  </div>
                </div>

                <div className="flex items-center gap-1">
                  {(['nginx', 'apache', 'caddy', 'cloudflare', 'express'] as const).map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setActiveSnippetTab(tab)}
                      className={`px-2.5 py-1 rounded-md text-xs font-mono capitalize transition ${
                        activeSnippetTab === tab
                          ? 'bg-cyan-600 text-white font-bold'
                          : 'text-slate-400 hover:text-slate-200 bg-slate-950'
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </div>
              </div>

              <div className="mt-3 relative">
                <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto">
                  {generateHardeningSnippet(activeSnippetTab)}
                </pre>
                <button
                  onClick={() => copyToClipboard(generateHardeningSnippet(activeSnippetTab), 'snippet')}
                  className="absolute top-3 right-3 p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                  title="Copy Snippet"
                >
                  {copied === 'snippet' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {/* Raw Headers Accordion */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 shadow-lg">
              <button
                onClick={() => setShowRawHeaders(!showRawHeaders)}
                className="w-full flex items-center justify-between text-xs font-mono text-slate-400 hover:text-slate-200"
              >
                <span className="flex items-center gap-2">
                  <FileJson className="w-4 h-4 text-cyan-400" />
                  Sanitized Raw Response Headers ({Object.keys(scanResult.raw_headers).length})
                </span>
                {showRawHeaders ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>

              {showRawHeaders && (
                <pre className="mt-3 p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-300 font-mono text-xs overflow-x-auto">
                  {JSON.stringify(scanResult.raw_headers, null, 2)}
                </pre>
              )}
            </div>
          </main>
        )}

        {/* Scan History Modal */}
        {showHistoryModal && (
          <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl max-h-[80vh] flex flex-col shadow-2xl">
              <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <History className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-base font-bold text-white">Local Scan History (SQLite)</h3>
                </div>
                <button
                  onClick={() => setShowHistoryModal(false)}
                  className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
                >
                  ✕
                </button>
              </div>

              <div className="p-4 overflow-y-auto flex-1 space-y-2">
                {history.length === 0 ? (
                  <p className="text-center py-8 text-xs text-slate-500">No previous scans stored in database.</p>
                ) : (
                  history.map((item) => (
                    <div
                      key={item.id}
                      className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 hover:border-slate-700 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="min-w-0">
                        <p className="font-mono font-bold text-slate-200 truncate">{item.original_url}</p>
                        <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                          {item.timestamp ? new Date(item.timestamp).toLocaleString() : ''} • Status {item.status_code}
                        </p>
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        <span className="font-mono font-bold text-cyan-400">
                          {item.score} / {item.max_score} pts
                        </span>
                        <button
                          onClick={() => loadPastScan(item.id)}
                          className="px-3 py-1.5 rounded-lg bg-cyan-600/20 border border-cyan-500/30 hover:bg-cyan-600/30 text-cyan-300 font-mono transition"
                        >
                          View Result
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* Footer */}
        <footer className="mt-12 pt-6 border-t border-slate-800/80 text-center text-xs text-slate-500">
          <p>HTTP Security Header Scanner — Strictly for authorized domains and self-owned infrastructure.</p>
        </footer>
      </div>
    </div>
  );
}
