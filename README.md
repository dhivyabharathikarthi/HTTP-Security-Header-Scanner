# HTTP Security Header Scanner

A production-quality defensive cybersecurity scanner built with Python 3.11+, FastAPI, and SQLite to analyze, evaluate, and score HTTP security headers, cookie security configurations, and redirect chains.

---

## 1. Project Description

The **HTTP Security Header Scanner** inspects live web server responses for vital security headers and cookie flags. It assists DevOps engineers, security analysts, and web developers in auditing defensive HTTP headers, diagnosing configuration gaps (such as permissive CSP directives, missing HSTS, or unflagged session cookies), and implementing actionable hardening recommendations.

---

## 2. Key Features

- **Safe Target Validation & Normalization**: Automatically normalizes schemes (`http://` vs `https://`) and applies SSRF defense filters to block restricted internal IP ranges and loopbacks.
- **In-Depth Header Analysis**:
  - **Strict-Transport-Security (HSTS)**: Validates `max-age` numeric thresholds (minimum 6 months / 1 year recommended), detects `includeSubDomains`, and checks `preload` eligibility.
  - **Content-Security-Policy (CSP)**: Audits for XSS/injection risks, `'unsafe-inline'`, `'unsafe-eval'`, broad wildcards (`*`), fallback `default-src`, `object-src`, and `frame-ancestors`.
  - **X-Content-Type-Options**: Enforces strict `nosniff` MIME-sniffing protection.
  - **X-Frame-Options**: Detects `DENY` / `SAMEORIGIN` clickjacking defenses and checks modern CSP `frame-ancestors` parity.
  - **Referrer-Policy**: Analyzes policy tokens (`strict-origin-when-cross-origin`, `no-referrer`, `unsafe-url`) and privacy leakage.
  - **Permissions-Policy**: Evaluates browser hardware and API access controls (camera, microphone, geolocation).
- **Cookie Security Inspection**: Parses `Set-Cookie` headers for `Secure`, `HttpOnly`, `SameSite`, `Path`, and `Domain` without ever disclosing sensitive cookie values.
- **Safe Redirect Tracing**: Audits redirect hops (e.g. `http://` ➔ `https://` ➔ `https://www.`), tracks HTTP status codes, and alerts when final destinations lack TLS encryption.
- **Transparent Weighted Scoring**: Displays an 11-point configuration score with detailed itemized point contributions.
- **Local Persistence & JSON Export**: Records historical scans in SQLite with no sensitive credentials or auth headers stored; allows one-click JSON report downloads.
- **Cybersecurity SOC UI & REST API**: Responsive SOC-style interface and clean FastAPI REST endpoints.

---

## 3. Technology Stack & Architecture

```text
http-security-header-scanner/
│
├── app/
│   ├── main.py                  # FastAPI server & route handlers
│   ├── scanner.py               # Core scanning engine & redirect tracer
│   ├── analyzers/               # Modular security analyzers
│   │   ├── __init__.py          # Analyzer orchestrator & scoring rules
│   │   ├── hsts.py              # Strict-Transport-Security analyzer
│   │   ├── csp.py               # Content-Security-Policy analyzer
│   │   ├── content_type.py      # X-Content-Type-Options analyzer
│   │   ├── frame_options.py     # X-Frame-Options analyzer
│   │   ├── referrer_policy.py   # Referrer-Policy analyzer
│   │   ├── permissions_policy.py# Permissions-Policy analyzer
│   │   └── cookies.py           # Set-Cookie attribute analyzer
│   │
│   ├── database.py              # SQLite engine & session management
│   ├── models.py                # SQLAlchemy ORM / SQLite schema models
│   ├── schemas.py               # Pydantic schemas for requests/responses
│   └── utils.py                 # SSRF protection, URL validation & sanitizer
│
├── templates/
│   └── index.html               # SOC Dashboard HTML5 template
│
├── static/
│   ├── style.css                # Modern SOC/Cybersecurity dark theme
│   └── app.js                   # Client-side UI logic & API connector
│
├── tests/
│   ├── test_scanner.py          # Scanner, scoring & DB persistence unit tests
│   └── test_analyzers.py        # Comprehensive header analyzer unit tests
│
├── requirements.txt             # Python dependencies
├── README.md                    # Documentation & setup guide
└── .gitignore                   # Ignored files
```

---

## 4. Installation & Setup

### Prerequisites
- Python 3.10 or Python 3.11+
- Git

### 1. Clone the repository
```bash
git clone https://github.com/example/http-security-header-scanner.git
cd http-security-header-scanner
```

### 2. Create Virtual Environment
```bash
# Linux / macOS
python3 -m venv .venv

# Windows
python -m venv .venv
```

### 3. Activate Virtual Environment
```bash
# Linux / macOS
source .venv/bin/activate

# Windows (Command Prompt)
.venv\Scripts\activate.bat

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 5. Running the Application

Start the development server with Uvicorn:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Access the application in your browser:
- **Dashboard UI**: [http://localhost:8000/](http://localhost:8000/)
- **Interactive Swagger API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc API Documentation**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 6. API Documentation

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the HTML5 SOC dashboard interface. |
| `POST` | `/api/scan` | Initiates an HTTP security header scan on the target URL. |
| `GET` | `/api/scans` | Returns a list of past scans from SQLite. |
| `GET` | `/api/scans/{id}` | Retrieves complete details for a specific scan ID. |
| `GET` | `/api/scans/{id}/json` | Downloads the scan report as a JSON file. |

---

## 7. Example Scan Request & Response

### Request
```bash
curl -X POST "http://localhost:8000/api/scan" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```

### Response
```json
{
  "id": "e4b92b6a-7214-46d5-a33f-91cb61d989f5",
  "target": "https://example.com/",
  "final_url": "https://example.com/",
  "timestamp": "2026-09-24T07:15:00.000000+00:00",
  "status_code": 200,
  "is_https": true,
  "score": 8,
  "max_score": 11,
  "score_percentage": 72.7,
  "redirect_count": 0,
  "redirect_chain": [
    {
      "step": 1,
      "url": "https://example.com/",
      "status_code": 200,
      "location": null
    }
  ],
  "findings": [
    {
      "header": "Strict-Transport-Security",
      "status": "PASS",
      "severity": "INFO",
      "value": "max-age=31536000; includeSubDomains",
      "message": "HSTS is securely configured: max-age=31536000 seconds (~365 days); includeSubDomains enabled.",
      "recommendation": "HSTS configuration is robust and securely enforcing encrypted transport.",
      "score_contribution": 2,
      "max_score_contribution": 2
    },
    {
      "header": "Content-Security-Policy",
      "status": "WARN",
      "severity": "HIGH",
      "value": null,
      "message": "Content-Security-Policy header is missing. The browser will not enforce origin boundaries for scripts, styles, objects, and framing.",
      "recommendation": "Implement a CSP policy starting with 'default-src \\'self\\'; script-src \\'self\\'; object-src \\'none\\'; frame-ancestors \\'self\\''.",
      "score_contribution": 0,
      "max_score_contribution": 3
    },
    {
      "header": "X-Content-Type-Options",
      "status": "PASS",
      "severity": "INFO",
      "value": "nosniff",
      "message": "X-Content-Type-Options is correctly set to 'nosniff', disabling MIME-sniffing.",
      "recommendation": "Maintain 'nosniff' across all static and dynamic HTTP responses.",
      "score_contribution": 2,
      "max_score_contribution": 2
    },
    {
      "header": "X-Frame-Options",
      "status": "PASS",
      "severity": "INFO",
      "value": "SAMEORIGIN",
      "message": "X-Frame-Options is set to 'SAMEORIGIN', mitigating clickjacking attacks.",
      "recommendation": "Ensure your Content-Security-Policy includes matching 'frame-ancestors' directives for modern standards alignment.",
      "score_contribution": 2,
      "max_score_contribution": 2
    },
    {
      "header": "Referrer-Policy",
      "status": "PASS",
      "severity": "INFO",
      "value": "strict-origin-when-cross-origin",
      "message": "Referrer-Policy is set to 'strict-origin-when-cross-origin'. Sends full URL to same-origin; sends only origin over HTTPS cross-origin; sends nothing to insecure HTTP.",
      "recommendation": "Maintain this policy to prevent unwanted parameter or path leakage to third parties.",
      "score_contribution": 1,
      "max_score_contribution": 1
    },
    {
      "header": "Permissions-Policy",
      "status": "PASS",
      "severity": "INFO",
      "value": "geolocation=(), camera=()",
      "message": "Permissions-Policy is configured (geolocation=(), camera=()). Controls execution context access to hardware and browser features.",
      "recommendation": "Periodically verify that newly introduced browser features are appropriately governed.",
      "score_contribution": 1,
      "max_score_contribution": 1
    }
  ],
  "cookies": [
    {
      "name": "session_id",
      "secure": true,
      "httponly": true,
      "samesite": "Lax",
      "path": "/",
      "domain": "example.com",
      "expires_or_max_age": "Max-Age=3600",
      "status": "PASS",
      "severity": "INFO",
      "notes": [
        "Cookie includes Secure, HttpOnly, and explicit SameSite protections."
      ]
    }
  ],
  "raw_headers": {
    "server": "ECS (dcb/7ea2)",
    "content-type": "text/html; charset=UTF-8",
    "cache-control": "max-age=604800",
    "x-content-type-options": "nosniff"
  },
  "scoring_methodology": [
    {
      "header": "Content-Security-Policy",
      "allocated_points": 3,
      "description": "Mitigates Cross-Site Scripting (XSS), data injections, and restricts resource execution boundaries."
    },
    {
      "header": "Strict-Transport-Security",
      "allocated_points": 2,
      "description": "Enforces encrypted HTTPS connections and protects against SSL stripping downgrade attacks."
    },
    {
      "header": "X-Content-Type-Options",
      "allocated_points": 2,
      "description": "Prevents MIME-type sniffing vulnerabilities by forcing browsers to adhere to declared Content-Type."
    },
    {
      "header": "X-Frame-Options",
      "allocated_points": 2,
      "description": "Provides anti-clickjacking protection by controlling whether the site can be rendered within frames or iframes."
    },
    {
      "header": "Referrer-Policy",
      "allocated_points": 1,
      "description": "Controls how much referrer information (paths, parameters, query strings) is leaked to external sites."
    },
    {
      "header": "Permissions-Policy",
      "allocated_points": 1,
      "description": "Restricts browser hardware access (camera, microphone, geolocation) and sensitive feature usage."
    }
  ],
  "disclaimer": "This score is a measurement of the checked HTTP security header configurations and cookie flags, not a definitive evaluation of overall application security or server posture."
}
```

---

## 8. Running Automated Unit Tests

Unit tests are written with Python's built-in `unittest` runner and are also compatible with `pytest`.

Run with `unittest`:
```bash
python3 -m unittest discover tests
```

Or run with `pytest`:
```bash
pytest tests/ -v
```

All 34 test cases validate header analyzers, cookie parsing edge cases, scoring logic, SSRF protections, and mocked HTTP network responses without sending unauthorized traffic over the internet.

---

## 9. Scoring Methodology

The scanner uses an 11-point weighted scoring model:

| Header | Max Points | Weight Justification |
|---|---|---|
| **Content-Security-Policy** | **3** | Direct defense against XSS, script injection, and clickjacking. |
| **Strict-Transport-Security** | **2** | Critical defense against MitM SSL-stripping and plaintext eavesdropping. |
| **X-Content-Type-Options** | **2** | Eliminates MIME confusion and drive-by script execution. |
| **X-Frame-Options** | **2** | Essential anti-clickjacking control. |
| **Referrer-Policy** | **1** | Governs cross-origin privacy and parameter leakages. |
| **Permissions-Policy** | **1** | Hardens hardware (camera/mic/GPS) access delegation. |
| **Total** | **11 Points** | Score = `(Earned Points / 11) * 100%` |

> **Disclaimer**: The score is a measurement of defensive HTTP response header settings and cookie flags. It does not measure source code security, authentication logic, cryptographic hygiene, or backend server vulnerability status.

---

## 10. Security & Privacy Protections

1. **SSRF Guard**: Target hosts are checked against IPv4/IPv6 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`) before opening sockets.
2. **Credential Redaction**: Cookie values, `Authorization` tokens, `Proxy-Authorization`, and `API-Key` headers are strictly stripped before storage or JSON generation.
3. **No Code Execution**: Scanner only inspects HTTP metadata; HTML, JavaScript, and binary bodies are never executed.
4. **Timeouts & Response Limits**: Connection timeout is capped at 10s and redirect chains are limited to 10 hops to mitigate denial-of-service or redirect bomb attacks.

---

## 11. Legal & Authorization Warning

> ⚠️ **IMPORTANT**: This tool is designed strictly for defensive security assessments. Users must only scan domains and systems they own or have explicit written permission to assess. Unauthorized scanning of third-party networks may violate applicable local, federal, or international computer crime laws.

---

## 12. Future Enhancements

- Certificate transparency and TLS cipher suite evaluation (e.g. TLS 1.3 vs TLS 1.0 deprecation).
- Support for `Cross-Origin-Opener-Policy` (COOP), `Cross-Origin-Embedder-Policy` (COEP), and `Cross-Origin-Resource-Policy` (CORP).
- Automated remediation config generator for Nginx, Apache, Caddy, Cloudflare, Traefik, and Express.js.
- Periodic scheduled recurring audits with diff alerting for header regressions.
