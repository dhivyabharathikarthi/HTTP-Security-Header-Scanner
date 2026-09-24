"""Core HTTP Security Scanner engine."""

from datetime import datetime, timezone
import json
import ssl
import urllib.parse
import urllib.request
import uuid
from typing import Dict, List, Optional, Any

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from .schemas import (
    ScanResponse, RedirectHop, HeaderFinding, CookieFinding,
    FindingStatus, FindingSeverity
)
from .models import ScanRecord
from .utils import validate_and_normalize_url, sanitize_headers_for_storage
from .analyzers import run_all_analyzers, SCORING_RULES

# Configuration constants
MAX_REDIRECTS = 10
TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2MB max payload check
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (DefensiveSecurityScanner/1.0)"


class ScannerError(Exception):
    """Custom exception raised when a scan operation encounters an unrecoverable error."""
    pass


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Tracks redirects and enforces maximum redirect limits."""
    def __init__(self, max_redirects=MAX_REDIRECTS):
        super().__init__()
        self.max_redirects = max_redirects
        self.redirect_chain: List[RedirectHop] = []
        self._count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._count += 1
        if self._count > self.max_redirects:
            raise urllib.error.HTTPError(
                req.full_url, code, f"Exceeded maximum redirect count of {self.max_redirects}", headers, fp
            )
        self.redirect_chain.append(RedirectHop(
            step=self._count,
            url=req.full_url,
            status_code=code,
            location=newurl
        ))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _scan_with_httpx(target_url: str):
    """Performs HTTP request using httpx if available."""
    redirect_chain: List[RedirectHop] = []
    collected_headers: Dict[str, str] = {}
    collected_set_cookies: List[str] = []

    transport = httpx.HTTPTransport(verify=True, retries=1)
    client_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        with httpx.Client(
            transport=transport,
            timeout=TIMEOUT_SECONDS,
            max_redirects=MAX_REDIRECTS,
            follow_redirects=True,
            headers=client_headers
        ) as client:
            response = client.get(target_url)

            step = 1
            if response.history:
                for hist_resp in response.history:
                    loc = hist_resp.headers.get("Location")
                    redirect_chain.append(RedirectHop(
                        step=step,
                        url=str(hist_resp.url),
                        status_code=hist_resp.status_code,
                        location=loc
                    ))
                    step += 1

            redirect_chain.append(RedirectHop(
                step=step,
                url=str(response.url),
                status_code=response.status_code,
                location=None
            ))

            final_url = str(response.url)
            final_status = response.status_code

            for k, v in response.headers.items():
                collected_headers[k] = v

            if hasattr(response.headers, "get_list"):
                collected_set_cookies = response.headers.get_list("set-cookie")
            elif "set-cookie" in response.headers:
                collected_set_cookies = [response.headers["set-cookie"]]

            return final_url, final_status, redirect_chain, collected_headers, collected_set_cookies

    except httpx.ConnectTimeout:
        raise ScannerError(f"Connection timed out after {TIMEOUT_SECONDS}s when contacting {target_url}.")
    except httpx.ReadTimeout:
        raise ScannerError(f"Server at {target_url} took too long to return HTTP headers (read timeout).")
    except httpx.TooManyRedirects:
        raise ScannerError(f"Target encountered a redirect loop (exceeded {MAX_REDIRECTS} hops).")
    except (httpx.ConnectError, httpx.NetworkError) as err:
        err_msg = str(err)
        if "getaddrinfo failed" in err_msg.lower() or "name resolution" in err_msg.lower():
            raise ScannerError(f"DNS resolution failure for host in '{target_url}'. Verify domain name.")
        elif "connection refused" in err_msg.lower():
            raise ScannerError(f"Connection refused by server at {target_url}.")
        else:
            raise ScannerError(f"Network connection failed: {err_msg}")
    except httpx.InvalidURL as err:
        raise ScannerError(f"Invalid URL encountered during request: {err}")
    except Exception as exc:
        raise ScannerError(f"Scan failed: {str(exc)}")


def _scan_with_urllib(target_url: str):
    """Fallback scanner using Python standard library urllib."""
    redirect_handler = SafeRedirectHandler(max_redirects=MAX_REDIRECTS)
    ssl_context = ssl.create_default_context()
    opener = urllib.request.build_opener(redirect_handler, urllib.request.HTTPSHandler(context=ssl_context))
    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"}
    )

    try:
        with opener.open(req, timeout=TIMEOUT_SECONDS) as response:
            final_url = response.geturl()
            final_status = response.getcode()
            headers = dict(response.headers.items())
            set_cookies = response.headers.get_all("Set-Cookie") or []

            chain = redirect_handler.redirect_chain
            step = len(chain) + 1
            chain.append(RedirectHop(
                step=step,
                url=final_url,
                status_code=final_status,
                location=None
            ))
            return final_url, final_status, chain, headers, set_cookies

    except urllib.error.HTTPError as he:
        # HTTP error (e.g. 403, 404, 500) still has valid headers!
        final_url = he.geturl() or target_url
        final_status = he.code
        headers = dict(he.headers.items()) if he.headers else {}
        set_cookies = he.headers.get_all("Set-Cookie") if he.headers else []
        chain = redirect_handler.redirect_chain
        chain.append(RedirectHop(
            step=len(chain) + 1,
            url=final_url,
            status_code=final_status,
            location=None
        ))
        return final_url, final_status, chain, headers, set_cookies
    except urllib.error.URLError as ue:
        reason = str(ue.reason)
        if "getaddrinfo failed" in reason.lower():
            raise ScannerError(f"DNS resolution failure for host in '{target_url}'. Verify domain name.")
        elif "timed out" in reason.lower():
            raise ScannerError(f"Connection timed out after {TIMEOUT_SECONDS}s when contacting {target_url}.")
        elif "certificate verify failed" in reason.lower():
            raise ScannerError(f"TLS certificate verification failed for '{target_url}': {reason}")
        else:
            raise ScannerError(f"Network error: {reason}")
    except Exception as exc:
        raise ScannerError(f"Scan request failed: {str(exc)}")


def perform_scan(target_url: str, db: Optional[Any] = None) -> ScanResponse:
    """
    Executes a security scan against the specified target URL.
    """
    normalized_url = validate_and_normalize_url(target_url)

    if HAS_HTTPX:
        final_url, final_status, redirect_chain, collected_headers, collected_set_cookies = _scan_with_httpx(normalized_url)
    else:
        final_url, final_status, redirect_chain, collected_headers, collected_set_cookies = _scan_with_urllib(normalized_url)

    is_https = final_url.lower().startswith("https://")

    # Run analyzers
    findings, cookies, earned_score, max_score = run_all_analyzers(
        headers=collected_headers,
        is_https=is_https,
        cookie_headers=collected_set_cookies
    )

    percentage = round((earned_score / max_score * 100), 1) if max_score > 0 else 0.0
    scan_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    sanitized_headers = sanitize_headers_for_storage(collected_headers)

    response_data = ScanResponse(
        id=scan_id,
        target=normalized_url,
        final_url=final_url,
        timestamp=now_iso,
        status_code=final_status,
        is_https=is_https,
        score=earned_score,
        max_score=max_score,
        score_percentage=percentage,
        redirect_count=max(0, len(redirect_chain) - 1),
        redirect_chain=redirect_chain,
        findings=findings,
        cookies=cookies,
        raw_headers=sanitized_headers,
        scoring_methodology=SCORING_RULES
    )

    # Persist in SQLite
    if db is not None:
        try:
            # Check if db is a SQLAlchemy Session or standard sqlite3 connection
            if hasattr(db, "add") and hasattr(db, "commit"):
                db_record = ScanRecord(
                    id=scan_id,
                    original_url=normalized_url,
                    final_url=final_url,
                    timestamp=datetime.now(timezone.utc),
                    status_code=final_status,
                    score=earned_score,
                    max_score=max_score,
                    result_json=response_data.model_dump_json()
                )
                db.add(db_record)
                db.commit()
            elif hasattr(db, "cursor"):
                cursor = db.cursor()
                cursor.execute(
                    "INSERT INTO scans (id, original_url, final_url, timestamp, status_code, score, max_score, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, normalized_url, final_url, now_iso, final_status, earned_score, max_score, response_data.model_dump_json())
                )
                db.commit()
        except Exception as db_err:
            if hasattr(db, "rollback"):
                db.rollback()
            print(f"[ERROR] Failed to save scan result to SQLite: {db_err}")

    return response_data
