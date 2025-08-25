#!/usr/bin/env python3
"""
Passive Web Security Crawler (for OWNED/AUTHORIZED targets)
===========================================================

This script performs **passive** web checks while crawling a site you own
or are explicitly authorized to test. It does not attempt to exploit
vulnerabilities or send dangerous payloads. It respects robots.txt by default
and rate-limits requests.

What it does (high level):
- Crawls internal links starting from a seed URL (same registrable domain).
- Extracts links, forms, and assets.
- Performs passive checks on each response and page content:
  * TLS/HTTPS enforcement (redirects from http→https; http-only pages).
  * Security headers present/missing: HSTS, CSP, X-Frame-Options or frame-ancestors,
    X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
  * Cookie flags: Secure, HttpOnly, SameSite.
  * Server / X-Powered-By banners exposed.
  * Mixed content (http assets on https pages).
  * Forms: method, password fields, action scheme (https), heuristic CSRF token presence.
- Writes results to CSV and JSON for easy review.

Usage:
  python passive_security_crawler.py \
      --url https://example.com \
      --max-pages 500 \
      --delay 0.5 \
      --respect-robots true \
      --out-prefix report_example

Install:
  pip install requests beautifulsoup4 tldextract urllib3

Ethics & Legal:
  * Only use against assets you own or have written permission to test.
  * Keep traffic gentle (set --delay and --max-pages accordingly).
  * This tool does NOT find "all" vulnerabilities; consider it an assistive
    passive scanner and pair it with manual review and approved tools (e.g.,
    OWASP ZAP baseline, Nuclei with safe templates, dependency scanners).

"""

import argparse
import csv
import json
import queue
import re
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple

import requests
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag, urlparse

requests.packages.urllib3.disable_warnings()  # avoid noisy InsecureRequestWarning if sites misconfigured

DEFAULT_HEADERS = {
    "User-Agent": "PassiveSecurityCrawler/1.0 (+authorized testing; contact admin)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

CSRF_HINT_NAMES = {"csrf", "xsrf", "anti_csrf", "authenticity_token", "requestverificationtoken"}

@dataclass
class PageIssue:
    url: str
    category: str  # e.g., "header", "cookie", "form", "content", "transport"
    severity: str  # "info", "low", "medium", "high"
    description: str
    evidence: Optional[str] = None

@dataclass
class PageResult:
    url: str
    status: int
    content_type: str
    secure_scheme: bool
    issues: List[PageIssue]


def is_same_registrable_domain(a: str, b: str) -> bool:
    ea = tldextract.extract(a)
    eb = tldextract.extract(b)
    da = f"{ea.domain}.{ea.suffix}" if ea.suffix else ea.domain
    db = f"{eb.domain}.{eb.suffix}" if eb.suffix else eb.domain
    return da.lower() == db.lower()


def normalize_url(base: str, link: str) -> Optional[str]:
    try:
        joined = urljoin(base, link)
        # drop fragments
        joined, _ = urldefrag(joined)
        parsed = urlparse(joined)
        if not parsed.scheme or not parsed.netloc:
            return None
        return joined
    except Exception:
        return None


def load_robots_allowlist(seed: str) -> Optional[re.Pattern]:
    """Very light robots handling: compile a regex for disallow rules to skip.
    Returns a pattern that matches disallowed paths, or None if we should ignore robots.
    """
    try:
        root = f"{urlparse(seed).scheme}://{urlparse(seed).netloc}"
        robots_url = urljoin(root, "/robots.txt")
        r = requests.get(robots_url, headers=DEFAULT_HEADERS, timeout=10, verify=True)
        if r.status_code != 200 or "Disallow" not in r.text:
            return re.compile(r"^(?!)$")  # match nothing
        disallows = []
        ua = None
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip()
            elif line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if ua in ("*", DEFAULT_HEADERS["User-Agent"].split("/",1)[0]):
                    # Convert robots wildcards to regex best-effort
                    path_regex = re.escape(path).replace("\\*", ".*")
                    disallows.append(path_regex)
        if not disallows:
            return re.compile(r"^(?!)$")
        pattern = re.compile("|".join(disallows))
        return pattern
    except Exception:
        return re.compile(r"^(?!)$")


def check_security_headers(url: str, resp: requests.Response) -> List[PageIssue]:
    issues: List[PageIssue] = []
    headers = {k.title(): v for k, v in resp.headers.items()}

    # Missing headers
    for h in SECURITY_HEADERS:
        if h not in headers:
            sev = "medium" if h in ("Content-Security-Policy", "Strict-Transport-Security") else "low"
            issues.append(PageIssue(url, "header", sev, f"Missing security header: {h}"))

    # X-Content-Type-Options validation
    xcto = headers.get("X-Content-Type-Options")
    if xcto and xcto.lower() != "nosniff":
        issues.append(PageIssue(url, "header", "low", "X-Content-Type-Options not set to 'nosniff'", xcto))

    # X-Frame-Options basic validation
    xfo = headers.get("X-Frame-Options")
    if xfo and xfo.lower() not in {"deny", "sameorigin"}:
        issues.append(PageIssue(url, "header", "low", "X-Frame-Options should be 'DENY' or 'SAMEORIGIN'", xfo))

    # HSTS present only on HTTPS
    if url.lower().startswith("https://"):
        if "Strict-Transport-Security" in headers:
            hsts = headers["Strict-Transport-Security"].lower()
            if "max-age" not in hsts:
                issues.append(PageIssue(url, "header", "low", "HSTS missing max-age directive", headers["Strict-Transport-Security"]))
        else:
            issues.append(PageIssue(url, "header", "medium", "HSTS not present on HTTPS response"))

    # Referrer-Policy basic guidance
    rp = headers.get("Referrer-Policy")
    if rp and rp.lower() not in {"no-referrer", "strict-origin-when-cross-origin", "same-origin", "no-referrer-when-downgrade"}:
        issues.append(PageIssue(url, "header", "low", "Referrer-Policy should follow safer values", rp))

    # Server/X-Powered-By banner exposure
    for banner in ("Server", "X-Powered-By"):
        if banner in headers:
            issues.append(PageIssue(url, "header", "info", f"Header exposes stack: {banner}", headers[banner]))

    return issues


def check_cookies(url: str, resp: requests.Response) -> List[PageIssue]:
    issues: List[PageIssue] = []
    set_cookies = resp.headers.get("Set-Cookie")
    if not set_cookies:
        return issues
    # Split naive by comma only when it separates cookies; a robust parser is complex.
    # Here we split on ", " followed by a token= to reduce false positives.
    parts = re.split(r",\s*(?=[^;,\s]+=)", set_cookies)
    for c in parts:
        cname = c.split("=", 1)[0].strip()
        flags = {seg.strip().lower() for seg in c.split(";")}
        # Secure flag on https
        if url.startswith("https://") and not any(seg.strip().lower() == "secure" for seg in c.split(";")):
            issues.append(PageIssue(url, "cookie", "medium", f"Cookie '{cname}' missing Secure flag", c))
        # HttpOnly flag for session-like cookies
        if "session" in cname.lower() and "httponly" not in flags:
            issues.append(PageIssue(url, "cookie", "medium", f"Likely session cookie '{cname}' missing HttpOnly", c))
        # SameSite
        if not any(seg.strip().lower().startswith("samesite") for seg in c.split(";")):
            issues.append(PageIssue(url, "cookie", "low", f"Cookie '{cname}' missing SameSite attribute", c))
    return issues


def find_mixed_content(page_url: str, soup: BeautifulSoup) -> List[PageIssue]:
    issues: List[PageIssue] = []
    if not page_url.startswith("https://"):
        return issues
    def is_insecure(link: Optional[str]) -> bool:
        return bool(link and link.strip().lower().startswith("http://"))
    tags_attrs = [
        ("img", "src"), ("script", "src"), ("link", "href"), ("iframe", "src"), ("audio", "src"), ("video", "src"),
        ("source", "src"), ("form", "action")
    ]
    for tag, attr in tags_attrs:
        for el in soup.find_all(tag):
            href = el.get(attr)
            if is_insecure(href):
                issues.append(PageIssue(page_url, "content", "medium", f"Mixed content: {tag} uses insecure {attr}", href))
    return issues


def analyze_forms(page_url: str, soup: BeautifulSoup) -> List[PageIssue]:
    issues: List[PageIssue] = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = form.get("action") or ""
        has_pwd = form.find("input", {"type": "password"}) is not None
        inputs = form.find_all("input")
        names = { (i.get("name") or "").lower() for i in inputs }
        has_csrf = any(any(hint in n for hint in CSRF_HINT_NAMES) for n in names) or form.find("input", {"type": "hidden", "name": re.compile(r"csrf|xsrf", re.I)}) is not None
        # HTTPS action recommended
        if action and urlparse(urljoin(page_url, action)).scheme == "http":
            issues.append(PageIssue(page_url, "form", "high", "Form action submits over HTTP (not HTTPS)", action))
        # Password + GET warning
        if has_pwd and method == "get":
            issues.append(PageIssue(page_url, "form", "high", "Password form uses GET method"))
        # CSRF token heuristic
        if method == "post" and not has_csrf:
            issues.append(PageIssue(page_url, "form", "medium", "POST form missing obvious CSRF token (heuristic)"))
    return issues


def check_transport(seed_url: str, final_url: str, history: List[requests.Response]) -> List[PageIssue]:
    issues: List[PageIssue] = []
    # http -> https redirect encouragement
    if seed_url.startswith("http://") and final_url.startswith("https://"):
        issues.append(PageIssue(final_url, "transport", "info", "HTTP redirected to HTTPS (good). Consider HSTS + 301 permanent."))
    # If on https but mixed redirect chains back to http at the end (rare)
    if final_url.startswith("http://"):
        issues.append(PageIssue(final_url, "transport", "high", "Final resource served over HTTP (not HTTPS)"))
    return issues


def crawl(seed_url: str, max_pages: int, delay: float, respect_robots: bool) -> Tuple[List[PageResult], List[PageIssue]]:
    results: List[PageResult] = []
    all_issues: List[PageIssue] = []

    domain = urlparse(seed_url).netloc
    base_origin = f"{urlparse(seed_url).scheme}://{domain}"

    disallow_pattern = None
    if respect_robots:
        disallow_pattern = load_robots_allowlist(seed_url)

    q: "queue.Queue[str]" = queue.Queue()
    seen: Set[str] = set()

    q.put(seed_url)
    seen.add(seed_url)

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    count = 0
    while not q.empty() and count < max_pages:
        url = q.get()
        count += 1
        try:
            if respect_robots and disallow_pattern:
                path = urlparse(url).path or "/"
                if disallow_pattern.search(path):
                    # Skip disallowed path
                    continue

            resp = session.get(url, timeout=15, allow_redirects=True, verify=True)
            final_url = resp.url
            ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            page_ok = ctype.startswith("text/html") and resp.status_code < 400

            issues = []  # type: List[PageIssue]
            issues.extend(check_security_headers(final_url, resp))
            issues.extend(check_cookies(final_url, resp))

            # Transport
            issues.extend(check_transport(url, final_url, resp.history))

            soup = None
            if page_ok:
                soup = BeautifulSoup(resp.text, "html.parser")
                # Mixed content & forms
                issues.extend(find_mixed_content(final_url, soup))
                issues.extend(analyze_forms(final_url, soup))

                # Enqueue new links
                for a in soup.find_all("a", href=True):
                    nxt = normalize_url(final_url, a.get("href"))
                    if not nxt:
                        continue
                    # Same registrable domain only
                    if not is_same_registrable_domain(seed_url, nxt):
                        continue
                    if nxt not in seen:
                        seen.add(nxt)
                        q.put(nxt)

            pr = PageResult(
                url=final_url,
                status=resp.status_code,
                content_type=ctype or "",
                secure_scheme=final_url.startswith("https://"),
                issues=issues,
            )
            results.append(pr)
            all_issues.extend(issues)

            time.sleep(max(0.0, delay))
        except requests.exceptions.RequestException as e:
            all_issues.append(PageIssue(url, "transport", "low", "Request error", str(e)))
        except Exception as e:
            all_issues.append(PageIssue(url, "other", "low", "Unhandled error", str(e)))

    return results, all_issues


def write_reports(results: List[PageResult], issues: List[PageIssue], out_prefix: str) -> Tuple[str, str]:
    json_path = f"{out_prefix}.json"
    csv_path = f"{out_prefix}.csv"

    # JSON
    serializable = [
        {
            **{k: v for k, v in asdict(r).items() if k != "issues"},
            "issues": [asdict(i) for i in r.issues],
        }
        for r in results
    ]
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"pages": serializable, "issue_count": len(issues)}, f, indent=2)

    # CSV (flat)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "status", "content_type", "secure_scheme", "issue_category", "severity", "description", "evidence"])
        for r in results:
            if not r.issues:
                w.writerow([r.url, r.status, r.content_type, r.secure_scheme, "", "", "", ""])
            else:
                for i in r.issues:
                    w.writerow([r.url, r.status, r.content_type, r.secure_scheme, i.category, i.severity, i.description, i.evidence or ""])

    return json_path, csv_path


def main():
    ap = argparse.ArgumentParser(description="Passive security crawler for authorized testing only")
    ap.add_argument("--url", required=True, help="Seed URL (http/https)")
    ap.add_argument("--max-pages", type=int, default=200, help="Max pages to crawl")
    ap.add_argument("--delay", type=float, default=0.2, help="Seconds delay between requests")
    ap.add_argument("--respect-robots", type=str, default="true", help="Respect robots.txt (true/false)")
    ap.add_argument("--out-prefix", type=str, default="security_report", help="Output file prefix")
    args = ap.parse_args()

    seed = args.url
    if not seed.startswith("http://") and not seed.startswith("https://"):
        print("--url must start with http:// or https://", file=sys.stderr)
        sys.exit(2)

    respect_robots = args.respect_robots.strip().lower() in {"1", "true", "yes", "y"}

    print(f"[+] Starting crawl at {seed} (max_pages={args.max_pages}, delay={args.delay}s, respect_robots={respect_robots})")
    results, issues = crawl(seed, args.max_pages, args.delay, respect_robots)
    json_path, csv_path = write_reports(results, issues, args.out_prefix)
    print(f"[+] Done. Pages crawled: {len(results)} | Issues found: {len(issues)}")
    print(f"[+] Reports: {json_path} , {csv_path}")


if __name__ == "__main__":
    main()
