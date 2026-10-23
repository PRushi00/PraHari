"""
PraHari — Real-browser verification of the served dashboard.

Every frontend check until now ran in jsdom. jsdom is not a browser: it
does not execute a real History API, does not round-trip a reload, and
does not fetch from a real server. Three of the defects this project has
recorded (ADR-084 routing, ADR-089 the binding card, the blank-page
`undefined.toFixed`) were only visible once something actually rendered.

This drives **real Chromium** against the **real backend** serving the
**real `frontend/dist` bundle**, and asserts what jsdom cannot:

* every canonical route and every alias resolves to its own page;
* a deep link typed directly into the address bar opens that page, not
  Overview (ADR-084);
* a reload stays on the page, and back/forward move between pages rather
  than leaving the application;
* an unknown path renders the Not Found page and does not blank the app;
* no page throws an uncaught error and no page leaves the React root
  empty — the blank-page failure mode;
* no unexpected HTTP failure. A 404 from `GET /api/v1/sources/<id>` is
  EXPECTED: the dashboard probes for optional sources (the Windows
  collector's `windows_local_host` does not exist on Linux) and handles
  the absence. Browsers log a console error for every 4xx, including
  handled ones, so console text alone cannot tell a defect from a probe —
  the responses are classified instead.

It never writes to an operational database: the caller supplies the
server URL, and `--check-only` asserts nothing beyond reachability.

Usage:
    python scripts/verify_browser_session.py --url http://127.0.0.1:8099
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

CHROMIUM = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"

# (path typed, expected heading fragment). Canonical routes first, then
# the aliases the router redirects.
ROUTES: list[tuple[str, str]] = [
    ("/", "Overview"),
    ("/live", "Live"),
    ("/import", "Import"),
    ("/stream", "Stream"),
    ("/events", "Events"),
    ("/sources", "Sources"),
    ("/analytics", "Analy"),
    ("/feasibility", "Feasibility"),
    ("/forecast", "Forecast"),
    ("/investigate", "Investigation"),
    # Renamed "Connections" when the nav was reduced to four
    # workspaces (ADR-124); the route and its /connections alias are
    # unchanged, so existing deep links still resolve.
    ("/traffic", "Connections"),
    ("/dns", "DNS"),
    ("/system-health", "Health"),
    ("/admin", "Admin"),
    ("/audit", "Audit"),
]

# A 4xx here is the application correctly discovering that an optional
# source is absent, not a fault. Anything else that fails is a fault.
EXPECTED_ABSENT_PREFIXES = ("/api/v1/sources/",)


ALIASES: list[tuple[str, str]] = [
    ("/overview", "/"),
    ("/live-telemetry", "/live"),
    ("/analysis", "/analytics"),
    ("/research", "/feasibility"),
    ("/forecasting", "/forecast"),
    ("/system", "/system-health"),
    ("/health", "/system-health"),
    ("/administration", "/admin"),
    ("/security", "/audit"),
    ("/telemetry-sources", "/sources"),
    ("/investigation", "/investigate"),
    ("/connections", "/traffic"),
    ("/dns-activity", "/dns"),
]


@dataclass
class Results:
    passed: int = 0
    failed: int = 0
    notes: list[str] = field(default_factory=list)

    def check(self, ok: bool, label: str, detail: str = "") -> None:
        if ok:
            self.passed += 1
            print(f"  PASS  {label}")
        else:
            self.failed += 1
            print(f"  FAIL  {label}{(' — ' + detail) if detail else ''}")
            self.notes.append(f"{label}: {detail}")


def _root_is_rendered(page) -> bool:
    """The React root has content. Empty is the blank-page failure."""
    return bool(
        page.evaluate(
            "() => { const r = document.getElementById('root');"
            " return !!r && r.innerHTML.trim().length > 200; }"
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8099")
    parser.add_argument("--chromium", default=CHROMIUM)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    base = args.url.rstrip("/")
    results = Results()
    page_errors: list[str] = []
    bad_responses: list[tuple[int, str]] = []

    def _record_response(response) -> None:
        if response.status < 400:
            return
        path = response.url.split(base, 1)[-1].split("?")[0] if base in response.url else response.url
        if response.status == 404 and path.startswith(EXPECTED_ABSENT_PREFIXES):
            return  # an optional source that is genuinely absent
        bad_responses.append((response.status, path))

    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=args.chromium, args=["--no-sandbox"]
        )
        page = browser.new_page()
        page.on("response", _record_response)
        page.on("pageerror", lambda e: page_errors.append(str(e)))

        try:
            page.goto(base + "/", wait_until="networkidle", timeout=45_000)
            results.check(_root_is_rendered(page), "application mounts at /")
            if args.check_only:
                browser.close()
                print(f"\ncheck-only: reachable, root rendered")
                return 0 if results.failed == 0 else 1

            # 1. Every canonical route, typed as a deep link.
            for path, fragment in ROUTES:
                page.goto(base + path, wait_until="networkidle", timeout=45_000)
                body = page.text_content("body") or ""
                rendered = _root_is_rendered(page)
                on_path = page.evaluate("() => location.pathname") == path
                results.check(
                    rendered and on_path and fragment.lower() in body.lower(),
                    f"deep link {path}",
                    f"rendered={rendered} path_kept={on_path} "
                    f"heading_found={fragment.lower() in body.lower()}",
                )

            # 2. Aliases redirect to the canonical path.
            for typed, canonical in ALIASES:
                page.goto(base + typed, wait_until="networkidle", timeout=45_000)
                landed = page.evaluate("() => location.pathname")
                results.check(
                    landed == canonical and _root_is_rendered(page),
                    f"alias {typed} -> {canonical}",
                    f"landed on {landed}",
                )

            # 3. A reload stays put. This is the ADR-084 defect: the page
            #    lived in React state, so every refresh returned to Overview.
            page.goto(base + "/forecast", wait_until="networkidle", timeout=45_000)
            page.reload(wait_until="networkidle", timeout=45_000)
            results.check(
                page.evaluate("() => location.pathname") == "/forecast"
                and _root_is_rendered(page),
                "reload stays on /forecast",
            )

            # 4. Back and forward move between pages, not out of the app.
            page.goto(base + "/events", wait_until="networkidle", timeout=45_000)
            page.goto(base + "/audit", wait_until="networkidle", timeout=45_000)
            page.go_back(wait_until="networkidle", timeout=45_000)
            results.check(
                page.evaluate("() => location.pathname") == "/events"
                and _root_is_rendered(page),
                "back returns to /events",
            )
            page.go_forward(wait_until="networkidle", timeout=45_000)
            results.check(
                page.evaluate("() => location.pathname") == "/audit"
                and _root_is_rendered(page),
                "forward returns to /audit",
            )

            # 5. An unknown path renders Not Found rather than blanking.
            page.goto(
                base + "/no-such-page", wait_until="networkidle", timeout=45_000
            )
            body = page.text_content("body") or ""
            results.check(
                _root_is_rendered(page)
                and ("not found" in body.lower() or "404" in body),
                "unknown path renders Not Found",
                body[:80],
            )

            # 6. Nothing threw, and nothing failed that was not an
            #    expected probe for an absent optional source.
            results.check(
                not page_errors,
                "no uncaught page errors across the session",
                "; ".join(page_errors[:3]),
            )
            results.check(
                not bad_responses,
                "no unexpected HTTP failures across the session",
                "; ".join(f"{s} {u}" for s, u in bad_responses[:3]),
            )
        finally:
            browser.close()

    print(f"\n{results.passed} passed, {results.failed} failed")
    for note in results.notes:
        print(f"  - {note}")
    return 0 if results.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
