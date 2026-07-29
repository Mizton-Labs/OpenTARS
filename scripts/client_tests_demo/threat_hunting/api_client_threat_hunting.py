#!/usr/bin/env python3
"""
OpenTARS — standalone Threat Hunting API client.

A dependency-free command-line client for /api/threat-hunting/* (issue-local-029),
covering every route documented in docs/api-threat-hunting.md: hunt packages,
evidence, IOCs, LLM-driven generation/runs, SIEM connectors, execution,
reports, Threat Intelligence, run comparison, run comments, and cross-hunt
tracking. Uses only the Python standard library (urllib/json/argparse), so it
runs under any Python 3 without the project virtualenv.

Every command prints a JSON document to stdout (binary downloads instead
write to a file — see --out on the *-pdf/-markdown/download commands).

Authentication — TWO independent modes, matching the server:

  1. Session cookie: pass --username (and --password, or you will be
     prompted). Requires an admin or threat-researcher account for writes;
     threat-viewer for reads only. Logs in once, reuses the cookie.
  2. API access key (issue-local-029): pass --api-key '<client_id>.<secret>'
     as shown once when the key was created in Configuration -> API Access.
     Authorized purely by the key's granted scopes, not a role — see
     docs/api-threat-hunting.md for which commands each scope unlocks. Only
     works when the server's Programmatic API access toggle is enabled.

Passing both is an error; passing neither only works against a server
started with --disable-auth.

Examples:

  # List hunt packages (API key with the hunts:read scope)
  api_client_threat_hunting.py --url http://HOST:8000 --api-key ak_xxx.yyy packages-list

  # Full lifecycle with a session login (admin/researcher)
  api_client_threat_hunting.py -u analyst packages-create --name "Suspicious logins"
  api_client_threat_hunting.py -u analyst evidence-add-text PKG_ID --text "notes..."
  api_client_threat_hunting.py -u analyst generate-start PKG_ID
  api_client_threat_hunting.py -u analyst generate-status PKG_ID
  api_client_threat_hunting.py -u analyst report-pdf PKG_ID --out report.pdf

  # Deep search + date-range filter on the package list
  api_client_threat_hunting.py -u analyst packages-list --search npm --date-from 2026-01-01

See docs/api-threat-hunting.md for the full endpoint reference this client wraps.
"""

from __future__ import annotations

import argparse
import getpass
import http.client
import http.cookiejar
import json
import mimetypes
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

DEFAULT_URL = "http://127.0.0.1:8000"
_TIMEOUT = 60
_API_PREFIX = "/api/threat-hunting"


# ── HTTP plumbing (mirrors scripts/api_client.py's conventions) ───────────────


def build_opener(insecure: bool = False) -> urllib.request.OpenerDirector:
    """Return an opener with an in-memory cookie jar (carries the session).

    When ``insecure`` is true, TLS certificate verification is disabled for
    HTTPS requests. This removes protection against man-in-the-middle
    attacks — use only against trusted self-signed or development endpoints.
    """
    jar = http.cookiejar.CookieJar()
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.HTTPCookieProcessor(jar),
    ]
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def normalize_url(url: str) -> str:
    """Validate and normalize the base ``--url`` (see scripts/api_client.py's
    twin for the full rationale — this turns a stray inline-comment foot-gun
    from a copied .env value into a clear error instead of an obscure
    urllib traceback)."""
    cleaned = url.strip()
    if not cleaned:
        raise ValueError("--url is empty")
    for ch in cleaned:
        if ch.isspace() or ord(ch) < 0x20:
            raise ValueError(
                f"--url contains whitespace or control characters: {url!r}. "
                "Check for a stray inline comment in your .env "
                "(e.g. 'url=https://host/alias  # note')."
            )
    return cleaned


def build_url(base: str, path: str, params: dict[str, object] | None = None) -> str:
    url = base.rstrip("/") + path
    if params:
        query = {k: v for k, v in params.items() if v is not None and v != []}
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)
    return url


class Client:
    """Thin HTTP wrapper bound to a base URL, an opener (session cookie jar),
    and an optional API-key bearer token. Every request adds the bearer
    header when an API key was supplied; a session login instead relies on
    the opener's cookie jar. The server accepts either, independently."""

    def __init__(self, opener: urllib.request.OpenerDirector, base: str, api_key: str | None):
        self.opener = opener
        self.base = base
        self.api_key = api_key

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = dict(extra or {})
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, object] | None = None,
        json_body: object | None = None,
        raw_body: bytes | None = None,
        content_type: str | None = None,
    ) -> tuple[bytes, str]:
        url = build_url(self.base, _API_PREFIX + path, params)
        headers = self._headers()
        data = raw_body
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with self.opener.open(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (trusted local API)
            body = resp.read()
            return body, resp.headers.get("Content-Type", "")

    def get(self, path: str, params: dict[str, object] | None = None) -> object:
        body, _ = self._request("GET", path, params=params)
        return json.loads(body.decode("utf-8")) if body else None

    def get_binary(self, path: str, params: dict[str, object] | None = None) -> tuple[bytes, str]:
        return self._request("GET", path, params=params)

    def post(
        self, path: str, json_body: object | None = None, params: dict[str, object] | None = None
    ) -> object:
        body, _ = self._request("POST", path, params=params, json_body=json_body or {})
        return json.loads(body.decode("utf-8")) if body else None

    def put(self, path: str, json_body: object) -> object:
        body, _ = self._request("PUT", path, json_body=json_body)
        return json.loads(body.decode("utf-8")) if body else None

    def patch(self, path: str, json_body: object) -> object:
        body, _ = self._request("PATCH", path, json_body=json_body)
        return json.loads(body.decode("utf-8")) if body else None

    def delete(self, path: str) -> object:
        body, _ = self._request("DELETE", path)
        return json.loads(body.decode("utf-8")) if body else {"status": "deleted"}

    def post_multipart_file(
        self, path: str, file_path: str, *, params: dict[str, object] | None = None
    ) -> object:
        """POST a single-field multipart/form-data body (evidence file upload)."""
        boundary = uuid.uuid4().hex
        filename = os.path.basename(file_path)
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        with open(file_path, "rb") as fh:
            file_bytes = fh.read()

        parts: list[bytes] = []
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
        )
        parts.append(f"Content-Type: {mime_type}\r\n\r\n".encode())
        parts.append(file_bytes)
        parts.append(f"\r\n--{boundary}--\r\n".encode())
        body = b"".join(parts)

        raw, _ = self._request(
            "POST",
            path,
            params=params,
            raw_body=body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )
        return json.loads(raw.decode("utf-8")) if raw else None


def login(opener: urllib.request.OpenerDirector, base: str, username: str, password: str) -> None:
    """Authenticate against /api/auth/login; the session cookie is stored in the jar."""
    req = urllib.request.Request(
        build_url(base, "/api/auth/login"),
        data=json.dumps({"username": username, "password": password}).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with opener.open(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (trusted local API)
        resp.read()


# ── body/JSON payload helpers ──────────────────────────────────────────────


def _read_json_arg(data: str | None, file: str | None, *, required: bool = False) -> object | None:
    """Resolve an inline JSON escape hatch (--data / --file) shared by the
    handful of commands whose body is too structured for individual flags
    (generate-start's run_config, compare's run_ids, iocs-verdict's updates,
    connector create/update, report-generate's report_formats)."""
    if file:
        with open(file, encoding="utf-8") as fh:
            raw = fh.read()
    elif data is not None:
        raw = data
    elif required:
        raise ValueError("this command requires --data or --file with a JSON body")
    else:
        return None
    return json.loads(raw)


def _print(obj: object) -> None:
    print(json.dumps(obj))


def _save_binary(content: bytes, out: str | None, default_name: str) -> None:
    dest = out or default_name
    with open(dest, "wb") as fh:
        fh.write(content)
    print(json.dumps({"saved": dest, "bytes": len(content)}))


# ── Hunt Packages ───────────────────────────────────────────────────────────


def cmd_packages_list(c: Client, args: argparse.Namespace) -> None:
    _print(
        c.get(
            "/packages",
            {"search": args.search, "date_from": args.date_from, "date_to": args.date_to},
        )
    )


def cmd_packages_create(c: Client, args: argparse.Namespace) -> None:
    _print(c.post("/packages", {"name": args.name, "description": args.description}))


def cmd_packages_get(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}"))


def cmd_packages_update(c: Client, args: argparse.Namespace) -> None:
    body = {}
    if args.name is not None:
        body["name"] = args.name
    if args.description is not None:
        body["description"] = args.description
    if args.status is not None:
        body["status"] = args.status
    _print(c.put(f"/packages/{args.pkg_id}", body))


def cmd_packages_delete(c: Client, args: argparse.Namespace) -> None:
    _print(c.delete(f"/packages/{args.pkg_id}"))


def cmd_packages_clone(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/clone", {"name": args.name}))


# ── Evidence ────────────────────────────────────────────────────────────────


def cmd_evidence_add_file(c: Client, args: argparse.Namespace) -> None:
    _print(
        c.post_multipart_file(
            f"/packages/{args.pkg_id}/evidence/file",
            args.path,
            params={"parser_mode": args.parser_mode},
        )
    )


def cmd_evidence_add_url(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/evidence/url", {"url": args.url, "label": args.label}))


def cmd_evidence_add_text(c: Client, args: argparse.Namespace) -> None:
    _print(
        c.post(
            f"/packages/{args.pkg_id}/evidence/text",
            {"text": args.text, "label": args.label, "source_ref": args.source_ref},
        )
    )


def cmd_evidence_add_watcher(c: Client, args: argparse.Namespace) -> None:
    _print(
        c.post(
            f"/packages/{args.pkg_id}/evidence/watcher",
            {"watcher_id": args.watcher_id, "label": args.label, "max_events": args.max_events},
        )
    )


def cmd_evidence_list(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/evidence"))


def cmd_evidence_delete(c: Client, args: argparse.Namespace) -> None:
    _print(c.delete(f"/packages/{args.pkg_id}/evidence/{args.item_id}"))


def cmd_evidence_download(c: Client, args: argparse.Namespace) -> None:
    content, _ct = c.get_binary(f"/packages/{args.pkg_id}/evidence/{args.item_id}/download")
    _save_binary(content, args.out, f"evidence-{args.item_id}.bin")


# ── IOCs ────────────────────────────────────────────────────────────────────


def cmd_iocs_list(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/iocs", {"run_id": args.run_id}))


# ── Generation & Runs ───────────────────────────────────────────────────────


def cmd_generate_start(c: Client, args: argparse.Namespace) -> None:
    body: dict[str, object] = {}
    if args.provider is not None:
        body["provider_name"] = args.provider
    if args.model is not None:
        body["model_name"] = args.model
    if args.effort is not None:
        body["research_effort"] = args.effort
    run_config = _read_json_arg(args.data, args.file)
    if run_config is not None:
        body["run_config"] = run_config
    _print(c.post(f"/packages/{args.pkg_id}/generate", body))


def cmd_generate_status(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/generate/status"))


def cmd_approve(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/approve", {"notes": args.notes}))


def cmd_reject(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/reject", {"notes": args.notes}))


def cmd_runs_list(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/runs"))


def cmd_run_status(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/runs/{args.run_id}/status"))


def cmd_run_approve(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/runs/{args.run_id}/approve", {"notes": args.notes}))


def cmd_run_reject(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/runs/{args.run_id}/reject", {"notes": args.notes}))


def cmd_run_cancel(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/runs/{args.run_id}/cancel"))


def cmd_hypothesis_discard(c: Client, args: argparse.Namespace) -> None:
    _print(
        c.patch(
            f"/packages/{args.pkg_id}/runs/{args.run_id}/hypotheses/{args.hypothesis_id}",
            {"discarded": args.discarded},
        )
    )


def cmd_lead_discard(c: Client, args: argparse.Namespace) -> None:
    _print(
        c.patch(
            f"/packages/{args.pkg_id}/runs/{args.run_id}/hunting-leads/{args.lead_id}",
            {"discarded": args.discarded},
        )
    )


def cmd_iocs_verdict(c: Client, args: argparse.Namespace) -> None:
    updates = _read_json_arg(args.data, args.file, required=True)
    _print(c.patch(f"/packages/{args.pkg_id}/runs/{args.run_id}/iocs", {"updates": updates}))


# ── SIEM Connectors ─────────────────────────────────────────────────────────


def cmd_connectors_list(c: Client, _args: argparse.Namespace) -> None:
    _print(c.get("/connectors"))


def cmd_connectors_create(c: Client, args: argparse.Namespace) -> None:
    _print(c.post("/connectors", _read_json_arg(args.data, args.file, required=True)))


def cmd_connectors_get(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/connectors/{args.conn_id}"))


def cmd_connectors_update(c: Client, args: argparse.Namespace) -> None:
    _print(
        c.put(f"/connectors/{args.conn_id}", _read_json_arg(args.data, args.file, required=True))
    )


def cmd_connectors_delete(c: Client, args: argparse.Namespace) -> None:
    _print(c.delete(f"/connectors/{args.conn_id}"))


def cmd_connectors_test(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/connectors/{args.conn_id}/test"))


# ── Execution ────────────────────────────────────────────────────────────────


def cmd_execute(c: Client, args: argparse.Namespace) -> None:
    body: dict[str, object] = {
        "connector_id": args.connector_id,
        "spl": args.spl,
        "earliest": args.earliest,
        "latest": args.latest,
    }
    if args.provider is not None:
        body["provider_name"] = args.provider
    if args.model is not None:
        body["model_name"] = args.model
    if args.run_id is not None:
        body["run_id"] = args.run_id
    _print(c.post(f"/packages/{args.pkg_id}/execute", body))


def cmd_results_list(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/results"))


def cmd_result_get(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/results/{args.result_id}"))


# ── Reports ──────────────────────────────────────────────────────────────────


def _report_formats_body(args: argparse.Namespace) -> dict[str, object]:
    body: dict[str, object] = {}
    if args.provider is not None:
        body["provider_name"] = args.provider
    if args.model is not None:
        body["model_name"] = args.model
    formats = _read_json_arg(args.data, args.file)
    if formats is not None:
        body["report_formats"] = formats
    return body


def cmd_report_get(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/report"))


def cmd_report_generate(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/report", _report_formats_body(args)))


def cmd_report_list(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/report/list"))


def cmd_report_markdown(c: Client, args: argparse.Namespace) -> None:
    content, _ct = c.get_binary(f"/packages/{args.pkg_id}/report/markdown")
    _save_binary(content, args.out, f"hunt_report_{args.pkg_id[:8]}.md")


def cmd_report_pdf(c: Client, args: argparse.Namespace) -> None:
    content, _ct = c.get_binary(f"/packages/{args.pkg_id}/report/pdf")
    _save_binary(content, args.out, f"hunt_report_{args.pkg_id[:8]}.pdf")


def cmd_run_report_get(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/runs/{args.run_id}/report"))


def cmd_run_report_generate(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/runs/{args.run_id}/report", _report_formats_body(args)))


def cmd_run_report_markdown(c: Client, args: argparse.Namespace) -> None:
    content, _ct = c.get_binary(f"/packages/{args.pkg_id}/runs/{args.run_id}/report/markdown")
    _save_binary(content, args.out, f"hunt_report_{args.pkg_id[:8]}_run_{args.run_id[:8]}.md")


def cmd_run_report_pdf(c: Client, args: argparse.Namespace) -> None:
    content, _ct = c.get_binary(f"/packages/{args.pkg_id}/runs/{args.run_id}/report/pdf")
    _save_binary(content, args.out, f"hunt_report_{args.pkg_id[:8]}_run_{args.run_id[:8]}.pdf")


def cmd_results_by_run(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/runs/{args.run_id}/results"))


# ── Threat Intelligence ──────────────────────────────────────────────────────


def cmd_threat_intel_get(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/threat-intel"))


def cmd_run_threat_intel_get(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/runs/{args.run_id}/threat-intel"))


def cmd_run_threat_intel_trigger(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/runs/{args.run_id}/threat-intel"))


# ── Comparison Module ────────────────────────────────────────────────────────


def cmd_compare(c: Client, args: argparse.Namespace) -> None:
    body: dict[str, object] = {}
    if args.provider is not None:
        body["provider_name"] = args.provider
    if args.model is not None:
        body["model_name"] = args.model
    run_ids = _read_json_arg(args.data, args.file)
    if run_ids is not None:
        body["run_ids"] = run_ids
    _print(c.post(f"/packages/{args.pkg_id}/compare", body))


def cmd_comparison_get(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/comparison"))


def cmd_comparison_markdown(c: Client, args: argparse.Namespace) -> None:
    content, _ct = c.get_binary(f"/packages/{args.pkg_id}/comparison/markdown")
    _save_binary(content, args.out, f"hunt_comparison_{args.pkg_id[:8]}.md")


def cmd_comparison_pdf(c: Client, args: argparse.Namespace) -> None:
    content, _ct = c.get_binary(f"/packages/{args.pkg_id}/comparison/pdf")
    _save_binary(content, args.out, f"hunt_comparison_{args.pkg_id[:8]}.pdf")


# ── Run Comments ─────────────────────────────────────────────────────────────


def cmd_comments_list(c: Client, args: argparse.Namespace) -> None:
    _print(c.get(f"/packages/{args.pkg_id}/runs/{args.run_id}/comments"))


def cmd_comment_add(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/packages/{args.pkg_id}/runs/{args.run_id}/comments", {"body": args.body}))


def cmd_comment_delete(c: Client, args: argparse.Namespace) -> None:
    _print(c.delete(f"/packages/{args.pkg_id}/runs/{args.run_id}/comments/{args.comment_id}"))


# ── Threat Intel Tracking ────────────────────────────────────────────────────


def cmd_tracking_dashboard(c: Client, args: argparse.Namespace) -> None:
    _print(c.get("/tracking/dashboard", {"search": args.search}))


def cmd_tracking_hunts(c: Client, _args: argparse.Namespace) -> None:
    _print(c.get("/tracking/hunts"))


def cmd_tracking_exclude(c: Client, args: argparse.Namespace) -> None:
    _print(c.post(f"/tracking/hunts/{args.pkg_id}/exclude", {"excluded": args.excluded}))


def cmd_tracking_delete(c: Client, args: argparse.Namespace) -> None:
    _print(c.delete(f"/tracking/hunts/{args.pkg_id}"))


# ── argparse wiring ──────────────────────────────────────────────────────────


def _pkg_id_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("pkg_id", help="Hunt package id")


def _run_id_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("run_id", help="Generation run id")


def _json_body_args(p: argparse.ArgumentParser, what: str) -> None:
    src = p.add_mutually_exclusive_group()
    src.add_argument("--data", help=f"Inline JSON for {what}")
    src.add_argument("--file", help=f"Path to a JSON file for {what}")


def _provider_model_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--provider", default=None, help="LLM provider name override")
    p.add_argument("--model", default=None, help="LLM model name override")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="api_client_threat_hunting.py",
        description="Standalone command-line client for the OpenTARS Threat Hunting API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  api_client_threat_hunting.py --api-key ak_x.y packages-list\n"
            "  api_client_threat_hunting.py -u analyst packages-create --name 'New hunt'\n"
            "  api_client_threat_hunting.py -u analyst evidence-add-text PKG_ID --text '...'\n"
            "  api_client_threat_hunting.py -u analyst generate-start PKG_ID\n"
            "  api_client_threat_hunting.py --api-key ak_x.y report-pdf PKG_ID --out report.pdf\n"
            "  api_client_threat_hunting.py --api-key ak_x.y iocs-list PKG_ID\n"
            "  api_client_threat_hunting.py --api-key ak_x.y tracking-dashboard --search ransomware\n"
        ),
    )
    parser.add_argument(
        "--url", default=DEFAULT_URL, help=f"Base API endpoint URL (default: {DEFAULT_URL})"
    )
    parser.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        help="Skip TLS certificate verification for HTTPS (accept self-signed / untrusted certs).",
    )
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--username", "-u", default=None, help="Session-cookie login username")
    auth.add_argument(
        "--api-key",
        default=None,
        help="API access key '<client_id>.<secret>' (Bearer auth, issue-local-029)",
    )
    parser.add_argument(
        "--password", "-p", default=None, help="Password for --username (prompted if omitted)"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # Packages
    p = sub.add_parser("packages-list", help="List hunt packages (search/date filters)")
    p.add_argument(
        "--search", default=None, help="Deep search: name/description/analysis JSON/IOCs"
    )
    p.add_argument(
        "--date-from", dest="date_from", default=None, help="ISO date lower bound on created_at"
    )
    p.add_argument(
        "--date-to", dest="date_to", default=None, help="ISO date upper bound on created_at"
    )
    p.set_defaults(func=cmd_packages_list)

    p = sub.add_parser("packages-create", help="Create a hunt package")
    p.add_argument("--name", required=True)
    p.add_argument("--description", default="")
    p.set_defaults(func=cmd_packages_create)

    p = sub.add_parser("packages-get", help="Get a hunt package")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_packages_get)

    p = sub.add_parser("packages-update", help="Update a hunt package's name/description/status")
    _pkg_id_arg(p)
    p.add_argument("--name", default=None)
    p.add_argument("--description", default=None)
    p.add_argument(
        "--status",
        default=None,
        choices=("draft", "planning", "approved", "executing", "completed", "archived"),
    )
    p.set_defaults(func=cmd_packages_update)

    p = sub.add_parser("packages-delete", help="Archive (soft-delete) a hunt package")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_packages_delete)

    p = sub.add_parser("packages-clone", help="Clone a package's evidence into a new draft")
    _pkg_id_arg(p)
    p.add_argument("--name", required=True, help="Name for the cloned package")
    p.set_defaults(func=cmd_packages_clone)

    # Evidence
    p = sub.add_parser("evidence-add-file", help="Upload a file as evidence")
    _pkg_id_arg(p)
    p.add_argument("path", help="Local path to the file to upload")
    p.add_argument("--parser-mode", dest="parser_mode", default="auto")
    p.set_defaults(func=cmd_evidence_add_file)

    p = sub.add_parser("evidence-add-url", help="Register a URL as evidence")
    _pkg_id_arg(p)
    p.add_argument("url")
    p.add_argument("--label", default="")
    p.set_defaults(func=cmd_evidence_add_url)

    p = sub.add_parser("evidence-add-text", help="Add manual text/notes as evidence")
    _pkg_id_arg(p)
    p.add_argument("--text", required=True)
    p.add_argument("--label", default="")
    p.add_argument("--source-ref", dest="source_ref", default="")
    p.set_defaults(func=cmd_evidence_add_text)

    p = sub.add_parser(
        "evidence-add-watcher", help="Import a Threat Intel watcher feed as evidence"
    )
    _pkg_id_arg(p)
    p.add_argument("watcher_id")
    p.add_argument("--label", default="")
    p.add_argument("--max-events", dest="max_events", type=int, default=500)
    p.set_defaults(func=cmd_evidence_add_watcher)

    p = sub.add_parser("evidence-list", help="List evidence items for a package")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_evidence_list)

    p = sub.add_parser("evidence-delete", help="Delete an evidence item")
    _pkg_id_arg(p)
    p.add_argument("item_id")
    p.set_defaults(func=cmd_evidence_delete)

    p = sub.add_parser("evidence-download", help="Download an evidence item's original file")
    _pkg_id_arg(p)
    p.add_argument("item_id")
    p.add_argument("--out", default=None, help="Output path (default: evidence-<id>.bin)")
    p.set_defaults(func=cmd_evidence_download)

    # IOCs
    p = sub.add_parser("iocs-list", help="List extracted IOCs for a package (optionally one run)")
    _pkg_id_arg(p)
    p.add_argument("--run-id", dest="run_id", default=None)
    p.set_defaults(func=cmd_iocs_list)

    # Generation & Runs
    p = sub.add_parser("generate-start", help="Start the LLM hunt-generation pipeline")
    _pkg_id_arg(p)
    _provider_model_args(p)
    p.add_argument("--effort", choices=("low", "medium", "high"), default=None)
    _json_body_args(p, 'run_config (e.g. {"ioc_mode": "active_cleaning"})')
    p.set_defaults(func=cmd_generate_start)

    p = sub.add_parser("generate-status", help="Poll generation status (latest run)")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_generate_status)

    p = sub.add_parser("approve", help="Approve the latest generation run (back-compat)")
    _pkg_id_arg(p)
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("reject", help="Reject the latest generation run (back-compat)")
    _pkg_id_arg(p)
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_reject)

    p = sub.add_parser("runs-list", help="List all generation runs for a package")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_runs_list)

    p = sub.add_parser("run-status", help="Poll generation status for a specific run")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.set_defaults(func=cmd_run_status)

    p = sub.add_parser("run-approve", help="Approve a specific generation run")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_run_approve)

    p = sub.add_parser("run-reject", help="Reject a specific generation run")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_run_reject)

    p = sub.add_parser("run-cancel", help="Cancel a currently-running generation run")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.set_defaults(func=cmd_run_cancel)

    p = sub.add_parser("hypothesis-discard", help="Set a hypothesis's discarded flag")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.add_argument("hypothesis_id")
    p.add_argument("--discarded", type=lambda v: v.lower() in ("1", "true", "yes"), required=True)
    p.set_defaults(func=cmd_hypothesis_discard)

    p = sub.add_parser("lead-discard", help="Set a hunting lead's discarded flag")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.add_argument("lead_id")
    p.add_argument("--discarded", type=lambda v: v.lower() in ("1", "true", "yes"), required=True)
    p.set_defaults(func=cmd_lead_discard)

    p = sub.add_parser("iocs-verdict", help="Batch-apply keep/remove IOC verdicts for a run")
    _pkg_id_arg(p)
    _run_id_arg(p)
    _json_body_args(
        p, 'updates list, e.g. \'[{"ioc":"1.2.3.4","ioc_type":"ipv4-addr","action":"remove"}]\''
    )
    p.set_defaults(func=cmd_iocs_verdict)

    # SIEM Connectors
    p = sub.add_parser("connectors-list", help="List SIEM connectors")
    p.set_defaults(func=cmd_connectors_list)

    p = sub.add_parser("connectors-create", help="Create a SIEM connector")
    _json_body_args(p, "the connector body (name/kind/base_url/auth_method/...)")
    p.set_defaults(func=cmd_connectors_create)

    p = sub.add_parser("connectors-get", help="Get a SIEM connector")
    p.add_argument("conn_id")
    p.set_defaults(func=cmd_connectors_get)

    p = sub.add_parser("connectors-update", help="Update a SIEM connector")
    p.add_argument("conn_id")
    _json_body_args(p, "the fields to change")
    p.set_defaults(func=cmd_connectors_update)

    p = sub.add_parser("connectors-delete", help="Delete a SIEM connector")
    p.add_argument("conn_id")
    p.set_defaults(func=cmd_connectors_delete)

    p = sub.add_parser("connectors-test", help="Test a SIEM connector's connection")
    p.add_argument("conn_id")
    p.set_defaults(func=cmd_connectors_test)

    # Execution
    p = sub.add_parser("execute", help="Start SIEM execution for an approved package")
    _pkg_id_arg(p)
    p.add_argument("connector_id")
    p.add_argument("spl", help="SPL query to execute")
    p.add_argument("--earliest", default="-24h")
    p.add_argument("--latest", default="now")
    p.add_argument("--run-id", dest="run_id", default=None, help="Link results to a specific run")
    _provider_model_args(p)
    p.set_defaults(func=cmd_execute)

    p = sub.add_parser("results-list", help="List task (execution) results for a package")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_results_list)

    p = sub.add_parser("result-get", help="Get a single task (execution) result")
    _pkg_id_arg(p)
    p.add_argument("result_id")
    p.set_defaults(func=cmd_result_get)

    p = sub.add_parser("results-by-run", help="List task results scoped to a specific run")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.set_defaults(func=cmd_results_by_run)

    # Reports
    p = sub.add_parser("report-get", help="Get the latest hunt report (package-level)")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_report_get)

    p = sub.add_parser("report-generate", help="Generate/replace the package-level report")
    _pkg_id_arg(p)
    _provider_model_args(p)
    _json_body_args(p, 'report_formats, e.g. \'{"pdf": true, "markdown": true}\'')
    p.set_defaults(func=cmd_report_generate)

    p = sub.add_parser("report-list", help="List every historical report for a package")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_report_list)

    p = sub.add_parser("report-markdown", help="Download the latest report as Markdown")
    _pkg_id_arg(p)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_report_markdown)

    p = sub.add_parser("report-pdf", help="Download the latest report as PDF")
    _pkg_id_arg(p)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_report_pdf)

    p = sub.add_parser("run-report-get", help="Get the report for a specific run")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.set_defaults(func=cmd_run_report_get)

    p = sub.add_parser("run-report-generate", help="Generate/replace a run-scoped report")
    _pkg_id_arg(p)
    _run_id_arg(p)
    _provider_model_args(p)
    _json_body_args(p, 'report_formats, e.g. \'{"pdf": true, "markdown": true}\'')
    p.set_defaults(func=cmd_run_report_generate)

    p = sub.add_parser("run-report-markdown", help="Download a run's report as Markdown")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_run_report_markdown)

    p = sub.add_parser("run-report-pdf", help="Download a run's report as PDF")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_run_report_pdf)

    # Threat Intelligence
    p = sub.add_parser("threat-intel-get", help="Get the latest Threat Intelligence analysis")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_threat_intel_get)

    p = sub.add_parser("run-threat-intel-get", help="Get a run's Threat Intelligence analysis")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.set_defaults(func=cmd_run_threat_intel_get)

    p = sub.add_parser(
        "run-threat-intel-trigger", help="(Re-)trigger Threat Intelligence analysis for a run"
    )
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.set_defaults(func=cmd_run_threat_intel_trigger)

    # Comparison
    p = sub.add_parser("compare", help="Compare hunt runs and persist a comparison report")
    _pkg_id_arg(p)
    _provider_model_args(p)
    _json_body_args(p, 'run_ids, e.g. \'["run-id-1", "run-id-2"]\' (omit for all runs)')
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("comparison-get", help="Get the latest comparison report")
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_comparison_get)

    p = sub.add_parser("comparison-markdown", help="Download the comparison report as Markdown")
    _pkg_id_arg(p)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_comparison_markdown)

    p = sub.add_parser("comparison-pdf", help="Download the comparison report as PDF")
    _pkg_id_arg(p)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_comparison_pdf)

    # Run Comments
    p = sub.add_parser("comments-list", help="List analyst comments on a run")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.set_defaults(func=cmd_comments_list)

    p = sub.add_parser("comment-add", help="Post a comment on a run")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.add_argument("--body", required=True)
    p.set_defaults(func=cmd_comment_add)

    p = sub.add_parser("comment-delete", help="Delete a run comment")
    _pkg_id_arg(p)
    _run_id_arg(p)
    p.add_argument("comment_id")
    p.set_defaults(func=cmd_comment_delete)

    # Threat Intel Tracking
    p = sub.add_parser("tracking-dashboard", help="Cross-hunt Threat Intel Tracking aggregation")
    p.add_argument("--search", default=None, help="Substring filter on the IOCs/CVEs panels")
    p.set_defaults(func=cmd_tracking_dashboard)

    p = sub.add_parser("tracking-hunts", help="List hunts with their correlation-inclusion state")
    p.set_defaults(func=cmd_tracking_hunts)

    p = sub.add_parser("tracking-exclude", help="Include/exclude a hunt from tracking aggregation")
    _pkg_id_arg(p)
    p.add_argument("--excluded", type=lambda v: v.lower() in ("1", "true", "yes"), required=True)
    p.set_defaults(func=cmd_tracking_exclude)

    p = sub.add_parser(
        "tracking-delete", help="Permanently archive a hunt from the Tracking Hunts tab"
    )
    _pkg_id_arg(p)
    p.set_defaults(func=cmd_tracking_delete)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.url = normalize_url(args.url)
        opener = build_opener(args.insecure)
        if args.username:
            password = args.password
            if password is None:
                password = getpass.getpass(f"Password for {args.username}: ")
            login(opener, args.url, args.username, password)
        client = Client(opener, args.url, args.api_key)
        args.func(client, args)
        return 0
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        if exc.code == 401:
            print(
                f"HTTP 401 Unauthorized: {detail}\n"
                "Hint: pass --username (session login) or --api-key (Bearer token) — "
                "and if using --api-key, confirm Programmatic API access is enabled "
                "in Configuration -> General -> API Access.",
                file=sys.stderr,
            )
        elif exc.code == 403:
            print(
                f"HTTP 403 Forbidden: {detail}\n"
                "Hint: a session account needs threat-researcher/admin for writes "
                "(threat-viewer is read-only); an API key needs a scope that covers "
                "this route — see docs/api-threat-hunting.md.",
                file=sys.stderr,
            )
        else:
            print(f"HTTP {exc.code} {exc.reason}: {detail}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"Connection error: {exc.reason}", file=sys.stderr)
        return 1
    except http.client.HTTPException as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
