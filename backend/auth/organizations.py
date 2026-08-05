"""
Organization management (issue-local-037).

An Organization is a lightweight (name, email_domain) pair. Users may
optionally be associated with one — used two ways:

  1. Manual admin user creation/org-change (backend/api/routes_auth.py) — the
     admin picks an org and an "email-username" toggle; the FINAL stored
     username is always built HERE, server-side, from a validated local-part
     + the org's own (trusted, DB-stored) email_domain — never from a
     client-typed full email string — so a stored username can never drift
     from what's actually configured for that org.

  2. SSO auto-provisioning/re-login (backend/auth/oidc.py) — an SSO user's
     username (already IdP-supplied, often already email-shaped) is matched
     against configured orgs by domain, best-effort, and org_id is set
     opportunistically. The username itself is NEVER touched by the SSO
     path — see oidc.py's _upsert_sso_user docstring for why (changing a
     user's login identifier as a side effect of an automated background
     login step would be surprising in a way an explicit admin action isn't).
"""

from __future__ import annotations

import re

# The admin-typed username LOCAL-PART (everything before any org-domain
# suffix this module may append) is validated with routes_auth.py's existing
# _validate_username()/_USERNAME_RE — deliberately NOT re-declared here, so
# there is exactly one place that decides what a valid local-part looks
# like, for both org-less and org-aware users alike.

# A bare domain — no scheme, no path, no '@'. Deliberately stricter than a
# full email-address regex since this validates the DOMAIN half only.
_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

_MAX_ORG_NAME_LEN = 100
_MAX_DOMAIN_LEN = 253  # RFC 1035 full-domain-name limit


def validate_organization(name: str, email_domain: str) -> tuple[str, str]:
    """Validate and normalise (name, email_domain). Returns the normalised
    pair (email_domain lower-cased). Raises ValueError with an admin-facing
    message on invalid input."""
    name = (name or "").strip()
    if not name:
        raise ValueError("Organization name is required")
    if len(name) > _MAX_ORG_NAME_LEN:
        raise ValueError(f"Organization name must be at most {_MAX_ORG_NAME_LEN} characters")

    email_domain = (email_domain or "").strip().lower()
    if not email_domain:
        raise ValueError("Email domain is required")
    if len(email_domain) > _MAX_DOMAIN_LEN:
        raise ValueError(f"Email domain must be at most {_MAX_DOMAIN_LEN} characters")
    if not _DOMAIN_RE.match(email_domain):
        raise ValueError(
            "Email domain must be a bare domain (e.g. 'acme.com') — no scheme, path, or '@'"
        )
    return name, email_domain


def build_username(local_part: str, org: dict | None, use_email_username: bool) -> str:
    """Build the FINAL username to store, given an already-validated local-part.

    - org is None ("Local user"): the username is just the local-part.
    - org is set AND use_email_username: "{local_part}@{org['email_domain']}"
      — the domain always comes from the trusted Organizations table row,
      never from client input, so the result can never disagree with what's
      actually configured for that org.
    - org is set but NOT use_email_username: the username stays the bare
      local-part — the org is still recorded (org_id), just not reflected in
      the login identifier.
    """
    if org is not None and use_email_username:
        return f"{local_part}@{org['email_domain']}"
    return local_part


def local_part_of(username: str) -> str:
    """Return the local-part of a (possibly email-shaped) username — used
    when an org change recomputes a NEW username from an user's EXISTING
    one, preserving whatever identifier they already had."""
    return username.split("@", 1)[0]


def domain_of_email(email_like: str) -> str | None:
    """Extract a lower-cased domain from an email-shaped string, or None if
    it isn't one (no '@', or nothing after it). Used by oidc.py for
    best-effort org auto-matching — this only does the string-parsing half;
    the actual lookup is backend.auth.db.get_organization_by_domain."""
    if "@" not in email_like:
        return None
    domain = email_like.rsplit("@", 1)[-1].strip().lower()
    return domain or None
