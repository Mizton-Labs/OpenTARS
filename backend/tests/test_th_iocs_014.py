"""Tests for issue-local-014 IOC parsing/verification consistency:
redaction/defanging handling and consolidated noise thresholds."""

from __future__ import annotations

from backend.threat_hunting.iocs import (
    HIGH_NOISE_THRESHOLD,
    NOISE_THRESHOLD,
    _defang,
    extract_iocs_from_text,
)


class TestDefang:
    def test_bracket_dot(self):
        assert _defang("evil[.]com") == "evil.com"

    def test_paren_dot(self):
        assert _defang("evil(.)com") == "evil.com"

    def test_brace_dot(self):
        assert _defang("evil{.}com") == "evil.com"

    def test_word_dot(self):
        assert _defang("evil[dot]com") == "evil.com"
        assert _defang("evil(dot)com") == "evil.com"

    def test_hxxp(self):
        assert _defang("hxxp://evil.com") == "http://evil.com"
        assert _defang("hxxps://evil.com") == "https://evil.com"

    def test_hxxp_bracketed_proto(self):
        assert _defang("hxxp[://]evil.com") == "http://evil.com"

    def test_at_defang(self):
        assert _defang("user[at]evil.com") == "user@evil.com"
        assert _defang("user(at)evil.com") == "user@evil.com"

    def test_idempotent_on_clean_text(self):
        assert _defang("evil.com") == "evil.com"
        assert _defang("http://evil.com") == "http://evil.com"

    def test_multiple_redactions_in_one_string(self):
        assert _defang("hxxp://sub[.]evil[.]com/path") == "http://sub.evil.com/path"


class TestExtractionOnRedactedText:
    def test_defanged_domain_is_extracted(self):
        iocs = extract_iocs_from_text("Traffic was seen going to evil[.]com over the weekend.")
        domains = [i["ioc"] for i in iocs if i["ioc_type"] == "domain"]
        assert "evil.com" in domains

    def test_defanged_ip_is_extracted(self):
        iocs = extract_iocs_from_text("Beaconing observed to 192[.]168[.]1[.]50 hourly.")
        ips = [i["ioc"] for i in iocs if i["ioc_type"] == "ip"]
        assert "192.168.1.50" in ips

    def test_defanged_url_is_extracted(self):
        iocs = extract_iocs_from_text("Payload dropped from hxxp://bad-domain[.]net/x.exe")
        urls = [i["ioc"] for i in iocs if i["ioc_type"] == "url"]
        assert any("bad-domain.net" in u for u in urls)

    def test_defanged_email_is_extracted(self):
        iocs = extract_iocs_from_text("Phishing sent from attacker[at]evil[.]com to targets.")
        emails = [i["ioc"] for i in iocs if i["ioc_type"] == "email"]
        assert "attacker@evil.com" in emails

    def test_defanged_and_normal_forms_dedupe(self):
        # Same domain, redacted once and plain once — must not double-count.
        iocs = extract_iocs_from_text("Seen at evil[.]com and again at evil.com in logs.")
        domains = [i["ioc"] for i in iocs if i["ioc_type"] == "domain"]
        assert domains.count("evil.com") == 1


class TestNoiseThresholdConsistency:
    def test_threshold_constants_ordering(self):
        assert 0.0 < NOISE_THRESHOLD < HIGH_NOISE_THRESHOLD < 1.0

    def test_flagged_noisy_matches_threshold_constant(self):
        # A private IP scores 0.95, well above NOISE_THRESHOLD — must be flagged.
        iocs = extract_iocs_from_text("Internal host 10.0.0.5 talked to evil.com.")
        private_ip = next(i for i in iocs if i["ioc"] == "10.0.0.5")
        assert private_ip["noise_score"] >= NOISE_THRESHOLD
        assert private_ip["flagged_noisy"] is True
