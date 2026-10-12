"""
VaraKavach Tests
Tests the core DPDP compliance detection engine end-to-end.
"""
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from varakavach.internals.dpdp_mapper import get_dpdp_info, build_compliance_summary, DPDP_PATTERN_MAP


# ── dpdp_mapper tests ────────────────────────────────────────────────────────

def test_aadhaar_mapping():
    info = get_dpdp_info("Aadhaar Number")
    assert info["risk_level"] == "critical"
    assert info["penalty_tier"] == "Tier 1"
    assert info["cert_in_applicable"] is True
    assert "₹250 Crore" in info["max_penalty_inr"]
    assert len(info["remediation"]) > 0


def test_pan_mapping():
    info = get_dpdp_info("PAN Card")
    assert info["risk_level"] == "critical"
    assert info["penalty_tier"] == "Tier 1"
    assert info["cert_in_applicable"] is True


def test_email_mapping():
    info = get_dpdp_info("Email Address")
    assert info["risk_level"] == "medium"
    assert info["penalty_tier"] == "Tier 3"
    assert info["cert_in_applicable"] is False


def test_credit_card_mapping():
    info = get_dpdp_info("Credit Card Number")
    assert info["risk_level"] == "critical"
    assert info["cert_in_applicable"] is True


def test_unknown_pattern_fallback():
    info = get_dpdp_info("Unknown Pattern XYZ")
    assert "data_category" in info
    assert "risk_level" in info
    assert info["risk_level"] == "medium"


def test_all_patterns_have_remediation():
    for pattern_name, info in DPDP_PATTERN_MAP.items():
        assert len(info.get("remediation", [])) > 0, f"No remediation for {pattern_name}"


def test_compliance_summary_critical_trigger():
    grouped = {
        "fs": [
            {"pattern_name": "Aadhaar Number", "matches": ["1234 5678 9012"]},
            {"pattern_name": "Credit Card Number", "matches": ["4111111111111111"]},
        ]
    }
    summary = build_compliance_summary(grouped)
    assert summary["total_findings"] == 2
    assert summary["critical_findings"] == 2
    assert summary["highest_penalty_tier"] == "Tier 1"
    assert summary["cert_in_breach_notification_required"] is True
    assert summary["max_penalty_exposure"] == "₹250 Crore"


def test_compliance_summary_no_findings():
    summary = build_compliance_summary({})
    assert summary["total_findings"] == 0
    assert summary["critical_findings"] == 0
    assert summary["cert_in_breach_notification_required"] is False


def test_compliance_summary_low_only():
    grouped = {
        "text": [
            {"pattern_name": "GSTIN", "matches": ["22AAAAA0000A1Z5"]},
        ]
    }
    summary = build_compliance_summary(grouped)
    assert summary["highest_penalty_tier"] == "Tier 3"
    assert summary["cert_in_breach_notification_required"] is False


# ── regex fingerprint tests ────────────────────────────────────────────────────

def test_fingerprint_patterns_loaded():
    import yaml
    fp_path = os.path.join(os.path.dirname(__file__), "..", "varakavach_fingerprint.yml")
    assert os.path.exists(fp_path), "varakavach_fingerprint.yml not found"
    with open(fp_path) as f:
        patterns = yaml.safe_load(f)
    assert "Aadhaar Number" in patterns
    assert "PAN Card" in patterns
    assert "Email Address" in patterns
    assert "AWS Access Key ID" in patterns
    assert "Credit Card Number" in patterns


def test_aadhaar_regex_matches():
    import re
    import yaml
    fp_path = os.path.join(os.path.dirname(__file__), "..", "varakavach_fingerprint.yml")
    with open(fp_path) as f:
        patterns = yaml.safe_load(f)
    regex = re.compile(patterns["Aadhaar Number"], re.IGNORECASE)
    assert regex.search("1234 5678 9012")
    assert regex.search("1234-5678-9012")
    assert regex.search("123456789012")
    assert not regex.search("12345")


def test_pan_regex_matches():
    import re
    import yaml
    fp_path = os.path.join(os.path.dirname(__file__), "..", "varakavach_fingerprint.yml")
    with open(fp_path) as f:
        patterns = yaml.safe_load(f)
    regex = re.compile(patterns["PAN Card"], re.IGNORECASE)
    assert regex.search("ABCDE1234F")
    assert not regex.search("ABC1234F")


def test_email_regex_matches():
    import re
    import yaml
    fp_path = os.path.join(os.path.dirname(__file__), "..", "varakavach_fingerprint.yml")
    with open(fp_path) as f:
        patterns = yaml.safe_load(f)
    regex = re.compile(patterns["Email Address"], re.IGNORECASE)
    assert regex.search("john.doe@example.com")
    assert regex.search("helisha@company.in")
    assert not regex.search("notanemail")


if __name__ == "__main__":
    test_aadhaar_mapping()
    test_pan_mapping()
    test_email_mapping()
    test_credit_card_mapping()
    test_unknown_pattern_fallback()
    test_all_patterns_have_remediation()
    test_compliance_summary_critical_trigger()
    test_compliance_summary_no_findings()
    test_compliance_summary_low_only()
    test_fingerprint_patterns_loaded()
    test_aadhaar_regex_matches()
    test_pan_regex_matches()
    test_email_regex_matches()
    print("All VaraKavach tests passed.")
