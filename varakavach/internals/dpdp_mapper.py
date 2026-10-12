"""
DPDP Act 2023 Compliance Mapper
Maps detected PII/sensitive data patterns to obligations under India's
Digital Personal Data Protection Act 2023 and CERT-In §70B Directions.
"""

# Maps each fingerprint pattern_name to its DPDP classification and obligations
DPDP_PATTERN_MAP = {
    "Aadhaar Number": {
        "data_category": "Sensitive Personal Data",
        "dpdp_section": "Section 2(t) – Sensitive Personal Data; Aadhaar Act 2016",
        "obligation": "Section 4 – Lawful Processing; Section 8(6) – Breach Notification; Section 16 – Children's Data (if applicable)",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Breach must be reported to CERT-In within 6 hours",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Mask Aadhaar numbers at rest using AES-256 encryption",
            "Restrict access via RBAC — only authorized personnel",
            "Obtain explicit consent before collecting Aadhaar (Section 6)",
            "Maintain processing logs for 180 days (CERT-In §70B)",
            "Have a breach response plan to notify CERT-In within 6 hours",
        ],
    },
    "PAN Card": {
        "data_category": "Sensitive Personal Data",
        "dpdp_section": "Section 2(t) – Financial Identifier; Income Tax Act 1961",
        "obligation": "Section 4 – Lawful Processing; Section 8(3) – Data Accuracy; Section 8(7) – Erasure",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Breach must be reported within 6 hours",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Encrypt PAN at rest using AES-256",
            "Apply tokenisation before storing in databases",
            "Limit retention to the period required by law, then erase (Section 8(7))",
            "Audit access logs monthly",
        ],
    },
    "Indian Passport Number": {
        "data_category": "Sensitive Personal Data",
        "dpdp_section": "Section 2(t) – Government-issued identifier",
        "obligation": "Section 4 – Lawful Processing; Section 8(6) – Breach Notification",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify CERT-In within 6 hours of breach",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Encrypt passport numbers using field-level encryption",
            "Do not store copies beyond what is operationally necessary",
            "Apply data minimisation principle (collect only what is needed)",
        ],
    },
    "Indian Voter ID": {
        "data_category": "Sensitive Personal Data",
        "dpdp_section": "Section 2(t) – Government-issued identifier",
        "obligation": "Section 4 – Lawful Processing; Section 8(6) – Breach Notification",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify CERT-In within 6 hours of breach",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Encrypt Voter ID at rest",
            "Limit access to authorised users only via RBAC",
        ],
    },
    "Indian Driving Licence": {
        "data_category": "Sensitive Personal Data",
        "dpdp_section": "Section 2(t) – Government-issued identifier",
        "obligation": "Section 4 – Lawful Processing; Section 8(6) – Breach Notification",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify CERT-In within 6 hours of breach",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Apply AES-256 encryption on DL numbers",
            "Collect only with explicit consent and for a defined purpose",
        ],
    },
    "Biometric Data Reference": {
        "data_category": "Sensitive Personal Data",
        "dpdp_section": "Section 2(t) – Biometric Data; highest DPDP protection category",
        "obligation": "Section 4 – Lawful Processing; Section 6 – Explicit Consent; Section 8(6) – Breach Notification",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Immediate CERT-In notification required",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Never store raw biometric data — store only cryptographic hashes",
            "Obtain explicit written consent before collection (Section 6)",
            "Implement HSM (Hardware Security Module) for biometric storage",
            "Conduct DPIA (Data Protection Impact Assessment) before processing",
        ],
    },
    "Health Record ID": {
        "data_category": "Sensitive Personal Data",
        "dpdp_section": "Section 2(t) – Health Data; ABDM/DISHA compliance required",
        "obligation": "Section 4 – Lawful Processing; Section 6 – Explicit Consent; Section 9 – Children's Data",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Health breaches must be reported within 6 hours",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Store health data in encrypted databases with row-level security",
            "Obtain specific consent for each health data processing purpose",
            "Comply with ABDM (Ayushman Bharat Digital Mission) data standards",
        ],
    },
    "Caste or Religion Field": {
        "data_category": "Sensitive Personal Data",
        "dpdp_section": "Section 2(t) – Special Category Data",
        "obligation": "Section 4 – Lawful Processing requires explicit justification; Section 6 – Explicit Consent",
        "cert_in_applicable": False,
        "cert_in_rule": "N/A",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Justify the lawful basis for storing this category of data",
            "Obtain explicit and specific consent",
            "Consider whether this data can be deleted entirely",
        ],
    },
    "Email Address": {
        "data_category": "Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data",
        "obligation": "Section 4 – Lawful Processing; Section 7 – Notice; Section 8(7) – Erasure on Request",
        "cert_in_applicable": False,
        "cert_in_rule": "N/A (unless breach involves >10,000 records)",
        "penalty_tier": "Tier 3",
        "max_penalty_inr": "₹50 Crore",
        "risk_level": "medium",
        "remediation": [
            "Provide clear notice of data use (Section 7)",
            "Allow data principals to request erasure (Section 12)",
            "Do not share email addresses with third parties without consent",
        ],
    },
    "Indian Mobile Number": {
        "data_category": "Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data; TRAI TCCCPR 2018",
        "obligation": "Section 4 – Lawful Processing; Section 7 – Notice; Section 8(7) – Erasure",
        "cert_in_applicable": False,
        "cert_in_rule": "N/A (unless breach involves >10,000 records)",
        "penalty_tier": "Tier 3",
        "max_penalty_inr": "₹50 Crore",
        "risk_level": "medium",
        "remediation": [
            "Hash or mask mobile numbers in non-production environments",
            "Ensure TCCCPR 2018 compliance for marketing communications",
            "Provide opt-out mechanism for data principals",
        ],
    },
    "Date of Birth": {
        "data_category": "Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data; Section 9 – Children's Data (if DOB < 18)",
        "obligation": "Section 9 – Verifiable Parental Consent for minors; Section 4 – Lawful Processing",
        "cert_in_applicable": False,
        "cert_in_rule": "N/A",
        "penalty_tier": "Tier 2",
        "max_penalty_inr": "₹200 Crore",
        "risk_level": "high",
        "remediation": [
            "Check if DOB indicates a minor — if yes, verify parental consent (Section 9)",
            "Do not profile children based on DOB",
            "Apply data minimisation — only collect DOB when strictly necessary",
        ],
    },
    "Gender Field": {
        "data_category": "Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data",
        "obligation": "Section 4 – Lawful Processing; Section 7 – Notice",
        "cert_in_applicable": False,
        "cert_in_rule": "N/A",
        "penalty_tier": "Tier 3",
        "max_penalty_inr": "₹50 Crore",
        "risk_level": "low",
        "remediation": [
            "Justify collection — is gender required for the service?",
            "Provide notice of use (Section 7)",
        ],
    },
    "Physical Address": {
        "data_category": "Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data",
        "obligation": "Section 4 – Lawful Processing; Section 8(3) – Data Accuracy; Section 8(7) – Erasure",
        "cert_in_applicable": False,
        "cert_in_rule": "N/A",
        "penalty_tier": "Tier 3",
        "max_penalty_inr": "₹50 Crore",
        "risk_level": "medium",
        "remediation": [
            "Encrypt address fields at rest",
            "Implement data accuracy mechanisms — allow users to update their address",
            "Restrict address access to fulfilment/logistics systems only",
        ],
    },
    "Full Name Field": {
        "data_category": "Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data",
        "obligation": "Section 4 – Lawful Processing; Section 7 – Notice",
        "cert_in_applicable": False,
        "cert_in_rule": "N/A",
        "penalty_tier": "Tier 3",
        "max_penalty_inr": "₹50 Crore",
        "risk_level": "low",
        "remediation": [
            "Anonymise name fields in analytics pipelines",
            "Ensure names are not exposed in logs or error messages",
        ],
    },
    "IP Address": {
        "data_category": "Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data (linked to a person)",
        "obligation": "Section 4 – Lawful Processing; CERT-In §70B – Log Retention 180 days",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Logs containing IP addresses must be retained for 180 days",
        "penalty_tier": "Tier 3",
        "max_penalty_inr": "₹50 Crore",
        "risk_level": "low",
        "remediation": [
            "Retain IP address logs for exactly 180 days (CERT-In §70B) — not more, not less",
            "Anonymise IPs in analytics (last octet masking)",
            "Do not share IP logs with third parties without valid legal basis",
        ],
    },
    "GSTIN": {
        "data_category": "Business Identifier / Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data for proprietors/individuals; GST Act 2017",
        "obligation": "Section 4 – Lawful Processing; data minimisation",
        "cert_in_applicable": False,
        "cert_in_rule": "N/A",
        "penalty_tier": "Tier 3",
        "max_penalty_inr": "₹50 Crore",
        "risk_level": "low",
        "remediation": [
            "Restrict GSTIN access to finance/billing systems only",
            "Do not expose GSTIN in front-end or public APIs",
        ],
    },
    "Indian Bank Account Number": {
        "data_category": "Sensitive Personal Data",
        "dpdp_section": "Section 2(t) – Financial Data; RBI Circular DPSS.CO.OD No.1016/2019",
        "obligation": "Section 4 – Lawful Processing; Section 8(6) – Breach Notification; RBI PCI-DSS",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Financial data breach notification within 6 hours",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Apply tokenisation for bank account numbers — store tokens, not raw numbers",
            "Comply with RBI PCI-DSS guidelines",
            "Implement field-level encryption",
            "Never log bank account numbers in application logs",
        ],
    },
    "UPI ID": {
        "data_category": "Financial Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data; NPCI UPI Ecosystem guidelines",
        "obligation": "Section 4 – Lawful Processing; Section 8(6) – Breach Notification",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Financial data breach notification within 6 hours",
        "penalty_tier": "Tier 2",
        "max_penalty_inr": "₹200 Crore",
        "risk_level": "high",
        "remediation": [
            "Do not store UPI IDs in plaintext — encrypt or tokenise",
            "Restrict UPI ID access to payment processing systems only",
        ],
    },
    "Credit Card Number": {
        "data_category": "Sensitive Financial Data",
        "dpdp_section": "Section 2(t) – Financial Data; PCI-DSS; RBI Guidelines",
        "obligation": "Section 4 – Lawful Processing; Section 8(6) – Breach Notification; PCI-DSS Requirement 3",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Immediate breach notification required",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "NEVER store full card numbers — PCI-DSS prohibits this",
            "Use payment gateway tokenisation (Razorpay, PayU, Stripe)",
            "If found in storage, treat as a live breach — notify CERT-In immediately",
            "Conduct a forensic audit of how cards ended up in this location",
        ],
    },
    "IFSC Code": {
        "data_category": "Financial Reference Data",
        "dpdp_section": "Section 2(x) – when linked to a personal bank account",
        "obligation": "Section 4 – Lawful Processing; data minimisation",
        "cert_in_applicable": False,
        "cert_in_rule": "N/A (unless found alongside bank account number)",
        "penalty_tier": "Tier 3",
        "max_penalty_inr": "₹50 Crore",
        "risk_level": "low",
        "remediation": [
            "Restrict access to IFSC + account combinations to payment systems",
        ],
    },
    "AWS Access Key ID": {
        "data_category": "Credential / Secret",
        "dpdp_section": "Not personal data — but enables access to personal data stores",
        "obligation": "CERT-In §70B – Exposed credentials are an incident; Section 8 – Data Fiduciary duty to protect",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify CERT-In within 6 hours of credential exposure incident",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore (if breach of personal data results)",
        "risk_level": "critical",
        "remediation": [
            "Rotate the exposed key IMMEDIATELY via AWS IAM console",
            "Audit CloudTrail for actions taken with the exposed key",
            "Move to IAM Roles — eliminate long-lived access keys",
            "Add pre-commit hooks to prevent key commits (git-secrets, trufflehog)",
            "Notify CERT-In within 6 hours if personal data was accessed",
        ],
    },
    "AWS Secret Key Pattern": {
        "data_category": "Credential / Secret",
        "dpdp_section": "Not personal data — enables access to personal data stores",
        "obligation": "CERT-In §70B – Incident notification; Section 8 – Data Fiduciary duty",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify CERT-In within 6 hours",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore (if personal data breach results)",
        "risk_level": "critical",
        "remediation": [
            "Rotate secret key immediately",
            "Use AWS Secrets Manager instead of hardcoded secrets",
            "Revoke and re-issue all tokens that may have been derived",
        ],
    },
    "Google API Key": {
        "data_category": "Credential / Secret",
        "dpdp_section": "Enables access to personal data — CERT-In §70B",
        "obligation": "CERT-In §70B – Incident notification; Section 8 – Data Fiduciary duty",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify CERT-In within 6 hours if data was accessed",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore (if personal data breach results)",
        "risk_level": "critical",
        "remediation": [
            "Revoke and regenerate the Google API key immediately",
            "Restrict API key by IP and referrer in Google Cloud Console",
            "Use Application Default Credentials (ADC) instead of API keys",
        ],
    },
    "Google Service Account": {
        "data_category": "Credential / Secret",
        "dpdp_section": "Enables access to personal data stores — CERT-In §70B",
        "obligation": "CERT-In §70B; Section 8 – Data Fiduciary duty",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Report if personal data could have been accessed",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Revoke the service account key from GCP IAM console immediately",
            "Never commit service account JSON files to version control",
            "Use Workload Identity Federation instead of service account key files",
        ],
    },
    "Slack Bot Token": {
        "data_category": "Credential / Secret",
        "dpdp_section": "Enables access to communications containing personal data",
        "obligation": "CERT-In §70B; Section 8 – Data Fiduciary duty to protect",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify CERT-In if personal data in Slack was exposed",
        "penalty_tier": "Tier 2",
        "max_penalty_inr": "₹200 Crore",
        "risk_level": "high",
        "remediation": [
            "Revoke the Slack token immediately at api.slack.com/apps",
            "Use environment variables or Vault for Slack tokens",
        ],
    },
    "Slack User Token": {
        "data_category": "Credential / Secret",
        "dpdp_section": "Enables access to personal communications",
        "obligation": "CERT-In §70B; Section 8 – Data Fiduciary duty",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify if personal data was accessible",
        "penalty_tier": "Tier 2",
        "max_penalty_inr": "₹200 Crore",
        "risk_level": "high",
        "remediation": [
            "Revoke token at api.slack.com/apps immediately",
            "Audit all Slack messages accessed with this token",
        ],
    },
    "Generic API Secret": {
        "data_category": "Credential / Secret",
        "dpdp_section": "CERT-In §70B if it protects personal data",
        "obligation": "CERT-In §70B; Section 8 – Data Fiduciary duty",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify within 6 hours if personal data exposed",
        "penalty_tier": "Tier 2",
        "max_penalty_inr": "₹200 Crore",
        "risk_level": "high",
        "remediation": [
            "Rotate the exposed secret immediately",
            "Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)",
            "Audit access logs to determine if personal data was accessed",
        ],
    },
    "Private Key Header": {
        "data_category": "Cryptographic Secret",
        "dpdp_section": "CERT-In §70B – Compromised private key is a security incident",
        "obligation": "CERT-In §70B; Section 8 – Data Fiduciary duty",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify CERT-In within 6 hours",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Treat as a live compromise — revoke the certificate immediately",
            "Issue a new key pair and rotate all certificates signed by this key",
            "Investigate how the private key ended up in this location",
        ],
    },
    "JWT Token": {
        "data_category": "Authentication Token",
        "dpdp_section": "Section 2(x) – May contain personal data claims; CERT-In §70B",
        "obligation": "CERT-In §70B; Section 8 – Data Fiduciary duty",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – If token grants access to personal data",
        "penalty_tier": "Tier 2",
        "max_penalty_inr": "₹200 Crore",
        "risk_level": "high",
        "remediation": [
            "Revoke the JWT signing secret and force re-authentication",
            "Implement short JWT expiry (15 minutes max)",
            "Never log JWTs — they are equivalent to passwords",
        ],
    },
    "Database Connection String": {
        "data_category": "Credential / Secret",
        "dpdp_section": "Enables direct access to personal data — CERT-In §70B",
        "obligation": "CERT-In §70B; Section 8 – Data Fiduciary duty",
        "cert_in_applicable": True,
        "cert_in_rule": "§70B – Notify within 6 hours if personal data exposed",
        "penalty_tier": "Tier 1",
        "max_penalty_inr": "₹250 Crore",
        "risk_level": "critical",
        "remediation": [
            "Rotate database credentials immediately",
            "Store connection strings in environment variables or secrets manager",
            "Restrict DB access by IP allowlist and IAM roles",
            "Audit the database for unauthorised queries since exposure",
        ],
    },
}

# Penalty tier descriptions
PENALTY_TIERS = {
    "Tier 1": {
        "amount": "₹250 Crore",
        "triggers": "Failure to protect sensitive personal data; major breach; Aadhaar/financial/biometric exposure",
    },
    "Tier 2": {
        "amount": "₹200 Crore",
        "triggers": "Failure to notify breach; non-compliance with data principal rights; UPI/auth token exposure",
    },
    "Tier 3": {
        "amount": "₹50 Crore",
        "triggers": "Failure to maintain data accuracy; inadequate notice; minor personal data exposure",
    },
}

# CERT-In §70B mandatory reporting timelines
CERT_IN_OBLIGATIONS = {
    "breach_notification_hours": 6,
    "log_retention_days": 180,
    "incident_types": [
        "Aadhaar/PAN/biometric/financial data breach",
        "Credential (API key, private key, DB connection string) exposure",
        "Unauthorised access to personal data systems",
    ],
}


def get_dpdp_info(pattern_name: str) -> dict:
    """Return DPDP compliance info for a given pattern name, or a default if unmapped."""
    return DPDP_PATTERN_MAP.get(pattern_name, {
        "data_category": "Personal Data",
        "dpdp_section": "Section 2(x) – Personal Data",
        "obligation": "Section 4 – Lawful Processing",
        "cert_in_applicable": False,
        "cert_in_rule": "Review against CERT-In §70B",
        "penalty_tier": "Tier 3",
        "max_penalty_inr": "₹50 Crore",
        "risk_level": "medium",
        "remediation": ["Review data collection justification", "Ensure explicit consent is obtained"],
    })


def build_compliance_summary(grouped_results: dict) -> dict:
    """
    Aggregate all findings into a DPDP compliance summary.
    Returns penalty exposure, CERT-In breach triggers, and obligation gaps.
    """
    total_findings = 0
    critical_count = 0
    cert_in_triggers = []
    penalty_exposure = set()
    obligation_gaps = set()
    data_categories_found = set()

    for source, findings in grouped_results.items():
        for finding in findings:
            total_findings += 1
            pattern = finding.get("pattern_name", "")
            info = get_dpdp_info(pattern)

            if info["risk_level"] == "critical":
                critical_count += 1

            if info["cert_in_applicable"]:
                cert_in_triggers.append({
                    "pattern": pattern,
                    "source": source,
                    "rule": info["cert_in_rule"],
                })

            penalty_exposure.add(info["penalty_tier"])
            obligation_gaps.add(info["obligation"])
            data_categories_found.add(info["data_category"])

    highest_penalty = "Tier 3"
    if "Tier 1" in penalty_exposure:
        highest_penalty = "Tier 1"
    elif "Tier 2" in penalty_exposure:
        highest_penalty = "Tier 2"

    return {
        "total_findings": total_findings,
        "critical_findings": critical_count,
        "cert_in_breach_triggers": cert_in_triggers,
        "cert_in_breach_notification_required": len(cert_in_triggers) > 0,
        "cert_in_notification_window_hours": CERT_IN_OBLIGATIONS["breach_notification_hours"],
        "log_retention_days_required": CERT_IN_OBLIGATIONS["log_retention_days"],
        "highest_penalty_tier": highest_penalty,
        "max_penalty_exposure": PENALTY_TIERS[highest_penalty]["amount"],
        "penalty_trigger_reason": PENALTY_TIERS[highest_penalty]["triggers"],
        "obligation_gaps": list(obligation_gaps),
        "data_categories_found": list(data_categories_found),
        "dpdp_act_sections_triggered": sorted(set(
            get_dpdp_info(f.get("pattern_name", ""))["dpdp_section"]
            for findings in grouped_results.values()
            for f in findings
        )),
    }
