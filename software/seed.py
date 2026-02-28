"""
seed.py — Populate the database with starter data for SRATMWA.

Run: python seed.py
"""

from app import create_app, db
from app.models import Asset, Threat, Vulnerability, RiskEntry, Control, ChecklistItem

app = create_app()

ASSETS = [
    {"name": "Browser Client", "layer": "Client Layer", "description": "End-user web browser interface."},
    {"name": "Mobile Client", "layer": "Client Layer", "description": "Native or PWA mobile application."},
    {"name": "CDN / WAF", "layer": "Perimeter", "description": "Content delivery network and web application firewall."},
    {"name": "Load Balancer", "layer": "Perimeter", "description": "Distributes inbound requests across app servers."},
    {"name": "REST API", "layer": "Application Layer", "description": "Primary backend REST API surface."},
    {"name": "GraphQL API", "layer": "Application Layer", "description": "GraphQL query interface."},
    {"name": "OAuth 2.0 / OIDC Provider", "layer": "Auth Layer", "description": "Identity and access management system."},
    {"name": "Session Manager", "layer": "Auth Layer", "description": "Server-side session store and management."},
    {"name": "Business Logic Service", "layer": "Backend Layer", "description": "Core application business rules."},
    {"name": "Relational Database", "layer": "Data Layer", "description": "Primary SQL database (PostgreSQL/MySQL)."},
    {"name": "Redis Cache", "layer": "Data Layer", "description": "In-memory cache layer."},
    {"name": "Object Storage", "layer": "Data Layer", "description": "Cloud object storage (S3-compatible)."},
    {"name": "Third-party APIs", "layer": "External Integrations", "description": "External service integrations."},
    {"name": "Payment Gateway", "layer": "External Integrations", "description": "Payment processing provider."},
]

THREATS = [
    {
        "title": "JWT Token Forgery via Weak Secret",
        "stride_category": "Spoofing",
        "description": "Attacker forges a JWT by exploiting a weak or default signing secret to impersonate arbitrary users.",
        "entry_point": "POST /api/auth/login",
        "attack_vector": "Network",
        "component": "AUTH",
        "pasta_stage": 6,
        "dread_damage": 9, "dread_reproducibility": 7, "dread_exploitability": 8,
        "dread_affected_users": 9, "dread_discoverability": 6,
        "mitigations": "Use strong random secrets (≥256-bit). Prefer RS256 asymmetric signing. Enforce token expiry.",
        "status": "Open",
    },
    {
        "title": "SQL Injection via User-Supplied Search Parameter",
        "stride_category": "Tampering",
        "description": "Unsanitised search query parameter passed directly into SQL, allowing data extraction or destruction.",
        "entry_point": "GET /api/search?q=",
        "attack_vector": "Network",
        "component": "API",
        "pasta_stage": 5,
        "dread_damage": 10, "dread_reproducibility": 9, "dread_exploitability": 8,
        "dread_affected_users": 10, "dread_discoverability": 8,
        "mitigations": "Use parameterised queries / ORM. Apply input validation. Least-privilege DB accounts.",
        "status": "Open",
    },
    {
        "title": "Missing Audit Logging on Privileged Actions",
        "stride_category": "Repudiation",
        "description": "Administrative actions (role changes, data deletions) are not logged, preventing forensic reconstruction.",
        "entry_point": "POST /api/admin/*",
        "attack_vector": "Network",
        "component": "ADMN",
        "pasta_stage": 4,
        "dread_damage": 6, "dread_reproducibility": 10, "dread_exploitability": 3,
        "dread_affected_users": 7, "dread_discoverability": 9,
        "mitigations": "Implement structured audit logging. Use tamper-evident log storage. Alert on anomalous admin actions.",
        "status": "Open",
    },
    {
        "title": "Verbose Error Messages Disclosing Stack Traces",
        "stride_category": "Information Disclosure",
        "description": "Unhandled exceptions return full stack traces including framework versions, file paths, and DB schema hints.",
        "entry_point": "Any API endpoint",
        "attack_vector": "Network",
        "component": "API",
        "pasta_stage": 3,
        "dread_damage": 5, "dread_reproducibility": 9, "dread_exploitability": 7,
        "dread_affected_users": 5, "dread_discoverability": 8,
        "mitigations": "Implement global exception handler returning generic error messages. Log full details server-side only.",
        "status": "Open",
    },
    {
        "title": "Unauthenticated Rate Limiting Bypass Leading to DoS",
        "stride_category": "Denial of Service",
        "description": "Missing or bypassable rate limiting allows an attacker to exhaust server resources via repeated requests.",
        "entry_point": "POST /api/auth/login, POST /api/password-reset",
        "attack_vector": "Network",
        "component": "AUTH",
        "pasta_stage": 6,
        "dread_damage": 7, "dread_reproducibility": 8, "dread_exploitability": 7,
        "dread_affected_users": 8, "dread_discoverability": 7,
        "mitigations": "Implement IP-based and account-based rate limiting. Use CAPTCHA on sensitive endpoints. Deploy WAF rules.",
        "status": "Open",
    },
    {
        "title": "Broken Object Level Authorization (IDOR) on User Resources",
        "stride_category": "Elevation of Privilege",
        "description": "API endpoints accept user-supplied object IDs without verifying ownership, enabling horizontal privilege escalation.",
        "entry_point": "GET /api/users/{id}/data",
        "attack_vector": "Network",
        "component": "AUTH",
        "pasta_stage": 5,
        "dread_damage": 8, "dread_reproducibility": 9, "dread_exploitability": 9,
        "dread_affected_users": 9, "dread_discoverability": 7,
        "mitigations": "Enforce ownership checks on every resource access. Use opaque UUIDs. Implement ABAC policy layer.",
        "status": "Open",
    },
]

VULNERABILITIES = [
    {
        "title": "Stored XSS in User Profile Bio Field",
        "severity": "High",
        "owasp_category": "A03:2021 – Injection",
        "cvss_score": 7.4,
        "cvss_vector": "AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "affected_component": "Frontend – Profile Page",
        "description": "The bio field stores and renders unsanitised HTML, allowing persistent XSS.",
        "remediation": "Apply HTML entity encoding on output. Implement Content-Security-Policy header.",
        "status": "Open",
    },
    {
        "title": "Session Fixation Attack on Login Flow",
        "severity": "Medium",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "cvss_score": 5.4,
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
        "affected_component": "Auth Layer – Session Manager",
        "description": "Session ID is not regenerated post-authentication, enabling session fixation.",
        "remediation": "Regenerate session ID on every successful login.",
        "status": "Open",
    },
    {
        "title": "Sensitive Data Transmitted Without HSTS",
        "severity": "Medium",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "cvss_score": 5.9,
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "affected_component": "Perimeter – Load Balancer",
        "description": "HTTP Strict Transport Security header is absent, allowing SSL stripping attacks.",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "status": "Open",
    },
    {
        "title": "GraphQL Introspection Enabled in Production",
        "severity": "Low",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "cvss_score": 3.1,
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "affected_component": "Application Layer – GraphQL API",
        "description": "Introspection queries expose the full schema to unauthenticated users.",
        "remediation": "Disable introspection in production environments.",
        "status": "Open",
    },
]

CONTROLS = [
    {
        "title": "Input Validation and Parameterised Queries",
        "control_type": "Preventive",
        "description": "All user input is validated against an allowlist and database queries use parameterised statements.",
        "nist_mapping": "NIST SP 800-53 SI-10",
        "owasp_mapping": "ASVS 5.3.4",
        "implementation_status": "Partially Implemented",
    },
    {
        "title": "Multi-Factor Authentication Enforcement",
        "control_type": "Preventive",
        "description": "MFA is enforced for all privileged accounts and sensitive operations.",
        "nist_mapping": "NIST SP 800-53 IA-2(1)",
        "owasp_mapping": "ASVS 2.8.1",
        "implementation_status": "Not Implemented",
    },
    {
        "title": "Centralised Security Logging and SIEM Integration",
        "control_type": "Detective",
        "description": "All authentication events, privileged actions, and anomalies are forwarded to a SIEM.",
        "nist_mapping": "NIST SP 800-53 AU-2",
        "owasp_mapping": "ASVS 7.1.1",
        "implementation_status": "Not Implemented",
    },
    {
        "title": "Web Application Firewall (WAF) Ruleset",
        "control_type": "Preventive",
        "description": "WAF deployed at the perimeter with OWASP Core Rule Set (CRS) enabled.",
        "nist_mapping": "NIST SP 800-53 SC-7",
        "owasp_mapping": "OWASP CRS",
        "implementation_status": "Implemented",
    },
    {
        "title": "Automated Dependency Vulnerability Scanning",
        "control_type": "Detective",
        "description": "CI/CD pipeline includes SCA tooling to detect known vulnerable dependencies.",
        "nist_mapping": "NIST SP 800-53 SI-2",
        "owasp_mapping": "ASVS 14.2.1",
        "implementation_status": "Partially Implemented",
    },
    {
        "title": "Incident Response and Patch Management Procedure",
        "control_type": "Corrective",
        "description": "Documented IR procedure with defined RTO/RPO and patch deployment SLAs.",
        "nist_mapping": "NIST SP 800-53 IR-4",
        "owasp_mapping": "OWASP SAMM IR-1",
        "implementation_status": "Not Implemented",
    },
]

CHECKLIST_ITEMS = [
    # OWASP Top 10
    {"domain": "OWASP Top 10", "item_code": "A01-01", "description": "Verify that access control is enforced server-side on every request.", "reference": "OWASP A01:2021"},
    {"domain": "OWASP Top 10", "item_code": "A02-01", "description": "Verify that no sensitive data is transmitted in clear text.", "reference": "OWASP A02:2021"},
    {"domain": "OWASP Top 10", "item_code": "A03-01", "description": "Verify all user-supplied input is validated and output is encoded.", "reference": "OWASP A03:2021"},
    {"domain": "OWASP Top 10", "item_code": "A04-01", "description": "Verify threat modeling is performed during design.", "reference": "OWASP A04:2021"},
    {"domain": "OWASP Top 10", "item_code": "A05-01", "description": "Verify no default credentials or unnecessary features are enabled in production.", "reference": "OWASP A05:2021"},
    {"domain": "OWASP Top 10", "item_code": "A06-01", "description": "Verify all third-party components are inventoried and monitored for CVEs.", "reference": "OWASP A06:2021"},
    {"domain": "OWASP Top 10", "item_code": "A07-01", "description": "Verify MFA is available and enforced for privileged accounts.", "reference": "OWASP A07:2021"},
    {"domain": "OWASP Top 10", "item_code": "A08-01", "description": "Verify software supply chain integrity is verified (e.g. signed packages).", "reference": "OWASP A08:2021"},
    {"domain": "OWASP Top 10", "item_code": "A09-01", "description": "Verify security events are logged and alerts configured.", "reference": "OWASP A09:2021"},
    {"domain": "OWASP Top 10", "item_code": "A10-01", "description": "Verify SSRF mitigations are in place for any server-side URL fetch.", "reference": "OWASP A10:2021"},
    # Authentication
    {"domain": "Authentication", "item_code": "AUTH-01", "description": "Passwords are stored using an adaptive hashing function (bcrypt, Argon2).", "reference": "ASVS 2.4.1"},
    {"domain": "Authentication", "item_code": "AUTH-02", "description": "Session IDs are regenerated after successful authentication.", "reference": "ASVS 3.3.1"},
    {"domain": "Authentication", "item_code": "AUTH-03", "description": "Account lockout or delay is applied after repeated failed login attempts.", "reference": "ASVS 2.2.1"},
    {"domain": "Authentication", "item_code": "AUTH-04", "description": "Tokens have appropriate expiry and are invalidated on logout.", "reference": "ASVS 2.8.3"},
    # API Security
    {"domain": "API Security", "item_code": "API-01", "description": "All API endpoints are authenticated and authorised before processing.", "reference": "ASVS 4.1.1"},
    {"domain": "API Security", "item_code": "API-02", "description": "API rate limiting is enforced on all public-facing endpoints.", "reference": "OWASP API Security Top 10 API4"},
    {"domain": "API Security", "item_code": "API-03", "description": "API responses do not expose excessive or sensitive object properties.", "reference": "OWASP API Security Top 10 API3"},
    {"domain": "API Security", "item_code": "API-04", "description": "GraphQL introspection and query depth are restricted in production.", "reference": "OWASP API Security Top 10 API7"},
    # Cryptography
    {"domain": "Cryptography", "item_code": "CRYPT-01", "description": "TLS 1.2+ is enforced; TLS 1.0/1.1 and SSLv3 are disabled.", "reference": "ASVS 9.1.1"},
    {"domain": "Cryptography", "item_code": "CRYPT-02", "description": "HSTS header is present with a max-age of at least one year.", "reference": "ASVS 9.1.3"},
    {"domain": "Cryptography", "item_code": "CRYPT-03", "description": "Sensitive data at rest is encrypted using AES-256 or equivalent.", "reference": "ASVS 6.2.1"},
    # Logging & Monitoring
    {"domain": "Logging & Monitoring", "item_code": "LOG-01", "description": "Authentication events (success and failure) are logged.", "reference": "ASVS 7.2.1"},
    {"domain": "Logging & Monitoring", "item_code": "LOG-02", "description": "Logs do not contain passwords, tokens, or PII.", "reference": "ASVS 7.1.2"},
    {"domain": "Logging & Monitoring", "item_code": "LOG-03", "description": "Alerts are configured for anomalous login or access patterns.", "reference": "ASVS 7.2.2"},
]

RISKS = [
    {
        "title": "Unauthenticated access to sensitive API endpoints",
        "component": "API",
        "description": "REST endpoints handling PII and financial data are accessible without valid authentication tokens.",
        "likelihood": 8, "impact": 9,
        "owner": "Backend Engineering",
        "treatment": "Mitigate",
        "status": "Open",
    },
    {
        "title": "Third-party dependency with known critical CVE",
        "component": "DEPS",
        "description": "Core library in production has an unpatched critical CVE with public exploit code available.",
        "likelihood": 7, "impact": 10,
        "owner": "Platform Team",
        "treatment": "Mitigate",
        "status": "Open",
    },
    {
        "title": "Insecure direct object reference in document download",
        "component": "API",
        "description": "Document download endpoint accepts user-supplied document IDs without ownership verification.",
        "likelihood": 6, "impact": 8,
        "owner": "Backend Engineering",
        "treatment": "Mitigate",
        "status": "In Progress",
    },
    {
        "title": "Missing security headers (CSP, X-Frame-Options)",
        "component": "WEB",
        "description": "Frontend responses are missing recommended security headers enabling clickjacking and XSS escalation.",
        "likelihood": 5, "impact": 5,
        "owner": "Frontend Engineering",
        "treatment": "Mitigate",
        "status": "Open",
    },
]


def seed():
    with app.app_context():
        db.create_all()

        # Only seed if tables are empty
        if Asset.query.count() == 0:
            for a in ASSETS:
                db.session.add(Asset(**a))
            db.session.commit()
            print(f"  ✓ Seeded {len(ASSETS)} assets")

        if Threat.query.count() == 0:
            for i, t in enumerate(THREATS):
                stride_initial = t["stride_category"][0].upper()
                comp = t.pop("component")
                threat_id = f"THREAT-{stride_initial}-{comp}-{i+1:03d}"
                db.session.add(Threat(threat_id=threat_id, **t))
            db.session.commit()
            print(f"  ✓ Seeded {len(THREATS)} threats")

        if Vulnerability.query.count() == 0:
            for i, v in enumerate(VULNERABILITIES):
                db.session.add(Vulnerability(vuln_id=f"VULN-{i+1:03d}", **v))
            db.session.commit()
            print(f"  ✓ Seeded {len(VULNERABILITIES)} vulnerabilities")

        if Control.query.count() == 0:
            for i, c in enumerate(CONTROLS):
                db.session.add(Control(control_id=f"CTRL-{i+1:03d}", **c))
            db.session.commit()
            print(f"  ✓ Seeded {len(CONTROLS)} controls")

        if ChecklistItem.query.count() == 0:
            for item in CHECKLIST_ITEMS:
                db.session.add(ChecklistItem(**item))
            db.session.commit()
            print(f"  ✓ Seeded {len(CHECKLIST_ITEMS)} checklist items")

        if RiskEntry.query.count() == 0:
            for i, r in enumerate(RISKS):
                comp = r.pop("component")
                db.session.add(RiskEntry(risk_id=f"RISK-{comp}-{i+1:03d}", **r))
            db.session.commit()
            print(f"  ✓ Seeded {len(RISKS)} risk entries")

        print("\n✅ Database seeded successfully.")


if __name__ == "__main__":
    print("Seeding SRATMWA database…\n")
    seed()
