from flask import Blueprint, jsonify, request
from app import db
from app.models import Report, Threat, RiskEntry, Vulnerability, Control, ChecklistItem
from datetime import datetime

reports_bp = Blueprint("reports", __name__)


def _generate_technical_report():
    """Auto-generate a technical report from current database state."""
    threats = Threat.query.all()
    risks = RiskEntry.query.all()
    vulns = Vulnerability.query.all()
    controls = Control.query.all()

    lines = [
        f"# Technical Security Report",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "---",
        "",
        f"## Summary",
        f"- **Threats identified:** {len(threats)}",
        f"- **Risk entries:** {len(risks)}",
        f"- **Vulnerabilities:** {len(vulns)}",
        f"- **Controls:** {len(controls)}",
        "",
        "---",
        "",
        "## Threat Register",
        "",
        "| ID | Title | STRIDE | DREAD Score | Status |",
        "|---|---|---|---|---|",
    ]
    for t in threats:
        lines.append(f"| {t.threat_id} | {t.title} | {t.stride_category} | {t.dread_score} | {t.status} |")

    lines += [
        "",
        "---",
        "",
        "## Risk Register",
        "",
        "| ID | Title | Likelihood | Impact | Score | Level | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in risks:
        lines.append(f"| {r.risk_id} | {r.title} | {r.likelihood} | {r.impact} | {r.risk_score} | {r.risk_level} | {r.status} |")

    lines += [
        "",
        "---",
        "",
        "## Vulnerabilities",
        "",
        "| ID | Title | CVSS | Severity | Status |",
        "|---|---|---|---|---|",
    ]
    for v in vulns:
        lines.append(f"| {v.vuln_id} | {v.title} | {v.cvss_score} | {v.severity} | {v.status} |")

    return "\n".join(lines)


def _generate_executive_report():
    """Auto-generate an executive summary."""
    threats = Threat.query.all()
    risks = RiskEntry.query.all()
    vulns = Vulnerability.query.all()

    critical = sum(1 for r in risks if r.risk_level == "Critical")
    high = sum(1 for r in risks if r.risk_level == "High")
    medium = sum(1 for r in risks if r.risk_level == "Medium")
    low = sum(1 for r in risks if r.risk_level == "Low")

    open_vulns = sum(1 for v in vulns if v.status == "Open")
    crit_vulns = sum(1 for v in vulns if v.severity == "Critical")

    content = f"""# Executive Security Summary
**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

---

## Key Findings

| Risk Level | Count |
|---|---|
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |

**Total Threats Identified:** {len(threats)}  
**Open Vulnerabilities:** {open_vulns} ({crit_vulns} Critical)

---

## Recommendations

1. Address all **Critical** risk items immediately.
2. Schedule **High** severity items for remediation within the current sprint.
3. Review and update security controls for all identified threat vectors.
4. Re-assess all **Open** vulnerabilities for exploitability.

---

## Methodology

This assessment was conducted using the STRIDE threat modeling framework, DREAD scoring,
PASTA attack simulation methodology, and NIST SP 800-30 risk assessment process,
aligned with OWASP Risk Rating Methodology.
"""
    return content


@reports_bp.route("/", methods=["GET"])
def get_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return jsonify([r.to_dict() for r in reports])


@reports_bp.route("/<int:report_id>", methods=["GET"])
def get_report(report_id):
    report = Report.query.get_or_404(report_id)
    return jsonify(report.to_dict())


@reports_bp.route("/generate", methods=["POST"])
def generate_report():
    data = request.get_json() or {}
    report_type = data.get("report_type", "Technical")
    content = (
        _generate_executive_report()
        if report_type == "Executive"
        else _generate_technical_report()
    )
    title = data.get("title", f"{report_type} Report — {datetime.utcnow().strftime('%Y-%m-%d')}")
    report = Report(title=title, report_type=report_type, content=content)
    db.session.add(report)
    db.session.commit()
    return jsonify(report.to_dict()), 201


@reports_bp.route("/", methods=["POST"])
def create_report():
    data = request.get_json()
    if not data or not data.get("title"):
        return jsonify({"error": "title is required"}), 400
    report = Report(
        title=data["title"],
        report_type=data.get("report_type", "Technical"),
        content=data.get("content", ""),
    )
    db.session.add(report)
    db.session.commit()
    return jsonify(report.to_dict()), 201


@reports_bp.route("/<int:report_id>", methods=["DELETE"])
def delete_report(report_id):
    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    return jsonify({"message": "Report deleted"}), 200
