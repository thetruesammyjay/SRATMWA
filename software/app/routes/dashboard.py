from flask import Blueprint, jsonify
from app.models import Threat, RiskEntry, Vulnerability, Control, ChecklistItem, Asset, STRIDE_CATEGORIES
from app import db

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/summary", methods=["GET"])
def summary():
    threats = Threat.query.all()
    risks = RiskEntry.query.all()
    vulns = Vulnerability.query.all()
    controls = Control.query.all()
    checklist_items = ChecklistItem.query.all()
    assets = Asset.query.all()

    # Risk level breakdown
    risk_levels = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in risks:
        risk_levels[r.risk_level] += 1

    # STRIDE breakdown
    stride_counts = {cat: 0 for cat in STRIDE_CATEGORIES}
    for t in threats:
        if t.stride_category in stride_counts:
            stride_counts[t.stride_category] += 1

    # Control implementation status
    ctrl_status = {}
    for c in controls:
        ctrl_status[c.implementation_status] = ctrl_status.get(c.implementation_status, 0) + 1

    # Vulnerability severity
    vuln_severity = {}
    for v in vulns:
        vuln_severity[v.severity] = vuln_severity.get(v.severity, 0) + 1

    # Checklist progress
    total_checks = len(checklist_items)
    passed = sum(1 for i in checklist_items if i.status == "Pass")
    completion_pct = round(passed / total_checks * 100, 1) if total_checks else 0

    return jsonify({
        "counts": {
            "assets": len(assets),
            "threats": len(threats),
            "risks": len(risks),
            "vulnerabilities": len(vulns),
            "controls": len(controls),
            "checklist_items": total_checks,
        },
        "risk_levels": risk_levels,
        "stride_breakdown": stride_counts,
        "control_status": ctrl_status,
        "vulnerability_severity": vuln_severity,
        "checklist_completion_pct": completion_pct,
        "open_threats": sum(1 for t in threats if t.status == "Open"),
        "open_risks": sum(1 for r in risks if r.status == "Open"),
        "open_vulns": sum(1 for v in vulns if v.status == "Open"),
    })
