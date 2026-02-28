from flask import Blueprint, jsonify, request
from app import db
from app.models import Vulnerability

vulns_bp = Blueprint("vulnerabilities", __name__)


@vulns_bp.route("/", methods=["GET"])
def get_vulns():
    severity = request.args.get("severity")
    status = request.args.get("status")
    owasp = request.args.get("owasp")
    query = Vulnerability.query
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if owasp:
        query = query.filter(Vulnerability.owasp_category.contains(owasp))
    return jsonify([v.to_dict() for v in query.order_by(Vulnerability.created_at.desc()).all()])


@vulns_bp.route("/<int:vuln_id>", methods=["GET"])
def get_vuln(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    return jsonify(vuln.to_dict())


@vulns_bp.route("/", methods=["POST"])
def create_vuln():
    data = request.get_json()
    if not data or not data.get("title"):
        return jsonify({"error": "title is required"}), 400
    count = Vulnerability.query.count()
    vuln = Vulnerability(
        vuln_id=data.get("vuln_id", f"VULN-{count + 1:03d}"),
        title=data["title"],
        description=data.get("description", ""),
        owasp_category=data.get("owasp_category", ""),
        cve_id=data.get("cve_id", ""),
        cvss_score=float(data.get("cvss_score", 0.0)),
        cvss_vector=data.get("cvss_vector", ""),
        severity=data.get("severity", "Medium"),
        affected_component=data.get("affected_component", ""),
        proof_of_concept=data.get("proof_of_concept", ""),
        remediation=data.get("remediation", ""),
        status=data.get("status", "Open"),
    )
    db.session.add(vuln)
    db.session.commit()
    return jsonify(vuln.to_dict()), 201


@vulns_bp.route("/<int:vuln_id>", methods=["PUT"])
def update_vuln(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    data = request.get_json()
    for field in ["title", "description", "owasp_category", "cve_id",
                  "cvss_score", "cvss_vector", "severity", "affected_component",
                  "proof_of_concept", "remediation", "status"]:
        if field in data:
            setattr(vuln, field, data[field])
    db.session.commit()
    return jsonify(vuln.to_dict())


@vulns_bp.route("/<int:vuln_id>", methods=["DELETE"])
def delete_vuln(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    db.session.delete(vuln)
    db.session.commit()
    return jsonify({"message": "Vulnerability deleted"}), 200
