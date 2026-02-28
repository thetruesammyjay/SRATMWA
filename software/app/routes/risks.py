from flask import Blueprint, jsonify, request
from app import db
from app.models import RiskEntry

risks_bp = Blueprint("risks", __name__)


def _next_risk_id(component):
    comp = component.upper()[:4] if component else "GEN"
    count = RiskEntry.query.filter(RiskEntry.risk_id.like(f"RISK-{comp}-%")).count()
    return f"RISK-{comp}-{count + 1:03d}"


@risks_bp.route("/", methods=["GET"])
def get_risks():
    level = request.args.get("level")
    status = request.args.get("status")
    query = RiskEntry.query
    if status:
        query = query.filter_by(status=status)
    risks = query.order_by(RiskEntry.created_at.desc()).all()
    if level:
        risks = [r for r in risks if r.risk_level.lower() == level.lower()]
    return jsonify([r.to_dict() for r in risks])


@risks_bp.route("/<int:risk_id>", methods=["GET"])
def get_risk(risk_id):
    risk = RiskEntry.query.get_or_404(risk_id)
    return jsonify(risk.to_dict())


@risks_bp.route("/", methods=["POST"])
def create_risk():
    data = request.get_json()
    if not data or not data.get("title"):
        return jsonify({"error": "title is required"}), 400
    component = data.get("component", "GEN")
    risk = RiskEntry(
        risk_id=data.get("risk_id") or _next_risk_id(component),
        asset_id=data.get("asset_id"),
        threat_id_fk=data.get("threat_id"),
        title=data["title"],
        description=data.get("description", ""),
        likelihood=int(data.get("likelihood", 5)),
        impact=int(data.get("impact", 5)),
        owner=data.get("owner", ""),
        treatment=data.get("treatment", "Mitigate"),
        status=data.get("status", "Open"),
        due_date=data.get("due_date", ""),
        notes=data.get("notes", ""),
    )
    db.session.add(risk)
    db.session.commit()
    return jsonify(risk.to_dict()), 201


@risks_bp.route("/<int:risk_id>", methods=["PUT"])
def update_risk(risk_id):
    risk = RiskEntry.query.get_or_404(risk_id)
    data = request.get_json()
    for field in ["title", "description", "likelihood", "impact",
                  "owner", "treatment", "status", "due_date", "notes",
                  "asset_id", "threat_id_fk"]:
        if field in data:
            setattr(risk, field, data[field])
    db.session.commit()
    return jsonify(risk.to_dict())


@risks_bp.route("/<int:risk_id>", methods=["DELETE"])
def delete_risk(risk_id):
    risk = RiskEntry.query.get_or_404(risk_id)
    db.session.delete(risk)
    db.session.commit()
    return jsonify({"message": "Risk entry deleted"}), 200


@risks_bp.route("/matrix", methods=["GET"])
def risk_matrix():
    """Returns risk counts grouped by level for the risk matrix."""
    all_risks = RiskEntry.query.all()
    matrix = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in all_risks:
        matrix[r.risk_level] += 1
    return jsonify(matrix)
