from flask import Blueprint, jsonify, request
from app import db
from app.models import Threat, STRIDE_CATEGORIES

threats_bp = Blueprint("threats", __name__)


def _next_threat_id(stride_category, component):
    """Auto-generate a threat ID like THREAT-S-AUTH-001."""
    initial = stride_category[0].upper()
    comp = component.upper()[:4] if component else "GEN"
    count = Threat.query.filter(
        Threat.threat_id.like(f"THREAT-{initial}-{comp}-%")
    ).count()
    return f"THREAT-{initial}-{comp}-{count + 1:03d}"


@threats_bp.route("/", methods=["GET"])
def get_threats():
    stride = request.args.get("stride")
    status = request.args.get("status")
    query = Threat.query
    if stride:
        query = query.filter_by(stride_category=stride)
    if status:
        query = query.filter_by(status=status)
    threats = query.order_by(Threat.created_at.desc()).all()
    return jsonify([t.to_dict() for t in threats])


@threats_bp.route("/<int:threat_id>", methods=["GET"])
def get_threat(threat_id):
    threat = Threat.query.get_or_404(threat_id)
    return jsonify(threat.to_dict())


@threats_bp.route("/", methods=["POST"])
def create_threat():
    data = request.get_json()
    if not data or not data.get("title") or not data.get("stride_category"):
        return jsonify({"error": "title and stride_category are required"}), 400
    if data["stride_category"] not in STRIDE_CATEGORIES:
        return jsonify({"error": f"stride_category must be one of {STRIDE_CATEGORIES}"}), 400

    component = data.get("component", "GEN")
    threat_id = _next_threat_id(data["stride_category"], component)

    threat = Threat(
        threat_id=threat_id,
        asset_id=data.get("asset_id"),
        title=data["title"],
        description=data.get("description", ""),
        stride_category=data["stride_category"],
        dread_damage=int(data.get("dread_damage", 5)),
        dread_reproducibility=int(data.get("dread_reproducibility", 5)),
        dread_exploitability=int(data.get("dread_exploitability", 5)),
        dread_affected_users=int(data.get("dread_affected_users", 5)),
        dread_discoverability=int(data.get("dread_discoverability", 5)),
        pasta_stage=int(data.get("pasta_stage", 1)),
        entry_point=data.get("entry_point", ""),
        attack_vector=data.get("attack_vector", "Network"),
        mitigations=data.get("mitigations", ""),
        status=data.get("status", "Open"),
    )
    db.session.add(threat)
    db.session.commit()
    return jsonify(threat.to_dict()), 201


@threats_bp.route("/<int:threat_id>", methods=["PUT"])
def update_threat(threat_id):
    threat = Threat.query.get_or_404(threat_id)
    data = request.get_json()
    for field in ["title", "description", "stride_category", "entry_point",
                  "attack_vector", "mitigations", "status", "pasta_stage",
                  "dread_damage", "dread_reproducibility", "dread_exploitability",
                  "dread_affected_users", "dread_discoverability", "asset_id"]:
        if field in data:
            setattr(threat, field, data[field])
    db.session.commit()
    return jsonify(threat.to_dict())


@threats_bp.route("/<int:threat_id>", methods=["DELETE"])
def delete_threat(threat_id):
    threat = Threat.query.get_or_404(threat_id)
    db.session.delete(threat)
    db.session.commit()
    return jsonify({"message": "Threat deleted"}), 200


@threats_bp.route("/stride-summary", methods=["GET"])
def stride_summary():
    """Returns count of threats per STRIDE category."""
    summary = {}
    for cat in STRIDE_CATEGORIES:
        summary[cat] = Threat.query.filter_by(stride_category=cat).count()
    return jsonify(summary)
