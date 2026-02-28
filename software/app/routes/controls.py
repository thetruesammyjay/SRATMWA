from flask import Blueprint, jsonify, request
from app import db
from app.models import Control

controls_bp = Blueprint("controls", __name__)


@controls_bp.route("/", methods=["GET"])
def get_controls():
    ctype = request.args.get("type")
    status = request.args.get("status")
    query = Control.query
    if ctype:
        query = query.filter_by(control_type=ctype)
    if status:
        query = query.filter_by(implementation_status=status)
    return jsonify([c.to_dict() for c in query.order_by(Control.created_at.desc()).all()])


@controls_bp.route("/<int:control_id>", methods=["GET"])
def get_control(control_id):
    control = Control.query.get_or_404(control_id)
    return jsonify(control.to_dict())


@controls_bp.route("/", methods=["POST"])
def create_control():
    data = request.get_json()
    if not data or not data.get("title"):
        return jsonify({"error": "title is required"}), 400
    count = Control.query.count()
    control = Control(
        control_id=data.get("control_id", f"CTRL-{count + 1:03d}"),
        title=data["title"],
        description=data.get("description", ""),
        control_type=data.get("control_type", "Preventive"),
        nist_mapping=data.get("nist_mapping", ""),
        owasp_mapping=data.get("owasp_mapping", ""),
        implementation_status=data.get("implementation_status", "Not Implemented"),
        owner=data.get("owner", ""),
        notes=data.get("notes", ""),
    )
    db.session.add(control)
    db.session.commit()
    return jsonify(control.to_dict()), 201


@controls_bp.route("/<int:control_id>", methods=["PUT"])
def update_control(control_id):
    control = Control.query.get_or_404(control_id)
    data = request.get_json()
    for field in ["title", "description", "control_type", "nist_mapping",
                  "owasp_mapping", "implementation_status", "owner", "notes"]:
        if field in data:
            setattr(control, field, data[field])
    db.session.commit()
    return jsonify(control.to_dict())


@controls_bp.route("/<int:control_id>", methods=["DELETE"])
def delete_control(control_id):
    control = Control.query.get_or_404(control_id)
    db.session.delete(control)
    db.session.commit()
    return jsonify({"message": "Control deleted"}), 200
