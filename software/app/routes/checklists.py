from flask import Blueprint, jsonify, request
from app import db
from app.models import ChecklistItem

checklists_bp = Blueprint("checklists", __name__)


@checklists_bp.route("/", methods=["GET"])
def get_items():
    domain = request.args.get("domain")
    status = request.args.get("status")
    query = ChecklistItem.query
    if domain:
        query = query.filter_by(domain=domain)
    if status:
        query = query.filter_by(status=status)
    return jsonify([i.to_dict() for i in query.order_by(ChecklistItem.id).all()])


@checklists_bp.route("/<int:item_id>", methods=["GET"])
def get_item(item_id):
    item = ChecklistItem.query.get_or_404(item_id)
    return jsonify(item.to_dict())


@checklists_bp.route("/", methods=["POST"])
def create_item():
    data = request.get_json()
    if not data or not data.get("description") or not data.get("domain"):
        return jsonify({"error": "description and domain are required"}), 400
    item = ChecklistItem(
        domain=data["domain"],
        item_code=data.get("item_code", ""),
        description=data["description"],
        reference=data.get("reference", ""),
        status=data.get("status", "Not Checked"),
        notes=data.get("notes", ""),
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201


@checklists_bp.route("/<int:item_id>", methods=["PUT"])
def update_item(item_id):
    item = ChecklistItem.query.get_or_404(item_id)
    data = request.get_json()
    for field in ["domain", "item_code", "description", "reference", "status", "notes"]:
        if field in data:
            setattr(item, field, data[field])
    db.session.commit()
    return jsonify(item.to_dict())


@checklists_bp.route("/<int:item_id>", methods=["DELETE"])
def delete_item(item_id):
    item = ChecklistItem.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({"message": "Checklist item deleted"}), 200


@checklists_bp.route("/domains", methods=["GET"])
def get_domains():
    rows = db.session.query(ChecklistItem.domain).distinct().all()
    return jsonify([r[0] for r in rows])


@checklists_bp.route("/progress", methods=["GET"])
def get_progress():
    all_items = ChecklistItem.query.all()
    total = len(all_items)
    passed = sum(1 for i in all_items if i.status == "Pass")
    failed = sum(1 for i in all_items if i.status == "Fail")
    na = sum(1 for i in all_items if i.status == "N/A")
    not_checked = total - passed - failed - na
    return jsonify({
        "total": total, "passed": passed, "failed": failed,
        "na": na, "not_checked": not_checked,
        "completion_pct": round((passed + failed + na) / total * 100, 1) if total else 0,
    })
