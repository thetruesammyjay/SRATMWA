from flask import Blueprint, jsonify, request
from app import db
from app.models import Asset

assets_bp = Blueprint("assets", __name__)


@assets_bp.route("/", methods=["GET"])
def get_assets():
    assets = Asset.query.order_by(Asset.created_at.desc()).all()
    return jsonify([a.to_dict() for a in assets])


@assets_bp.route("/<int:asset_id>", methods=["GET"])
def get_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    return jsonify(asset.to_dict())


@assets_bp.route("/", methods=["POST"])
def create_asset():
    data = request.get_json()
    if not data or not data.get("name") or not data.get("layer"):
        return jsonify({"error": "name and layer are required"}), 400
    asset = Asset(
        name=data["name"],
        layer=data["layer"],
        description=data.get("description", ""),
    )
    db.session.add(asset)
    db.session.commit()
    return jsonify(asset.to_dict()), 201


@assets_bp.route("/<int:asset_id>", methods=["PUT"])
def update_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    data = request.get_json()
    asset.name = data.get("name", asset.name)
    asset.layer = data.get("layer", asset.layer)
    asset.description = data.get("description", asset.description)
    db.session.commit()
    return jsonify(asset.to_dict())


@assets_bp.route("/<int:asset_id>", methods=["DELETE"])
def delete_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    db.session.delete(asset)
    db.session.commit()
    return jsonify({"message": "Asset deleted"}), 200
