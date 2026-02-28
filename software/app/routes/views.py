from flask import Blueprint, render_template

views_bp = Blueprint("views", __name__)


@views_bp.route("/")
def index():
    return render_template("index.html")


@views_bp.route("/threats")
def threats_page():
    return render_template("threats.html")


@views_bp.route("/risks")
def risks_page():
    return render_template("risks.html")


@views_bp.route("/vulnerabilities")
def vulns_page():
    return render_template("vulnerabilities.html")


@views_bp.route("/controls")
def controls_page():
    return render_template("controls.html")


@views_bp.route("/checklists")
def checklists_page():
    return render_template("checklists.html")


@views_bp.route("/reports")
def reports_page():
    return render_template("reports.html")
