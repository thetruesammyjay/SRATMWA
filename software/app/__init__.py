from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from config import Config

db = SQLAlchemy()


def create_app():
    app = Flask(__name__, static_folder="../frontend/static",
                template_folder="../frontend/templates")
    app.config.from_object(Config)

    db.init_app(app)
    CORS(app)

    from app.routes.assets import assets_bp
    from app.routes.threats import threats_bp
    from app.routes.vulnerabilities import vulns_bp
    from app.routes.risks import risks_bp
    from app.routes.controls import controls_bp
    from app.routes.checklists import checklists_bp
    from app.routes.reports import reports_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.views import views_bp

    app.register_blueprint(assets_bp, url_prefix="/api/assets")
    app.register_blueprint(threats_bp, url_prefix="/api/threats")
    app.register_blueprint(vulns_bp, url_prefix="/api/vulnerabilities")
    app.register_blueprint(risks_bp, url_prefix="/api/risks")
    app.register_blueprint(controls_bp, url_prefix="/api/controls")
    app.register_blueprint(checklists_bp, url_prefix="/api/checklists")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(views_bp)

    return app
